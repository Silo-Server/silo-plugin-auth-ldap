package ldapauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Attributes read to decide whether an account is disabled. Servers ignore
// requested attributes they do not know.
const (
	attrUserAccountControl   = "userAccountControl"   // Active Directory, Samba
	attrNSAccountLock        = "nsAccountLock"        // FreeIPA, 389 Directory Server
	attrAuthentikActive      = "ak-active"            // authentik LDAP outpost
	attrPwdAccountLockedTime = "pwdAccountLockedTime" // OpenLDAP ppolicy
	attrAccountExpires       = "accountExpires"       // Active Directory, Samba
	attrAccountStatus        = "accountStatus"        // GLAuth
	attrKanidmExpire         = "account_expire"       // Kanidm (RFC 3339)
	attrKanidmValidFrom      = "account_valid_from"   // Kanidm (RFC 3339)
	// adAccountDisable is the ACCOUNTDISABLE bit of userAccountControl.
	adAccountDisable = 0x2
	// adNeverExpires is the accountExpires value, besides 0, for an account
	// without an expiry date.
	adNeverExpires = 0x7FFFFFFFFFFFFFFF
	// fileTimeUnixOffset is the number of seconds from the FILETIME epoch
	// (1601-01-01 UTC) to the Unix epoch.
	fileTimeUnixOffset = 11644473600
	// permanentLockTime is the ppolicy value for an administrative lock.
	permanentLockTime = "000001010000Z"
	// membershipProbeSize bounds the entries groupsVisible reads.
	membershipProbeSize = 50
)

// session is one directory connection, opened for a single RPC and closed
// when it returns. The plugin keeps no pools, so it can restart at any time.
type session struct {
	conn      *ldap.Conn
	url       *url.URL
	settings  *Settings
	stopClose func() bool
	// encryption describes the transport for operator messages.
	encryption string
}

// dialAttempt records a failed connection attempt for TestConnection.
type dialAttempt struct {
	url string
	err error
}

// connect dials the configured URLs in order and returns the first that
// answers. Only connection failures fail over; a working server that refuses
// a bind is an answer, not an outage.
func connect(ctx context.Context, s *Settings) (*session, []dialAttempt, error) {
	var attempts []dialAttempt
	for i, u := range s.URLs {
		sess, err := dialOne(ctx, s, u, dialTimeout(ctx, s.ConnectTimeout, len(s.URLs)-i))
		if err == nil {
			return sess, attempts, nil
		}
		attempts = append(attempts, dialAttempt{url: u.Redacted(), err: err})
		if ctx.Err() != nil {
			break
		}
	}
	if len(attempts) == 0 {
		return nil, nil, errors.New("no directory URL is configured")
	}
	parts := make([]string, 0, len(attempts))
	for _, a := range attempts {
		parts = append(parts, fmt.Sprintf("%s: %v", a.url, a.err))
	}
	return nil, attempts, fmt.Errorf("could not connect to the directory (%s)", strings.Join(parts, "; "))
}

// dialTimeout bounds one connection attempt. With a deadline on ctx (the host
// gives each auth call about 10 seconds), the remaining time is split across
// the URLs not yet tried, so an unresponsive first server cannot use up the
// whole budget before the next one is tried.
func dialTimeout(ctx context.Context, connectTimeout time.Duration, untried int) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok || untried < 1 {
		return connectTimeout
	}
	return min(connectTimeout, time.Until(deadline)/time.Duration(untried))
}

func dialOne(ctx context.Context, s *Settings, u *url.URL, timeout time.Duration) (*session, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = ldap.DefaultLdapPort
		if u.Scheme == "ldaps" {
			port = ldap.DefaultLdapsPort
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		ServerName: host,
		RootCAs:    s.RootCAs,
		MinVersion: tls.VersionTLS12,
	}
	isTLS := u.Scheme == "ldaps"
	encryption := "none (unencrypted ldap://)"
	if isTLS {
		tlsConn := tls.Client(raw, tlsConfig)
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		raw = tlsConn
		encryption = "LDAPS " + tlsVersion(tlsConn.ConnectionState().Version)
	}
	conn := ldap.NewConn(raw, isTLS)
	conn.Start()
	conn.SetTimeout(s.RequestTimeout)
	// Closing the connection unblocks any request in flight when the RPC's
	// context ends.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	sess := &session{conn: conn, url: u, settings: s, stopClose: stop, encryption: encryption}
	if s.StartTLS && !isTLS {
		// StartTLS belongs to this URL's share too: go-ldap waits for the
		// reply for the full request timeout and then handshakes with no
		// deadline, so a server that stalls here would otherwise use up the
		// whole budget before the next URL is tried.
		stopDial := context.AfterFunc(dialCtx, func() { _ = conn.Close() })
		err := conn.StartTLS(tlsConfig)
		if !stopDial() {
			err = dialCtx.Err()
		}
		if err != nil {
			sess.close()
			return nil, fmt.Errorf("StartTLS: %w", err)
		}
		state, _ := conn.TLSConnectionState()
		sess.encryption = "StartTLS " + tlsVersion(state.Version)
	}
	return sess, nil
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "(TLS 1.2)"
	case tls.VersionTLS13:
		return "(TLS 1.3)"
	default:
		return ""
	}
}

func (sess *session) close() {
	if sess == nil {
		return
	}
	sess.stopClose()
	_ = sess.conn.Close()
}

// bindService binds with the service account, or stays anonymous when none
// is configured.
func (sess *session) bindService() error {
	if sess.settings.BindDN == "" {
		return nil
	}
	return sess.conn.Bind(sess.settings.BindDN, sess.settings.BindPassword)
}

// bindUser binds as the account and returns the server's response controls.
// It asks for password-policy information so expired and locked passwords
// can be told apart from wrong ones.
func (sess *session) bindUser(dn, password string) ([]ldap.Control, error) {
	if password == "" {
		// An empty password is an unauthenticated bind (RFC 4513 5.1.2),
		// which many servers answer with success.
		return nil, errors.New("empty password")
	}
	result, err := sess.conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: dn,
		Password: password,
		Controls: []ldap.Control{ldap.NewControlBeheraPasswordPolicy()},
	})
	if result != nil {
		return result.Controls, err
	}
	return nil, err
}

// userAttributes lists what the plugin reads from an account entry.
func (s *Settings) userAttributes() []string {
	attrs := []string{s.UsernameAttribute, s.UniqueIDAttribute, attrUserAccountControl, attrNSAccountLock, attrAuthentikActive, attrPwdAccountLockedTime, attrAccountExpires, attrAccountStatus, attrKanidmExpire, attrKanidmValidFrom}
	attrs = append(attrs, s.usernameAssertionAttrs...)
	for _, a := range []string{s.EmailAttribute, s.DisplayNameAttr, s.PictureURLAttribute} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	if s.GroupSource == groupSourceMemberOf {
		attrs = append(attrs, s.MembershipAttribute)
	}
	return dedupeFold(attrs)
}

func dedupeFold(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := values[:0]
	for _, v := range values {
		key := strings.ToLower(v)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out
}

// searchUsers runs a subtree search under the user base DN. It returns at
// most two entries, enough to tell one match from an ambiguous filter.
func (sess *session) searchUsers(filter string) ([]*ldap.Entry, error) {
	return sess.search(sess.settings.UserBaseDN, filter, sess.settings.userAttributes(), 2)
}

func (sess *session) search(base, filter string, attrs []string, sizeLimit int) ([]*ldap.Entry, error) {
	timeLimit := int(sess.settings.RequestTimeout / time.Second)
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, sizeLimit, timeLimit, false, filter, attrs, nil)
	result, err := sess.conn.Search(req)
	if err != nil {
		// A size limit the caller asked for is expected once it has its
		// entries. Any other truncation is the server's own limit, and a
		// partial list (of groups, say) must not pass as the whole answer.
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || sizeLimit <= 0 || result == nil || len(result.Entries) < sizeLimit {
			return nil, err
		}
	}
	if result == nil {
		return nil, nil
	}
	return result.Entries, nil
}

// readBase checks that dn exists with a base-scope search. It reports
// whether the entry itself was returned: some directories (Kanidm) answer a
// search on their suffix without returning the suffix entry, and a missing
// DN is an error (noSuchObject) on every directory that has one.
func (sess *session) readBase(dn string) (visible bool, err error) {
	timeLimit := int(sess.settings.RequestTimeout / time.Second)
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, timeLimit, false, "(objectClass=*)", []string{"1.1"}, nil)
	result, err := sess.conn.Search(req)
	if err != nil {
		return false, err
	}
	return len(result.Entries) > 0, nil
}

// usernameAssertion matches an equality assertion on the username
// placeholder, such as "(uid={username})".
var usernameAssertion = regexp.MustCompile(`\(([A-Za-z0-9][A-Za-z0-9.;-]*)=\{username\}\)`)

// usernameAssertionAttributes lists the attributes a user filter compares
// with the username for equality.
func usernameAssertionAttributes(filter string) []string {
	var attrs []string
	for _, m := range usernameAssertion.FindAllStringSubmatch(filter, -1) {
		attrs = append(attrs, m[1])
	}
	return dedupeFold(attrs)
}

// matchingUsername keeps the entries that really hold the username in one of
// the attributes the filter compares it with. The escaped filter should
// already guarantee that, but some servers (the authentik LDAP outpost, as
// of 2026.8) turn an escaped "\2a" back into a wildcard, so "al*" would
// otherwise find alice. Filters that use {username} only in other forms,
// such as substrings, are not re-checked.
func (s *Settings) matchingUsername(entries []*ldap.Entry, username string) []*ldap.Entry {
	if len(s.usernameAssertionAttrs) == 0 {
		return entries
	}
	var out []*ldap.Entry
	for _, e := range entries {
		if entryHasValue(e, s.usernameAssertionAttrs, username) {
			out = append(out, e)
		}
	}
	return out
}

func entryHasValue(e *ldap.Entry, attrs []string, want string) bool {
	for _, attr := range attrs {
		for _, v := range e.GetEqualFoldAttributeValues(attr) {
			if strings.EqualFold(v, want) {
				return true
			}
		}
	}
	return false
}

// matchingSubject keeps the entries whose unique id is subject, for the same
// reason as matchingUsername.
func (s *Settings) matchingSubject(entries []*ldap.Entry, subject string) []*ldap.Entry {
	var out []*ldap.Entry
	for _, e := range entries {
		if id, err := uniqueIDValue(e, s.UniqueIDAttribute); err == nil && id != "" && strings.EqualFold(id, subject) {
			out = append(out, e)
		}
	}
	return out
}

// userFilter substitutes the escaped username into the configured filter
// (RFC 4515).
func (s *Settings) userFilter(username string) string {
	return strings.ReplaceAll(s.UserFilter, usernamePlaceholder, ldap.EscapeFilter(username))
}

// presenceFilter is the user filter with {username} as a presence wildcard:
// it matches every account the filter admits.
func (s *Settings) presenceFilter() string {
	return strings.ReplaceAll(s.UserFilter, usernamePlaceholder, "*")
}

// uniqueIDFilters returns the lookup filter for an account's unique id,
// restricted by the user filter, and the same lookup without the user filter.
// The second tells "gone" apart from "no longer matches the user filter".
func (s *Settings) uniqueIDFilters(subject string) (restricted, bare string, err error) {
	value, err := uniqueIDFilterValue(s.UniqueIDAttribute, subject)
	if err != nil {
		return "", "", err
	}
	bare = fmt.Sprintf("(%s=%s)", s.UniqueIDAttribute, value)
	// "{username}" becomes a presence wildcard, so the rest of the user
	// filter (object classes, group restrictions) still applies.
	restricted = fmt.Sprintf("(&%s%s)", s.presenceFilter(), bare)
	return restricted, bare, nil
}

// readGroups returns the account's groups from memberOf values or from a
// group search.
func (sess *session) readGroups(entry *ldap.Entry) ([]directoryGroup, error) {
	s := sess.settings
	if s.GroupSource == groupSourceMemberOf {
		values := entry.GetEqualFoldAttributeValues(s.MembershipAttribute)
		groups := make([]directoryGroup, 0, len(values))
		for _, v := range values {
			groups = append(groups, groupFromDN(v))
		}
		return groups, nil
	}
	username := entry.GetEqualFoldAttributeValue(s.UsernameAttribute)
	filter := strings.ReplaceAll(s.GroupFilter, dnPlaceholder, ldap.EscapeFilter(entry.DN))
	filter = strings.ReplaceAll(filter, usernamePlaceholder, ldap.EscapeFilter(username))
	entries, err := sess.search(s.GroupBaseDN, filter, []string{s.GroupNameAttribute}, 0)
	if err != nil {
		return nil, fmt.Errorf("group search: %w", err)
	}
	groups := make([]directoryGroup, 0, len(entries))
	for _, e := range entries {
		g := groupFromDN(e.DN)
		if name := e.GetEqualFoldAttributeValue(s.GroupNameAttribute); name != "" {
			g.name = name
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// groupsVisible guards the group verdicts of CheckAccount. An account's
// groups look empty both when it left them and when the service account
// cannot read group data, so before a missing group ends someone's sessions
// or demotes them, check that group data is visible at all:
//
//   - memberOf: some entry under the user base DN shows a membership value;
//   - group search: one of the configured allowed or admin groups exists.
func (sess *session) groupsVisible() (bool, string) {
	s := sess.settings
	if s.GroupSource == groupSourceMemberOf {
		// Some servers ignore the presence filter (the authentik outpost
		// returns every account), so look through a batch for a value.
		attr := s.MembershipAttribute
		entries, err := sess.search(s.UserBaseDN, "("+attr+"=*)", []string{attr}, membershipProbeSize)
		if err != nil {
			return false, "membership check failed: " + err.Error()
		}
		for _, e := range entries {
			if len(e.GetEqualFoldAttributeValues(attr)) > 0 {
				return true, ""
			}
		}
		return false, "the service account sees no " + attr + " values under " + s.UserBaseDN
	}
	for _, ref := range slices.Concat(s.AllowedGroups, s.AdminGroups) {
		if ref.dn != nil {
			visible, err := sess.readBase(ref.raw)
			if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				return false, "group check failed: " + err.Error()
			}
			if visible {
				return true, ""
			}
			continue
		}
		filter := "(" + s.GroupNameAttribute + "=" + ldap.EscapeFilter(ref.name) + ")"
		entries, err := sess.search(s.GroupBaseDN, filter, []string{"1.1"}, 1)
		if err != nil {
			return false, "group check failed: " + err.Error()
		}
		if len(entries) > 0 {
			return true, ""
		}
	}
	return false, "the service account sees none of the configured groups under " + s.GroupBaseDN
}

// disabledReason reports why the directory marks an entry disabled, or "".
// Temporary lockouts after failed passwords are not reported: anyone who can
// guess at a username could otherwise end that person's sessions.
func disabledReason(entry *ldap.Entry, now time.Time) string {
	if v := entry.GetEqualFoldAttributeValue(attrUserAccountControl); v != "" {
		var uac int64
		if _, err := fmt.Sscan(v, &uac); err == nil && uac&adAccountDisable != 0 {
			return "userAccountControl has ACCOUNTDISABLE set"
		}
	}
	if strings.EqualFold(entry.GetEqualFoldAttributeValue(attrNSAccountLock), "true") {
		return "nsAccountLock is TRUE"
	}
	if strings.EqualFold(entry.GetEqualFoldAttributeValue(attrAuthentikActive), "false") {
		return "ak-active is FALSE"
	}
	if entry.GetEqualFoldAttributeValue(attrPwdAccountLockedTime) == permanentLockTime {
		return "pwdAccountLockedTime marks an administrative lock"
	}
	if expires, ok := adExpiry(entry.GetEqualFoldAttributeValue(attrAccountExpires)); ok && !expires.After(now) {
		return "accountExpires passed on " + expires.UTC().Format(time.DateOnly)
	}
	if strings.EqualFold(entry.GetEqualFoldAttributeValue(attrAccountStatus), "inactive") {
		return "accountStatus is inactive"
	}
	if expires, err := time.Parse(time.RFC3339, entry.GetEqualFoldAttributeValue(attrKanidmExpire)); err == nil && !expires.After(now) {
		return "account_expire passed on " + expires.UTC().Format(time.DateOnly)
	}
	if validFrom, err := time.Parse(time.RFC3339, entry.GetEqualFoldAttributeValue(attrKanidmValidFrom)); err == nil && validFrom.After(now) {
		return "account_valid_from is " + validFrom.UTC().Format(time.DateOnly)
	}
	return ""
}

// adExpiry reads an accountExpires value: a FILETIME count of 100-nanosecond
// intervals since 1601-01-01 UTC. It reports false for a missing or
// malformed value and for the two "never expires" values.
func adExpiry(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	var ft int64
	if _, err := fmt.Sscan(value, &ft); err != nil || ft <= 0 || ft == adNeverExpires {
		return time.Time{}, false
	}
	return time.Unix(ft/1e7-fileTimeUnixOffset, (ft%1e7)*100), true
}
