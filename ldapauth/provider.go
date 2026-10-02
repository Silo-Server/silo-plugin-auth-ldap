// Package ldapauth implements Silo's LDAP auth provider: it checks a username
// and password against a directory and returns typed facts about the
// account. It holds no Silo account logic; the host decides what to do with
// the facts.
package ldapauth

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// maxUsernameBytes bounds the username before it reaches a filter.
	maxUsernameBytes = 256
	// maxSignInProbes bounds the username values CheckAccount tries when
	// it re-runs the sign-in lookup for an account.
	maxSignInProbes = 4
)

// Provider serves AuthProvider and AuthProviderChecks.
type Provider struct {
	pluginv1.UnimplementedAuthProviderServer
	pluginv1.UnimplementedAuthProviderChecksServer

	settings atomic.Pointer[Settings]
	logger   hclog.Logger
}

var (
	_ pluginv1.AuthProviderServer       = (*Provider)(nil)
	_ pluginv1.AuthProviderChecksServer = (*Provider)(nil)
)

// New returns a provider with an empty configuration.
func New(logger hclog.Logger) *Provider {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	p := &Provider{logger: logger}
	p.settings.Store(ParseConfig(nil))
	return p
}

// Configure stores the saved settings. It never fails: incomplete settings
// are kept and reported by TestConnection and at sign-in.
func (p *Provider) Configure(_ context.Context, entries []*pluginv1.ConfigEntry) error {
	s := ParseConfig(entries)
	p.settings.Store(s)
	if !s.Ready() {
		p.logger.Warn("LDAP settings are incomplete", "problems", s.ProblemSummary())
	}
	return nil
}

// Settings returns the running configuration.
func (p *Provider) Settings() *Settings { return p.settings.Load() }

// Authenticate checks a username and password against the directory.
func (p *Provider) Authenticate(ctx context.Context, req *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	s := p.Settings()
	resp, d := authenticate(ctx, s, req.GetUsername(), req.GetPassword())
	if d != nil {
		p.logger.Info("LDAP sign-in refused", "denial", d.code.String(), "detail", d.detail)
		return &pluginv1.AuthenticateResponse{Denial: d.code, DenialDetail: d.detail}, nil
	}
	return resp, nil
}

func authenticate(ctx context.Context, s *Settings, rawUsername, password string) (*pluginv1.AuthenticateResponse, *denial) {
	if !s.Ready() {
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "LDAP settings are incomplete: %s", s.ProblemSummary())
	}
	username := strings.TrimSpace(rawUsername)
	if username == "" || password == "" {
		// Never send an empty password: RFC 4513 makes that an
		// unauthenticated bind, which many servers accept.
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "empty username or password")
	}
	if len(username) > maxUsernameBytes || strings.ContainsFunc(username, unicode.IsControl) {
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "username is too long or contains control characters")
	}

	sess, _, err := connect(ctx, s)
	if err != nil {
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "%v", err)
	}
	defer sess.close()
	if err := sess.bindService(); err != nil {
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "service account bind failed: %v", err)
	}
	entry, subject, d := sess.findUser(username)
	if d != nil {
		return nil, d
	}
	// Read groups with the service account before the user bind, so group
	// visibility doesn't depend on the user's own read rights.
	ev, err := sess.evaluate(entry)
	if err != nil {
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "%v", err)
	}

	controls, err := sess.bindUser(entry.DN, password)
	if err != nil {
		return nil, classifyBindError(err, controls)
	}
	if d := policyControlDenial(controls); d != nil {
		return nil, d
	}
	// Report the directory's disabled flags and the group rules only once
	// the password is proven, so they don't reveal account state to a
	// guesser.
	if ev.disabled != "" {
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED, "%s", ev.disabled)
	}
	if !ev.gate.allowed {
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "not a member of an allowed group")
	}
	resp := accountFacts(s, entry, subject, ev)
	if resp.GetUsername() == "" {
		resp.Username = username
		if resp.GetDisplayName() == "" {
			resp.DisplayName = username
		}
	}
	return resp, nil
}

// findUser runs the sign-in lookup for a username and reads the account's
// unique ID. It refuses a username that matches no entry or several, and,
// unless the directory assigns the ID, an entry whose unique ID another entry
// shares: CheckAccount could not tell the two apart later, and a reused ID
// would hand one person's Silo account to another.
func (sess *session) findUser(username string) (*ldap.Entry, string, *denial) {
	s := sess.settings
	entry, d := sess.userByName(username)
	if d != nil {
		return nil, "", d
	}
	subject, err := uniqueIDValue(entry, s.UniqueIDAttribute)
	if err != nil || subject == "" {
		return nil, "", deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "entry %s has no usable %s attribute", entry.DN, s.UniqueIDAttribute)
	}
	if s.uniqueIDServerAssigned {
		return entry, subject, nil
	}
	_, bare, err := s.uniqueIDFilters(subject)
	if err != nil {
		return nil, "", deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "entry %s: %v", entry.DN, err)
	}
	holders, err := sess.search(s.UserBaseDN, bare, []string{s.UniqueIDAttribute}, 2)
	if err != nil {
		return nil, "", deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "unique ID lookup failed: %v", err)
	}
	if len(s.matchingSubject(holders, subject)) > 1 {
		return nil, "", deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "more than one entry has %s %s", s.UniqueIDAttribute, subject)
	}
	return entry, subject, nil
}

// userByName finds the one entry the user filter matches for a username.
func (sess *session) userByName(username string) (*ldap.Entry, *denial) {
	s := sess.settings
	entries, err := sess.searchUsers(s.userFilter(username))
	if err != nil {
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "user search failed: %v", err)
	}
	entries = s.matchingUsername(entries, username)
	switch len(entries) {
	case 0:
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "no entry matched the user filter")
	case 1:
		return entries[0], nil
	default:
		return nil, deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "the user filter matched more than one entry")
	}
}

// evaluation is what the directory says about an account: its groups, the
// group rules' verdict, and why it is disabled ("" when it isn't).
type evaluation struct {
	groups   []directoryGroup
	gate     gateResult
	disabled string
}

// evaluate reads an account's groups and applies the group rules and the
// disabled flags. Sign-in, CheckAccount, and the connection test share it.
func (sess *session) evaluate(entry *ldap.Entry) (evaluation, error) {
	groups, err := sess.readGroups(entry)
	if err != nil {
		return evaluation{}, err
	}
	return evaluation{
		groups:   groups,
		gate:     applyGates(sess.settings, groups),
		disabled: disabledReason(entry, time.Now()),
	}, nil
}

// accountFacts builds the typed identity for an entry. Without a username
// attribute value it falls back to the value the user filter matches, and
// the display name falls back to the username.
func accountFacts(s *Settings, entry *ldap.Entry, subject string, ev evaluation) *pluginv1.AuthenticateResponse {
	resp := &pluginv1.AuthenticateResponse{
		ExternalSubject: subject,
		Issuer:          s.Issuer(),
		Username:        entry.GetEqualFoldAttributeValue(s.UsernameAttribute),
		Groups:          groupNames(ev.groups),
		ManagedRole:     ev.gate.role,
	}
	if resp.Username == "" {
		for _, attr := range s.usernameAssertionAttrs {
			if v := entry.GetEqualFoldAttributeValue(attr); v != "" {
				resp.Username = v
				break
			}
		}
	}
	if s.DisplayNameAttr != "" {
		resp.DisplayName = entry.GetEqualFoldAttributeValue(s.DisplayNameAttr)
	}
	if resp.DisplayName == "" {
		resp.DisplayName = resp.Username
	}
	if s.EmailAttribute != "" {
		resp.Email = entry.GetEqualFoldAttributeValue(s.EmailAttribute)
	}
	if resp.Email != "" {
		switch s.EmailTrust {
		case emailTrustVerified:
			resp.EmailVerified = proto.Bool(true)
		case emailTrustUnverified:
			resp.EmailVerified = proto.Bool(false)
		}
	}
	if s.PictureURLAttribute != "" {
		resp.PictureUrl = pictureURL(entry.GetEqualFoldAttributeValue(s.PictureURLAttribute))
	}
	if claims, err := structpb.NewStruct(map[string]any{"dn": entry.DN}); err == nil {
		resp.Claims = claims
	}
	return resp
}

// pictureURL keeps only absolute http(s) URLs. labeledURI values may carry a
// label after a space.
func pictureURL(value string) string {
	value = strings.TrimSpace(value)
	if i := strings.IndexAny(value, " \t"); i >= 0 {
		value = value[:i]
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return ""
	}
	return u.String()
}

// CheckAccount re-checks an account by its unique id with the service
// account.
func (p *Provider) CheckAccount(ctx context.Context, req *pluginv1.CheckAccountRequest) (*pluginv1.CheckAccountResponse, error) {
	status, account, detail := checkAccount(ctx, p.Settings(), req.GetExternalSubject())
	if status == checkUnavailable {
		p.logger.Warn("LDAP account check could not reach a verdict", "detail", detail)
	} else if status != checkActive {
		p.logger.Info("LDAP account check", "status", status.String(), "detail", detail)
	}
	return &pluginv1.CheckAccountResponse{Status: status, Account: account}, nil
}

const (
	checkActive       = pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE
	checkNotFound     = pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND
	checkDisabled     = pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_DISABLED
	checkNotPermitted = pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED
	checkUnavailable  = pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE
)

// checkAccount re-checks an account. NOT_FOUND, DISABLED, and NOT_PERMITTED
// end the person's Silo sessions, so each is answered only when the service
// account can see the data behind it; otherwise the answer is UNAVAILABLE and
// the host retries.
func checkAccount(ctx context.Context, s *Settings, subject string) (pluginv1.CheckAccountStatus, *pluginv1.AuthenticateResponse, string) {
	if !s.Ready() {
		return checkUnavailable, nil, "LDAP settings are incomplete: " + s.ProblemSummary()
	}
	if strings.TrimSpace(subject) == "" {
		return checkNotFound, nil, "empty external subject"
	}
	sess, _, err := connect(ctx, s)
	if err != nil {
		return checkUnavailable, nil, err.Error()
	}
	defer sess.close()
	if err := sess.bindService(); err != nil {
		return checkUnavailable, nil, "service account bind failed: " + err.Error()
	}
	entry, status, detail := sess.accountBySubject(subject)
	if entry == nil {
		return status, nil, detail
	}
	ev, err := sess.evaluate(entry)
	if err != nil {
		return checkUnavailable, nil, err.Error()
	}
	if ev.disabled != "" {
		return checkDisabled, nil, ev.disabled
	}
	// No allowed group, or no groups at all while admin groups decide the
	// role: make sure group data is visible before revoking or demoting.
	if !ev.gate.allowed || (len(ev.groups) == 0 && len(s.AdminGroups) > 0) {
		if visible, detail := sess.groupsVisible(); !visible {
			return checkUnavailable, nil, detail
		}
	}
	if !ev.gate.allowed {
		return checkNotPermitted, nil, "not a member of an allowed group"
	}
	return checkActive, accountFacts(s, entry, subject, ev), ""
}

// accountBySubject finds the account with an external subject. It returns
// the entry, or nil with the status to answer and a detail.
func (sess *session) accountBySubject(subject string) (*ldap.Entry, pluginv1.CheckAccountStatus, string) {
	s := sess.settings
	restricted, bare, err := s.uniqueIDFilters(subject)
	if err != nil {
		return nil, checkNotFound, err.Error()
	}
	entries, err := sess.searchUsers(restricted)
	if err != nil {
		return nil, checkUnavailable, "account lookup failed: " + err.Error()
	}
	switch entries = s.matchingSubject(entries, subject); len(entries) {
	case 0:
	case 1:
		return entries[0], checkActive, ""
	default:
		return nil, checkUnavailable, "more than one entry has this unique id"
	}

	// The restricted lookup turns {username} into "*", which is a presence
	// test only in a plain equality assertion: with a filter such as
	// (uid:caseExactMatch:={username}) it matches nobody. Look the ID up
	// without the user filter and ask whether sign-in would still find it.
	entries, err = sess.search(s.UserBaseDN, bare, s.userAttributes(), 2)
	if err != nil {
		return nil, checkUnavailable, "account lookup failed: " + err.Error()
	}
	switch entries = s.matchingSubject(entries, subject); len(entries) {
	case 0:
		if visible, detail := sess.accountsVisible(); !visible {
			return nil, checkUnavailable, detail
		}
		return nil, checkNotFound, "no entry has this unique id"
	case 1:
	default:
		return nil, checkUnavailable, "more than one entry has this unique id"
	}
	entry := entries[0]
	found, err := sess.signInFinds(entry)
	if err != nil {
		return nil, checkUnavailable, "account lookup failed: " + err.Error()
	}
	if found {
		return entry, checkActive, ""
	}
	if visible, detail := sess.accountsVisible(); !visible {
		return nil, checkUnavailable, detail
	}
	return nil, checkNotPermitted, "the account no longer matches the user filter"
}

// signInFinds reports whether the sign-in lookup, run with the entry's own
// username values, still finds this entry.
func (sess *session) signInFinds(entry *ldap.Entry) (bool, error) {
	s := sess.settings
	attrs := append([]string{s.UsernameAttribute}, s.usernameAssertionAttrs...)
	var tried []string
	for _, attr := range attrs {
		for _, name := range entry.GetEqualFoldAttributeValues(attr) {
			if name == "" || slices.Contains(tried, name) || len(tried) >= maxSignInProbes {
				continue
			}
			tried = append(tried, name)
			found, d := sess.userByName(name)
			switch {
			case d == nil && sameDN(found.DN, entry.DN):
				return true, nil
			case d != nil && d.code == pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE:
				return false, errors.New(d.detail)
			}
		}
	}
	return false, nil
}

// accountsVisible guards NOT_FOUND and NOT_PERMITTED: it checks that the
// service account sees any account the user filter admits, so a revoked read
// permission or a wrong base DN doesn't sign everyone out.
func (sess *session) accountsVisible() (bool, string) {
	s := sess.settings
	visible, err := sess.search(s.UserBaseDN, s.presenceFilter(), []string{"1.1"}, 1)
	if err != nil {
		return false, "account lookup failed: " + err.Error()
	}
	if len(visible) == 0 {
		return false, "the service account sees no accounts under " + s.UserBaseDN
	}
	return true, ""
}

// EndSessionUrl answers with no URL: a directory has no sign-in session to
// end.
func (p *Provider) EndSessionUrl(context.Context, *pluginv1.AuthEndSessionUrlRequest) (*pluginv1.AuthEndSessionUrlResponse, error) {
	return &pluginv1.AuthEndSessionUrlResponse{}, nil
}
