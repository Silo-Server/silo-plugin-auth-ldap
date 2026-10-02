package ldapauth

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/go-ldap/ldap/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

// Global config keys the plugin reads. Each key is one global_config_schema
// entry in manifest.json; the host sends each saved entry as a ConfigEntry
// whose value is an object with the fields listed in that schema. The host
// itself reads display_name and icon_url_path.
const (
	configKeyDirectory = "directory"
	configKeyUsers     = "users"
	configKeyGroups    = "groups"
)

// Group sources.
const (
	groupSourceDefault  = "default"
	groupSourceMemberOf = "memberof"
	groupSourceSearch   = "search"
)

// Email trust values: how to report email_verified.
const (
	emailTrustUnknown    = "unknown"
	emailTrustVerified   = "verified"
	emailTrustUnverified = "unverified"
)

const (
	defaultConnectTimeout = 5 * time.Second
	defaultRequestTimeout = 10 * time.Second
	maxTimeout            = 120 * time.Second
	usernamePlaceholder   = "{username}"
	dnPlaceholder         = "{dn}"
)

// Settings is the parsed, preset-resolved plugin configuration. It is
// immutable once built; Configure swaps in a new value.
type Settings struct {
	Preset string

	URLs           []*url.URL
	StartTLS       bool
	RootCAs        *x509.CertPool
	BindDN         string
	BindPassword   string
	ConnectTimeout time.Duration
	RequestTimeout time.Duration

	UserBaseDN string
	UserFilter string
	// usernameAssertionAttrs are the attributes the user filter compares
	// with {username} for equality; results are re-checked against them.
	usernameAssertionAttrs []string
	UsernameAttribute      string
	EmailAttribute         string
	DisplayNameAttr        string
	UniqueIDAttribute      string
	// uniqueIDServerAssigned reports that the directory assigns unique IDs
	// and never reuses them, so sign-in can skip checking that no other
	// entry holds the same one.
	uniqueIDServerAssigned bool
	PictureURLAttribute    string
	EmailTrust             string
	TestUsername           string

	GroupSource         string
	MembershipAttribute string
	GroupBaseDN         string
	GroupFilter         string
	GroupNameAttribute  string
	AllowedGroups       []groupRef
	AdminGroups         []groupRef

	// Problems lists settings that are missing or invalid. Authenticate and
	// CheckAccount refuse to run while it is non-empty; TestConnection
	// reports it as a failed step.
	Problems []string
}

// Issuer is the informational issuer reported with each identity: the first
// configured directory URL.
func (s *Settings) Issuer() string {
	if s == nil || len(s.URLs) == 0 {
		return ""
	}
	return s.URLs[0].String()
}

// Ready reports whether the settings are complete enough to talk to a
// directory.
func (s *Settings) Ready() bool { return s != nil && len(s.Problems) == 0 }

// ProblemSummary joins the problems for a denial detail or a test message.
func (s *Settings) ProblemSummary() string {
	if s == nil {
		return "the plugin has not been configured"
	}
	return strings.Join(s.Problems, "; ")
}

// rawConfig is the decoded ConfigEntry set before presets and validation.
type rawConfig struct {
	directory map[string]any
	users     map[string]any
	groups    map[string]any
}

// ParseConfig turns ConfigEntry values into Settings. It never fails: missing
// or invalid values are recorded in Settings.Problems so the plugin can start
// on an empty or half-finished configuration and report the gaps later.
func ParseConfig(entries []*pluginv1.ConfigEntry) *Settings {
	raw := rawConfig{}
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		value := structMap(entry.GetValue())
		switch entry.GetKey() {
		case configKeyDirectory:
			raw.directory = value
		case configKeyUsers:
			raw.users = value
		case configKeyGroups:
			raw.groups = value
		}
	}
	return raw.settings()
}

func structMap(value *structpb.Struct) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value.AsMap()
}

func (raw rawConfig) settings() *Settings {
	s := &Settings{}
	var problems []string
	problem := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	presetID := strings.ToLower(stringValue(raw.directory, "preset"))
	if presetID == "" {
		presetID = presetGeneric
	}
	p, ok := presets[presetID]
	if !ok {
		problem("directory type %q is not recognized", presetID)
		p = presets[presetGeneric]
		presetID = presetGeneric
	}
	s.Preset = presetID

	// Connection. URLs go one per line; a line is never split further, so a
	// password with a space or comma can't be cut into pieces that each get
	// quoted back as a URL of their own.
	lines := splitLines(stringValue(raw.directory, "urls"))
	for i, line := range lines {
		u, err := parseDirectoryURL(line)
		if err != nil {
			problem("%s: %v", directoryURLLabel(i, line), err)
			continue
		}
		s.URLs = append(s.URLs, u)
	}
	if len(lines) == 0 {
		problem("directory URL is required")
	}
	s.StartTLS = boolValue(raw.directory, "start_tls")
	for _, u := range s.URLs {
		if s.StartTLS && u.Scheme == "ldaps" {
			problem("StartTLS applies only to ldap:// URLs; %s already uses TLS", u.Redacted())
		}
		if p.RequireLDAPS && u.Scheme != "ldaps" {
			problem("%s accepts only ldaps:// connections; %s is not ldaps://", p.Label, u.Redacted())
		}
	}
	if s.StartTLS && p.NoStartTLS {
		problem("%s does not support StartTLS; use an ldaps:// URL instead", p.Label)
	}
	if pem := strings.TrimSpace(stringValue(raw.directory, "ca_pem")); pem != "" {
		pool, err := certPool(pem)
		if err != nil {
			problem("CA certificate: %v", err)
		} else {
			s.RootCAs = pool
		}
	}
	s.BindDN = strings.TrimSpace(stringValue(raw.directory, "bind_dn"))
	s.BindPassword = stringValue(raw.directory, "bind_password")
	if s.BindDN != "" && s.BindPassword == "" {
		problem("service account password is required when a service account DN is set")
	}
	// The service bind name is not checked as a DN: Active Directory also
	// accepts a user principal name such as svc-silo@corp.example.
	s.ConnectTimeout = durationValue(raw.directory, "connect_timeout_seconds", defaultConnectTimeout, problem)
	s.RequestTimeout = durationValue(raw.directory, "request_timeout_seconds", defaultRequestTimeout, problem)

	// Users.
	s.UserBaseDN = strings.TrimSpace(stringValue(raw.users, "base_dn"))
	if s.UserBaseDN == "" {
		problem("user base DN is required")
	} else if _, err := ldap.ParseDN(s.UserBaseDN); err != nil {
		problem("user base DN is not a valid DN: %v", err)
	}
	s.UserFilter = orDefault(stringValue(raw.users, "filter"), p.UserFilter)
	if err := validateTemplateFilter(s.UserFilter, usernamePlaceholder); err != nil {
		problem("user filter: %v", err)
	}
	s.usernameAssertionAttrs = usernameAssertionAttributes(s.UserFilter)
	s.UsernameAttribute = orDefault(stringValue(raw.users, "username_attribute"), p.UsernameAttribute)
	s.EmailAttribute = orDefault(stringValue(raw.users, "email_attribute"), p.EmailAttribute)
	s.DisplayNameAttr = orDefault(stringValue(raw.users, "display_name_attribute"), p.DisplayNameAttribute)
	s.UniqueIDAttribute = orDefault(stringValue(raw.users, "unique_id_attribute"), p.UniqueIDAttribute)
	_, standardID := serverAssignedIDAttributes[strings.ToLower(s.UniqueIDAttribute)]
	s.uniqueIDServerAssigned = standardID || (p.ServerAssignedID && strings.EqualFold(s.UniqueIDAttribute, p.UniqueIDAttribute))
	s.PictureURLAttribute = strings.TrimSpace(stringValue(raw.users, "picture_url_attribute"))
	for name, value := range map[string]string{
		"username attribute":  s.UsernameAttribute,
		"unique ID attribute": s.UniqueIDAttribute,
	} {
		if value == "" {
			problem("%s is required", name)
		}
	}
	for _, attr := range []string{s.UsernameAttribute, s.EmailAttribute, s.DisplayNameAttr, s.UniqueIDAttribute, s.PictureURLAttribute} {
		if attr != "" && !validAttributeName(attr) {
			problem("attribute name %q is not valid", attr)
		}
	}
	s.EmailTrust = strings.ToLower(orDefault(stringValue(raw.users, "email_verified"), emailTrustUnknown))
	switch s.EmailTrust {
	case emailTrustUnknown, emailTrustVerified, emailTrustUnverified:
	default:
		problem("email verification value %q is not recognized", s.EmailTrust)
	}
	s.TestUsername = strings.TrimSpace(stringValue(raw.users, "test_username"))

	// Groups.
	s.GroupSource = strings.ToLower(stringValue(raw.groups, "source"))
	if s.GroupSource == "" || s.GroupSource == groupSourceDefault {
		s.GroupSource = p.GroupSource
	}
	switch s.GroupSource {
	case groupSourceMemberOf:
		s.MembershipAttribute = orDefault(stringValue(raw.groups, "membership_attribute"), p.MembershipAttribute)
		if !validAttributeName(s.MembershipAttribute) {
			problem("group membership attribute %q is not valid", s.MembershipAttribute)
		}
	case groupSourceSearch:
		s.GroupBaseDN = orDefault(stringValue(raw.groups, "base_dn"), s.UserBaseDN)
		if _, err := ldap.ParseDN(s.GroupBaseDN); err != nil && s.GroupBaseDN != "" {
			problem("group base DN is not a valid DN: %v", err)
		}
		s.GroupFilter = orDefault(stringValue(raw.groups, "filter"), p.GroupFilter)
		if err := validateTemplateFilter(s.GroupFilter, dnPlaceholder, usernamePlaceholder); err != nil {
			problem("group filter: %v", err)
		}
		s.GroupNameAttribute = orDefault(stringValue(raw.groups, "name_attribute"), p.GroupNameAttribute)
		if !validAttributeName(s.GroupNameAttribute) {
			problem("group name attribute %q is not valid", s.GroupNameAttribute)
		}
	default:
		problem("group source %q is not recognized", s.GroupSource)
	}
	var err error
	if s.AllowedGroups, err = parseGroupRefs(stringValue(raw.groups, "allowed_groups")); err != nil {
		problem("allowed groups: %v", err)
	}
	if s.AdminGroups, err = parseGroupRefs(stringValue(raw.groups, "admin_groups")); err != nil {
		problem("admin groups: %v", err)
	}
	if !p.UniqueGroupNames {
		// A bare name matches a group of that name in any container, so
		// anyone who can create a group elsewhere could make themselves
		// an admin.
		for _, ref := range s.AdminGroups {
			if ref.dn == nil {
				problem("admin groups: %q is a group name; with %s, list admin groups as full DNs, because group names are unique only within their container", ref.raw, p.Label)
			}
		}
	}

	s.Problems = problems
	return s
}

func parseDirectoryURL(raw string) (*url.URL, error) {
	if strings.ContainsFunc(raw, unicode.IsSpace) {
		return nil, fmt.Errorf("must not contain spaces; put one URL per line")
	}
	if unbracketedIPv6(raw) {
		return nil, errUnbracketedIPv6
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a valid URL")
	}
	switch u.Scheme {
	case "ldap", "ldaps":
	default:
		return nil, fmt.Errorf("scheme must be ldap:// or ldaps://")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("host is required")
	}
	// A comma- or semicolon-separated host list parses as one odd host name,
	// and "ldaps://a,ldaps://b" as a host followed by a path. Reject both
	// here so the operator sees why, not a DN hint or a later dial error.
	if !strings.HasPrefix(u.Host, "[") && strings.ContainsFunc(u.Hostname(), func(r rune) bool {
		return !isHostNameRune(r)
	}) {
		return nil, fmt.Errorf("host must not contain commas or other separators; put one URL per line")
	}
	if u.User != nil {
		return nil, fmt.Errorf("must not contain credentials")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("must not contain a DN, query, or fragment; set the base DN separately")
	}
	u.Path = ""
	return u, nil
}

var errUnbracketedIPv6 = errors.New("put IPv6 addresses in brackets, e.g. ldap://[fe80::1]")

// unbracketedIPv6 reports an ldap:// or ldaps:// URL whose host, port
// included, is a bare IPv6 address. url.Parse reads "ldap://fe80::1" as host
// "fe80:" and port "1", and rejects a zone outright, so without this the
// operator sees a separator or invalid-URL message.
func unbracketedIPv6(raw string) bool {
	rest, ok := strings.CutPrefix(raw, "ldap://")
	if !ok {
		if rest, ok = strings.CutPrefix(raw, "ldaps://"); !ok {
			return false
		}
	}
	host, _, _ := strings.Cut(rest, "/")
	if strings.ContainsAny(host, "@?#[") || strings.Count(host, ":") < 2 {
		return false
	}
	if unescaped, err := url.PathUnescape(host); err == nil {
		host = unescaped
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Is6()
}

func isHostNameRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_'
}

// directoryURLLabel names a rejected URL in an operator message. It never
// quotes the raw value, which may carry a password. Only an ldap:// or
// ldaps:// URL with a host and no "@" anywhere is shown, as scheme and host
// only. Anything else (no scheme, another scheme such as the "admin" in
// "admin:secret@host", an opaque part, or whitespace) could put the password
// anywhere in the string, so it is named only by its position in the list.
// So is any URL containing "@": a password may itself hold "@", "/", "?" or
// "#", and then what url.Parse calls the host ("ssw0rd" in
// "ldap://svc:P@ssw0rd#1@host", "admin:123" in "ldap://admin:123/x@host") is
// part of the credentials. parseDirectoryURL rejects user info anyway, so
// the position alone identifies the line.
func directoryURLLabel(index int, raw string) string {
	label := fmt.Sprintf("directory URL #%d", index+1)
	if strings.ContainsFunc(raw, unicode.IsSpace) {
		return label
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" || u.Opaque != "" {
		return label
	}
	if strings.Contains(raw, "@") {
		return label
	}
	shown := url.URL{Scheme: u.Scheme, Host: u.Host}
	return label + " " + shown.String()
}

func certPool(pemData string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return nil, fmt.Errorf("no PEM certificate found")
	}
	return pool, nil
}

// validateTemplateFilter checks that a filter template names at least one of
// the placeholders and compiles once they are substituted.
func validateTemplateFilter(template string, placeholders ...string) error {
	if strings.TrimSpace(template) == "" {
		return fmt.Errorf("is required")
	}
	found := false
	probe := template
	for _, placeholder := range placeholders {
		if strings.Contains(probe, placeholder) {
			found = true
			probe = strings.ReplaceAll(probe, placeholder, "probe")
		}
	}
	if !found {
		return fmt.Errorf("must contain %s", strings.Join(placeholders, " or "))
	}
	if _, err := ldap.CompileFilter(probe); err != nil {
		return fmt.Errorf("is not a valid LDAP filter: %v", err)
	}
	return nil
}

// validAttributeName accepts an attribute description: a name or OID with
// optional options, such as "mail" or "mail;primary".
func validAttributeName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == ';', r == '_':
		default:
			return false
		}
	}
	return true
}

func orDefault(value, fallback string) string {
	if v := strings.TrimSpace(value); v != "" {
		return v
	}
	return fallback
}

func stringValue(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%g", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func boolValue(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func durationValue(m map[string]any, key string, fallback time.Duration, problem func(string, ...any)) time.Duration {
	var seconds float64
	switch v := m[key].(type) {
	case nil:
		return fallback
	case float64:
		seconds = v
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return fallback
		}
		if _, err := fmt.Sscanf(v, "%g", &seconds); err != nil {
			problem("%s must be a number of seconds", key)
			return fallback
		}
	default:
		problem("%s must be a number of seconds", key)
		return fallback
	}
	if seconds <= 0 {
		return fallback
	}
	d := time.Duration(seconds * float64(time.Second))
	if d > maxTimeout {
		problem("%s must be at most %d seconds", key, int(maxTimeout/time.Second))
		return maxTimeout
	}
	return d
}

// splitLines splits on newlines only: group DNs contain commas.
func splitLines(value string) []string {
	var out []string
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
