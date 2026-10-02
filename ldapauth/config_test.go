package ldapauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/go-ldap/ldap/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

func entry(t *testing.T, key string, fields map[string]any) *pluginv1.ConfigEntry {
	t.Helper()
	value, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatal(err)
	}
	return &pluginv1.ConfigEntry{Key: key, Value: value}
}

func TestParseConfigAppliesPresetDefaults(t *testing.T) {
	s := ParseConfig([]*pluginv1.ConfigEntry{
		entry(t, "display_name", map[string]any{"value": "Corp"}),
		entry(t, configKeyDirectory, map[string]any{"preset": "active_directory", "urls": "ldaps://dc1.corp.example\nldaps://dc2.corp.example:3269", "bind_dn": "svc@corp.example", "bind_password": "pw", "connect_timeout_seconds": 3.0}),
		entry(t, configKeyUsers, map[string]any{"base_dn": "DC=corp,DC=example", "email_attribute": "userPrincipalName"}),
		entry(t, configKeyGroups, map[string]any{"allowed_groups": "Silo Users\nCN=Silo Admins,OU=Groups,DC=corp,DC=example", "admin_groups": ""}),
	})
	if !s.Ready() {
		t.Fatalf("problems: %s", s.ProblemSummary())
	}
	if s.UniqueIDAttribute != "objectGUID" || s.UsernameAttribute != "sAMAccountName" || s.GroupSource != groupSourceMemberOf {
		t.Fatalf("preset defaults missing: %+v", s)
	}
	if s.EmailAttribute != "userPrincipalName" {
		t.Fatalf("an explicit value must override the preset, got %q", s.EmailAttribute)
	}
	if len(s.URLs) != 2 || s.Issuer() != "ldaps://dc1.corp.example" || s.ConnectTimeout.Seconds() != 3 || s.RequestTimeout != defaultRequestTimeout {
		t.Fatalf("connection settings: %+v", s)
	}
	if len(s.AllowedGroups) != 2 || s.AllowedGroups[0].name != "Silo Users" || s.AllowedGroups[1].dn == nil {
		t.Fatalf("allowed groups: %+v", s.AllowedGroups)
	}
}

func TestParseConfigReportsProblems(t *testing.T) {
	for _, tc := range []struct {
		name      string
		directory map[string]any
		users     map[string]any
		groups    map[string]any
		want      string
	}{
		{"empty", nil, nil, nil, "directory URL is required"},
		{"http url", map[string]any{"urls": "https://ldap.example"}, map[string]any{"base_dn": "dc=x"}, nil, "scheme must be ldap:// or ldaps://"},
		{"dn in url", map[string]any{"urls": "ldap://ldap.example/dc=x"}, map[string]any{"base_dn": "dc=x"}, nil, "must not contain a DN"},
		{"starttls on ldaps", map[string]any{"urls": "ldaps://ldap.example", "start_tls": true}, map[string]any{"base_dn": "dc=x"}, nil, "StartTLS applies only"},
		{"kanidm plain", map[string]any{"preset": "kanidm", "urls": "ldap://idm.example"}, map[string]any{"base_dn": "dc=x"}, nil, "accepts only ldaps://"},
		{"unknown preset", map[string]any{"preset": "nope", "urls": "ldaps://x"}, map[string]any{"base_dn": "dc=x"}, nil, `directory type "nope"`},
		{"bind dn without password", map[string]any{"urls": "ldaps://x", "bind_dn": "cn=svc"}, map[string]any{"base_dn": "dc=x"}, nil, "service account password is required"},
		{"bad ca", map[string]any{"urls": "ldaps://x", "ca_pem": "not pem"}, map[string]any{"base_dn": "dc=x"}, nil, "no PEM certificate"},
		{"filter without placeholder", map[string]any{"urls": "ldaps://x"}, map[string]any{"base_dn": "dc=x", "filter": "(uid=alice)"}, nil, "must contain {username}"},
		{"broken filter", map[string]any{"urls": "ldaps://x"}, map[string]any{"base_dn": "dc=x", "filter": "(uid={username}"}, nil, "not a valid LDAP filter"},
		{"bad attribute", map[string]any{"urls": "ldaps://x"}, map[string]any{"base_dn": "dc=x", "unique_id_attribute": "entry UUID"}, nil, "is not valid"},
		{"bad group dn", map[string]any{"urls": "ldaps://x"}, map[string]any{"base_dn": "dc=x"}, map[string]any{"admin_groups": "cn=a,,dc=x"}, "admin groups"},
		{"group filter placeholder", map[string]any{"urls": "ldaps://x"}, map[string]any{"base_dn": "dc=x"}, map[string]any{"source": "search", "filter": "(cn=x)"}, "must contain {dn} or {username}"},
		{"huge timeout", map[string]any{"urls": "ldaps://x", "request_timeout_seconds": 999.0}, map[string]any{"base_dn": "dc=x"}, nil, "at most 120 seconds"},
		{"lldap StartTLS", map[string]any{"preset": "lldap", "urls": "ldap://x", "start_tls": true}, map[string]any{"base_dn": "dc=x"}, nil, "does not support StartTLS"},
		{"authentik StartTLS", map[string]any{"preset": "authentik", "urls": "ldap://x", "start_tls": true}, map[string]any{"base_dn": "dc=x"}, nil, "does not support StartTLS"},
		{"AD admin group by name", map[string]any{"preset": "active_directory", "urls": "ldaps://x"}, map[string]any{"base_dn": "dc=x"}, map[string]any{"admin_groups": "Domain Admins"}, "list admin groups as full DNs"},
		{"generic admin group by name", map[string]any{"urls": "ldaps://x"}, map[string]any{"base_dn": "dc=x"}, map[string]any{"admin_groups": "silo-admins"}, "list admin groups as full DNs"},
		{"openldap admin group by name", map[string]any{"preset": "openldap", "urls": "ldaps://x"}, map[string]any{"base_dn": "dc=x"}, map[string]any{"admin_groups": "silo-admins"}, "list admin groups as full DNs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var entries []*pluginv1.ConfigEntry
			if tc.directory != nil {
				entries = append(entries, entry(t, configKeyDirectory, tc.directory))
			}
			if tc.users != nil {
				entries = append(entries, entry(t, configKeyUsers, tc.users))
			}
			if tc.groups != nil {
				entries = append(entries, entry(t, configKeyGroups, tc.groups))
			}
			s := ParseConfig(entries)
			if s.Ready() || !strings.Contains(s.ProblemSummary(), tc.want) {
				t.Fatalf("problems = %q, want one containing %q", s.ProblemSummary(), tc.want)
			}
		})
	}
}

func TestParseConfigAllowsAdminGroupNamesWhereNamesAreUnique(t *testing.T) {
	for _, preset := range []string{"lldap", "authentik", "freeipa", "kanidm", "glauth"} {
		s := ParseConfig([]*pluginv1.ConfigEntry{
			entry(t, configKeyDirectory, map[string]any{"preset": preset, "urls": "ldaps://x"}),
			entry(t, configKeyUsers, map[string]any{"base_dn": "dc=x"}),
			entry(t, configKeyGroups, map[string]any{"allowed_groups": "silo-users", "admin_groups": "silo-admins"}),
		})
		if !s.Ready() {
			t.Errorf("%s: %s", preset, s.ProblemSummary())
		}
	}
	// Allowed groups may be names with every preset.
	s := ParseConfig([]*pluginv1.ConfigEntry{
		entry(t, configKeyDirectory, map[string]any{"preset": "active_directory", "urls": "ldaps://x"}),
		entry(t, configKeyUsers, map[string]any{"base_dn": "dc=x"}),
		entry(t, configKeyGroups, map[string]any{"allowed_groups": "Silo Users", "admin_groups": "CN=Silo Admins,OU=Groups,DC=x"}),
	})
	if !s.Ready() {
		t.Fatal(s.ProblemSummary())
	}
}

func TestParseConfigNeverEchoesURLCredentials(t *testing.T) {
	for _, urls := range []string{
		"ldaps://svc:hunter2@ldap.example",
		"ldaps://svc:hunter2@ldap.example/%zz",
		"ldaps://ok.example\nldap://svc:hunter2@[::1",
		"admin:hunter2@ldap.example.com",
		"admin:hunter2@ldap.example.com:389",
		"ldap//admin:hunter2@ldap.example.com",
		"ldap://admin:hun ter2@ldap.example.com",
		"ldap://admin:hunter2,x@ldap.example.com",
		"ldap://admin:hunter2/x@ldap.example.com",
		"ldaps://ldap.example/?pw=hunter2",
		"ldaps://ldap.example/#hunter2",
		"ldaps://hunter2@ldap.example",
	} {
		assertURLProblemHides(t, urls, "hunter2")
	}
	// A password holding "@" plus an unencoded "#", "/" or "?" makes
	// url.Parse report user info and a host that is really part of the
	// password, so each case gets its own sentinel.
	for _, tc := range []struct {
		urls   string
		hidden []string
	}{
		{"ldap://svc:P@ssw0rd#1@dc1.example", []string{"ssw0rd"}},
		{"ldap://svc:Summer@2024/Q3@dc1.example", []string{"2024"}},
		{"ldaps://svc:a@secretpart?x@dc1.example", []string{"secretpart"}},
		{"ldap://svc@corp:4711/pw@dc.example", []string{"4711", "corp"}},
		// "en" alone also occurs in the message text, so look for it as
		// the host the label would show.
		{"ldap://tok@en/rest@dc1.example", []string{"://en"}},
	} {
		assertURLProblemHides(t, tc.urls, tc.hidden...)
	}
}

func assertURLProblemHides(t *testing.T, urls string, hidden ...string) {
	t.Helper()
	s := ParseConfig([]*pluginv1.ConfigEntry{
		entry(t, configKeyDirectory, map[string]any{"urls": urls}),
		entry(t, configKeyUsers, map[string]any{"base_dn": "dc=x"}),
	})
	summary := s.ProblemSummary()
	if s.Ready() || !strings.Contains(summary, "directory URL #") {
		t.Fatalf("%q: problems = %q", urls, summary)
	}
	for _, secret := range hidden {
		if strings.Contains(summary, secret) {
			t.Fatalf("%q: the problem summary leaks %q: %q", urls, secret, summary)
		}
	}
}

func TestDirectoryURLLabelShowsOnlyLDAPURLs(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		// A leading "admin:" reads as a URL scheme and the rest as an opaque
		// part, so these must be named by position only.
		{"admin:hunter2@ldap.example.com", "directory URL #1"},
		{"admin:hunter2@ldap.example.com:389", "directory URL #1"},
		// No scheme at all: the whole string parses as a path.
		{"ldap//admin:hunter2@ldap.example.com", "directory URL #1"},
		{"ldap://admin:hun ter2@ldap.example.com", "directory URL #1"},
		{"ldap:admin:hunter2@ldap.example.com", "directory URL #1"},
		{"ldap:///dc=x", "directory URL #1"},
		// An unencoded "/" or "#" in the password ends the authority early,
		// so url.Parse reports part of the credentials as the host.
		{"ldap://admin:123/ter2@ldap.example.com", "directory URL #1"},
		{"ldap://admin:12#34@ldap.example.com", "directory URL #1"},
		{"ldap://tok/en@ldap.example.com", "directory URL #1"},
		// Any "@" hides the host: a password may itself contain "@", and
		// then url.Parse reports part of it as the host.
		{"ldaps://svc:hunter2@ldap.example:636/dc=x?pw#frag", "directory URL #1"},
		{"ldap://s3cr3t-token@ldap.example", "directory URL #1"},
		{"ldap://svc:P@ssw0rd#1@dc1.example", "directory URL #1"},
		{"ldap://svc:Summer@2024/Q3@dc1.example", "directory URL #1"},
		{"ldaps://svc:a@secretpart?x@dc1.example", "directory URL #1"},
		{"ldap://svc@corp:4711/pw@dc.example", "directory URL #1"},
		{"ldap://tok@en/rest@dc1.example", "directory URL #1"},
		{"ldaps://ldap.example:636/dc=x", "directory URL #1 ldaps://ldap.example:636"},
		{"ldap://ldap.example", "directory URL #1 ldap://ldap.example"},
	} {
		if got := directoryURLLabel(0, tc.raw); got != tc.want {
			t.Errorf("directoryURLLabel(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestParseConfigSplitsURLsOnlyOnNewlines(t *testing.T) {
	s := ParseConfig([]*pluginv1.ConfigEntry{
		entry(t, configKeyDirectory, map[string]any{"urls": "ldaps://a.example\r\n\n  ldaps://b.example:636  \n"}),
		entry(t, configKeyUsers, map[string]any{"base_dn": "dc=x"}),
	})
	if !s.Ready() || len(s.URLs) != 2 || s.URLs[0].Host != "a.example" || s.URLs[1].Host != "b.example:636" {
		t.Fatalf("urls = %v, problems = %q", s.URLs, s.ProblemSummary())
	}
	for _, urls := range []string{
		"ldaps://a.example ldaps://b.example",
		"ldaps://a.example,ldaps://b.example",
		"ldaps://a.example\tldaps://b.example",
		"ldaps://dc1.example,dc2.example",
		"ldaps://dc1.example;dc2.example:636",
		"ldaps://h1.example:636,h2.example:636",
		"ldaps://a.example,",
	} {
		s := ParseConfig([]*pluginv1.ConfigEntry{
			entry(t, configKeyDirectory, map[string]any{"urls": urls}),
			entry(t, configKeyUsers, map[string]any{"base_dn": "dc=x"}),
		})
		summary := s.ProblemSummary()
		if s.Ready() || !strings.Contains(summary, "directory URL #1") || !strings.Contains(summary, "one URL per line") {
			t.Errorf("%q: urls = %v, problems = %q", urls, s.URLs, summary)
		}
	}
	// IPv6 literals keep their colons and zone.
	s = ParseConfig([]*pluginv1.ConfigEntry{
		entry(t, configKeyDirectory, map[string]any{"urls": "ldaps://[2001:db8::1]:636\nldap://[fe80::1%25en0]"}),
		entry(t, configKeyUsers, map[string]any{"base_dn": "dc=x"}),
	})
	if !s.Ready() || len(s.URLs) != 2 {
		t.Fatalf("urls = %v, problems = %q", s.URLs, s.ProblemSummary())
	}
}

func TestParseConfigAsksToBracketIPv6(t *testing.T) {
	for _, urls := range []string{
		"ldap://fe80::1",
		"ldaps://2001:db8::10",
		"ldap://2001:db8::1:389",
		"ldap://::1",
		"ldap://fe80::1%25en0",
		"ldaps://fe80::1%en0/",
	} {
		s := ParseConfig([]*pluginv1.ConfigEntry{
			entry(t, configKeyDirectory, map[string]any{"urls": urls}),
			entry(t, configKeyUsers, map[string]any{"base_dn": "dc=x"}),
		})
		summary := s.ProblemSummary()
		if s.Ready() || !strings.Contains(summary, "put IPv6 addresses in brackets, e.g. ldap://[fe80::1]") {
			t.Errorf("%q: urls = %v, problems = %q", urls, s.URLs, summary)
		}
	}
	// Host lists, credentials, and other schemes keep their own messages.
	for _, tc := range []struct{ urls, want string }{
		{"ldaps://h1.example:636,h2.example:636", "one URL per line"},
		{"ldap://svc:pw@fe80::1", "directory URL #1"},
		{"http://fe80::1", "directory URL #1"},
	} {
		s := ParseConfig([]*pluginv1.ConfigEntry{
			entry(t, configKeyDirectory, map[string]any{"urls": tc.urls}),
			entry(t, configKeyUsers, map[string]any{"base_dn": "dc=x"}),
		})
		summary := s.ProblemSummary()
		if s.Ready() || !strings.Contains(summary, tc.want) || strings.Contains(summary, "brackets") {
			t.Errorf("%q: problems = %q, want %q", tc.urls, summary, tc.want)
		}
	}
}

func TestConfigureNeverFails(t *testing.T) {
	p := New(nil)
	weird := []*pluginv1.ConfigEntry{
		nil,
		{Key: configKeyDirectory},
		entry(t, configKeyUsers, map[string]any{"base_dn": 42.0, "filter": []any{"x"}}),
		entry(t, "unknown", map[string]any{"x": true}),
	}
	if err := p.Configure(context.Background(), weird); err != nil {
		t.Fatalf("Configure failed: %v", err)
	}
	if p.Settings().Ready() {
		t.Fatal("garbage settings reported ready")
	}
}

func TestGroupNames(t *testing.T) {
	groups := []directoryGroup{
		groupFromDN("spn=silo-users@idm.example.com,dc=idm,dc=example,dc=com"),
		groupFromDN("cn=Silo Admins,ou=groups,dc=example"),
		groupFromDN("cn=silo admins,ou=other,dc=example"),
		groupFromDN("not a dn"),
	}
	if got := strings.Join(groupNames(groups), "|"); got != "Silo Admins|not a dn|silo-users" {
		t.Fatalf("names = %q", got)
	}
	refs, err := parseGroupRefs("silo-users@idm.example.com\nsilo-users\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if !groups[0].matches(ref) {
			t.Fatalf("kanidm group should match %q", ref)
		}
	}
	dnRef, _ := parseGroupRefs("CN=silo admins, OU=groups, DC=example")
	if !groups[1].matches(dnRef[0]) || groups[2].matches(dnRef[0]) {
		t.Fatal("DN refs must match the whole DN, case-insensitively")
	}
}

func TestGroupMatchingIgnoresUnicodeLookAlikes(t *testing.T) {
	nameRef, _ := parseGroupRefs("silo-admins\nk-admins")
	dnRef, _ := parseGroupRefs("cn=silo-admins,ou=groups,dc=example")
	for _, tc := range []struct {
		value       string
		nameMatches bool
	}{
		{"cn=\u017filo-admins,ou=groups,dc=example", false}, // LATIN SMALL LETTER LONG S
		{"cn=\u212a-admins,ou=groups,dc=example", false},    // KELVIN SIGN
		{"cn=silo-admins,ou=team-x,dc=example", true},       // same name, other container
		{"cn=silo-admins,ou=group\u017f,dc=example", true},  // look-alike in the DN
	} {
		g := groupFromDN(tc.value)
		if g.matches(dnRef[0]) {
			t.Errorf("%q matched the admin DN", tc.value)
		}
		if got := g.matches(nameRef[0]) || g.matches(nameRef[1]); got != tc.nameMatches {
			t.Errorf("%q matched an admin name: %v, want %v", tc.value, got, tc.nameMatches)
		}
	}
	if !groupFromDN("CN=SILO-ADMINS,OU=Groups,DC=Example").matches(dnRef[0]) {
		t.Fatal("ASCII case must still be ignored")
	}
	if !groupFromDN("cn=K-Admins,dc=example").matches(nameRef[1]) {
		t.Fatal("ASCII case must still be ignored in names")
	}
}

func TestSearchTreatsServerSizeLimitAsFailure(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	d.add("cn=silo-extra,"+testGroups, "", map[string][]string{
		"objectClass": {"groupOfNames"},
		"cn":          {"silo-extra"},
		"member":      {"uid=bob," + testPeople},
	})
	p := newTestProvider(t, d, configOverrides{
		configKeyDirectory: {"preset": "openldap"},
		configKeyGroups:    {"base_dn": testGroups},
	})
	if bob := signIn(t, p, "bob", testPasswords["bob"]); len(bob.GetGroups()) != 3 {
		t.Fatalf("bob groups = %v (%s)", bob.GetGroups(), bob.GetDenialDetail())
	}
	// The server cuts every result at two entries; bob is in three groups.
	d.setServerSizeLimit(2)
	wantDenial(t, signIn(t, p, "bob", testPasswords["bob"]), pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE)
	if got := check(t, p, "uuid-bob").GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE {
		t.Fatalf("truncated group list = %v", got)
	}
	// A limit the plugin asked for is still fine: alice is in one group.
	if alice := signIn(t, p, "alice", testPasswords["alice"]); alice.GetExternalSubject() != "uuid-alice" {
		t.Fatalf("alice = %v %s", alice.GetDenial(), alice.GetDenialDetail())
	}
}

func TestDialTimeoutSplitsTheDeadline(t *testing.T) {
	if got := dialTimeout(context.Background(), 5*time.Second, 3); got != 5*time.Second {
		t.Fatalf("without a deadline = %v", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	if got := dialTimeout(ctx, 5*time.Second, 3); got > 3*time.Second || got < 2*time.Second {
		t.Fatalf("9 s over three URLs = %v", got)
	}
	if got := dialTimeout(ctx, 2*time.Second, 1); got != 2*time.Second {
		t.Fatalf("a shorter connect timeout wins, got %v", got)
	}
}

func TestGUIDRoundTrip(t *testing.T) {
	raw := []byte{0xe0, 0x04, 0x25, 0x3f, 0x89, 0x4f, 0xd3, 0x11, 0x9a, 0x0c, 0x03, 0x05, 0xe8, 0x2c, 0x33, 0x01}
	s, err := formatGUID(raw)
	if err != nil || s != "3f2504e0-4f89-11d3-9a0c-0305e82c3301" {
		t.Fatalf("formatGUID = %q, %v", s, err)
	}
	back, err := parseGUID("{3F2504E0-4F89-11D3-9A0C-0305E82C3301}")
	if err != nil || string(back) != string(raw) {
		t.Fatalf("parseGUID = %x, %v", back, err)
	}
	filter, err := uniqueIDFilterValue("objectGUID", s)
	if err != nil || filter != `\e0\04\25\3f\89\4f\d3\11\9a\0c\03\05\e8\2c\33\01` {
		t.Fatalf("filter value = %q, %v", filter, err)
	}
	if _, err := formatGUID(raw[:4]); err == nil {
		t.Fatal("short GUID accepted")
	}
}

func TestClassifyBindError(t *testing.T) {
	ad := func(code string) error {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data "+code+", v4563"))
	}
	for _, tc := range []struct {
		name string
		err  error
		want pluginv1.AuthDenial
	}{
		{"AD 52e", ad("52e"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"AD 525", ad("525"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"AD 530", ad("530"), pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"AD 531", ad("531"), pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"AD 532", ad("532"), pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED},
		{"AD 533", ad("533"), pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED},
		{"AD 701", ad("701"), pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED},
		{"AD 773", ad("773"), pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED},
		{"AD 775", ad("775"), pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED},
		{"Samba 52e", ldap.NewError(49, errors.New("80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e, v1db1")), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"plain 49", ldap.NewError(49, errors.New("")), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"389 expired", ldap.NewError(49, errors.New("password expired!")), pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED},
		{"FreeIPA 53", ldap.NewError(53, errors.New("Account inactivated. Contact system administrator.")), pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED},
		{"389 retry limit", ldap.NewError(19, errors.New("Exceed password retry limit. Please try later.")), pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED},
		{"confidentiality", ldap.NewError(13, errors.New("TLS confidentiality required")), pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE},
		{"no such object", ldap.NewError(32, errors.New("")), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"network", ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset")), pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE},
		{"busy", ldap.NewError(51, errors.New("busy")), pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE},
	} {
		if got := classifyBindError(tc.err, nil); got.code != tc.want {
			t.Errorf("%s: %v (%s), want %v", tc.name, got.code, got.detail, tc.want)
		}
	}
	changeAfterReset := &ldap.ControlBeheraPasswordPolicy{Error: beheraChangeAfterReset, ErrorString: "Password must be changed"}
	if got := classifyBindError(ldap.NewError(49, errors.New("")), []ldap.Control{changeAfterReset}); got.code != pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED {
		t.Fatalf("changeAfterReset = %v", got.code)
	}
}

// testNow is a fixed clock for expiry checks: 2026-01-01 UTC.
var testNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestDisabledReason(t *testing.T) {
	for _, tc := range []struct {
		attr, value string
		disabled    bool
	}{
		{attrUserAccountControl, "514", true},
		{attrUserAccountControl, "512", false},
		{attrUserAccountControl, "66050", true},
		{attrNSAccountLock, "TRUE", true},
		{attrNSAccountLock, "false", false},
		{attrAuthentikActive, "FALSE", true},
		{attrAuthentikActive, "TRUE", false},
		{attrPwdAccountLockedTime, permanentLockTime, true},
		{attrPwdAccountLockedTime, "20260101000000Z", false},
		// accountExpires is a FILETIME: 100 ns intervals since 1601.
		{attrAccountExpires, "0", false},
		{attrAccountExpires, "9223372036854775807", false},
		{attrAccountExpires, "132223104000000000", true},  // 2020-01-01
		{attrAccountExpires, "134102880000000000", true},  // 2025-12-15, just before now
		{attrAccountExpires, "157469184000000000", false}, // 2100-01-01
		{attrAccountExpires, "not a number", false},
		{attrAccountStatus, "inactive", true},
		{attrAccountStatus, "active", false},
		{attrKanidmExpire, "2020-01-01T00:00:00Z", true},
		{attrKanidmExpire, "2100-01-01T00:00:00+00:00", false},
		{attrKanidmExpire, "garbage", false},
		{attrKanidmValidFrom, "2100-01-01T00:00:00Z", true},
		{attrKanidmValidFrom, "2020-01-01T00:00:00Z", false},
	} {
		e := ldap.NewEntry("uid=x,dc=example", map[string][]string{tc.attr: {tc.value}})
		if got := disabledReason(e, testNow) != ""; got != tc.disabled {
			t.Errorf("%s=%s disabled=%v, want %v", tc.attr, tc.value, got, tc.disabled)
		}
	}
}

func TestPictureURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://img.example/a.png":            "https://img.example/a.png",
		"https://img.example/a.png My picture": "https://img.example/a.png",
		"javascript:alert(1)":                  "",
		"/relative.png":                        "",
		"https://user:pw@img.example/a.png":    "",
	} {
		if got := pictureURL(in); got != want {
			t.Errorf("pictureURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAssetRoutes(t *testing.T) {
	routes := NewAssetRoutes(fstest.MapFS{"ldap.svg": {Data: []byte("<svg/>")}})
	get := func(method, path string) *pluginv1.HandleHTTPResponse {
		resp, err := routes.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: method, Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	ok := get(http.MethodGet, "/assets/ldap.svg")
	if ok.GetStatusCode() != http.StatusOK || ok.GetHeaders()["Content-Type"] != "image/svg+xml" || string(ok.GetBody()) != "<svg/>" {
		t.Fatalf("GET icon = %d %v", ok.GetStatusCode(), ok.GetHeaders())
	}
	for _, path := range []string{"/assets/../manifest.json", "/assets/", "/assets/missing.svg", "/other/ldap.svg", "/assets/ldap.txt", `/assets/a\b.svg`} {
		if got := get(http.MethodGet, path).GetStatusCode(); got != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, got)
		}
	}
	if got := get(http.MethodPost, "/assets/ldap.svg").GetStatusCode(); got != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d", got)
	}
}
