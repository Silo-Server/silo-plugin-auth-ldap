package ldapauth

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/jimlambrt/gldap"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	testBase      = "dc=example,dc=test"
	testPeople    = "ou=people," + testBase
	testGroups    = "ou=groups," + testBase
	testService   = "cn=svc," + testBase
	testSvcPass   = "svc-secret"
	usersGroupDN  = "cn=silo-users," + testGroups
	adminsGroupDN = "cn=silo-admins," + testGroups
)

var testPasswords = map[string]string{
	"alice": "alice-pw",
	"bob":   "bob-pw",
	"carol": "carol-pw",
	"dave":  "dave-pw",
}

// seedDirectory creates the lab's people: alice (silo-users), bob
// (silo-users, silo-admins), carol (no group), dave (silo-users).
func seedDirectory(d *fakeDirectory) {
	d.add(testBase, "", map[string][]string{"objectClass": {"domain"}, "dc": {"example"}})
	d.add(testPeople, "", map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"people"}})
	d.add(testGroups, "", map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"groups"}})
	d.add(testService, testSvcPass, map[string][]string{"cn": {"svc"}})
	person := func(uid, name string, groups ...string) {
		d.add("uid="+uid+","+testPeople, testPasswords[uid], map[string][]string{
			"objectClass": {"inetOrgPerson", "person"},
			"uid":         {uid},
			"cn":          {name},
			"displayName": {name},
			"mail":        {uid + "@example.com"},
			"entryUUID":   {"uuid-" + uid},
			"memberOf":    groups,
		})
	}
	person("alice", "Alice Adams", usersGroupDN)
	person("bob", "Bob Baker", usersGroupDN, adminsGroupDN)
	person("carol", "Carol Clark")
	person("dave", "Dave Davis", usersGroupDN)
	d.add(usersGroupDN, "", map[string][]string{
		"objectClass": {"groupOfNames"},
		"cn":          {"silo-users"},
		"member":      {"uid=alice," + testPeople, "uid=bob," + testPeople, "uid=dave," + testPeople},
	})
	d.add(adminsGroupDN, "", map[string][]string{
		"objectClass": {"groupOfNames"},
		"cn":          {"silo-admins"},
		"member":      {"uid=bob," + testPeople},
	})
}

type configOverrides map[string]map[string]any

// testConfig builds ConfigEntry values for the fake directory. Overrides
// replace individual fields; a nil field value deletes it.
func testConfig(t *testing.T, d *fakeDirectory, overrides configOverrides) []*pluginv1.ConfigEntry {
	t.Helper()
	sections := map[string]map[string]any{
		configKeyDirectory: {
			"preset":        "generic",
			"urls":          d.url(),
			"ca_pem":        d.caPEM,
			"bind_dn":       testService,
			"bind_password": testSvcPass,
		},
		configKeyUsers: {"base_dn": testPeople},
		configKeyGroups: {
			"allowed_groups": "silo-users",
			"admin_groups":   adminsGroupDN,
		},
	}
	for section, fields := range overrides {
		if sections[section] == nil {
			sections[section] = map[string]any{}
		}
		for k, v := range fields {
			if v == nil {
				delete(sections[section], k)
				continue
			}
			sections[section][k] = v
		}
	}
	entries := make([]*pluginv1.ConfigEntry, 0, len(sections))
	for key, fields := range sections {
		value, err := structpb.NewStruct(fields)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, &pluginv1.ConfigEntry{Key: key, Value: value})
	}
	return entries
}

func newTestProvider(t *testing.T, d *fakeDirectory, overrides configOverrides) *Provider {
	t.Helper()
	p := New(nil)
	if err := p.Configure(context.Background(), testConfig(t, d, overrides)); err != nil {
		t.Fatal(err)
	}
	if !p.Settings().Ready() {
		t.Fatalf("settings not ready: %s", p.Settings().ProblemSummary())
	}
	return p
}

func signIn(t *testing.T, p *Provider, username, password string) *pluginv1.AuthenticateResponse {
	t.Helper()
	resp, err := p.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{Username: username, Password: password})
	if err != nil {
		t.Fatalf("Authenticate returned a gRPC error: %v", err)
	}
	return resp
}

func wantDenial(t *testing.T, resp *pluginv1.AuthenticateResponse, want pluginv1.AuthDenial) {
	t.Helper()
	if resp.GetDenial() != want {
		t.Fatalf("denial = %v (%s), want %v", resp.GetDenial(), resp.GetDenialDetail(), want)
	}
	if resp.GetExternalSubject() != "" {
		t.Fatalf("denied response carries external_subject %q", resp.GetExternalSubject())
	}
}

func TestAuthenticateReturnsFacts(t *testing.T) {
	for _, mode := range []fakeMode{fakeLDAPS, fakePlainWithStartTLS} {
		d := startFakeDirectory(t, mode)
		seedDirectory(d)
		overrides := configOverrides{}
		if mode == fakePlainWithStartTLS {
			overrides[configKeyDirectory] = map[string]any{"start_tls": true}
		}
		p := newTestProvider(t, d, overrides)

		alice := signIn(t, p, "alice", testPasswords["alice"])
		if alice.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED {
			t.Fatalf("alice denied: %v %s", alice.GetDenial(), alice.GetDenialDetail())
		}
		if alice.GetExternalSubject() != "uuid-alice" || alice.GetUsername() != "alice" ||
			alice.GetEmail() != "alice@example.com" || alice.GetDisplayName() != "Alice Adams" {
			t.Fatalf("alice facts = %+v", alice)
		}
		if alice.EmailVerified != nil {
			t.Fatalf("email_verified = %v, want unset", alice.GetEmailVerified())
		}
		if alice.GetIssuer() != d.url() {
			t.Fatalf("issuer = %q, want %q", alice.GetIssuer(), d.url())
		}
		if !slices.Equal(alice.GetGroups(), []string{"silo-users"}) {
			t.Fatalf("alice groups = %v", alice.GetGroups())
		}
		if alice.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER {
			t.Fatalf("alice role = %v", alice.GetManagedRole())
		}

		bob := signIn(t, p, "bob", testPasswords["bob"])
		if bob.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
			t.Fatalf("bob role = %v (%s)", bob.GetManagedRole(), bob.GetDenialDetail())
		}
		if !slices.Equal(bob.GetGroups(), []string{"silo-admins", "silo-users"}) {
			t.Fatalf("bob groups = %v", bob.GetGroups())
		}

		wantDenial(t, signIn(t, p, "carol", testPasswords["carol"]), pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED)
		wantDenial(t, signIn(t, p, "alice", "wrong"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
		wantDenial(t, signIn(t, p, "nobody", "whatever"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
	}
}

func TestAuthenticateRejectsEmptyPasswordWithoutBinding(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	p := newTestProvider(t, d, nil)
	// The fake accepts unauthenticated binds, like many real servers.
	wantDenial(t, signIn(t, p, "alice", ""), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
	wantDenial(t, signIn(t, p, "", "x"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
	wantDenial(t, signIn(t, p, "alice\x00", "x"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
	for _, dn := range d.seenBinds() {
		if strings.Contains(dn, "alice") {
			t.Fatalf("bound as %q for an empty password", dn)
		}
	}
}

func TestAuthenticateEscapesFilterInjection(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	p := newTestProvider(t, d, configOverrides{configKeyGroups: {"allowed_groups": nil, "admin_groups": nil}})

	for _, username := range []string{"*)(uid=*", "*", "al*", "alice)(|(uid=*"} {
		resp := signIn(t, p, username, testPasswords["alice"])
		wantDenial(t, resp, pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
	}
	filters := d.seenFilters()
	if !slices.Contains(filters, `(&(objectClass=person)(uid=\2a\29\28uid=\2a))`) {
		t.Fatalf("injection attempt was not escaped on the wire; filters sent: %q", filters)
	}
	for _, dn := range d.seenBinds() {
		if strings.HasPrefix(dn, "uid=") {
			t.Fatalf("an injection attempt reached a user bind as %q", dn)
		}
	}
}

func TestResultsAreRecheckedWhenTheServerIgnoresEscapes(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	d.unescapedWildcards = true
	p := newTestProvider(t, d, nil)
	// Without the re-check, "al*" would find alice and her password would
	// sign in under a username she never typed.
	wantDenial(t, signIn(t, p, "al*", testPasswords["alice"]), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
	wantDenial(t, signIn(t, p, "*", testPasswords["alice"]), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
	if a := signIn(t, p, "ALICE", testPasswords["alice"]); a.GetExternalSubject() != "uuid-alice" {
		t.Fatalf("case-insensitive username = %v %s", a.GetDenial(), a.GetDenialDetail())
	}
	if got := check(t, p, "uuid-*").GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND {
		t.Fatalf("wildcard subject = %v", got)
	}
	if got := check(t, p, "uuid-bob").GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE {
		t.Fatalf("bob = %v", got)
	}
}

func TestAuthenticateGroupSearch(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	// A DN with RFC 4514 escapes must survive the {dn} substitution.
	oddDN := `cn=Smith\, Erin (ops),` + testPeople
	d.add(oddDN, "erin-pw", map[string][]string{
		"objectClass": {"inetOrgPerson"},
		"uid":         {"erin"},
		"entryUUID":   {"uuid-erin"},
	})
	d.setAttr(usersGroupDN, "member", "uid=alice,"+testPeople, "uid=bob,"+testPeople, oddDN)
	p := newTestProvider(t, d, configOverrides{
		configKeyDirectory: {"preset": "openldap"},
		configKeyGroups:    {"base_dn": testGroups},
	})
	if s := p.Settings(); s.GroupSource != groupSourceSearch || s.GroupFilter != openLDAPGroupFilter {
		t.Fatalf("openldap preset not applied: %+v", s)
	}
	bob := signIn(t, p, "bob", testPasswords["bob"])
	if bob.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN || !slices.Equal(bob.GetGroups(), []string{"silo-admins", "silo-users"}) {
		t.Fatalf("bob = role %v groups %v (%s)", bob.GetManagedRole(), bob.GetGroups(), bob.GetDenialDetail())
	}
	erin := signIn(t, p, "erin", "erin-pw")
	if erin.GetExternalSubject() != "uuid-erin" || !slices.Equal(erin.GetGroups(), []string{"silo-users"}) {
		t.Fatalf("erin = %+v", erin)
	}
	wantDenial(t, signIn(t, p, "carol", testPasswords["carol"]), pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED)
}

func TestAuthenticateGatesAndRoles(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)

	open := newTestProvider(t, d, configOverrides{configKeyGroups: {"allowed_groups": nil, "admin_groups": nil}})
	carol := signIn(t, open, "carol", testPasswords["carol"])
	if carol.GetExternalSubject() != "uuid-carol" || carol.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED {
		t.Fatalf("carol without gates = %+v", carol)
	}

	// Admin-group members pass the allowed gate, and groups match by DN.
	byDN := newTestProvider(t, d, configOverrides{configKeyGroups: {
		"allowed_groups": "cn=nobody," + testGroups,
		"admin_groups":   strings.ToUpper(adminsGroupDN),
	}})
	if bob := signIn(t, byDN, "bob", testPasswords["bob"]); bob.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
		t.Fatalf("bob by DN = %v %s", bob.GetDenial(), bob.GetDenialDetail())
	}
	wantDenial(t, signIn(t, byDN, "alice", testPasswords["alice"]), pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED)

	verified := newTestProvider(t, d, configOverrides{configKeyUsers: {"email_verified": "verified"}})
	if a := signIn(t, verified, "alice", testPasswords["alice"]); a.EmailVerified == nil || !a.GetEmailVerified() {
		t.Fatalf("email_verified = %v", a.EmailVerified)
	}
}

func TestAuthenticateDisabledAccount(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	p := newTestProvider(t, d, nil)
	d.setAttr("uid=dave,"+testPeople, attrNSAccountLock, "TRUE")
	// A wrong password must not reveal the account state.
	wantDenial(t, signIn(t, p, "dave", "wrong"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
	wantDenial(t, signIn(t, p, "dave", testPasswords["dave"]), pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED)
	d.setAttr("uid=dave,"+testPeople, attrNSAccountLock)
	d.setAttr("uid=dave,"+testPeople, attrUserAccountControl, "514")
	wantDenial(t, signIn(t, p, "dave", testPasswords["dave"]), pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED)
}

func TestAuthenticateMapsDirectoryRefusals(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	p := newTestProvider(t, d, nil)
	aliceDN := "uid=alice," + testPeople

	expired, err := gldap.NewControlBeheraPasswordPolicy(gldap.WithErrorCode(beheraPasswordExpired))
	if err != nil {
		t.Fatal(err)
	}
	locked, err := gldap.NewControlBeheraPasswordPolicy(gldap.WithErrorCode(beheraAccountLocked))
	if err != nil {
		t.Fatal(err)
	}
	mustChange, err := gldap.NewControlString("2.16.840.1.113730.3.4.4", gldap.WithControlValue("0"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		outcome bindOutcome
		want    pluginv1.AuthDenial
	}{
		{"AD locked out", bindOutcome{code: 49, message: "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v4563"}, pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED},
		{"AD password expired", bindOutcome{code: 49, message: "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 532, v4563"}, pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED},
		{"FreeIPA inactivated", bindOutcome{code: 53, message: "Account inactivated. Contact system administrator."}, pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED},
		{"389 retry limit", bindOutcome{code: 19, message: "Exceed password retry limit. Please try later."}, pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED},
		{"ppolicy expired", bindOutcome{code: 49, controls: []gldap.Control{expired}}, pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED},
		{"ppolicy locked", bindOutcome{code: 49, controls: []gldap.Control{locked}}, pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED},
		{"389 expired on successful bind", bindOutcome{code: gldap.ResultSuccess, controls: []gldap.Control{mustChange}}, pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.failBindFor(aliceDN, tc.outcome)
			wantDenial(t, signIn(t, p, "alice", testPasswords["alice"]), tc.want)
		})
	}
}

func TestAuthenticateProviderProblems(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)

	badService := newTestProvider(t, d, configOverrides{configKeyDirectory: {"bind_password": "nope"}})
	wantDenial(t, signIn(t, badService, "alice", testPasswords["alice"]), pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE)

	// Certificate checks cannot be skipped: without the CA the handshake fails.
	noCA := newTestProvider(t, d, configOverrides{configKeyDirectory: {"ca_pem": nil}})
	resp := signIn(t, noCA, "alice", testPasswords["alice"])
	wantDenial(t, resp, pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE)
	if !strings.Contains(resp.GetDenialDetail(), "certificate") {
		t.Fatalf("detail = %q, want a certificate error", resp.GetDenialDetail())
	}
	if strings.Contains(resp.GetDenialDetail(), testSvcPass) {
		t.Fatal("denial detail leaks the service password")
	}

	empty := New(nil)
	if err := empty.Configure(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	resp = signIn(t, empty, "alice", "x")
	wantDenial(t, resp, pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE)
	if !strings.Contains(resp.GetDenialDetail(), "directory URL is required") {
		t.Fatalf("detail = %q", resp.GetDenialDetail())
	}
}

func TestAuthenticateFailsOverToNextURL(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := "ldaps://" + closed.Addr().String()
	_ = closed.Close()
	p := newTestProvider(t, d, configOverrides{configKeyDirectory: {"urls": deadURL + "\n" + d.url()}})
	if a := signIn(t, p, "alice", testPasswords["alice"]); a.GetExternalSubject() != "uuid-alice" {
		t.Fatalf("failover sign-in = %v %s", a.GetDenial(), a.GetDenialDetail())
	}
	if p.Settings().Issuer() != deadURL {
		t.Fatalf("issuer should stay the first configured URL, got %q", p.Settings().Issuer())
	}
}

func check(t *testing.T, p *Provider, subject string) *pluginv1.CheckAccountResponse {
	t.Helper()
	resp, err := p.CheckAccount(context.Background(), &pluginv1.CheckAccountRequest{ExternalSubject: subject})
	if err != nil {
		t.Fatalf("CheckAccount returned a gRPC error: %v", err)
	}
	return resp
}

func TestCheckAccount(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	p := newTestProvider(t, d, nil)

	bob := check(t, p, "uuid-bob")
	if bob.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE {
		t.Fatalf("bob status = %v", bob.GetStatus())
	}
	if acct := bob.GetAccount(); acct.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN ||
		acct.GetUsername() != "bob" || acct.GetExternalSubject() != "uuid-bob" || acct.GetRefreshState() != nil {
		t.Fatalf("bob account = %+v", acct)
	}
	for _, tc := range []struct {
		subject string
		want    pluginv1.CheckAccountStatus
	}{
		{"uuid-alice", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE},
		{"uuid-carol", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED},
		{"uuid-gone", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND},
		{"*", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND},
		{"", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND},
	} {
		if got := check(t, p, tc.subject).GetStatus(); got != tc.want {
			t.Errorf("CheckAccount(%q) = %v, want %v", tc.subject, got, tc.want)
		}
	}

	d.setAttr("uid=dave,"+testPeople, attrNSAccountLock, "TRUE")
	if got := check(t, p, "uuid-dave").GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_DISABLED {
		t.Fatalf("disabled dave = %v", got)
	}
	// Removed from the admin group: still active, now a user.
	d.setAttr("uid=bob,"+testPeople, "memberOf", usersGroupDN)
	if acct := check(t, p, "uuid-bob").GetAccount(); acct.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER {
		t.Fatalf("demoted bob role = %v", acct.GetManagedRole())
	}
	// No longer matched by the user filter (object class changed).
	d.setAttr("uid=alice,"+testPeople, "objectClass", "account")
	if got := check(t, p, "uuid-alice").GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED {
		t.Fatalf("filtered-out alice = %v", got)
	}

	for _, f := range d.seenFilters() {
		if strings.Contains(f, "uuid-*") || strings.Contains(f, "(entryUUID=*)") {
			t.Fatalf("subject was not escaped: %q", f)
		}
	}

	// A base DN with no visible accounts is an outage, not a mass NOT_FOUND.
	blind := newTestProvider(t, d, configOverrides{configKeyUsers: {"base_dn": testGroups}})
	if got := check(t, blind, "uuid-bob").GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE {
		t.Fatalf("no visible accounts = %v", got)
	}

	unreachable := newTestProvider(t, d, configOverrides{configKeyDirectory: {"urls": "ldaps://127.0.0.1:1"}})
	if got := check(t, unreachable, "uuid-bob").GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE {
		t.Fatalf("unreachable = %v", got)
	}
	if got := check(t, New(nil), "uuid-bob").GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE {
		t.Fatalf("unconfigured = %v", got)
	}
}

func TestObjectGUIDSubject(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	guid := string([]byte{0xe0, 0x04, 0x25, 0x3f, 0x89, 0x4f, 0xd3, 0x11, 0x9a, 0x0c, 0x03, 0x05, 0xe8, 0x2c, 0x33, 0x01})
	d.add("cn=Frank Ford,"+testPeople, "frank-pw", map[string][]string{
		"objectClass":        {"user", "person"},
		"objectCategory":     {"person"},
		"sAMAccountName":     {"frank"},
		"objectGUID":         {guid},
		"userAccountControl": {"512"},
		"memberOf":           {usersGroupDN},
	})
	p := newTestProvider(t, d, configOverrides{configKeyDirectory: {"preset": "active_directory"}})
	const want = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	frank := signIn(t, p, "frank", "frank-pw")
	if frank.GetExternalSubject() != want || frank.GetUsername() != "frank" {
		t.Fatalf("frank = %+v", frank)
	}
	if got := check(t, p, want).GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE {
		t.Fatalf("CheckAccount by GUID = %v", got)
	}
	if got := check(t, p, "not-a-guid").GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND {
		t.Fatalf("CheckAccount with a malformed GUID = %v", got)
	}
	// An expired account binds with "data 701"; the re-check reads
	// accountExpires instead.
	d.setAttr("cn=Frank Ford,"+testPeople, attrAccountExpires, "132223104000000000")
	if got := check(t, p, want).GetStatus(); got != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_DISABLED {
		t.Fatalf("CheckAccount for an expired account = %v", got)
	}
}

func TestTestConnection(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	running := newTestProvider(t, d, nil)
	before := running.Settings()

	staged := testConfig(t, d, configOverrides{configKeyUsers: {"test_username": "bob"}, configKeyDirectory: {"preset": "openldap"}, configKeyGroups: {"base_dn": testGroups}})
	resp, err := running.TestConnection(context.Background(), &pluginv1.AuthTestConnectionRequest{Config: staged})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, step := range resp.GetSteps() {
		ids = append(ids, step.GetId())
		if !step.GetOk() {
			t.Fatalf("step %s failed: %s", step.GetId(), step.GetMessage())
		}
		if strings.Contains(step.GetMessage(), testSvcPass) || strings.Contains(step.GetLabel(), testSvcPass) {
			t.Fatalf("step %s echoes the service password", step.GetId())
		}
	}
	if !resp.GetOk() || !slices.Equal(ids, []string{"settings", "connect", "service_bind", "user_base", "user_filter", "group_base", "test_user"}) {
		t.Fatalf("ok=%v steps=%v", resp.GetOk(), ids)
	}
	if last := resp.GetSteps()[len(ids)-1].GetMessage(); !strings.Contains(last, "role admin") || !strings.Contains(last, "silo-admins") {
		t.Fatalf("test user message = %q", last)
	}
	if running.Settings() != before {
		t.Fatal("TestConnection changed the running settings")
	}

	for _, tc := range []struct {
		name      string
		overrides configOverrides
		failAt    string
	}{
		{"bad service password", configOverrides{configKeyDirectory: {"bind_password": "nope"}}, "service_bind"},
		{"missing base", configOverrides{configKeyUsers: {"base_dn": nil}}, "settings"},
		{"kanidm over ldap", configOverrides{configKeyDirectory: {"preset": "kanidm", "urls": "ldap://127.0.0.1:389"}}, "settings"},
		{"wrong base", configOverrides{configKeyUsers: {"base_dn": "ou=elsewhere,dc=other"}}, "user_base"},
		{"carol not allowed", configOverrides{configKeyUsers: {"test_username": "carol"}}, "test_user"},
		{"unreachable", configOverrides{configKeyDirectory: {"urls": "ldaps://127.0.0.1:1"}}, "connect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := running.TestConnection(context.Background(), &pluginv1.AuthTestConnectionRequest{Config: testConfig(t, d, tc.overrides)})
			if err != nil {
				t.Fatal(err)
			}
			steps := resp.GetSteps()
			last := steps[len(steps)-1]
			if resp.GetOk() || last.GetId() != tc.failAt || last.GetOk() {
				t.Fatalf("ok=%v last=%s/%v: %s", resp.GetOk(), last.GetId(), last.GetOk(), last.GetMessage())
			}
		})
	}
}

func TestEndSessionURLIsEmpty(t *testing.T) {
	resp, err := New(nil).EndSessionUrl(context.Background(), &pluginv1.AuthEndSessionUrlRequest{})
	if err != nil || resp.GetUrl() != "" {
		t.Fatalf("EndSessionUrl = %q, %v", resp.GetUrl(), err)
	}
}

func wantStatus(t *testing.T, p *Provider, subject string, want pluginv1.CheckAccountStatus) *pluginv1.CheckAccountResponse {
	t.Helper()
	resp := check(t, p, subject)
	if resp.GetStatus() != want {
		t.Fatalf("CheckAccount(%s) = %v, want %v", subject, resp.GetStatus(), want)
	}
	return resp
}

// A user filter whose {username} is not a plain equality assertion cannot
// become a presence test: "*" is a literal in an extensible match. CheckAccount
// must then re-run the sign-in lookup instead of treating the account as
// filtered out.
func TestCheckAccountExtensibleUserFilter(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	p := newTestProvider(t, d, configOverrides{configKeyUsers: {"filter": "(&(objectClass=person)(uid:caseExactMatch:={username}))"}})

	if a := signIn(t, p, "alice", testPasswords["alice"]); a.GetExternalSubject() != "uuid-alice" {
		t.Fatalf("alice = %v %s", a.GetDenial(), a.GetDenialDetail())
	}
	wantDenial(t, signIn(t, p, "ALICE", testPasswords["alice"]), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS)
	if acct := wantStatus(t, p, "uuid-alice", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE).GetAccount(); acct.GetUsername() != "alice" {
		t.Fatalf("alice account = %+v", acct)
	}
	wantStatus(t, p, "uuid-bob", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
	wantStatus(t, p, "uuid-carol", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	// The presence test matches nobody, so "gone" and "filtered out"
	// cannot be told from an unreadable directory.
	wantStatus(t, p, "uuid-gone", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
	d.setAttr("uid=alice,"+testPeople, "objectClass", "account")
	wantStatus(t, p, "uuid-alice", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)

	// With a plain equality test elsewhere in the filter, a filtered-out
	// account is NOT_PERMITTED again.
	mixed := newTestProvider(t, d, configOverrides{configKeyUsers: {"filter": "(&(objectClass=person)(mail=*)(|(uid:caseExactMatch:={username})(cn={username})))"}})
	wantStatus(t, mixed, "uuid-bob", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
	wantStatus(t, mixed, "uuid-alice", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)

	// The connection test checks such a filter through the test user.
	resp, err := p.TestConnection(context.Background(), &pluginv1.AuthTestConnectionRequest{
		Config: testConfig(t, d, configOverrides{configKeyUsers: {"filter": "(&(objectClass=person)(uid:caseExactMatch:={username}))", "test_username": "bob"}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetOk() {
		for _, step := range resp.GetSteps() {
			t.Logf("%s ok=%v: %s", step.GetId(), step.GetOk(), step.GetMessage())
		}
		t.Fatal("TestConnection failed")
	}
}

// Group data the service account cannot read looks like an empty group list.
// CheckAccount must not turn that into NOT_PERMITTED or a demotion.
func TestCheckAccountHiddenGroups(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	p := newTestProvider(t, d, nil)
	wantStatus(t, p, "uuid-carol", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)

	d.hideAttr("memberOf")
	for _, subject := range []string{"uuid-alice", "uuid-bob", "uuid-carol"} {
		wantStatus(t, p, subject, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
	}
	// Without allowed groups, bob would otherwise be demoted to user.
	open := newTestProvider(t, d, configOverrides{configKeyGroups: {"allowed_groups": nil}})
	wantStatus(t, open, "uuid-bob", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
	d.unhide()
	if acct := wantStatus(t, open, "uuid-bob", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE).GetAccount(); acct.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
		t.Fatalf("bob role = %v", acct.GetManagedRole())
	}
	if acct := wantStatus(t, open, "uuid-carol", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE).GetAccount(); acct.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER {
		t.Fatalf("carol role = %v", acct.GetManagedRole())
	}

	// Group search: the group entries themselves are hidden.
	search := newTestProvider(t, d, configOverrides{
		configKeyDirectory: {"preset": "openldap"},
		configKeyGroups:    {"base_dn": testGroups},
	})
	wantStatus(t, search, "uuid-carol", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	d.hideDN(usersGroupDN)
	d.hideDN(adminsGroupDN)
	for _, subject := range []string{"uuid-alice", "uuid-carol"} {
		wantStatus(t, search, subject, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
	}
	d.unhide()
	// A real removal is still NOT_PERMITTED.
	d.setAttr(usersGroupDN, "member", "uid=bob,"+testPeople)
	wantStatus(t, search, "uuid-alice", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
}

// The authentik outpost ignores (memberOf=*) and lists accounts without
// groups first; the membership check must look past them.
func TestCheckAccountWhenPresenceFiltersAreIgnored(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	for _, name := range []string{"outpost-1", "outpost-2", "outpost-3"} {
		d.add("uid="+name+","+testPeople, "", map[string][]string{"objectClass": {"account"}, "uid": {name}})
	}
	seedDirectory(d)
	d.ignorePresence = true
	p := newTestProvider(t, d, nil)
	wantStatus(t, p, "uuid-carol", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	wantStatus(t, p, "uuid-bob", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
}

// Admin groups must not match a same-named group in another container or a
// Unicode look-alike.
func TestAdminGroupsIgnoreLookAlikes(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	d.setAttr("uid=carol,"+testPeople, "memberOf",
		usersGroupDN,
		"cn=silo-admins,ou=team-x,"+testBase,
		"cn=ſilo-admins,"+testGroups,
	)
	p := newTestProvider(t, d, nil)
	if carol := signIn(t, p, "carol", testPasswords["carol"]); carol.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER {
		t.Fatalf("carol role = %v (%s)", carol.GetManagedRole(), carol.GetDenialDetail())
	}
	// Presets with directory-wide unique names accept names, and still
	// ignore look-alikes.
	d.setAttr("uid=carol,"+testPeople, "memberOf", usersGroupDN, "cn=ſilo-admins,"+testGroups)
	lldap := newTestProvider(t, d, configOverrides{configKeyDirectory: {"preset": "lldap"}, configKeyGroups: {"admin_groups": "silo-admins"}})
	if carol := signIn(t, lldap, "carol", testPasswords["carol"]); carol.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER {
		t.Fatalf("carol role with lldap = %v (%s)", carol.GetManagedRole(), carol.GetDenialDetail())
	}
	if bob := signIn(t, lldap, "bob", testPasswords["bob"]); bob.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
		t.Fatalf("bob role with lldap = %v (%s)", bob.GetManagedRole(), bob.GetDenialDetail())
	}
}

func TestGLAuthPreset(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	const base = "dc=glauth,dc=test"
	people := "ou=users," + base
	d.add(base, "", map[string][]string{"objectClass": {"domain"}})
	d.add(testService, testSvcPass, map[string][]string{"cn": {"svc"}})
	user := func(uid, uidNumber string, groups ...string) {
		d.add("cn="+uid+","+people, testPasswords[uid], map[string][]string{
			"objectClass":   {"posixAccount", "shadowAccount"},
			"uid":           {uid},
			"cn":            {uid},
			"uidNumber":     {uidNumber},
			"mail":          {uid + "@example.com"},
			"memberOf":      groups,
			"accountStatus": {"active"},
		})
	}
	users := "ou=silo-users,ou=groups," + base
	admins := "ou=silo-admins,ou=groups," + base
	user("alice", "5001", users)
	user("bob", "5002", users, admins)
	user("dave", "5004", users)
	p := newTestProvider(t, d, configOverrides{
		configKeyDirectory: {"preset": "glauth"},
		configKeyUsers:     {"base_dn": base},
		configKeyGroups:    {"allowed_groups": "silo-users", "admin_groups": "silo-admins"},
	})
	bob := signIn(t, p, "bob", testPasswords["bob"])
	if bob.GetExternalSubject() != "5002" || bob.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
		t.Fatalf("bob = %+v", bob)
	}
	wantStatus(t, p, "5001", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)

	d.setAttr("cn=dave,"+people, "accountStatus", "inactive")
	wantDenial(t, signIn(t, p, "dave", testPasswords["dave"]), pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED)
	wantStatus(t, p, "5004", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_DISABLED)

	// A reused uidNumber would hand alice's Silo account to carol.
	user("carol", "5001", users)
	wantDenial(t, signIn(t, p, "alice", testPasswords["alice"]), pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE)
	wantDenial(t, signIn(t, p, "carol", testPasswords["carol"]), pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE)
	wantStatus(t, p, "5001", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
}

// Sign-in and CheckAccount report the same facts, and neither leaves the
// username blank when the username attribute is missing.
func TestAccountFactsMatchBetweenSignInAndCheck(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	d.setAttr("uid=bob,"+testPeople, "displayName")
	p := newTestProvider(t, d, configOverrides{configKeyUsers: {"username_attribute": "sAMAccountName"}})
	signedIn := signIn(t, p, "bob", testPasswords["bob"])
	checked := wantStatus(t, p, "uuid-bob", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE).GetAccount()
	for _, acct := range []*pluginv1.AuthenticateResponse{signedIn, checked} {
		if acct.GetUsername() != "bob" || acct.GetDisplayName() != "bob" || acct.GetEmail() != "bob@example.com" {
			t.Fatalf("facts = username %q display %q email %q", acct.GetUsername(), acct.GetDisplayName(), acct.GetEmail())
		}
	}
	if !slices.Equal(signedIn.GetGroups(), checked.GetGroups()) || signedIn.GetManagedRole() != checked.GetManagedRole() {
		t.Fatalf("sign-in %v/%v, check %v/%v", signedIn.GetGroups(), signedIn.GetManagedRole(), checked.GetGroups(), checked.GetManagedRole())
	}
}

func TestStartTLSStallFailsOverToNextURL(t *testing.T) {
	// Two servers that accept the connection and never answer StartTLS.
	accepted := make(chan int, 2)
	var urls []*url.URL
	for i := range 2 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				t.Cleanup(func() { _ = c.Close() })
				accepted <- i
			}
		}()
		urls = append(urls, &url.URL{Scheme: "ldap", Host: l.Addr().String()})
	}
	s := &Settings{URLs: urls, StartTLS: true, ConnectTimeout: 5 * time.Second, RequestTimeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if _, _, err := connect(ctx, s); err == nil || !strings.Contains(err.Error(), "StartTLS") {
		t.Fatalf("connect error = %v, want a StartTLS failure", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("connect took %s; StartTLS was not bounded by the dial share", elapsed)
	}
	// The dial to the second URL completed, so its accept is at most a
	// scheduling delay away.
	wait := time.After(2 * time.Second)
	for {
		select {
		case i := <-accepted:
			if i == 1 {
				return
			}
		case <-wait:
			t.Fatal("the second URL was never tried")
		}
	}
}
