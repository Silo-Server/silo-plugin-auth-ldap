package ldapauth

import (
	"bufio"
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// Live tests against real directories. Both variants run the same checks on
// four people with the same groups in every directory: alice (silo-users),
// bob (silo-users, silo-admins), carol (no group), and dave (silo-users).
//
// TestContainerDirectories runs against lldap and OpenLDAP containers that
// scripts/directory-containers.sh starts and seeds; CI runs it on every
// change. It reads the LDAPTEST_* variables from the env file the script
// writes.
//
// TestLabDirectories runs against the maintainers' SSO lab (lldap, the
// authentik LDAP outpost, Kanidm, OpenLDAP). It runs only with SSO_LAB=1 and
// reads:
//
//	SSO_LAB_ENV  path to the lab's credential file (KEY=value lines)
//	SSO_LAB_CA   path to the lab's root CA PEM

type labDirectory struct {
	name      string
	directory map[string]any
	users     map[string]any
	groups    map[string]any
	// missingStatus is the CheckAccount answer for an unknown ID:
	// NOT_FOUND unless the user filter cannot become a presence test.
	missingStatus pluginv1.CheckAccountStatus
	// extraGroups lists groups a person must have besides silo-users.
	extraGroups map[string][]string
}

func labEnv(t *testing.T) (map[string]string, string) {
	t.Helper()
	if os.Getenv("SSO_LAB") != "1" {
		t.Skip("set SSO_LAB=1, SSO_LAB_ENV, and SSO_LAB_CA to run the live directory tests")
	}
	envPath, caPath := os.Getenv("SSO_LAB_ENV"), os.Getenv("SSO_LAB_CA")
	if envPath == "" || caPath == "" {
		t.Fatal("SSO_LAB=1 needs SSO_LAB_ENV and SSO_LAB_CA")
	}
	env := readEnvFile(t, envPath)
	for _, key := range []string{"LAB_HOST", "ALICE_PASSWORD", "BOB_PASSWORD", "CAROL_PASSWORD", "DAVE_PASSWORD"} {
		if env[key] == "" {
			t.Fatalf("lab env lacks %s", key)
		}
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read lab CA: %v", err)
	}
	return env, string(ca)
}

// readEnvFile reads KEY=value lines, skipping blanks and # comments.
func readEnvFile(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open env file: %v", err)
	}
	defer func() { _ = f.Close() }()
	env := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			env[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read env file: %v", err)
	}
	return env
}

func labDirectories(env map[string]string, ca string) []labDirectory {
	host := env["LAB_HOST"]
	kanidmBase := "dc=" + strings.ReplaceAll(host, ".", ",dc=")
	gates := map[string]any{"allowed_groups": "silo-users", "admin_groups": "silo-admins"}
	openLDAPGates := map[string]any{"allowed_groups": "silo-users", "admin_groups": "cn=silo-admins,ou=groups,dc=silo,dc=test"}
	return []labDirectory{
		{
			name:      "lldap LDAPS",
			directory: map[string]any{"preset": "lldap", "urls": "ldaps://" + host + ":9711", "ca_pem": ca, "bind_dn": "uid=ssolab-bind,ou=people,dc=silo,dc=test", "bind_password": env["LLDAP_BIND_PASSWORD"]},
			users:     map[string]any{"base_dn": "ou=people,dc=silo,dc=test"},
			groups:    gates,
		},
		{
			name:      "lldap plain LDAP",
			directory: map[string]any{"preset": "lldap", "urls": "ldap://" + host + ":9710", "bind_dn": "uid=ssolab-bind,ou=people,dc=silo,dc=test", "bind_password": env["LLDAP_BIND_PASSWORD"]},
			users:     map[string]any{"base_dn": "ou=people,dc=silo,dc=test"},
			// Groups by DN rather than name.
			groups: map[string]any{"allowed_groups": "cn=silo-users,ou=groups,dc=silo,dc=test", "admin_groups": "cn=silo-admins,ou=groups,dc=silo,dc=test"},
		},
		{
			name:      "authentik LDAP outpost",
			directory: map[string]any{"preset": "authentik", "urls": "ldaps://" + host + ":9713", "ca_pem": ca, "bind_dn": "cn=ldapservice,ou=users,dc=ldap,dc=goauthentik,dc=io", "bind_password": env["AUTHENTIK_LDAP_BIND_PASSWORD"], "request_timeout_seconds": 20.0},
			users:     map[string]any{"base_dn": "ou=users,dc=ldap,dc=goauthentik,dc=io"},
			groups:    gates,
		},
		{
			name:      "Kanidm LDAPS",
			directory: map[string]any{"preset": "kanidm", "urls": "ldaps://" + host + ":9714", "ca_pem": ca, "bind_dn": "dn=token", "bind_password": env["KANIDM_LDAP_TOKEN"]},
			users:     map[string]any{"base_dn": kanidmBase},
			groups:    gates,
		},
		{
			name:      "OpenLDAP StartTLS with group search",
			directory: map[string]any{"preset": "openldap", "urls": "ldap://" + host + ":9715", "start_tls": true, "ca_pem": ca, "bind_dn": "cn=readonly,dc=silo,dc=test", "bind_password": env["OPENLDAP_READONLY_PASSWORD"]},
			users:     map[string]any{"base_dn": "ou=people,dc=silo,dc=test"},
			groups:    merge(openLDAPGates, map[string]any{"base_dn": "ou=groups,dc=silo,dc=test"}),
		},
		{
			name:      "OpenLDAP LDAPS with memberOf",
			directory: map[string]any{"preset": "openldap", "urls": "ldaps://" + host + ":9716", "ca_pem": ca, "bind_dn": "cn=readonly,dc=silo,dc=test", "bind_password": env["OPENLDAP_READONLY_PASSWORD"]},
			users:     map[string]any{"base_dn": "ou=people,dc=silo,dc=test"},
			groups:    merge(openLDAPGates, map[string]any{"source": "memberof"}),
		},
		{
			name:          "OpenLDAP LDAPS with an extensible-match user filter",
			directory:     map[string]any{"preset": "openldap", "urls": "ldaps://" + host + ":9716", "ca_pem": ca, "bind_dn": "cn=readonly,dc=silo,dc=test", "bind_password": env["OPENLDAP_READONLY_PASSWORD"]},
			users:         map[string]any{"base_dn": "ou=people,dc=silo,dc=test", "filter": extensibleUserFilter},
			groups:        merge(openLDAPGates, map[string]any{"source": "memberof"}),
			missingStatus: pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE,
		},
	}
}

// extensibleUserFilter compares the username with an extensible match, so
// "{username}" cannot become a presence test.
const extensibleUserFilter = "(&(objectClass=inetOrgPerson)(uid:caseExactMatch:={username}))"

// containerDirectories describes the containers of
// scripts/directory-containers.sh from the variables it writes.
func containerDirectories(env map[string]string, ca string) []labDirectory {
	lldap := func(url string) map[string]any {
		return map[string]any{"preset": "lldap", "urls": url, "ca_pem": ca, "bind_dn": env["LDAPTEST_LLDAP_BIND_DN"], "bind_password": env["LDAPTEST_LLDAP_BIND_PASSWORD"]}
	}
	openLDAP := func(url string, startTLS bool) map[string]any {
		return map[string]any{"preset": "openldap", "urls": url, "start_tls": startTLS, "ca_pem": ca, "bind_dn": env["LDAPTEST_OPENLDAP_BIND_DN"], "bind_password": env["LDAPTEST_OPENLDAP_BIND_PASSWORD"]}
	}
	lldapGroups, openLDAPGroups := env["LDAPTEST_LLDAP_GROUP_BASE_DN"], env["LDAPTEST_OPENLDAP_GROUP_BASE_DN"]
	openLDAPGates := map[string]any{"allowed_groups": "silo-users", "admin_groups": "cn=silo-admins," + openLDAPGroups}
	return []labDirectory{
		{
			name:      "lldap LDAPS",
			directory: lldap(env["LDAPTEST_LLDAP_LDAPS_URL"]),
			users:     map[string]any{"base_dn": env["LDAPTEST_LLDAP_USER_BASE_DN"]},
			groups:    map[string]any{"allowed_groups": "silo-users", "admin_groups": "silo-admins"},
		},
		{
			name:      "lldap plain LDAP with group DNs",
			directory: lldap(env["LDAPTEST_LLDAP_URL"]),
			users:     map[string]any{"base_dn": env["LDAPTEST_LLDAP_USER_BASE_DN"]},
			groups:    map[string]any{"allowed_groups": "cn=silo-users," + lldapGroups, "admin_groups": "cn=silo-admins," + lldapGroups},
		},
		{
			name:        "OpenLDAP StartTLS with group search",
			directory:   openLDAP(env["LDAPTEST_OPENLDAP_URL"], true),
			users:       map[string]any{"base_dn": env["LDAPTEST_OPENLDAP_USER_BASE_DN"]},
			groups:      merge(openLDAPGates, map[string]any{"base_dn": openLDAPGroups}),
			extraGroups: map[string][]string{"alice": {"silo-viewers"}, "dave": {"silo-posix"}},
		},
		{
			name:      "OpenLDAP LDAPS with memberOf",
			directory: openLDAP(env["LDAPTEST_OPENLDAP_LDAPS_URL"], false),
			users:     map[string]any{"base_dn": env["LDAPTEST_OPENLDAP_USER_BASE_DN"]},
			groups:    merge(openLDAPGates, map[string]any{"source": "memberof"}),
		},
		{
			name:          "OpenLDAP LDAPS with an extensible-match user filter",
			directory:     openLDAP(env["LDAPTEST_OPENLDAP_LDAPS_URL"], false),
			users:         map[string]any{"base_dn": env["LDAPTEST_OPENLDAP_USER_BASE_DN"], "filter": extensibleUserFilter},
			groups:        merge(openLDAPGates, map[string]any{"source": "memberof"}),
			missingStatus: pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE,
		},
	}
}

func merge(base, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func (l labDirectory) entries(t *testing.T, users, groups map[string]any) []*pluginv1.ConfigEntry {
	t.Helper()
	var entries []*pluginv1.ConfigEntry
	for key, fields := range map[string]map[string]any{
		configKeyDirectory: l.directory,
		configKeyUsers:     merge(l.users, users),
		configKeyGroups:    merge(l.groups, groups),
	} {
		value, err := structpb.NewStruct(fields)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, &pluginv1.ConfigEntry{Key: key, Value: value})
	}
	return entries
}

func TestLabDirectories(t *testing.T) {
	env, ca := labEnv(t)
	password := func(user string) string { return env[strings.ToUpper(user)+"_PASSWORD"] }
	for _, dir := range labDirectories(env, ca) {
		t.Run(dir.name, func(t *testing.T) { checkDirectory(t, dir, password) })
	}
}

func TestContainerDirectories(t *testing.T) {
	if os.Getenv("LDAPTEST") != "1" {
		t.Skip("run scripts/directory-containers.sh up and load its env file (make test-directories) to test against lldap and OpenLDAP containers")
	}
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if key, value, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(key, "LDAPTEST_") {
			env[key] = value
		}
	}
	for _, key := range []string{"LDAPTEST_CA_FILE", "LDAPTEST_ALICE_PASSWORD", "LDAPTEST_LLDAP_URL", "LDAPTEST_OPENLDAP_URL"} {
		if env[key] == "" {
			t.Fatalf("LDAPTEST=1 needs %s", key)
		}
	}
	ca, err := os.ReadFile(env["LDAPTEST_CA_FILE"])
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	password := func(user string) string { return env["LDAPTEST_"+strings.ToUpper(user)+"_PASSWORD"] }
	for _, dir := range containerDirectories(env, string(ca)) {
		t.Run(dir.name, func(t *testing.T) { checkDirectory(t, dir, password) })
	}
}

// checkDirectory signs the four people in, re-checks them, and runs the
// connection test.
func checkDirectory(t *testing.T, dir labDirectory, password func(user string) string) {
	ctx := context.Background()
	p := New(nil)
	if err := p.Configure(ctx, dir.entries(t, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if !p.Settings().Ready() {
		t.Fatalf("settings: %s", p.Settings().ProblemSummary())
	}
	signIn := func(user, pw string) *pluginv1.AuthenticateResponse {
		t.Helper()
		resp, err := p.Authenticate(ctx, &pluginv1.AuthenticateRequest{Username: user, Password: pw})
		if err != nil {
			t.Fatalf("Authenticate(%s): gRPC error %v", user, err)
		}
		return resp
	}

	subjects := map[string]string{}
	for _, tc := range []struct {
		user string
		role pluginv1.AuthManagedRole
	}{
		{"alice", pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER},
		{"bob", pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN},
		{"dave", pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER},
	} {
		resp := signIn(tc.user, password(tc.user))
		if resp.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED {
			t.Fatalf("%s denied: %v %s", tc.user, resp.GetDenial(), resp.GetDenialDetail())
		}
		wantGroups := append([]string{"silo-users"}, dir.extraGroups[tc.user]...)
		if resp.GetExternalSubject() == "" || resp.GetManagedRole() != tc.role ||
			resp.GetUsername() != tc.user || resp.GetEmail() != tc.user+"@example.com" ||
			!containsAll(resp.GetGroups(), wantGroups) {
			t.Fatalf("%s facts: subject=%q role=%v username=%q email=%q groups=%v",
				tc.user, resp.GetExternalSubject(), resp.GetManagedRole(), resp.GetUsername(), resp.GetEmail(), resp.GetGroups())
		}
		subjects[tc.user] = resp.GetExternalSubject()
		t.Logf("%s: subject=%s role=%v display=%q groups=%v", tc.user, resp.GetExternalSubject(), resp.GetManagedRole(), resp.GetDisplayName(), resp.GetGroups())
	}

	for _, tc := range []struct {
		name, user, pw string
		want           pluginv1.AuthDenial
	}{
		{"carol not in an allowed group", "carol", password("carol"), pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"wrong password", "alice", password("alice") + "x", pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"empty password", "alice", "", pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"filter injection", "*)(uid=*", password("alice"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"wildcard username", "*", password("alice"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"wildcard suffix", "al*", password("alice"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
		{"unknown user", "mallory", password("alice"), pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS},
	} {
		resp := signIn(tc.user, tc.pw)
		if resp.GetDenial() != tc.want || resp.GetExternalSubject() != "" {
			t.Errorf("%s: denial=%v subject=%q detail=%s", tc.name, resp.GetDenial(), resp.GetExternalSubject(), resp.GetDenialDetail())
		}
	}

	// carol's subject comes from a provider without group gates.
	open := New(nil)
	if err := open.Configure(ctx, dir.entries(t, nil, map[string]any{"allowed_groups": "", "admin_groups": ""})); err != nil {
		t.Fatal(err)
	}
	carol, err := open.Authenticate(ctx, &pluginv1.AuthenticateRequest{Username: "carol", Password: password("carol")})
	if err != nil || carol.GetExternalSubject() == "" || carol.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED {
		t.Fatalf("carol without gates: %v %v %s", err, carol.GetDenial(), carol.GetDenialDetail())
	}
	subjects["carol"] = carol.GetExternalSubject()

	missing := dir.missingStatus
	if missing == pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSPECIFIED {
		missing = pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND
	}
	for _, tc := range []struct {
		subject string
		want    pluginv1.CheckAccountStatus
		role    pluginv1.AuthManagedRole
	}{
		{subjects["alice"], pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE, pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER},
		{subjects["bob"], pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE, pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN},
		{subjects["dave"], pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE, pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER},
		{subjects["carol"], pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED, 0},
		{"00000000-0000-0000-0000-000000000000", missing, 0},
		{"*", missing, 0},
	} {
		resp, err := p.CheckAccount(ctx, &pluginv1.CheckAccountRequest{ExternalSubject: tc.subject})
		if err != nil {
			t.Fatalf("CheckAccount(%s): %v", tc.subject, err)
		}
		if resp.GetStatus() != tc.want || (tc.role != 0 && resp.GetAccount().GetManagedRole() != tc.role) {
			t.Errorf("CheckAccount(%s) = %v role %v, want %v role %v", tc.subject, resp.GetStatus(), resp.GetAccount().GetManagedRole(), tc.want, tc.role)
		}
	}

	test, err := p.TestConnection(ctx, &pluginv1.AuthTestConnectionRequest{Config: dir.entries(t, map[string]any{"test_username": "bob"}, nil)})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range test.GetSteps() {
		t.Logf("test step %s ok=%v: %s", step.GetId(), step.GetOk(), step.GetMessage())
	}
	if !test.GetOk() {
		t.Fatal("TestConnection failed")
	}
}

func containsAll(have, want []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}
