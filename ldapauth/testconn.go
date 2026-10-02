package ldapauth

import (
	"context"
	"fmt"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// TestConnection checks staged settings without saving anything: settings,
// connection, service bind, base DN searches, and an optional test-user
// lookup. It stops at the first failed step.
func (p *Provider) TestConnection(ctx context.Context, req *pluginv1.AuthTestConnectionRequest) (*pluginv1.AuthTestConnectionResponse, error) {
	return testConnection(ctx, ParseConfig(req.GetConfig())), nil
}

type stepRecorder struct {
	resp *pluginv1.AuthTestConnectionResponse
}

func (r *stepRecorder) add(id, label string, ok bool, format string, args ...any) bool {
	r.resp.Steps = append(r.resp.Steps, &pluginv1.AuthTestStep{
		Id:      id,
		Label:   label,
		Ok:      ok,
		Message: fmt.Sprintf(format, args...),
	})
	if !ok {
		r.resp.Ok = false
	}
	return ok
}

func testConnection(ctx context.Context, s *Settings) *pluginv1.AuthTestConnectionResponse {
	rec := &stepRecorder{resp: &pluginv1.AuthTestConnectionResponse{Ok: true}}

	if !s.Ready() {
		rec.add("settings", "Settings are complete", false, "%s", s.ProblemSummary())
		return rec.resp
	}
	rec.add("settings", "Settings are complete", true, "Directory type: %s. Group source: %s.", presets[s.Preset].Label, s.GroupSource)

	sess, attempts, err := connect(ctx, s)
	if err != nil {
		rec.add("connect", "Connect to the directory", false, "%v", err)
		return rec.resp
	}
	defer sess.close()
	message := fmt.Sprintf("Connected to %s. Encryption: %s.", sess.url.Redacted(), sess.encryption)
	if len(attempts) > 0 {
		failed := make([]string, 0, len(attempts))
		for _, a := range attempts {
			failed = append(failed, fmt.Sprintf("%s (%v)", a.url, a.err))
		}
		message += " Unreachable first: " + strings.Join(failed, "; ") + "."
	}
	if sess.url.Scheme == "ldap" && !s.StartTLS {
		message += " Passwords cross the network unencrypted; use ldaps:// or StartTLS outside a trusted network."
	}
	rec.add("connect", "Connect to the directory", true, "%s", message)

	if s.BindDN == "" {
		rec.add("service_bind", "Service account bind", true, "No service account is set; searching anonymously.")
	} else if err := sess.bindService(); err != nil {
		rec.add("service_bind", "Service account bind", false, "Bind as %s failed: %v", s.BindDN, err)
		return rec.resp
	} else {
		rec.add("service_bind", "Service account bind", true, "Bound as %s.", s.BindDN)
	}

	if !baseStep(sess, rec, "user_base", "Read the user base DN", s.UserBaseDN) {
		return rec.resp
	}

	// A raw "*" in place of {username} turns the assertion into a presence
	// test, so this finds any account the filter admits.
	entries, err := sess.search(s.UserBaseDN, s.presenceFilter(), []string{"1.1"}, 1)
	if err != nil {
		rec.add("user_filter", "Find accounts with the user filter", false, "%v", err)
		return rec.resp
	}
	switch {
	case len(entries) > 0:
		rec.add("user_filter", "Find accounts with the user filter", true, "The user filter matches accounts under %s.", s.UserBaseDN)
	case len(s.usernameAssertionAttrs) == 0 && s.TestUsername != "":
		// {username} appears only in a form such as an extensible match,
		// where "*" is a literal value; the test user step checks the
		// filter instead.
		rec.add("user_filter", "Find accounts with the user filter", true, "The user filter has no plain (attribute={username}) test, so it cannot list accounts; the test user step checks it. Without one, Silo's re-check cannot confirm that a deleted account is gone and reports the directory as unavailable for it.")
	default:
		rec.add("user_filter", "Find accounts with the user filter", false, "No entry under %s matches the user filter. Check the base DN, the filter, and the service account's read rights.", s.UserBaseDN)
		return rec.resp
	}

	if s.GroupSource == groupSourceSearch {
		if !baseStep(sess, rec, "group_base", "Read the group base DN", s.GroupBaseDN) {
			return rec.resp
		}
	}

	if s.TestUsername != "" {
		testUser(sess, s, rec)
	}
	return rec.resp
}

func baseStep(sess *session, rec *stepRecorder, id, label, dn string) bool {
	visible, err := sess.readBase(dn)
	switch {
	case err != nil:
		return rec.add(id, label, false, "%s: %v", dn, err)
	case visible:
		return rec.add(id, label, true, "%s is readable.", dn)
	default:
		return rec.add(id, label, true, "The directory accepted a search at %s but did not return the entry itself; the next step checks that accounts are visible.", dn)
	}
}

func testUser(sess *session, s *Settings, rec *stepRecorder) {
	const id, label = "test_user", "Look up the test user"
	entry, subject, d := sess.findUser(s.TestUsername)
	if d != nil {
		rec.add(id, label, false, "Looking up %q: %s.", s.TestUsername, d.detail)
		return
	}
	ev, err := sess.evaluate(entry)
	if err != nil {
		rec.add(id, label, false, "Found %s, but reading its groups failed: %v", entry.DN, err)
		return
	}
	names := groupNames(ev.groups)
	groupText := "none"
	if len(names) > 0 {
		groupText = strings.Join(names, ", ")
	}
	facts := fmt.Sprintf("Found %s (%s %s). Groups: %s.", entry.DN, s.UniqueIDAttribute, subject, groupText)
	if ev.disabled != "" {
		rec.add(id, label, false, "%s The directory marks the account disabled: %s.", facts, ev.disabled)
		return
	}
	if !ev.gate.allowed {
		rec.add(id, label, false, "%s The account is not in an allowed group, so sign-in would be refused.", facts)
		return
	}
	// Silo re-checks signed-in accounts by unique ID; make sure that lookup
	// finds the same entry, or every re-check would fail.
	found, status, detail := sess.accountBySubject(subject)
	if found == nil || !sameDN(found.DN, entry.DN) {
		if found != nil {
			detail = "it found " + found.DN
		}
		rec.add(id, label, false, "%s Sign-in would work, but looking the account up by %s answers %s: %s.", facts, s.UniqueIDAttribute, status, detail)
		return
	}
	role := "left to Silo"
	switch ev.gate.role {
	case pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN:
		role = "admin"
	case pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER:
		role = "user"
	}
	rec.add(id, label, true, "%s Sign-in allowed; role %s.", facts, role)
}
