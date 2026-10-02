package ldapauth

import (
	"fmt"
	"sort"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/go-ldap/ldap/v3"
)

// groupRef is one configured allowed or admin group: a full DN, or a bare
// name matched against the group's name.
type groupRef struct {
	raw  string
	dn   *ldap.DN
	name string
}

func (r groupRef) String() string { return r.raw }

// parseGroupRefs reads one group per line. A line containing "=" is a DN;
// anything else is a group name.
func parseGroupRefs(value string) ([]groupRef, error) {
	var refs []groupRef
	for _, line := range splitLines(value) {
		ref := groupRef{raw: line}
		if strings.Contains(line, "=") {
			dn, err := ldap.ParseDN(line)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid DN: %v", line, err)
			}
			ref.dn = dn
		} else {
			ref.name = line
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// directoryGroup is one group the account belongs to.
type directoryGroup struct {
	dn *ldap.DN
	// name is the display form: the group name attribute, or the value of
	// the DN's first RDN with a Kanidm "@domain" suffix removed.
	name string
	// rawName is the first RDN value as written, such as
	// "silo-users@idm.example.com" for Kanidm.
	rawName string
}

// groupFromDN builds a group from a DN such as a memberOf value. Values that
// are not DNs are kept as bare names.
func groupFromDN(value string) directoryGroup {
	dn, err := ldap.ParseDN(value)
	if err != nil || len(dn.RDNs) == 0 || len(dn.RDNs[0].Attributes) == 0 {
		return directoryGroup{name: value, rawName: value}
	}
	first := dn.RDNs[0].Attributes[0]
	g := directoryGroup{dn: dn, rawName: first.Value, name: first.Value}
	if strings.EqualFold(first.Type, "spn") {
		if at := strings.LastIndex(first.Value, "@"); at > 0 {
			g.name = first.Value[:at]
		}
	}
	return g
}

func (g directoryGroup) matches(ref groupRef) bool {
	if ref.dn != nil {
		return g.dn != nil && dnEqualFold(ref.dn, g.dn)
	}
	return asciiEqualFold(ref.name, g.name) || asciiEqualFold(ref.name, g.rawName)
}

// asciiEqualFold compares strings ignoring ASCII case only. strings.EqualFold
// applies Unicode folding, which makes look-alikes such as "ſilo-admins"
// (U+017F) or a Kelvin sign (U+212A) match "silo-admins" and "k".
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// dnEqualFold compares two DNs with asciiEqualFold on attribute types and
// values. The values of a multi-valued RDN may come in any order.
func dnEqualFold(a, b *ldap.DN) bool {
	if a == nil || b == nil || len(a.RDNs) != len(b.RDNs) {
		return false
	}
	for i, ra := range a.RDNs {
		rb := b.RDNs[i]
		if len(ra.Attributes) != len(rb.Attributes) {
			return false
		}
		for _, x := range ra.Attributes {
			found := false
			for _, y := range rb.Attributes {
				if asciiEqualFold(x.Type, y.Type) && asciiEqualFold(x.Value, y.Value) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// sameDN reports whether two DN strings name the same entry.
func sameDN(a, b string) bool {
	if asciiEqualFold(a, b) {
		return true
	}
	da, errA := ldap.ParseDN(a)
	db, errB := ldap.ParseDN(b)
	return errA == nil && errB == nil && dnEqualFold(da, db)
}

func memberOfAny(groups []directoryGroup, refs []groupRef) bool {
	for _, ref := range refs {
		for _, g := range groups {
			if g.matches(ref) {
				return true
			}
		}
	}
	return false
}

// groupNames returns sorted, de-duplicated display names.
func groupNames(groups []directoryGroup) []string {
	seen := make(map[string]struct{}, len(groups))
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		if g.name == "" {
			continue
		}
		key := strings.ToLower(g.name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		names = append(names, g.name)
	}
	sort.Strings(names)
	return names
}

// gateResult is the outcome of the allowed-groups and admin-groups rules.
type gateResult struct {
	allowed bool
	role    pluginv1.AuthManagedRole
}

// applyGates evaluates the group rules. An empty allowed list lets everyone
// in; members of an admin group always pass the allowed gate. The role is
// managed only when admin groups are configured.
func applyGates(s *Settings, groups []directoryGroup) gateResult {
	admin := memberOfAny(groups, s.AdminGroups)
	result := gateResult{
		allowed: len(s.AllowedGroups) == 0 || admin || memberOfAny(groups, s.AllowedGroups),
		role:    pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED,
	}
	if len(s.AdminGroups) > 0 {
		result.role = pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER
		if admin {
			result.role = pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN
		}
	}
	return result
}
