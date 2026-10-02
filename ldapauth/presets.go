package ldapauth

// Directory presets. A preset supplies defaults for every user and group
// setting the operator leaves blank; an explicit value always wins.
const (
	presetGeneric         = "generic"
	presetLLDAP           = "lldap"
	presetAuthentik       = "authentik"
	presetActiveDirectory = "active_directory"
	presetFreeIPA         = "freeipa"
	presetOpenLDAP        = "openldap"
	presetKanidm          = "kanidm"
	presetGLAuth          = "glauth"
)

type preset struct {
	Label                string
	UserFilter           string
	UsernameAttribute    string
	EmailAttribute       string
	DisplayNameAttribute string
	UniqueIDAttribute    string
	GroupSource          string
	MembershipAttribute  string
	GroupFilter          string
	GroupNameAttribute   string
	// RequireLDAPS rejects ldap:// URLs and StartTLS (Kanidm serves LDAPS only).
	RequireLDAPS bool
	// NoStartTLS rejects StartTLS for servers that refuse it (lldap answers
	// 53, the authentik outpost a protocol error); use ldaps:// instead.
	NoStartTLS bool
	// ServerAssignedID marks a UniqueIDAttribute the directory assigns and
	// never reuses, beyond the standard ones in serverAssignedIDAttributes.
	ServerAssignedID bool
	// UniqueGroupNames marks directories whose group names are unique across
	// the whole directory. Elsewhere a name is unique only within its
	// container, so admin groups must be full DNs.
	UniqueGroupNames bool
}

// openLDAPGroupFilter matches the three common static group shapes, so a
// directory without the memberOf overlay still resolves groups.
const openLDAPGroupFilter = "(|(&(objectClass=groupOfNames)(member={dn}))(&(objectClass=groupOfUniqueNames)(uniqueMember={dn}))(&(objectClass=posixGroup)(memberUid={username})))"

var presets = map[string]preset{
	presetGeneric: {
		Label:                "Generic LDAP",
		UserFilter:           "(&(objectClass=person)(uid={username}))",
		UsernameAttribute:    "uid",
		EmailAttribute:       "mail",
		DisplayNameAttribute: "displayName",
		UniqueIDAttribute:    "entryUUID",
		GroupSource:          groupSourceMemberOf,
		MembershipAttribute:  "memberOf",
		GroupFilter:          openLDAPGroupFilter,
		GroupNameAttribute:   "cn",
	},
	presetLLDAP: {
		Label:                "lldap",
		UserFilter:           "(&(objectClass=person)(uid={username}))",
		UsernameAttribute:    "uid",
		EmailAttribute:       "mail",
		DisplayNameAttribute: "displayName",
		UniqueIDAttribute:    "entryUUID",
		GroupSource:          groupSourceMemberOf,
		MembershipAttribute:  "memberOf",
		GroupFilter:          "(&(objectClass=groupOfUniqueNames)(uniqueMember={dn}))",
		GroupNameAttribute:   "cn",
		NoStartTLS:           true,
		UniqueGroupNames:     true,
	},
	presetAuthentik: {
		Label:                "authentik LDAP outpost",
		UserFilter:           "(&(objectClass=user)(cn={username}))",
		UsernameAttribute:    "cn",
		EmailAttribute:       "mail",
		DisplayNameAttribute: "displayName",
		// authentik's uid is a stable hash of the user's primary key.
		UniqueIDAttribute:   "uid",
		ServerAssignedID:    true,
		GroupSource:         groupSourceMemberOf,
		MembershipAttribute: "memberOf",
		GroupFilter:         "(&(objectClass=group)(member={dn}))",
		GroupNameAttribute:  "cn",
		NoStartTLS:          true,
		UniqueGroupNames:    true,
	},
	presetActiveDirectory: {
		Label:                "Active Directory / Samba",
		UserFilter:           "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))",
		UsernameAttribute:    "sAMAccountName",
		EmailAttribute:       "mail",
		DisplayNameAttribute: "displayName",
		UniqueIDAttribute:    "objectGUID",
		// memberOf lists direct memberships only. It stays the default
		// because in-chain searches can be slow on large domains; choose
		// the group search to resolve nested groups with the
		// LDAP_MATCHING_RULE_IN_CHAIN filter below.
		GroupSource:         groupSourceMemberOf,
		MembershipAttribute: "memberOf",
		GroupFilter:         "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={dn}))",
		GroupNameAttribute:  "cn",
	},
	presetFreeIPA: {
		Label:                "FreeIPA",
		UserFilter:           "(&(objectClass=person)(uid={username}))",
		UsernameAttribute:    "uid",
		EmailAttribute:       "mail",
		DisplayNameAttribute: "displayName",
		UniqueIDAttribute:    "ipaUniqueID",
		GroupSource:          groupSourceMemberOf,
		MembershipAttribute:  "memberOf",
		GroupFilter:          "(&(objectClass=groupOfNames)(member={dn}))",
		GroupNameAttribute:   "cn",
		UniqueGroupNames:     true,
	},
	presetOpenLDAP: {
		Label:                "OpenLDAP",
		UserFilter:           "(&(objectClass=inetOrgPerson)(uid={username}))",
		UsernameAttribute:    "uid",
		EmailAttribute:       "mail",
		DisplayNameAttribute: "displayName",
		UniqueIDAttribute:    "entryUUID",
		// Group search works with or without the memberOf overlay.
		GroupSource:         groupSourceSearch,
		MembershipAttribute: "memberOf",
		GroupFilter:         openLDAPGroupFilter,
		GroupNameAttribute:  "cn",
	},
	presetKanidm: {
		Label:                "Kanidm",
		UserFilter:           "(&(class=person)(name={username}))",
		UsernameAttribute:    "name",
		EmailAttribute:       "mail",
		DisplayNameAttribute: "displayname",
		UniqueIDAttribute:    "uuid",
		ServerAssignedID:     true,
		GroupSource:          groupSourceMemberOf,
		MembershipAttribute:  "memberof",
		GroupFilter:          "(&(class=group)(member={dn}))",
		GroupNameAttribute:   "name",
		RequireLDAPS:         true,
		UniqueGroupNames:     true,
	},
	presetGLAuth: {
		Label:                "GLAuth",
		UserFilter:           "(&(objectClass=posixAccount)(uid={username}))",
		UsernameAttribute:    "uid",
		EmailAttribute:       "mail",
		DisplayNameAttribute: "cn",
		// GLAuth has no server-assigned ID. uidNumber is assigned by the
		// operator and must never be reused after a user is deleted, or the
		// next holder inherits the old Silo account.
		UniqueIDAttribute:   "uidNumber",
		GroupSource:         groupSourceMemberOf,
		MembershipAttribute: "memberOf",
		GroupFilter:         "(&(objectClass=posixGroup)(memberUid={username}))",
		GroupNameAttribute:  "cn",
		UniqueGroupNames:    true,
	},
}
