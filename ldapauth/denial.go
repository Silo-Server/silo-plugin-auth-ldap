package ldapauth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/go-ldap/ldap/v3"
)

// Behera password-policy error values (draft-behera-ldap-password-policy).
const (
	beheraPasswordExpired  = 0
	beheraAccountLocked    = 1
	beheraChangeAfterReset = 2
)

// adDataCode extracts the sub-code Active Directory and Samba put in the
// diagnostic message of a failed bind, such as "... data 52e, v4563".
var adDataCode = regexp.MustCompile(`(?i)\bdata ([0-9a-f]{3,8})\b`)

// adDenials maps Active Directory bind sub-codes to denials.
var adDenials = map[string]struct {
	code   pluginv1.AuthDenial
	reason string
}{
	"525": {pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "user not found"},
	"52e": {pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "invalid credentials"},
	"530": {pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "logon not permitted at this time"},
	"531": {pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "logon not permitted at this workstation"},
	"532": {pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED, "password expired"},
	"533": {pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED, "account disabled"},
	"568": {pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED, "too many security IDs"},
	"701": {pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED, "account expired"},
	"773": {pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED, "password must be reset"},
	"775": {pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED, "account locked out"},
}

// denial is a refusal with an operator-facing detail.
type denial struct {
	code   pluginv1.AuthDenial
	detail string
}

func deny(code pluginv1.AuthDenial, format string, args ...any) *denial {
	return &denial{code: code, detail: fmt.Sprintf(format, args...)}
}

// classifyBindError turns a failed user bind into a denial. controls are the
// response controls of the bind, when the server sent any.
func classifyBindError(err error, controls []ldap.Control) *denial {
	if d := policyControlDenial(controls); d != nil {
		return d
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "user bind failed: %v", err)
	}
	message := diagnosticMessage(ldapErr)
	lower := strings.ToLower(message)
	switch ldapErr.ResultCode {
	case ldap.LDAPResultInvalidCredentials:
		if m := adDataCode.FindStringSubmatch(message); m != nil {
			sub := strings.ToLower(m[1])
			if ad, ok := adDenials[sub]; ok {
				return deny(ad.code, "directory refused the bind: %s (data %s)", ad.reason, sub)
			}
		}
		switch {
		case strings.Contains(lower, "password expired"), strings.Contains(lower, "password has expired"),
			strings.Contains(lower, "must change"), strings.Contains(lower, "must be changed"):
			return deny(pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED, "directory refused the bind: password expired (%s)", message)
		case strings.Contains(lower, "account inactivated"), strings.Contains(lower, "account is locked"),
			strings.Contains(lower, "account locked"), strings.Contains(lower, "account disabled"):
			return deny(pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED, "directory refused the bind: account disabled or locked (%s)", message)
		}
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "directory refused the bind: invalid credentials")
	case ldap.LDAPResultUnwillingToPerform:
		// FreeIPA and 389 Directory Server answer a bind to a locked
		// (nsAccountLock) account with "Account inactivated".
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED, "directory refused the bind as unwilling to perform: %s", orNone(message))
	case ldap.LDAPResultConstraintViolation:
		// 389 Directory Server: "Exceed password retry limit. Please try later."
		if strings.Contains(lower, "retry limit") || strings.Contains(lower, "locked") {
			return deny(pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED, "directory refused the bind: account locked (%s)", message)
		}
		if strings.Contains(lower, "expired") {
			return deny(pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED, "directory refused the bind: password expired (%s)", message)
		}
	case ldap.LDAPResultNoSuchObject, ldap.LDAPResultInvalidDNSyntax:
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "directory refused the bind: %s", ldap.LDAPResultCodeMap[ldapErr.ResultCode])
	case ldap.LDAPResultConfidentialityRequired, ldap.LDAPResultStrongAuthRequired:
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "directory requires an encrypted connection; use ldaps:// or StartTLS")
	}
	return deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "user bind failed with LDAP result %d (%s): %s",
		ldapErr.ResultCode, ldap.LDAPResultCodeMap[ldapErr.ResultCode], orNone(message))
}

// policyControlDenial reads password-policy response controls. They can
// arrive on a failed bind (OpenLDAP ppolicy) or on a successful one (389
// Directory Server and FreeIPA send the password-expired control and let the
// bind through so the user can change the password).
func policyControlDenial(controls []ldap.Control) *denial {
	for _, control := range controls {
		switch c := control.(type) {
		case *ldap.ControlBeheraPasswordPolicy:
			switch c.Error {
			case beheraPasswordExpired, beheraChangeAfterReset:
				return deny(pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED, "password policy: %s", c.ErrorString)
			case beheraAccountLocked:
				return deny(pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED, "password policy: %s", c.ErrorString)
			}
		case *ldap.ControlVChuPasswordMustChange:
			if c.MustChange {
				return deny(pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED, "directory reports the password has expired")
			}
		}
	}
	return nil
}

// diagnosticMessage returns the server's diagnostic text without the
// library's "LDAP Result Code" prefix.
func diagnosticMessage(err *ldap.Error) string {
	if err == nil || err.Err == nil {
		return ""
	}
	return strings.TrimSpace(err.Err.Error())
}

func orNone(message string) string {
	if message == "" {
		return "no diagnostic message"
	}
	return message
}
