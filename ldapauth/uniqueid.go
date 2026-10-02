package ldapauth

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// binaryIDAttributes hold 16-byte GUIDs in Microsoft byte order. Their
// external_subject is the canonical GUID string.
var binaryIDAttributes = map[string]struct{}{
	"objectguid":            {},
	"ms-ds-consistencyguid": {},
	"msds-consistencyguid":  {},
}

// serverAssignedIDAttributes are set by the directory when an entry is
// created and never reused, so two entries cannot share a value.
var serverAssignedIDAttributes = map[string]struct{}{
	"entryuuid":   {},
	"objectguid":  {},
	"ipauniqueid": {},
	"nsuniqueid":  {},
}

func isBinaryIDAttribute(attr string) bool {
	_, ok := binaryIDAttributes[strings.ToLower(attr)]
	return ok
}

// uniqueIDValue reads the unique id attribute from an entry and returns it in
// the form used as external_subject. It returns "" when the entry lacks it.
func uniqueIDValue(entry *ldap.Entry, attr string) (string, error) {
	if isBinaryIDAttribute(attr) {
		raw := entry.GetEqualFoldRawAttributeValue(attr)
		if len(raw) == 0 {
			return "", nil
		}
		return formatGUID(raw)
	}
	return entry.GetEqualFoldAttributeValue(attr), nil
}

// uniqueIDFilterValue turns an external_subject back into an escaped filter
// assertion value for the unique id attribute.
func uniqueIDFilterValue(attr, subject string) (string, error) {
	if !isBinaryIDAttribute(attr) {
		return ldap.EscapeFilter(subject), nil
	}
	raw, err := parseGUID(subject)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range raw {
		fmt.Fprintf(&b, "\\%02x", c)
	}
	return b.String(), nil
}

// formatGUID renders a Microsoft GUID: the first three fields are stored
// little-endian, the last two big-endian.
func formatGUID(raw []byte) (string, error) {
	if len(raw) != 16 {
		return "", fmt.Errorf("GUID has %d bytes, want 16", len(raw))
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		raw[8:10],
		raw[10:16],
	), nil
}

func parseGUID(value string) ([]byte, error) {
	clean := strings.ReplaceAll(strings.Trim(value, "{}"), "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return nil, fmt.Errorf("%q is not a GUID", value)
	}
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], binary.BigEndian.Uint32(b[0:4]))
	binary.LittleEndian.PutUint16(out[4:6], binary.BigEndian.Uint16(b[4:6]))
	binary.LittleEndian.PutUint16(out[6:8], binary.BigEndian.Uint16(b[6:8]))
	copy(out[8:], b[8:])
	return out, nil
}
