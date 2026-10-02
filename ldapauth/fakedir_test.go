package ldapauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
)

// fakeDirectory is an in-process LDAP server with real wire protocol, TLS,
// StartTLS, and filter evaluation, so tests exercise go-ldap end to end,
// including how usernames are escaped on the wire.
type fakeDirectory struct {
	t      *testing.T
	server *gldap.Server
	addr   string
	caPEM  string
	scheme string

	mu       sync.Mutex
	entries  []*fakeEntry
	filters  []string
	binds    []string
	bound    map[int]string
	failBind map[string]bindOutcome
	// unescapedWildcards mimics the authentik LDAP outpost, which treats an
	// escaped "\2a" in an equality assertion as a wildcard.
	unescapedWildcards bool
	// ignorePresence mimics the authentik outpost too, which treats a
	// presence test such as (memberOf=*) as true for every entry.
	ignorePresence bool
	// hiddenAttrs and hiddenDNs mimic access controls: the service account
	// can neither read nor filter on these attributes and entries.
	hiddenAttrs []string
	hiddenDNs   []string
	// serverSizeLimit mimics a server-side size limit (OpenLDAP's soft
	// limit, AD's MaxPageSize) that applies whatever the client asks for.
	serverSizeLimit int
}

type fakeEntry struct {
	dn       string
	password string
	attrs    map[string][]string
}

// bindOutcome overrides what a bind to one DN returns.
type bindOutcome struct {
	code     int
	message  string
	controls []gldap.Control
}

type fakeMode int

const (
	fakeLDAPS fakeMode = iota
	fakePlainWithStartTLS
)

func startFakeDirectory(t *testing.T, mode fakeMode) *fakeDirectory {
	t.Helper()
	caPEM, serverCert := testCertificates(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}

	d := &fakeDirectory{
		t:        t,
		caPEM:    caPEM,
		bound:    map[int]string{},
		failBind: map[string]bindOutcome{},
	}
	server, err := gldap.NewServer(gldap.WithLogger(hclog.NewNullLogger()), gldap.WithDisablePanicRecovery())
	if err != nil {
		t.Fatal(err)
	}
	mux, err := gldap.NewMux()
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(mux.Bind(d.handleBind))
	must(mux.Search(d.handleSearch))
	must(mux.ExtendedOperation(func(w *gldap.ResponseWriter, r *gldap.Request) {
		res := r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultSuccess))
		res.SetResponseName(gldap.ExtendedOperationStartTLS)
		_ = w.Write(res)
		_ = r.StartTLS(tlsConfig)
	}, gldap.ExtendedOperationStartTLS))
	must(mux.DefaultRoute(func(w *gldap.ResponseWriter, r *gldap.Request) {
		_ = w.Write(r.NewResponse(gldap.WithResponseCode(gldap.ResultUnwillingToPerform)))
	}))
	must(server.Router(mux))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.addr = listener.Addr().String()
	_ = listener.Close()
	var runOpts []gldap.Option
	d.scheme = "ldap"
	if mode == fakeLDAPS {
		runOpts = append(runOpts, gldap.WithTLSConfig(tlsConfig))
		d.scheme = "ldaps"
	}
	go func() { _ = server.Run(d.addr, runOpts...) }()
	deadline := time.Now().Add(5 * time.Second)
	for !server.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("fake directory did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.server = server
	t.Cleanup(func() { _ = server.Stop() })
	return d
}

func (d *fakeDirectory) url() string { return d.scheme + "://" + d.addr }

func (d *fakeDirectory) add(dn, password string, attrs map[string][]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = append(d.entries, &fakeEntry{dn: dn, password: password, attrs: attrs})
}

func (d *fakeDirectory) setAttr(dn, attr string, values ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.entries {
		if strings.EqualFold(e.dn, dn) {
			e.attrs[attr] = values
		}
	}
}

func (d *fakeDirectory) hideAttr(attr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hiddenAttrs = append(d.hiddenAttrs, attr)
}

func (d *fakeDirectory) hideDN(dn string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hiddenDNs = append(d.hiddenDNs, dn)
}

func (d *fakeDirectory) unhide() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hiddenAttrs, d.hiddenDNs = nil, nil
}

func (d *fakeDirectory) setServerSizeLimit(n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.serverSizeLimit = n
}

// visibleEntries returns copies of the entries the service account may see,
// without hidden attributes. Callers hold d.mu.
func (d *fakeDirectory) visibleEntries() []*fakeEntry {
	var out []*fakeEntry
	for _, e := range d.entries {
		if slices.ContainsFunc(d.hiddenDNs, func(dn string) bool { return strings.EqualFold(dn, e.dn) }) {
			continue
		}
		attrs := make(map[string][]string, len(e.attrs))
		for name, values := range e.attrs {
			if !slices.ContainsFunc(d.hiddenAttrs, func(a string) bool { return strings.EqualFold(a, name) }) {
				attrs[name] = values
			}
		}
		out = append(out, &fakeEntry{dn: e.dn, password: e.password, attrs: attrs})
	}
	return out
}

func (d *fakeDirectory) failBindFor(dn string, outcome bindOutcome) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failBind[strings.ToLower(dn)] = outcome
}

func (d *fakeDirectory) seenFilters() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.filters...)
}

func (d *fakeDirectory) seenBinds() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.binds...)
}

func (d *fakeDirectory) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { _ = w.Write(resp) }()
	m, err := r.GetSimpleBindMessage()
	if err != nil || m.AuthChoice != gldap.SimpleAuthChoice {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.binds = append(d.binds, m.UserName)
	delete(d.bound, r.ConnectionID())
	if outcome, ok := d.failBind[strings.ToLower(m.UserName)]; ok {
		if outcome.code != gldap.ResultSuccess {
			resp.SetResultCode(outcome.code)
			resp.SetDiagnosticMessage(outcome.message)
		} else if string(m.Password) == d.passwordFor(m.UserName) {
			resp.SetResultCode(gldap.ResultSuccess)
			d.bound[r.ConnectionID()] = m.UserName
		}
		resp.SetControls(outcome.controls...)
		return
	}
	if m.Password == "" {
		// Mimic servers that accept unauthenticated binds.
		resp.SetResultCode(gldap.ResultSuccess)
		return
	}
	if want := d.passwordFor(m.UserName); want != "" && string(m.Password) == want {
		resp.SetResultCode(gldap.ResultSuccess)
		d.bound[r.ConnectionID()] = m.UserName
	}
}

func (d *fakeDirectory) passwordFor(dn string) string {
	target, err := ldap.ParseDN(dn)
	if err != nil {
		return ""
	}
	for _, e := range d.entries {
		if parsed, err := ldap.ParseDN(e.dn); err == nil && parsed.EqualFold(target) {
			return e.password
		}
	}
	return ""
}

func (d *fakeDirectory) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	defer func() { _ = w.Write(done) }()
	m, err := r.GetSearchMessage()
	if err != nil {
		done.SetResultCode(gldap.ResultProtocolError)
		return
	}
	d.mu.Lock()
	d.filters = append(d.filters, m.Filter)
	_, bound := d.bound[r.ConnectionID()]
	entries := d.visibleEntries()
	wildcards := d.unescapedWildcards
	presence := d.ignorePresence
	sizeLimit := m.SizeLimit
	if d.serverSizeLimit > 0 && (sizeLimit == 0 || int64(d.serverSizeLimit) < sizeLimit) {
		sizeLimit = int64(d.serverSizeLimit)
	}
	d.mu.Unlock()
	if !bound {
		done.SetResultCode(gldap.ResultInsufficientAccessRights)
		return
	}
	filter, err := ldap.CompileFilter(m.Filter)
	if err != nil {
		done.SetResultCode(gldap.ResultProtocolError)
		return
	}
	base, err := ldap.ParseDN(m.BaseDN)
	if err != nil {
		done.SetResultCode(gldap.ResultInvalidDNSyntax)
		return
	}
	baseFound := false
	var matches []*fakeEntry
	for _, e := range entries {
		dn, _ := ldap.ParseDN(e.dn)
		if dn.EqualFold(base) {
			baseFound = true
		}
		switch m.Scope {
		case gldap.BaseObject:
			if !dn.EqualFold(base) {
				continue
			}
		default:
			if !dn.EqualFold(base) && !base.AncestorOfFold(dn) {
				continue
			}
		}
		if evalFilter(filter, e, wildcards, presence) {
			matches = append(matches, e)
		}
	}
	if !baseFound && len(base.RDNs) > 0 {
		// Treat any ancestor of a stored entry as existing, like a real
		// directory's organizational units.
		for _, e := range entries {
			if dn, _ := ldap.ParseDN(e.dn); base.AncestorOfFold(dn) {
				baseFound = true
				break
			}
		}
	}
	if !baseFound {
		done.SetResultCode(gldap.ResultNoSuchObject)
		return
	}
	for i, e := range matches {
		if sizeLimit > 0 && int64(i) >= sizeLimit {
			done.SetResultCode(gldap.ResultSizeLimitExceeded)
			return
		}
		entry := r.NewSearchResponseEntry(e.dn)
		for name, values := range e.attrs {
			if wantAttribute(m.Attributes, name) {
				entry.AddAttribute(name, values)
			}
		}
		_ = w.Write(entry)
	}
}

func wantAttribute(requested []string, name string) bool {
	if len(requested) == 0 {
		return true
	}
	for _, r := range requested {
		if r == "*" || strings.EqualFold(r, name) {
			return true
		}
	}
	return false
}

func (e *fakeEntry) values(attr string) []string {
	for name, values := range e.attrs {
		if strings.EqualFold(name, attr) {
			return values
		}
	}
	return nil
}

func valueEqual(attr, a, b string) bool {
	if isBinaryIDAttribute(attr) {
		return a == b
	}
	return strings.EqualFold(a, b)
}

// evalFilter evaluates the subset of RFC 4515 the plugin sends.
func evalFilter(p *ber.Packet, e *fakeEntry, wildcards, ignorePresence bool) bool {
	switch p.Tag {
	case ldap.FilterAnd:
		for _, c := range p.Children {
			if !evalFilter(c, e, wildcards, ignorePresence) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, c := range p.Children {
			if evalFilter(c, e, wildcards, ignorePresence) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return !evalFilter(p.Children[0], e, wildcards, ignorePresence)
	case ldap.FilterPresent:
		attr := p.Data.String()
		if ignorePresence || strings.EqualFold(attr, "objectClass") {
			return true
		}
		return len(e.values(attr)) > 0
	case ldap.FilterEqualityMatch:
		attr := p.Children[0].Data.String()
		want := p.Children[1].Data.String()
		for _, v := range e.values(attr) {
			if valueEqual(attr, v, want) || (wildcards && strings.Contains(want, "*") && globMatch(strings.ToLower(want), strings.ToLower(v))) {
				return true
			}
		}
		return false
	case ldap.FilterExtensibleMatch:
		// Only attribute:rule:=value, with caseExactMatch compared exactly
		// and any other rule case-insensitively. A value of "*" is a
		// literal, as on a real server.
		var rule, attr, want string
		for _, c := range p.Children {
			switch c.Tag {
			case ldap.MatchingRuleAssertionMatchingRule:
				rule = c.Data.String()
			case ldap.MatchingRuleAssertionType:
				attr = c.Data.String()
			case ldap.MatchingRuleAssertionMatchValue:
				want = c.Data.String()
			}
		}
		for _, v := range e.values(attr) {
			if v == want || (!strings.EqualFold(rule, "caseExactMatch") && strings.EqualFold(v, want)) {
				return true
			}
		}
		return false
	case ldap.FilterSubstrings:
		attr := p.Children[0].Data.String()
		for _, v := range e.values(attr) {
			if substringMatch(strings.ToLower(v), p.Children[1].Children) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// globMatch matches pattern with "*" wildcards against value.
func globMatch(pattern, value string) bool {
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(value, part)
		if i < 0 {
			return false
		}
		value = value[i+len(part):]
	}
	return strings.HasSuffix(value, parts[len(parts)-1])
}

func substringMatch(value string, parts []*ber.Packet) bool {
	for _, part := range parts {
		s := strings.ToLower(part.Data.String())
		switch part.Tag {
		case ldap.FilterSubstringsInitial:
			if !strings.HasPrefix(value, s) {
				return false
			}
			value = value[len(s):]
		case ldap.FilterSubstringsAny:
			i := strings.Index(value, s)
			if i < 0 {
				return false
			}
			value = value[i+len(s):]
		case ldap.FilterSubstringsFinal:
			if !strings.HasSuffix(value, s) {
				return false
			}
		}
	}
	return true
}

// testCertificates returns a CA PEM and a server certificate for 127.0.0.1
// signed by it.
func testCertificates(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake directory CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), cert
}
