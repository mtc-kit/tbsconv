package tbsconv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// logEntryFields holds the DER encoding of each field of a TBSCertificateLogEntry.
type logEntryFields struct {
	version, issuer, validity, subject, spkiAlgorithm, spkiHash, trailer []byte
}

func parseLogEntry(t testing.TB, der []byte) logEntryFields {
	t.Helper()
	input := cryptobyte.String(der)
	var body, version, issuer, validity, subject, alg cryptobyte.String
	var hash []byte
	if !input.ReadASN1(&body, cbasn1.SEQUENCE) || !input.Empty() ||
		!readOptionalElement(&body, &version, tagVersion) ||
		!body.ReadASN1Element(&issuer, cbasn1.SEQUENCE) ||
		!body.ReadASN1Element(&validity, cbasn1.SEQUENCE) ||
		!body.ReadASN1Element(&subject, cbasn1.SEQUENCE) ||
		!body.ReadASN1Element(&alg, cbasn1.SEQUENCE) ||
		!body.ReadASN1Bytes(&hash, cbasn1.OCTET_STRING) {
		t.Fatalf("cannot parse TBSCertificateLogEntry %x", der)
	}
	return logEntryFields{version, issuer, validity, subject, alg, hash, body}
}

// newTestCertificate returns a certificate whose subject key (P-384) differs
// from the dummy one (P-256).
func newTestCertificate(t testing.TB) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"Test"}, CommonName: "Test CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	leaf := &x509.Certificate{
		SerialNumber: new(big.Int).Lsh(big.NewInt(1), 100),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "www.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.AddDate(0, 0, 7),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// parseTBSCertificate wraps tbs in a Certificate with a bogus signature so
// that it can be parsed by crypto/x509.
func parseTBSCertificate(t *testing.T, tbs []byte) *x509.Certificate {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(dummySignatureAlgorithm)
		b.AddASN1BitString([]byte{0})
	})
	cert, err := x509.ParseCertificate(b.BytesOrPanic())
	if err != nil {
		t.Fatalf("cannot parse converted TBSCertificate: %v", err)
	}
	return cert
}

func TestDummyLogEntryIssuer(t *testing.T) {
	// The draft gives the CA ID name for 32473.1 as
	// 1.3.6.1.5.5.7.25.3=#0d0481fd5901 in RFC 4514 syntax.
	want, _ := hex.DecodeString("3014" + "3112" + "3010" + "06082b06010505071903" + "0d0481fd5901")
	if !bytes.Equal(dummyLogEntryIssuer, want) {
		t.Errorf("dummy log entry issuer = %x, want %x", dummyLogEntryIssuer, want)
	}
}

// parseCAIDName returns the RELATIVE-OID contents octets of a CA ID name.
func parseCAIDName(t testing.TB, name []byte) []byte {
	t.Helper()
	s := cryptobyte.String(name)
	var rdns, rdn, attribute cryptobyte.String
	var oid asn1.ObjectIdentifier
	var value []byte
	if !s.ReadASN1(&rdns, cbasn1.SEQUENCE) || !s.Empty() ||
		!rdns.ReadASN1(&rdn, cbasn1.SET) || !rdns.Empty() ||
		!rdn.ReadASN1(&attribute, cbasn1.SEQUENCE) || !rdn.Empty() ||
		!attribute.ReadASN1ObjectIdentifier(&oid) || !oid.Equal(oidTrustAnchorID) ||
		!attribute.ReadASN1Bytes(&value, tagRelativeOID) || !attribute.Empty() {
		t.Fatalf("%x is not a CA ID name", name)
	}
	return value
}

func TestCAIDName(t *testing.T) {
	for id, want := range map[string]string{
		"0":                    "00",
		"127":                  "7f",
		"128":                  "8100",
		"32473.1":              "81fd5901",
		"1.2.3":                "010203",
		"18446744073709551615": "81ffffffffffffffff7f",
	} {
		name, err := caIDName(id)
		if err != nil {
			t.Errorf("caIDName(%q): %v", id, err)
			continue
		}
		if got := hex.EncodeToString(parseCAIDName(t, name)); got != want {
			t.Errorf("caIDName(%q) RELATIVE-OID = %s, want %s", id, got, want)
		}
	}

	for _, id := range []string{"", ".", "1.", ".1", "1..2", "01", "1.02", "a", "-1", "+1", " 1", "18446744073709551616"} {
		if name, err := caIDName(id); err == nil {
			t.Errorf("caIDName(%q) = %x, want error", id, name)
		}
	}
}

func TestDummyTBSCertificateIssuer(t *testing.T) {
	var name pkix.RDNSequence
	if _, err := asn1.Unmarshal(dummyTBSCertificateIssuer, &name); err != nil {
		t.Fatal(err)
	}
	if got, want := name.String(), "CN=Dummy Merkle Tree CA,O=Dummy Organization,C=XX"; got != want {
		t.Errorf("dummy TBSCertificate issuer = %q, want %q", got, want)
	}
	for _, rdn := range name {
		if len(rdn) != 1 {
			t.Errorf("RDN %v has %d attributes, want 1", rdn, len(rdn))
		}
	}
}

func TestToTBSCertificateLogEntry(t *testing.T) {
	cert := newTestCertificate(t)
	entry, err := ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	got := parseLogEntry(t, entry)

	// Extract the fields that should be copied from the certificate.
	tbs := cryptobyte.String(cert.RawTBSCertificate)
	var body, version, validity, spkiAlgorithm cryptobyte.String
	if !tbs.ReadASN1(&body, cbasn1.SEQUENCE) ||
		!body.ReadASN1Element(&version, tagVersion) ||
		!body.SkipASN1(cbasn1.INTEGER) ||
		!body.SkipASN1(cbasn1.SEQUENCE) ||
		!body.SkipASN1(cbasn1.SEQUENCE) ||
		!body.ReadASN1Element(&validity, cbasn1.SEQUENCE) ||
		!body.SkipASN1(cbasn1.SEQUENCE) ||
		!body.SkipASN1(cbasn1.SEQUENCE) {
		t.Fatal("cannot parse test TBSCertificate")
	}
	spki := cryptobyte.String(cert.RawSubjectPublicKeyInfo)
	var spkiBody cryptobyte.String
	if !spki.ReadASN1(&spkiBody, cbasn1.SEQUENCE) || !spkiBody.ReadASN1Element(&spkiAlgorithm, cbasn1.SEQUENCE) {
		t.Fatal("cannot parse test SubjectPublicKeyInfo")
	}
	wantHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	for _, c := range []struct {
		field     string
		got, want []byte
	}{
		{"version", got.version, version},
		{"issuer", got.issuer, dummyLogEntryIssuer},
		{"validity", got.validity, validity},
		{"subject", got.subject, cert.RawSubject},
		{"subjectPublicKeyAlgorithm", got.spkiAlgorithm, spkiAlgorithm},
		{"subjectPublicKeyInfoHash", got.spkiHash, wantHash[:]},
		{"trailer", got.trailer, body},
	} {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s = %x, want %x", c.field, c.got, c.want)
		}
	}
}

func TestToTBSCertificateLogEntryWithIssuer(t *testing.T) {
	cert := newTestCertificate(t)
	entry, err := ToTBSCertificateLogEntryWithIssuer(cert.RawTBSCertificate, "32473.2")
	if err != nil {
		t.Fatal(err)
	}
	defaultEntry, err := ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	wantIssuer, err := caIDName("32473.2")
	if err != nil {
		t.Fatal(err)
	}

	// Only the issuer differs from the default conversion.
	got, want := parseLogEntry(t, entry), parseLogEntry(t, defaultEntry)
	want.issuer = wantIssuer
	if !reflect.DeepEqual(got, want) {
		t.Errorf("log entry = %x, want %x with issuer %x", entry, defaultEntry, wantIssuer)
	}

	if _, err := ToTBSCertificateLogEntryWithIssuer(cert.RawTBSCertificate, "32473.01"); err == nil {
		t.Error("ToTBSCertificateLogEntryWithIssuer with an invalid trust anchor ID succeeded, want error")
	}
}

func TestToTBSCertificate(t *testing.T) {
	orig := newTestCertificate(t)
	entry, err := ToTBSCertificateLogEntry(orig.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := ToTBSCertificate(entry)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseTBSCertificate(t, tbs)

	if cert.Version != 3 {
		t.Errorf("version = %d, want 3", cert.Version)
	}
	if cert.SerialNumber.Sign() <= 0 || len(cert.SerialNumber.Bytes()) != 16 {
		t.Errorf("serial number = %x, want a positive 16-octet value", cert.SerialNumber)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("signature algorithm = %v, want %v", cert.SignatureAlgorithm, x509.ECDSAWithSHA256)
	}
	if !bytes.Equal(cert.RawIssuer, dummyTBSCertificateIssuer) {
		t.Errorf("issuer = %v, want the dummy issuer", cert.Issuer)
	}
	if !bytes.Equal(cert.RawSubject, orig.RawSubject) {
		t.Errorf("subject = %v, want %v", cert.Subject, orig.Subject)
	}
	if !cert.NotBefore.Equal(orig.NotBefore) || !cert.NotAfter.Equal(orig.NotAfter) {
		t.Errorf("validity = [%v, %v], want [%v, %v]", cert.NotBefore, cert.NotAfter, orig.NotBefore, orig.NotAfter)
	}
	if !reflect.DeepEqual(cert.Extensions, orig.Extensions) {
		t.Errorf("extensions = %v, want %v", cert.Extensions, orig.Extensions)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("public key = %T, want a P-256 *ecdsa.PublicKey", cert.PublicKey)
	}
	if params := elliptic.P256().Params(); pub.X.Cmp(params.Gx) != 0 || pub.Y.Cmp(params.Gy) != 0 {
		t.Errorf("public key is not the P-256 base point")
	}
}

func TestRoundTrip(t *testing.T) {
	cert := newTestCertificate(t)
	entry, err := ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := ToTBSCertificate(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry2, err := ToTBSCertificateLogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}
	tbs2, err := ToTBSCertificate(entry2)
	if err != nil {
		t.Fatal(err)
	}

	// Only the public key information is lost, as it is replaced by the dummy key.
	got, want := parseLogEntry(t, entry2), parseLogEntry(t, entry)
	got.spkiAlgorithm, got.spkiHash = nil, nil
	want.spkiAlgorithm, want.spkiHash = nil, nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the log entry:\n got %x\nwant %x", entry2, entry)
	}
	// From then on, conversions are stable.
	entry3, err := ToTBSCertificateLogEntry(tbs2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entry3, entry2) {
		t.Errorf("second round trip changed the log entry:\n got %x\nwant %x", entry3, entry2)
	}
}

func TestOptionalFields(t *testing.T) {
	// A v1 log entry with issuerUniqueID and subjectUniqueID but no extensions.
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(dummyLogEntryIssuer)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1UTCTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			b.AddASN1GeneralizedTime(time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC))
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {}) // empty subject
		b.AddBytes(dummySignatureAlgorithm)
		b.AddASN1OctetString(make([]byte, 32))
		b.AddASN1(tagIssuerUniqueID, func(b *cryptobyte.Builder) { b.AddBytes([]byte{0, 1}) })
		b.AddASN1(tagSubjectUniqueID, func(b *cryptobyte.Builder) { b.AddBytes([]byte{0, 2}) })
	})
	entry := b.BytesOrPanic()

	tbs, err := ToTBSCertificate(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry2, err := ToTBSCertificateLogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}
	got, want := parseLogEntry(t, entry2), parseLogEntry(t, entry)
	if got.version != nil {
		t.Errorf("version = %x, want it omitted", got.version)
	}
	if !bytes.Equal(got.validity, want.validity) || !bytes.Equal(got.subject, want.subject) || !bytes.Equal(got.trailer, want.trailer) {
		t.Errorf("round trip changed the log entry:\n got %x\nwant %x", entry2, entry)
	}
}

func TestDeterministic(t *testing.T) {
	cert := newTestCertificate(t)
	entry1, _ := ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	entry2, _ := ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if !bytes.Equal(entry1, entry2) {
		t.Error("ToTBSCertificateLogEntry is not deterministic")
	}
	tbs1, _ := ToTBSCertificate(entry1)
	tbs2, _ := ToTBSCertificate(entry1)
	if !bytes.Equal(tbs1, tbs2) {
		t.Error("ToTBSCertificate is not deterministic")
	}

	other, _ := ToTBSCertificateLogEntry(newTestCertificate(t).RawTBSCertificate)
	tbs3, _ := ToTBSCertificate(other)
	if parseTBSCertificate(t, tbs1).SerialNumber.Cmp(parseTBSCertificate(t, tbs3).SerialNumber) == 0 {
		t.Error("distinct log entries got the same serial number")
	}
}

func TestMalformed(t *testing.T) {
	cert := newTestCertificate(t)
	tbs := cert.RawTBSCertificate
	entry, err := ToTBSCertificateLogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}

	for name, input := range map[string][]byte{
		"empty":          nil,
		"truncated":      tbs[:len(tbs)-1],
		"trailing data":  append(append([]byte{}, tbs...), 0),
		"not a SEQUENCE": append([]byte{0x31}, tbs[1:]...),
		"log entry":      entry,
	} {
		if _, err := ToTBSCertificateLogEntry(input); err == nil {
			t.Errorf("ToTBSCertificateLogEntry(%s) succeeded, want error", name)
		}
	}
	for name, input := range map[string][]byte{
		"empty":          nil,
		"truncated":      entry[:len(entry)-1],
		"trailing data":  append(append([]byte{}, entry...), 0),
		"not a SEQUENCE": append([]byte{0x31}, entry[1:]...),
		"TBSCertificate": tbs,
	} {
		if _, err := ToTBSCertificate(input); err == nil {
			t.Errorf("ToTBSCertificate(%s) succeeded, want error", name)
		}
	}
}

// elements returns the DER elements inside a SEQUENCE.
func elements(t testing.TB, der []byte) [][]byte {
	t.Helper()
	s := cryptobyte.String(der)
	var body cryptobyte.String
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !s.Empty() {
		t.Fatalf("%x is not a SEQUENCE", der)
	}
	var elems [][]byte
	for !body.Empty() {
		var elem cryptobyte.String
		var tag cbasn1.Tag
		if !body.ReadAnyASN1Element(&elem, &tag) {
			t.Fatalf("cannot parse the elements of %x", der)
		}
		elems = append(elems, elem)
	}
	return elems
}

// sequence returns a SEQUENCE holding the given DER elements.
func sequence(elems ...[]byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, elem := range elems {
			b.AddBytes(elem)
		}
	})
	return b.BytesOrPanic()
}

// splice returns a SEQUENCE of elems with elems[i] replaced by replacements.
func splice(elems [][]byte, i int, replacements ...[]byte) []byte {
	var out [][]byte
	out = append(out, elems[:i]...)
	out = append(out, replacements...)
	return sequence(append(out, elems[i+1:]...)...)
}

var (
	testNull            = []byte{0x05, 0x00}
	testIssuerUniqueID  = []byte{0x81, 0x02, 0x00, 0x01}
	testSubjectUniqueID = []byte{0x82, 0x02, 0x00, 0x02}
)

// testElements returns the elements of a test TBSCertificate (version,
// serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo,
// extensions) and of its log entry (version, issuer, validity, subject,
// subjectPublicKeyAlgorithm, subjectPublicKeyInfoHash, extensions).
func testElements(t *testing.T) (tbs, entry [][]byte) {
	t.Helper()
	cert := newTestCertificate(t)
	der, err := ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	tbs, entry = elements(t, cert.RawTBSCertificate), elements(t, der)
	if len(tbs) != 8 || len(entry) != 7 {
		t.Fatalf("test structures have %d and %d elements, want 8 and 7", len(tbs), len(entry))
	}
	return tbs, entry
}

func TestMalformedFields(t *testing.T) {
	tbs, entry := testElements(t)
	spki := elements(t, tbs[6])
	ext := tbs[7]
	primitiveExt := append([]byte{0x83}, ext[1:]...)

	for name, input := range map[string][]byte{
		"version not EXPLICIT":                    splice(tbs, 0, []byte{0x02, 0x01, 0x02}),
		"missing serialNumber":                    splice(tbs, 1),
		"issuer not a SEQUENCE":                   splice(tbs, 3, testNull),
		"missing subjectPublicKeyInfo":            splice(tbs, 6),
		"subjectPublicKeyInfo not a SEQUENCE":     splice(tbs, 6, testNull),
		"subjectPublicKeyInfo without key":        splice(tbs, 6, sequence(spki[0])),
		"subjectPublicKeyInfo key not BIT STRING": splice(tbs, 6, sequence(spki[0], testNull)),
		"subjectPublicKeyInfo with trailing data": splice(tbs, 6, sequence(spki[0], spki[1], testNull)),
		"unique IDs out of order":                 splice(tbs, 7, testSubjectUniqueID, testIssuerUniqueID, ext),
		"extensions before issuerUniqueID":        splice(tbs, 7, ext, testIssuerUniqueID),
		"duplicate extensions":                    splice(tbs, 7, ext, ext),
		"primitive extensions":                    splice(tbs, 7, primitiveExt),
		"unknown trailing field":                  splice(tbs, 7, ext, testNull),
		"truncated issuerUniqueID":                splice(tbs, 7, []byte{0x81, 0x05, 0x00}),
	} {
		if _, err := ToTBSCertificateLogEntry(input); err == nil {
			t.Errorf("ToTBSCertificateLogEntry(%s) succeeded, want error", name)
		}
	}

	for name, input := range map[string][]byte{
		"missing issuer":                       splice(entry, 1),
		"missing subjectPublicKeyAlgorithm":    splice(entry, 4),
		"missing subjectPublicKeyInfoHash":     splice(entry, 5),
		"hash not an OCTET STRING":             splice(entry, 5, []byte{0x03, 0x01, 0x00}),
		"unique IDs out of order":              splice(entry, 6, testSubjectUniqueID, testIssuerUniqueID, ext),
		"extensions before issuerUniqueID":     splice(entry, 6, ext, testIssuerUniqueID),
		"duplicate extensions":                 splice(entry, 6, ext, ext),
		"primitive extensions":                 splice(entry, 6, primitiveExt),
		"unknown trailing field":               splice(entry, 6, ext, testNull),
		"truncated issuerUniqueID":             splice(entry, 6, []byte{0x81, 0x05, 0x00}),
		"subjectPublicKeyInfo instead of hash": splice(entry, 5, tbs[6]),
	} {
		if _, err := ToTBSCertificate(input); err == nil {
			t.Errorf("ToTBSCertificate(%s) succeeded, want error", name)
		}
	}
}

func TestUniqueIDs(t *testing.T) {
	tbs, _ := testElements(t)
	ext := tbs[7]
	for _, trailer := range [][][]byte{
		{},
		{testIssuerUniqueID},
		{testSubjectUniqueID},
		{testIssuerUniqueID, testSubjectUniqueID},
		{testSubjectUniqueID, ext},
		{testIssuerUniqueID, testSubjectUniqueID, ext},
	} {
		want := bytes.Join(trailer, nil)
		entry, err := ToTBSCertificateLogEntry(splice(tbs, 7, trailer...))
		if err != nil {
			t.Errorf("ToTBSCertificateLogEntry with trailer %x: %v", want, err)
			continue
		}
		if got := bytes.Join(elements(t, entry)[6:], nil); !bytes.Equal(got, want) {
			t.Errorf("log entry trailer = %x, want %x", got, want)
		}
		tbs2, err := ToTBSCertificate(entry)
		if err != nil {
			t.Errorf("ToTBSCertificate with trailer %x: %v", want, err)
			continue
		}
		if got := bytes.Join(elements(t, tbs2)[7:], nil); !bytes.Equal(got, want) {
			t.Errorf("TBSCertificate trailer = %x, want %x", got, want)
		}
	}
}

// decodeRelativeOID returns the dotted decimal form of RELATIVE-OID contents
// octets, or "" if they are not minimally encoded.
func decodeRelativeOID(b []byte) string {
	var arcs []string
	var arc uint64
	for _, c := range b {
		if arc == 0 && c == 0x80 {
			return ""
		}
		arc = arc<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			arcs = append(arcs, strconv.FormatUint(arc, 10))
			arc = 0
		}
	}
	return strings.Join(arcs, ".")
}

func FuzzCAIDName(f *testing.F) {
	for _, id := range []string{"32473.1", "0", "1.2.3", "18446744073709551615", "01", "1..2", ""} {
		f.Add(id)
	}
	f.Fuzz(func(t *testing.T, id string) {
		name, err := caIDName(id)
		if err != nil {
			return
		}
		if got := decodeRelativeOID(parseCAIDName(t, name)); got != id {
			t.Errorf("caIDName(%q) encodes %q", id, got)
		}
	})
}

func FuzzToTBSCertificateLogEntry(f *testing.F) {
	f.Add(newTestCertificate(f).RawTBSCertificate)
	f.Fuzz(func(t *testing.T, tbs []byte) {
		entry, err := ToTBSCertificateLogEntry(tbs)
		if err != nil {
			return
		}
		if got := parseLogEntry(t, entry).issuer; !bytes.Equal(got, dummyLogEntryIssuer) {
			t.Errorf("issuer = %x, want the dummy issuer", got)
		}
		if _, err := ToTBSCertificate(entry); err != nil {
			t.Errorf("cannot convert log entry %x back: %v", entry, err)
		}
	})
}

func FuzzToTBSCertificate(f *testing.F) {
	entry, err := ToTBSCertificateLogEntry(newTestCertificate(f).RawTBSCertificate)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(entry)
	f.Fuzz(func(t *testing.T, entry []byte) {
		tbs, err := ToTBSCertificate(entry)
		if err != nil {
			return
		}
		entry2, err := ToTBSCertificateLogEntry(tbs)
		if err != nil {
			t.Fatalf("cannot convert TBSCertificate %x back: %v", tbs, err)
		}
		// Only the issuer and public key information are replaced.
		got, want := parseLogEntry(t, entry2), parseLogEntry(t, entry)
		want.issuer = dummyLogEntryIssuer
		got.spkiAlgorithm, got.spkiHash = nil, nil
		want.spkiAlgorithm, want.spkiHash = nil, nil
		if !reflect.DeepEqual(got, want) {
			t.Errorf("round trip changed the log entry:\n got %x\nwant %x", entry2, entry)
		}
	})
}
