package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mtc-kit/tbsconv"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func testCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.AddDate(0, 0, 7),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func runTool(stdin []byte, args ...string) (stdout []byte, stderr string, status int) {
	var out, errOut bytes.Buffer
	status = run(args, bytes.NewReader(stdin), &out, &errOut)
	return out.Bytes(), errOut.String(), status
}

func writeFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// contentsOctets strips the outer tag and length from a DER SEQUENCE.
func contentsOctets(t *testing.T, der []byte) []byte {
	t.Helper()
	s := cryptobyte.String(der)
	var body cryptobyte.String
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !s.Empty() {
		t.Fatalf("not a SEQUENCE: %x", der)
	}
	return body
}

type testCase struct {
	stdin []byte
	args  []string
}

func checkOutput(t *testing.T, cases map[string]testCase, want []byte) {
	t.Helper()
	for name, c := range cases {
		got, stderr, status := runTool(c.stdin, c.args...)
		if status != 0 {
			t.Errorf("%s: exit status %d, stderr %q", name, status, stderr)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: output = %x, want %x", name, got, want)
		}
	}
}

func TestToEntry(t *testing.T) {
	cert := testCertificate(t)
	want, err := tbsconv.ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pemEncode("CERTIFICATE", cert.Raw)
	checkOutput(t, map[string]testCase{
		"Certificate DER file":     {nil, []string{"toentry", writeFile(t, cert.Raw)}},
		"Certificate PEM file":     {nil, []string{"toentry", writeFile(t, certPEM)}},
		"Certificate DER stdin":    {cert.Raw, []string{"toentry"}},
		"Certificate PEM stdin":    {certPEM, []string{"toentry", "-"}},
		"PEM with blank lines":     {append([]byte("\n\n"), certPEM...), []string{"toentry"}},
		"TBSCertificate DER stdin": {cert.RawTBSCertificate, []string{"toentry"}},
		"TBSCertificate PEM stdin": {pemEncode("TBS CERTIFICATE", cert.RawTBSCertificate), []string{"toentry"}},
	}, want)
}

func TestToEntryIssuer(t *testing.T) {
	cert := testCertificate(t)
	want, err := tbsconv.ToTBSCertificateLogEntryWithIssuer(cert.RawTBSCertificate, "32473.2")
	if err != nil {
		t.Fatal(err)
	}
	checkOutput(t, map[string]testCase{
		"-issuer value": {cert.Raw, []string{"toentry", "-issuer", "32473.2"}},
		"-issuer=value": {cert.Raw, []string{"toentry", "-issuer=32473.2"}},
	}, want)

	out, stderr, status := runTool(cert.Raw, "toentry", "-issuer", "32473.02")
	if status != 1 || len(out) != 0 || !strings.Contains(stderr, "invalid trust anchor ID") {
		t.Errorf("invalid -issuer: exit status %d, output %x, stderr %q; want status 1 and an error", status, out, stderr)
	}
}

func TestFromEntry(t *testing.T) {
	cert := testCertificate(t)
	entry, err := tbsconv.ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	want, err := tbsconv.ToTBSCertificate(entry)
	if err != nil {
		t.Fatal(err)
	}
	checkOutput(t, map[string]testCase{
		"DER file":        {nil, []string{"fromentry", writeFile(t, entry)}},
		"DER stdin":       {entry, []string{"fromentry"}},
		"PEM stdin":       {pemEncode("TBS CERTIFICATE LOG ENTRY", entry), []string{"fromentry"}},
		"contents octets": {contentsOctets(t, entry), []string{"fromentry"}},
	}, want)
}

func TestPEMOutput(t *testing.T) {
	cert := testCertificate(t)
	entry, err := tbsconv.ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := tbsconv.ToTBSCertificate(entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		stdin     []byte
		args      []string
		blockType string
		want      []byte
	}{
		{cert.Raw, []string{"toentry", "-pem"}, "TBS CERTIFICATE LOG ENTRY", entry},
		{entry, []string{"fromentry", "-pem"}, "TBS CERTIFICATE", tbs},
	} {
		out, stderr, status := runTool(c.stdin, c.args...)
		if status != 0 {
			t.Errorf("%v: exit status %d, stderr %q", c.args, status, stderr)
			continue
		}
		block, rest := pem.Decode(out)
		if block == nil || len(rest) != 0 {
			t.Errorf("%v: output is not a single PEM block: %q", c.args, out)
			continue
		}
		if block.Type != c.blockType || !bytes.Equal(block.Bytes, c.want) {
			t.Errorf("%v: got %s block %x, want %s block %x", c.args, block.Type, block.Bytes, c.blockType, c.want)
		}
	}
}

func TestUsage(t *testing.T) {
	cert := testCertificate(t)
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"entry"},
		{"-pem", "toentry"},
		{"toentry", "-bogus"},
		{"toentry", "a", "b"},
		{"fromentry", "-issuer", "32473.1"},
	} {
		out, stderr, status := runTool(cert.Raw, args...)
		if status != 2 || len(out) != 0 || !strings.Contains(stderr, "Usage:") {
			t.Errorf("%q: exit status %d, output %x, stderr %q; want status 2 and usage", args, status, out, stderr)
		}
	}

	out, stderr, status := runTool(nil, "toentry", "-h")
	if status != 0 || len(out) != 0 || !strings.Contains(stderr, "Usage:") {
		t.Errorf("-h: exit status %d, output %x, stderr %q; want status 0 and usage", status, out, stderr)
	}
}

func TestErrors(t *testing.T) {
	cert := testCertificate(t)
	entry, err := tbsconv.ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		testCase
		wantErr string
	}{
		"missing file":                {testCase{nil, []string{"toentry", filepath.Join(t.TempDir(), "missing")}}, "missing"},
		"malformed PEM":               {testCase{[]byte("-----BEGIN CERTIFICATE-----\n!!!\n"), []string{"toentry"}}, "standard input: malformed PEM"},
		"empty input":                 {testCase{nil, []string{"toentry"}}, "malformed TBSCertificate"},
		"log entry to toentry":        {testCase{entry, []string{"toentry"}}, "malformed TBSCertificate"},
		"empty log entry":             {testCase{[]byte{0x30, 0x00}, []string{"fromentry"}}, "malformed TBSCertificateLogEntry"},
		"Certificate to fromentry":    {testCase{cert.Raw, []string{"fromentry"}}, "malformed TBSCertificateLogEntry"},
		"TBSCertificate to fromentry": {testCase{cert.RawTBSCertificate, []string{"fromentry"}}, "malformed TBSCertificateLogEntry"},
	} {
		out, stderr, status := runTool(c.stdin, c.args...)
		if status != 1 || len(out) != 0 || !strings.Contains(stderr, c.wantErr) {
			t.Errorf("%s: exit status %d, output %x, stderr %q; want status 1 and %q", name, status, out, stderr, c.wantErr)
		}
	}
}
