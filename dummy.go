package tbsconv

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidCountryName      = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganizationName = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidCommonName       = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidECDSAWithSHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

var (
	dummyLogEntryIssuer       = buildDummyLogEntryIssuer()
	dummyTBSCertificateIssuer = buildDummyTBSCertificateIssuer()
	dummySignatureAlgorithm   = buildDummySignatureAlgorithm()
	dummySubjectPublicKeyInfo = buildDummySubjectPublicKeyInfo()
)

// buildDummyLogEntryIssuer returns the CA ID name (draft-ietf-plants-merkle-tree-certs,
// "Certification Authority Identifiers") for trust anchor ID 32473.1.
func buildDummyLogEntryIssuer() []byte {
	name, err := caIDName("32473.1")
	if err != nil {
		panic(err)
	}
	return name
}

// buildDummyTBSCertificateIssuer returns a name that meets the Baseline
// Requirements for the subject of a CA certificate (Section 7.1.2.10.2) and
// the name encoding rules (Section 7.1.4): countryName, organizationName and
// commonName, in that order, each in its own RDN.
func buildDummyTBSCertificateIssuer() []byte {
	attributes := []struct {
		oid   asn1.ObjectIdentifier
		tag   cbasn1.Tag
		value string
	}{
		// XX is the ISO 3166-1 user-assigned code for an unknown country.
		{oidCountryName, cbasn1.PrintableString, "XX"},
		{oidOrganizationName, cbasn1.UTF8String, "Dummy Organization"},
		{oidCommonName, cbasn1.UTF8String, "Dummy Merkle Tree CA"},
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, a := range attributes {
			b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(a.oid)
					b.AddASN1(a.tag, func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(a.value))
					})
				})
			})
		}
	})
	return b.BytesOrPanic()
}

// buildDummySignatureAlgorithm returns the ecdsa-with-SHA256
// AlgorithmIdentifier, with the parameters omitted as required by RFC 5758.
func buildDummySignatureAlgorithm() []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidECDSAWithSHA256)
	})
	return b.BytesOrPanic()
}

// buildDummySubjectPublicKeyInfo returns a P-256 SubjectPublicKeyInfo holding
// the curve's base point, i.e. the public key for private key 1, which makes
// it obvious that the key is not a real one.
func buildDummySubjectPublicKeyInfo() []byte {
	privateKey := make([]byte, 32)
	privateKey[31] = 1
	key, err := ecdh.P256().NewPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		panic(err)
	}
	return spki
}
