// Package tbsconv converts between the TBSCertificate structure of RFC 5280
// and the TBSCertificateLogEntry structure of Merkle Tree Certificates
// (draft-ietf-plants-merkle-tree-certs).
//
// The two structures are defined as follows:
//
//	TBSCertificate ::= SEQUENCE {
//	    version               [0] EXPLICIT Version DEFAULT v1,
//	    serialNumber              CertificateSerialNumber,
//	    signature                 AlgorithmIdentifier,
//	    issuer                    Name,
//	    validity                  Validity,
//	    subject                   Name,
//	    subjectPublicKeyInfo      SubjectPublicKeyInfo,
//	    issuerUniqueID        [1] IMPLICIT UniqueIdentifier OPTIONAL,
//	    subjectUniqueID       [2] IMPLICIT UniqueIdentifier OPTIONAL,
//	    extensions            [3] EXPLICIT Extensions OPTIONAL }
//
//	TBSCertificateLogEntry ::= SEQUENCE {
//	    version               [0] EXPLICIT Version DEFAULT v1,
//	    issuer                    Name,
//	    validity                  Validity,
//	    subject                   Name,
//	    subjectPublicKeyAlgorithm AlgorithmIdentifier,
//	    subjectPublicKeyInfoHash  OCTET STRING,
//	    issuerUniqueID        [1] IMPLICIT UniqueIdentifier OPTIONAL,
//	    subjectUniqueID       [2] IMPLICIT UniqueIdentifier OPTIONAL,
//	    extensions            [3] EXPLICIT Extensions OPTIONAL }
//
// The version, validity, subject, issuerUniqueID, subjectUniqueID and
// extensions fields are copied byte-for-byte in both directions. The remaining
// fields cannot be carried across, so they are dropped or replaced by dummy
// values:
//
//   - serialNumber and signature are dropped when converting to a
//     TBSCertificateLogEntry. When converting to a TBSCertificate, the serial
//     number is a positive 16-octet value derived from a SHA-256 hash of the
//     log entry, and the signature algorithm is ecdsa-with-SHA256.
//   - subjectPublicKeyInfo is replaced by its algorithm and SHA-256 hash when
//     converting to a TBSCertificateLogEntry. As the log entry only has the
//     hash, converting to a TBSCertificate yields a dummy P-256 public key: the
//     curve's base point, whose private key is 1.
//   - issuer is replaced by a name that meets the rules of the target
//     structure. A TBSCertificateLogEntry gets the CA ID name of a Merkle
//     Tree CA: the one passed to [ToTBSCertificateLogEntryWithIssuer], or by
//     default the dummy one with trust anchor ID 32473.1, which uses the
//     private enterprise number reserved for documentation by RFC 5612. A
//     TBSCertificate gets the dummy name "C=XX, O=Dummy Organization,
//     CN=Dummy Merkle Tree CA", which meets the CA/Browser Forum Baseline
//     Requirements for a CA certificate subject.
//
// The conversions are therefore lossy. A TBSCertificate produced by this
// package is suitable for inspection and linting only, and must never be
// signed by a real CA. A TBSCertificateLogEntry produced with a real trust
// anchor ID is the entry that the Merkle Tree CA logs for the certificate.
//
// Both functions take and return DER encodings. A TBSCertificate can be
// obtained from a parsed certificate with [crypto/x509.Certificate.RawTBSCertificate].
// Note that an MTCLogEntry carries the contents octets of a
// TBSCertificateLogEntry, i.e. its encoding without the outer SEQUENCE tag
// and length.
package tbsconv

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	tagVersion         = cbasn1.Tag(0).Constructed().ContextSpecific()
	tagIssuerUniqueID  = cbasn1.Tag(1).ContextSpecific()
	tagSubjectUniqueID = cbasn1.Tag(2).ContextSpecific()
	tagExtensions      = cbasn1.Tag(3).Constructed().ContextSpecific()
	tagRelativeOID     = cbasn1.Tag(13)
)

var oidTrustAnchorID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3} // id-rdna-trustAnchorID

var (
	errMalformedTBSCertificate = errors.New("tbsconv: malformed TBSCertificate")
	errMalformedLogEntry       = errors.New("tbsconv: malformed TBSCertificateLogEntry")
)

// ToTBSCertificateLogEntry converts a DER-encoded TBSCertificate to a
// DER-encoded TBSCertificateLogEntry.
//
// The serial number and signature algorithm are dropped, the issuer is
// replaced by a dummy Merkle Tree CA ID name, and the subject public key info
// is replaced by its algorithm and SHA-256 hash. All other fields are copied
// unmodified.
func ToTBSCertificateLogEntry(tbsCertificate []byte) ([]byte, error) {
	return toTBSCertificateLogEntry(tbsCertificate, dummyLogEntryIssuer)
}

// ToTBSCertificateLogEntryWithIssuer is like [ToTBSCertificateLogEntry], but
// sets the issuer to the CA ID name of the Merkle Tree CA with the given trust
// anchor ID, in dotted decimal form such as "32473.1".
func ToTBSCertificateLogEntryWithIssuer(tbsCertificate []byte, trustAnchorID string) ([]byte, error) {
	issuer, err := caIDName(trustAnchorID)
	if err != nil {
		return nil, err
	}
	return toTBSCertificateLogEntry(tbsCertificate, issuer)
}

func toTBSCertificateLogEntry(tbsCertificate, issuer []byte) ([]byte, error) {
	input := cryptobyte.String(tbsCertificate)
	var body, version, validity, subject, spki cryptobyte.String
	if !input.ReadASN1(&body, cbasn1.SEQUENCE) || !input.Empty() ||
		!readOptionalElement(&body, &version, tagVersion) ||
		!body.SkipASN1(cbasn1.INTEGER) || // serialNumber
		!body.SkipASN1(cbasn1.SEQUENCE) || // signature
		!body.SkipASN1(cbasn1.SEQUENCE) || // issuer
		!body.ReadASN1Element(&validity, cbasn1.SEQUENCE) ||
		!body.ReadASN1Element(&subject, cbasn1.SEQUENCE) ||
		!body.ReadASN1Element(&spki, cbasn1.SEQUENCE) {
		return nil, errMalformedTBSCertificate
	}
	trailer, ok := readTrailer(&body)
	if !ok {
		return nil, errMalformedTBSCertificate
	}

	spkiHash := sha256.Sum256(spki)
	var spkiBody, spkiAlgorithm cryptobyte.String
	if !spki.ReadASN1(&spkiBody, cbasn1.SEQUENCE) ||
		!spkiBody.ReadASN1Element(&spkiAlgorithm, cbasn1.SEQUENCE) ||
		!spkiBody.SkipASN1(cbasn1.BIT_STRING) ||
		!spkiBody.Empty() {
		return nil, errMalformedTBSCertificate
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(version)
		b.AddBytes(issuer)
		b.AddBytes(validity)
		b.AddBytes(subject)
		b.AddBytes(spkiAlgorithm)
		b.AddASN1OctetString(spkiHash[:])
		b.AddBytes(trailer)
	})
	return b.Bytes()
}

// ToTBSCertificate converts a DER-encoded TBSCertificateLogEntry to a
// DER-encoded TBSCertificate.
//
// The serial number, signature algorithm, issuer and subject public key info
// are dummy values, as described in the package documentation. All other
// fields are copied unmodified.
func ToTBSCertificate(logEntry []byte) ([]byte, error) {
	input := cryptobyte.String(logEntry)
	var body, version, validity, subject cryptobyte.String
	if !input.ReadASN1(&body, cbasn1.SEQUENCE) || !input.Empty() ||
		!readOptionalElement(&body, &version, tagVersion) ||
		!body.SkipASN1(cbasn1.SEQUENCE) || // issuer
		!body.ReadASN1Element(&validity, cbasn1.SEQUENCE) ||
		!body.ReadASN1Element(&subject, cbasn1.SEQUENCE) ||
		!body.SkipASN1(cbasn1.SEQUENCE) || // subjectPublicKeyAlgorithm
		!body.SkipASN1(cbasn1.OCTET_STRING) { // subjectPublicKeyInfoHash
		return nil, errMalformedLogEntry
	}
	trailer, ok := readTrailer(&body)
	if !ok {
		return nil, errMalformedLogEntry
	}

	// Clearing the top bit keeps the serial number positive, and setting the
	// next one keeps it at 16 octets (128 bits) in its minimal DER encoding.
	serial := sha256.Sum256(logEntry)
	serial[0] = serial[0]&0x7f | 0x40

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(version)
		b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) {
			b.AddBytes(serial[:16])
		})
		b.AddBytes(dummySignatureAlgorithm)
		b.AddBytes(dummyTBSCertificateIssuer)
		b.AddBytes(validity)
		b.AddBytes(subject)
		b.AddBytes(dummySubjectPublicKeyInfo)
		b.AddBytes(trailer)
	})
	return b.Bytes()
}

// caIDName returns the CA ID name for a trust anchor ID: a single RDN holding a
// single id-rdna-trustAnchorID attribute whose value is a RELATIVE-OID.
func caIDName(trustAnchorID string) ([]byte, error) {
	var arcs []uint64
	for _, s := range strings.Split(trustAnchorID, ".") {
		// Rejecting leading zeros gives each trust anchor ID a single spelling.
		arc, err := strconv.ParseUint(s, 10, 64)
		if err != nil || len(s) > 1 && s[0] == '0' {
			return nil, fmt.Errorf("tbsconv: invalid trust anchor ID %q", trustAnchorID)
		}
		arcs = append(arcs, arc)
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidTrustAnchorID)
				b.AddASN1(tagRelativeOID, func(b *cryptobyte.Builder) {
					for _, arc := range arcs {
						addBase128(b, arc)
					}
				})
			})
		})
	})
	return b.Bytes()
}

// addBase128 adds n in the base-128 encoding used for OID arcs.
func addBase128(b *cryptobyte.Builder, n uint64) {
	digits := 1
	for m := n >> 7; m > 0; m >>= 7 {
		digits++
	}
	for i := digits - 1; i >= 0; i-- {
		digit := byte(n>>(7*i)) & 0x7f
		if i > 0 {
			digit |= 0x80
		}
		b.AddUint8(digit)
	}
}

// readOptionalElement reads the element with the given tag into out if it is
// next in s, and leaves out empty otherwise.
func readOptionalElement(s, out *cryptobyte.String, tag cbasn1.Tag) bool {
	if !s.PeekASN1Tag(tag) {
		*out = nil
		return true
	}
	return s.ReadASN1Element(out, tag)
}

// readTrailer consumes the issuerUniqueID, subjectUniqueID and extensions
// fields, which end both structures, and returns their encoding.
func readTrailer(s *cryptobyte.String) ([]byte, bool) {
	trailer := *s
	for _, tag := range []cbasn1.Tag{tagIssuerUniqueID, tagSubjectUniqueID, tagExtensions} {
		var element cryptobyte.String
		if !readOptionalElement(s, &element, tag) {
			return nil, false
		}
	}
	return trailer, s.Empty()
}
