# tbsconv
Convert between TBSCertificate and TBSCertificateLogEntry

`tbsconv` is a Go library and command-line tool that converts between the
`TBSCertificate` structure of
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280#section-4.1) and the
`TBSCertificateLogEntry` structure of
[Merkle Tree Certificates](https://github.com/ietf-plants-wg/merkle-tree-certs)
(draft-ietf-plants-merkle-tree-certs).

## Use cases

* **Lint MTC log entries (entry → `TBSCertificate`).** Certificate linters
  such as zlint and pkilint only understand `TBSCertificate`. A Merkle Tree CA
  can convert each entry before adding it to its issuance log, and a monitor
  can do the same for entries it finds in a log. Either way, existing linters
  can then check the subject, validity and extensions, which are copied
  unchanged.
* **Issue MTCs from a classic CA (`TBSCertificate` → entry).** A CA's existing
  issuance software already builds `TBSCertificate`s from its certificate
  profiles. To issue the same certificate as an MTC, the CA converts the
  `TBSCertificate` with its own trust anchor ID and adds the resulting
  `TBSCertificateLogEntry` to its issuance log. The `TBSCertificate`'s serial
  number and signature algorithm are dropped and the subject public key is
  hashed, as the draft requires. The CA keeps its profiles, request validation
  and issuance software, and replaces signing each certificate with logging it.

## Installation

Library:

```sh
go get github.com/mtc-kit/tbsconv
```

Command-line tool:

```sh
go install github.com/mtc-kit/tbsconv/cmd/tbsconv@latest
```

## Command-line usage

```
tbsconv toentry [-issuer id] [-pem] [file]
tbsconv fromentry [-pem] [file]
```

* `toentry` converts a `Certificate` or `TBSCertificate` to a
  `TBSCertificateLogEntry`. With `-issuer`, the issuer is the CA ID name for
  the given trust anchor ID, such as `32473.1`. Without it, the issuer is a
  dummy.
* `fromentry` converts a `TBSCertificateLogEntry` to a `TBSCertificate`. The
  input can also be just the contents octets, as found in an `MTCLogEntry`.

The tool reads `file`, or standard input if `file` is omitted or `-`. The input
can be DER or PEM. The output goes to standard output as DER, or as PEM with
`-pem`.

```sh
tbsconv toentry -issuer 32473.1 -pem cert.pem > entry.pem
tbsconv fromentry entry.pem | openssl asn1parse -inform DER -i
```

## Library usage

```go
// TBSCertificate -> TBSCertificateLogEntry
cert, err := x509.ParseCertificate(certDER)
// ...
entry, err := tbsconv.ToTBSCertificateLogEntry(cert.RawTBSCertificate)

// TBSCertificate -> TBSCertificateLogEntry for the CA with trust anchor ID 32473.1
entry, err = tbsconv.ToTBSCertificateLogEntryWithIssuer(cert.RawTBSCertificate, "32473.1")

// TBSCertificateLogEntry -> TBSCertificate
tbs, err := tbsconv.ToTBSCertificate(entry)
```

All functions take and return complete DER encodings. In an `MTCLogEntry`,
`tbs_cert_entry_data` holds only the *contents octets* of a
`TBSCertificateLogEntry`. Add or remove the outer `SEQUENCE` tag and length
when you move data between the two.

## Field mapping

| TBSCertificate         | TBSCertificateLogEntry      | TBSCertificate → entry          | entry → TBSCertificate            |
|------------------------|-----------------------------|---------------------------------|-----------------------------------|
| `version`              | `version`                   | copied                          | copied                            |
| `serialNumber`         | —                           | dropped                         | dummy (see below)                 |
| `signature`            | —                           | dropped                         | `ecdsa-with-SHA256`               |
| `issuer`               | `issuer`                    | CA ID name (dummy by default)   | dummy BR-compliant CA name        |
| `validity`             | `validity`                  | copied                          | copied                            |
| `subject`              | `subject`                   | copied                          | copied                            |
| `subjectPublicKeyInfo` | `subjectPublicKeyAlgorithm` | SPKI `algorithm`                | dummy P-256 SPKI                  |
|                        | `subjectPublicKeyInfoHash`  | SHA-256 of the DER SPKI         | (discarded)                       |
| `issuerUniqueID`       | `issuerUniqueID`            | copied                          | copied                            |
| `subjectUniqueID`      | `subjectUniqueID`           | copied                          | copied                            |
| `extensions`           | `extensions`                | copied                          | copied                            |

The library copies fields byte for byte, so it never re-encodes them.

### Dummy values

* **Issuer in a `TBSCertificateLogEntry`.** The draft requires the issuer to be
  the Merkle Tree CA's *CA ID* name. This name has one RDN with one
  `id-rdna-trustAnchorID` (1.3.6.1.5.5.7.25.3) attribute, whose value is a
  `RELATIVE-OID`. Unless you pass the CA's own trust anchor ID, the library
  uses trust anchor ID `32473.1`, which is built
  on the private enterprise number reserved for documentation by RFC 5612. In
  RFC 4514 syntax, the name is `1.3.6.1.5.5.7.25.3=#0d0481fd5901`.
* **Issuer in a `TBSCertificate`.** The CA/Browser Forum Baseline Requirements
  require a subscriber certificate's issuer to match the issuing CA's subject.
  For CA certificates, sections 7.1.2.10.2 and 7.1.4 require `countryName`,
  `organizationName` and `commonName`, each in its own RDN and in that order.
  The library uses `C=XX, O=Dummy Organization, CN=Dummy Merkle Tree CA`, where
  `XX` is the ISO 3166-1 user-assigned code. `countryName` is a
  `PrintableString` and the other attributes are `UTF8String`s.
* **Subject public key in a `TBSCertificate`.** A log entry carries only a hash
  of the key, so the library uses a P-256 `id-ecPublicKey` key, which works with
  classic certificate linters. The key is the curve's base point, whose private
  key is 1, so it is clearly not a real key. The original
  `subjectPublicKeyAlgorithm` is not preserved.
* **Serial number in a `TBSCertificate`.** The serial number is a positive
  16-octet integer taken from the SHA-256 hash of the log entry. As a result,
  the output is deterministic and distinct entries get distinct serial numbers.
* **Signature algorithm in a `TBSCertificate`.** The library uses
  `ecdsa-with-SHA256` with the parameters omitted.

## Caveats

* The conversions lose information. Converting a log entry to a
  `TBSCertificate` and back keeps every field except
  `subjectPublicKeyAlgorithm` and `subjectPublicKeyInfoHash`, which then
  describe the dummy key.
* A `TBSCertificate` produced by this library is only for inspection and
  linting. Never sign it with a real CA key.
* The input is parsed only enough to locate each field. Field contents, such
  as extensions, are not validated. A CA that issues MTCs with this library
  must validate and lint its `TBSCertificate`s as it does today.
