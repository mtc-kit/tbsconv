package tbsconv_test

import (
	"crypto/x509"
	"log"
	"os"

	"github.com/mtc-kit/tbsconv"
)

func ExampleToTBSCertificateLogEntry() {
	der, err := os.ReadFile("cert.der")
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	entry, err := tbsconv.ToTBSCertificateLogEntry(cert.RawTBSCertificate)
	if err != nil {
		log.Fatal(err)
	}
	// An MTCLogEntry's tbs_cert_entry_data holds the contents octets, i.e.
	// entry without its SEQUENCE tag and length.
	_ = entry
}

func ExampleToTBSCertificateLogEntryWithIssuer() {
	// A TBSCertificate built by the CA's existing issuance software.
	tbs, err := os.ReadFile("tbs_cert.der")
	if err != nil {
		log.Fatal(err)
	}
	entry, err := tbsconv.ToTBSCertificateLogEntryWithIssuer(tbs, "32473.1")
	if err != nil {
		log.Fatal(err)
	}
	// The Merkle Tree CA with trust anchor ID 32473.1 can now add entry to its
	// issuance log.
	_ = entry
}

func ExampleToTBSCertificate() {
	entry, err := os.ReadFile("tbs_cert_entry.der")
	if err != nil {
		log.Fatal(err)
	}
	tbs, err := tbsconv.ToTBSCertificate(entry)
	if err != nil {
		log.Fatal(err)
	}
	// tbs can now be wrapped in a Certificate with a placeholder signature
	// and passed to a certificate linter.
	_ = tbs
}
