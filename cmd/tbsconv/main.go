// Command tbsconv converts between the TBSCertificate structure of RFC 5280
// and the TBSCertificateLogEntry structure of Merkle Tree Certificates.
package main

import (
	"bytes"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mtc-kit/tbsconv"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const usage = `Usage: tbsconv toentry [-issuer id] [-pem] [file]
       tbsconv fromentry [-pem] [file]

Commands:
  toentry    convert a Certificate or TBSCertificate to a
             TBSCertificateLogEntry
  fromentry  convert a TBSCertificateLogEntry, or its contents octets as found
             in an MTCLogEntry, to a TBSCertificate

The input is read from file, or from standard input if file is omitted or "-",
and may be DER or PEM. The output is written to standard output.

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run runs the command with the given arguments, excluding the program name,
// and returns the exit status.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("tbsconv", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), usage)
		flags.PrintDefaults()
	}
	pemOut := flags.Bool("pem", false, "write PEM instead of DER")
	issuer := flags.String("issuer", "", "`trust anchor ID` of the Merkle Tree CA, such as 32473.1, whose CA ID\nname becomes the log entry's issuer (toentry only; default: a dummy)")
	if len(args) < 1 || args[0] != "toentry" && args[0] != "fromentry" {
		flags.Usage()
		return 2
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() > 1 || args[0] == "fromentry" && *issuer != "" {
		flags.Usage()
		return 2
	}

	in, err := readInput(flags.Arg(0), stdin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	var out []byte
	var pemType string
	switch args[0] {
	case "toentry":
		if *issuer == "" {
			out, err = tbsconv.ToTBSCertificateLogEntry(tbsCertificate(in))
		} else {
			out, err = tbsconv.ToTBSCertificateLogEntryWithIssuer(tbsCertificate(in), *issuer)
		}
		pemType = "TBS CERTIFICATE LOG ENTRY"
	case "fromentry":
		if in, err = logEntry(in); err == nil {
			out, err = tbsconv.ToTBSCertificate(in)
		}
		pemType = "TBS CERTIFICATE"
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if *pemOut {
		out = pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: out})
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// readInput reads the named file, or stdin, and decodes it if it is PEM.
func readInput(name string, stdin io.Reader) ([]byte, error) {
	var data []byte
	var err error
	if name == "" || name == "-" {
		name = "standard input"
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(name)
	}
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: malformed PEM", name)
		}
		return block.Bytes, nil
	}
	return data, nil
}

// tbsCertificate returns the tbsCertificate field of der if it is a
// Certificate, and der otherwise.
func tbsCertificate(der []byte) []byte {
	// A TBSCertificate starts with a [0] or an INTEGER, never a SEQUENCE.
	s := cryptobyte.String(der)
	var body, tbs cryptobyte.String
	if s.ReadASN1(&body, cbasn1.SEQUENCE) && body.ReadASN1Element(&tbs, cbasn1.SEQUENCE) {
		return tbs
	}
	return der
}

// logEntry adds the outer SEQUENCE tag and length to data if it holds only
// the contents octets of a TBSCertificateLogEntry.
func logEntry(data []byte) ([]byte, error) {
	s := cryptobyte.String(data)
	if s.SkipASN1(cbasn1.SEQUENCE) && s.Empty() {
		return data, nil
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(data)
	})
	return b.Bytes()
}
