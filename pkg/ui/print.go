// Copyright 2018 Adam Shannon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ui

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

var (
	defaultFormat = "table"
	printers      = map[string]printer{
		"openssl":  opensslPrinter{},
		"table":    tablePrinter{},
		"long":     longPrinter{},
		jsonFormat: jsonPrinter{},
	}

	fingerprintPreviewLength = 16
)

// DefaultFormat returns the standard output format
func DefaultFormat() string {
	return defaultFormat
}

// GetFormats returns the names of all output formats, sorted.
func GetFormats() []string {
	out := make([]string, 0, len(printers)+1)
	seen := map[string]bool{}
	for k := range printers {
		out = append(out, k)
		seen[k] = true
	}
	if !seen[observatoryFormat] {
		out = append(out, observatoryFormat)
	}
	sort.Strings(out)
	return out
}

type printer interface {
	close()
	write(io.Writer, []*x509.Certificate) error
}

func getPrinter(name string) (printer, bool) {
	p, ok := printers[strings.ToLower(name)]
	return p, ok
}

// KnownFormat reports whether name is a list output format.
// Matching is case-insensitive, the same as getPrinter. observatory is
// included even though it is not in the printers map.
func KnownFormat(name string) bool {
	if _, ok := getPrinter(name); ok {
		return true
	}
	return strings.EqualFold(name, observatoryFormat)
}

// UnknownFormatError reports that name is not a list output format and
// includes the valid names from GetFormats.
func UnknownFormatError(name string) error {
	return fmt.Errorf("unknown format %q (formats: %s)", name, strings.Join(GetFormats(), ", "))
}

// tableColumnWidth caps the SUBJECT and ISSUER columns of table output.
const tableColumnWidth = 40

// tableMaxLineWidth is the widest a non-verbose table line can be: two capped
// name columns plus KEY, DAYS and the fingerprint preview.
const tableMaxLineWidth = 2*tableColumnWidth + 40

// soonExpiryDays is the exclusive upper bound for the "soon" DAYS marker in
// non-verbose table output (0 ≤ days < soonExpiryDays).
const soonExpiryDays = 90

// formatTableDays formats the DAYS cell for non-verbose table output.
// Expired certs show "expired"; certs with fewer than soonExpiryDays left show
// the day count with a trailing "!" (e.g. "42!"); otherwise the plain integer.
func formatTableDays(days int) string {
	if days < 0 {
		return "expired"
	}
	if days < soonExpiryDays {
		return fmt.Sprintf("%d!", days)
	}
	return fmt.Sprintf("%d", days)
}

// truncateColumn shortens s to at most n runes, ending with an ellipsis when cut.
func truncateColumn(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// tablePrinter outputs a nicely formatted table of the certs found. This uses golang's
// native text/tabwriter package to align based on the rows given to it.
type tablePrinter struct {
	verbose bool
	path    string
	now     time.Time // zero means time.Now()
}

func (tablePrinter) close() {}
func (p tablePrinter) write(fd io.Writer, certs []*x509.Certificate) error {
	w := tabwriter.NewWriter(fd, 0, 0, 1, ' ', 0)
	now := p.now
	if now.IsZero() {
		now = time.Now()
	}
	if p.verbose {
		fmt.Fprintln(w, "SUBJECT\tISSUER\tKEY\tDAYS\tSHA256-FINGERPRINT\tSERIAL\tPATH\tNOT-BEFORE\tNOT-AFTER")
	} else {
		fmt.Fprintln(w, "SUBJECT\tISSUER\tKEY\tDAYS\tSHA256-FINGERPRINT")
	}

	rows := make([]string, len(certs))
	for i := range certs {
		fingerprint := certutil.GetHexSHA256Fingerprint(*certs[i])
		subject := certutil.StringifyPKIXName(certs[i].Subject)
		issuer := certutil.StringifyPKIXName(certs[i].Issuer)
		c1 := truncateColumn(subject, tableColumnWidth)
		c2 := "="
		if !bytes.Equal(certs[i].RawIssuer, certs[i].RawSubject) {
			c2 = truncateColumn(issuer, tableColumnWidth)
		}
		key := certutil.FormatKeyLabel(certs[i])
		daysLeft := certutil.DaysUntilExpiry(certs[i], now)
		var days string
		if p.verbose {
			days = fmt.Sprintf("%d", daysLeft)
		} else {
			days = formatTableDays(daysLeft)
		}
		if p.verbose {
			serial := certs[i].SerialNumber.String()
			path := p.path
			if path == "" {
				path = "-"
			}
			c5 := certs[i].NotBefore.Format("2006-01-02")
			c6 := certs[i].NotAfter.Format("2006-01-02")
			rows[i] = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s", c1, c2, key, days, fingerprint, serial, path, c5, c6)
		} else {
			rows[i] = fmt.Sprintf("%s\t%s\t%s\t%s\t%s", c1, c2, key, days, fingerprint[:fingerprintPreviewLength])
		}
	}

	file.SortNames(rows)
	for i := range rows {
		fmt.Fprintln(w, rows[i])
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flushing output table: %w", err)
	}
	return nil
}

type opensslPrinter struct {
	tmp *os.File
}

func (p opensslPrinter) printCertificate(w io.Writer, cert []*x509.Certificate) error {
	err := certutil.ToFile(p.tmp.Name(), cert)
	if err != nil {
		return err
	}

	out, err := exec.Command("openssl", "x509", "-in", p.tmp.Name(), "-noout", "-text").CombinedOutput()
	if err != nil {
		return err
	}

	fmt.Fprintln(w, string(out))
	return nil
}

// printCertsOpenSSL shells out to openssl (if available) to print out each certificate
func (p opensslPrinter) write(w io.Writer, certs []*x509.Certificate) error {
	if p.tmp == nil {
		tmp, err := os.CreateTemp("", "cert-manage-print-cert")
		if err != nil {
			return err
		}
		p.tmp = tmp
	}

	for i := range certs {
		err := p.printCertificate(w, certs[i:i+1])
		if err != nil {
			return err
		}
	}
	return nil
}

func (p opensslPrinter) close() {
	if p.tmp != nil {
		_ = os.Remove(p.tmp.Name())
	}
}

// longPrinter prints each certificate as a multi-line block.
// Empty slice fields stay hidden, matching the former short listing.
type longPrinter struct {
	now time.Time // zero means time.Now()
}

func (longPrinter) close() {}
func (p longPrinter) write(w io.Writer, certs []*x509.Certificate) error {
	now := p.now
	if now.IsZero() {
		now = time.Now()
	}
	writef := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}
	for i := range certs {
		if err := writef("Certificate\n"); err != nil {
			return err
		}
		if err := writef("  SHA256 Fingerprint: %s\n", certutil.GetHexSHA256Fingerprint(*certs[i])); err != nil {
			return err
		}
		if err := writef("  SerialNumber: %d\n", certs[i].SerialNumber); err != nil {
			return err
		}
		if err := writef("  Subject: %s\n", certutil.StringifyPKIXName(certs[i].Subject)); err != nil {
			return err
		}
		if err := writef("  Issuer: %s\n", certutil.StringifyPKIXName(certs[i].Issuer)); err != nil {
			return err
		}
		if err := writef("  NotBefore: %s | NotAfter: %s\n", certs[i].NotBefore, certs[i].NotAfter); err != nil {
			return err
		}
		if err := writef("  KEY: %s\n", certutil.FormatKeyLabel(certs[i])); err != nil {
			return err
		}
		if err := writef("  DAYS: %d\n", certutil.DaysUntilExpiry(certs[i], now)); err != nil {
			return err
		}

		if certs[i].IsCA {
			if err := writef("  IsCA: %t\n", certs[i].IsCA); err != nil {
				return err
			}
		}

		if len(certs[i].DNSNames) > 0 {
			if err := writef("  DNSNames:\n"); err != nil {
				return err
			}
			for j := range certs[i].DNSNames {
				if err := writef("    %s\n", certs[i].DNSNames[j]); err != nil {
					return err
				}
			}
		}

		if len(certs[i].EmailAddresses) > 0 {
			if err := writef("  EmailAddresses:\n"); err != nil {
				return err
			}
			for j := range certs[i].EmailAddresses {
				if err := writef("    %s\n", certs[i].EmailAddresses[j]); err != nil {
					return err
				}
			}
		}

		if len(certs[i].IPAddresses) > 0 {
			if err := writef("  IPAddresses:\n"); err != nil {
				return err
			}
			for j := range certs[i].IPAddresses {
				if err := writef("    %s\n", certs[i].IPAddresses[j]); err != nil {
					return err
				}
			}
		}

		if len(certs[i].PermittedDNSDomains) > 0 {
			if err := writef("  PermittedDNSDomains:\n"); err != nil {
				return err
			}
			for j := range certs[i].PermittedDNSDomains {
				if err := writef("    %s\n", certs[i].PermittedDNSDomains[j]); err != nil {
					return err
				}
			}
		}

		if len(certs[i].CRLDistributionPoints) > 0 {
			if err := writef("  CRLDistributionPoints:\n"); err != nil {
				return err
			}
			for j := range certs[i].CRLDistributionPoints {
				if err := writef("    %s\n", certs[i].CRLDistributionPoints[j]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
