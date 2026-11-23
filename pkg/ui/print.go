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
	"time"
	"unicode/utf8"

	"github.com/adamdecaf/trustprune/pkg/certutil"
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

// tablePrinter outputs a table of the certificates. Each column is as wide as
// its longest header or cell, and columns are separated by two spaces.
// Verbose output adds the full fingerprint, serial, and dates. When every row
// has the same path, that path is printed once as "PATH: <path>" and the PATH
// column is omitted. Mixed paths keep the PATH column.
type tablePrinter struct {
	verbose bool
	path    string
	// paths, when non-nil, is one source path per certificate in write order.
	// Nil uses path for every row. An empty path is printed as "-".
	paths []string
	now   time.Time // zero means time.Now()
}

func (tablePrinter) close() {}
func (p tablePrinter) write(w io.Writer, certs []*x509.Certificate) error {
	now := p.now
	if now.IsZero() {
		now = time.Now()
	}

	headers := []string{"SUBJECT", "ISSUER", "KEY", "DAYS", "SHA256-FINGERPRINT"}
	if p.verbose {
		headers = append(headers, "SERIAL", "PATH", "NOT-BEFORE", "NOT-AFTER")
	}

	rows := make([][]string, len(certs))
	for i := range certs {
		rows[i] = p.tableCells(certs[i], now, i)
	}

	if p.verbose && len(rows) > 0 && columnEqual(rows, columnIndex(headers, "PATH")) {
		if _, err := fmt.Fprintf(w, "PATH: %s\n", rows[0][columnIndex(headers, "PATH")]); err != nil {
			return err
		}
		headers, rows = dropColumn(headers, rows, "PATH")
	}

	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(strings.Join(rows[i], "\t")) < strings.ToLower(strings.Join(rows[j], "\t"))
	})

	_, err := io.WriteString(w, alignTable(headers, rows))
	return err
}

func (p tablePrinter) tableCells(cert *x509.Certificate, now time.Time, i int) []string {
	fingerprint := certutil.GetHexSHA256Fingerprint(*cert)
	subject := truncateColumn(certutil.StringifyPKIXName(cert.Subject), tableColumnWidth)
	issuer := "="
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		issuer = truncateColumn(certutil.StringifyPKIXName(cert.Issuer), tableColumnWidth)
	}
	key := certutil.FormatKeyLabel(cert)
	daysLeft := certutil.DaysUntilExpiry(cert, now)
	days := formatTableDays(daysLeft)
	fp := fingerprint[:fingerprintPreviewLength]
	if p.verbose {
		days = fmt.Sprintf("%d", daysLeft)
		fp = fingerprint
	}
	cells := []string{subject, issuer, key, days, fp}
	if !p.verbose {
		return cells
	}
	return append(cells,
		cert.SerialNumber.String(),
		p.rowPath(i),
		cert.NotBefore.Format("2006-01-02"),
		cert.NotAfter.Format("2006-01-02"),
	)
}

// rowPath is the verbose PATH cell for certificate i.
func (p tablePrinter) rowPath(i int) string {
	path := p.path
	if p.paths != nil {
		path = ""
		if i >= 0 && i < len(p.paths) {
			path = p.paths[i]
		}
	}
	if path == "" {
		return "-"
	}
	return path
}

func columnIndex(headers []string, name string) int {
	for i, header := range headers {
		if header == name {
			return i
		}
	}
	return -1
}

func columnEqual(rows [][]string, idx int) bool {
	if idx < 0 || len(rows) == 0 {
		return false
	}
	first := rows[0][idx]
	for _, row := range rows[1:] {
		if row[idx] != first {
			return false
		}
	}
	return true
}

func dropColumn(headers []string, rows [][]string, name string) ([]string, [][]string) {
	idx := columnIndex(headers, name)
	if idx < 0 {
		return headers, rows
	}
	nextHeaders := make([]string, 0, len(headers)-1)
	nextHeaders = append(nextHeaders, headers[:idx]...)
	nextHeaders = append(nextHeaders, headers[idx+1:]...)
	for i, row := range rows {
		if idx >= len(row) {
			continue
		}
		next := make([]string, 0, len(row)-1)
		next = append(next, row[:idx]...)
		next = append(next, row[idx+1:]...)
		rows[i] = next
	}
	return nextHeaders, rows
}

// alignTable left-aligns cells and separates columns with two spaces.
// Each column is as wide as its longest header or cell. There is no minimum
// width. Each row, including the last, ends with a newline. No trailing spaces.
func alignTable(headers []string, rows [][]string) string {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				break
			}
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	var b strings.Builder
	writeRow := func(cells []string) {
		for i, cell := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			b.WriteString(cell)
			if i == len(cells)-1 || i >= len(widths) {
				continue
			}
			if pad := widths[i] - utf8.RuneCountInString(cell); pad > 0 {
				b.WriteString(strings.Repeat(" ", pad))
			}
		}
		b.WriteByte('\n')
	}
	writeRow(headers)
	for _, row := range rows {
		writeRow(row)
	}
	return b.String()
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
		notBefore := certs[i].NotBefore.UTC().Format(time.RFC3339)
		notAfter := certs[i].NotAfter.UTC().Format(time.RFC3339)
		if err := writef("  NotBefore: %s | NotAfter: %s\n", notBefore, notAfter); err != nil {
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

		if names := certs[i].DNSNames; len(names) > 0 {
			if err := writef("  DNSNames:\n"); err != nil {
				return err
			}
			for _, name := range names {
				if err := writef("    %s\n", name); err != nil {
					return err
				}
			}
		}

		if emails := certs[i].EmailAddresses; len(emails) > 0 {
			if err := writef("  EmailAddresses:\n"); err != nil {
				return err
			}
			for _, email := range emails {
				if err := writef("    %s\n", email); err != nil {
					return err
				}
			}
		}

		if ips := certs[i].IPAddresses; len(ips) > 0 {
			if err := writef("  IPAddresses:\n"); err != nil {
				return err
			}
			for _, ip := range ips {
				if err := writef("    %s\n", ip); err != nil {
					return err
				}
			}
		}

		if domains := certs[i].PermittedDNSDomains; len(domains) > 0 {
			if err := writef("  PermittedDNSDomains:\n"); err != nil {
				return err
			}
			for _, domain := range domains {
				if err := writef("    %s\n", domain); err != nil {
					return err
				}
			}
		}

		if points := certs[i].CRLDistributionPoints; len(points) > 0 {
			if err := writef("  CRLDistributionPoints:\n"); err != nil {
				return err
			}
			for _, point := range points {
				if err := writef("    %s\n", point); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
