// Copyright 2026 Adam Shannon
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

package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

// DiffFormats is the diff --format list, in help text and errors.
const DiffFormats = "json, text"

const (
	diffFormatText = "text"
	diffFormatJSON = "json"
)

// DiffOptions controls output from a certificate diff.
// The zero value prints text.
type DiffOptions struct {
	// Format is "text" (the default) or "json".
	// Empty means text. Matching is case-insensitive.
	Format string
}

// ErrCertificatesDiffer is returned after the diff report is written when
// at least one compared field differs. The report is the command output;
// this error is only the signal that the certificates are not the same.
var ErrCertificatesDiffer = errors.New("certificates differ")

// NormalizeDiffFormat accepts text (the default, including "") and json.
// Matching is case-insensitive. Any other value is an error that lists the
// valid formats. The returned name is lowercase. The error quotes format
// unchanged so the caller can show what was passed.
func NormalizeDiffFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", diffFormatText:
		return diffFormatText, nil
	case diffFormatJSON:
		return diffFormatJSON, nil
	default:
		return "", fmt.Errorf("unknown format %q (formats: %s)", format, DiffFormats)
	}
}

// DiffCertificates reads two certificate files and writes which fields differ.
// Each file is PEM or DER and must contain one certificate. The first path
// is the left side. Text and JSON use the same fields. A nil error means
// every field matches. ErrCertificatesDiffer means the report was written
// and at least one field differs.
func DiffCertificates(leftPath, rightPath string, opts DiffOptions) error {
	return diffCertificates(os.Stdout, leftPath, rightPath, opts)
}

func diffCertificates(w io.Writer, leftPath, rightPath string, opts DiffOptions) error {
	format, err := NormalizeDiffFormat(opts.Format)
	if err != nil {
		return err
	}
	left, err := readOneCertificate(leftPath)
	if err != nil {
		return err
	}
	right, err := readOneCertificate(rightPath)
	if err != nil {
		return err
	}
	changes := compareCerts(left, right)
	out, err := formatDiff(leftPath, rightPath, format, changes)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, out); err != nil {
		return fmt.Errorf("writing diff: %w", err)
	}
	if len(changes) > 0 {
		return ErrCertificatesDiffer
	}
	return nil
}

// diffChange is one field whose formatted values are not equal.
// Left is the first file and Right is the second.
type diffChange struct {
	Field string `json:"field"`
	Left  string `json:"left"`
	Right string `json:"right"`
}

// diffJSON is the document written by diff --format json.
type diffJSON struct {
	Identical   bool         `json:"identical"`
	Left        string       `json:"left"`
	Right       string       `json:"right"`
	Differences []diffChange `json:"differences"`
}

// compareCerts reports fields that differ, in report order.
// An empty slice (non-nil) means the certificates match.
// Compared fields are subject, issuer, serial, validity, key, sans,
// sha256, and signature_algorithm.
func compareCerts(left, right *x509.Certificate) []diffChange {
	pairs := []struct {
		field string
		left  string
		right string
	}{
		{"subject", left.Subject.String(), right.Subject.String()},
		{"issuer", left.Issuer.String(), right.Issuer.String()},
		{"serial", formatSerial(left), formatSerial(right)},
		{"validity", formatValidity(left), formatValidity(right)},
		{"key", certutil.FormatKeyLabel(left), certutil.FormatKeyLabel(right)},
		{"sans", formatSANs(left), formatSANs(right)},
		{"sha256", formatSHA256(left), formatSHA256(right)},
		{"signature_algorithm", left.SignatureAlgorithm.String(), right.SignatureAlgorithm.String()},
	}
	out := make([]diffChange, 0)
	for _, p := range pairs {
		if p.left == p.right {
			continue
		}
		out = append(out, diffChange{Field: p.field, Left: p.left, Right: p.right})
	}
	return out
}

func formatSerial(c *x509.Certificate) string {
	if c == nil || c.SerialNumber == nil {
		return ""
	}
	return c.SerialNumber.String()
}

// formatValidity is NotBefore and NotAfter in UTC RFC3339, joined by " .. ".
func formatValidity(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	return c.NotBefore.UTC().Format(time.RFC3339) + " .. " + c.NotAfter.UTC().Format(time.RFC3339)
}

// formatSANs lists DNS names, emails, IP addresses, and URIs, in that order.
// Order inside each group is the certificate order. Names are not sorted.
func formatSANs(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	parts := make([]string, 0, len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses)+len(c.URIs))
	parts = append(parts, c.DNSNames...)
	parts = append(parts, c.EmailAddresses...)
	for _, ip := range c.IPAddresses {
		if len(ip) == 0 {
			continue
		}
		parts = append(parts, ip.String())
	}
	for _, u := range c.URIs {
		if u == nil {
			continue
		}
		parts = append(parts, u.String())
	}
	return strings.Join(parts, ", ")
}

func formatSHA256(c *x509.Certificate) string {
	if c == nil || len(c.Raw) == 0 {
		return ""
	}
	return certutil.GetHexSHA256Fingerprint(*c)
}

func formatDiff(leftPath, rightPath, format string, changes []diffChange) (string, error) {
	switch format {
	case diffFormatJSON:
		return formatDiffJSON(leftPath, rightPath, changes)
	case diffFormatText:
		return formatDiffText(changes), nil
	default:
		return "", fmt.Errorf("unknown format %q (formats: %s)", format, DiffFormats)
	}
}

// formatDiffText prints one line per differing field.
// Identical certificates are the single line "identical".
// Values are Go-quoted. The left value is the first file.
func formatDiffText(changes []diffChange) string {
	if len(changes) == 0 {
		return "identical\n"
	}
	var b strings.Builder
	for _, ch := range changes {
		b.WriteString(ch.Field)
		b.WriteString(": ")
		b.WriteString(strconv.Quote(ch.Left))
		b.WriteString(" != ")
		b.WriteString(strconv.Quote(ch.Right))
		b.WriteByte('\n')
	}
	return b.String()
}

// formatDiffJSON formats the diff as one JSON object.
// differences is an empty array when the certificates match.
// The result ends with a newline.
func formatDiffJSON(leftPath, rightPath string, changes []diffChange) (string, error) {
	if changes == nil {
		changes = []diffChange{}
	}
	doc := diffJSON{
		Identical:   len(changes) == 0,
		Left:        leftPath,
		Right:       rightPath,
		Differences: changes,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// readOneCertificate reads path as one PEM or DER certificate.
// A PEM file may contain comments and non-certificate blocks. More than
// one CERTIFICATE block is an error. DER is the raw certificate encoding.
func readOneCertificate(path string) (*x509.Certificate, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s does not exist", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return parseOneCertificate(path, body)
}

func parseOneCertificate(path string, body []byte) (*x509.Certificate, error) {
	if bytes.Contains(body, []byte("-----BEGIN")) {
		certs, err := parsePEMCertificates(body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		switch len(certs) {
		case 0:
			return nil, fmt.Errorf("%s: no certificate", path)
		case 1:
			return certs[0], nil
		default:
			return nil, fmt.Errorf("%s: expected one certificate, found %d", path, len(certs))
		}
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("%s: no certificate", path)
	}
	cert, err := certutil.ParseCertificate(body)
	if err != nil {
		return nil, fmt.Errorf("%s: not a PEM or DER certificate: %w", path, err)
	}
	return cert, nil
}

// parsePEMCertificates returns CERTIFICATE blocks in file order.
// Other PEM types are ignored. A block that does not parse is an error.
func parsePEMCertificates(body []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := body
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		n++
		cert, err := certutil.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", n, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
