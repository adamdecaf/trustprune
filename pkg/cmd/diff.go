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
	"sort"
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
	// Verbose prints left: and right: path lines in bundle text.
	// JSON ignores Verbose. Single-certificate text does not print paths.
	Verbose bool
}

// ErrCertificatesDiffer is returned after the diff report is written when
// the certificates are not the same. For one certificate on each side, a
// compared field differs. For a bundle, a certificate was added or removed.
// The report is the command output; this error is only the signal that the
// certificates are not the same.
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

// DiffCertificates reads two certificate files and writes how they differ.
// Each file is PEM or DER. PEM may include comments and non-certificate
// blocks. DER is one certificate. Zero certificates is an error. The first
// path is the left side.
//
// When both files contain one certificate, the report is a field diff.
// When either file contains more than one, certificates are matched by
// SHA-256 fingerprint. Bundle text lists each removed or added certificate
// and a summary. Identical bundles print "identical". Verbose prints the
// file paths in that bundle text. A nil error means the certificates match.
// ErrCertificatesDiffer means the report was written and they do not.
func DiffCertificates(leftPath, rightPath string, opts DiffOptions) error {
	return diffCertificates(os.Stdout, leftPath, rightPath, opts)
}

func diffCertificates(w io.Writer, leftPath, rightPath string, opts DiffOptions) error {
	format, err := NormalizeDiffFormat(opts.Format)
	if err != nil {
		return err
	}
	left, err := readCertificates(leftPath)
	if err != nil {
		return err
	}
	right, err := readCertificates(rightPath)
	if err != nil {
		return err
	}
	if len(left) > 1 || len(right) > 1 {
		return diffBundles(w, leftPath, rightPath, format, opts.Verbose, left, right)
	}
	changes := compareCerts(left[0], right[0])
	out, err := formatDiff(leftPath, rightPath, format, changes)
	if err != nil {
		return err
	}
	return writeDiff(w, out, len(changes) > 0)
}

func writeDiff(w io.Writer, out string, differ bool) error {
	if _, err := io.WriteString(w, out); err != nil {
		return fmt.Errorf("writing diff: %w", err)
	}
	if differ {
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

// bundleCert is one certificate in a bundle diff, matched by SHA-256.
type bundleCert struct {
	Subject string `json:"subject"`
	SHA256  string `json:"sha256"`
}

// bundleDiffJSON is the document written by diff --format json for a bundle.
// Single-certificate JSON does not use this shape and has no mode field.
type bundleDiffJSON struct {
	Identical bool         `json:"identical"`
	Left      string       `json:"left"`
	Right     string       `json:"right"`
	Mode      string       `json:"mode"`
	Removed   []bundleCert `json:"removed"`
	Added     []bundleCert `json:"added"`
	Unchanged int          `json:"unchanged"`
}

func diffBundles(w io.Writer, leftPath, rightPath, format string, verbose bool, left, right []*x509.Certificate) error {
	removed, added, unchanged := compareBundles(left, right)
	out, err := formatBundleDiff(leftPath, rightPath, format, verbose, removed, added, unchanged)
	if err != nil {
		return err
	}
	return writeDiff(w, out, len(removed) > 0 || len(added) > 0)
}

// compareBundles matches certificates by SHA-256 fingerprint.
// A fingerprint only in left is removed. A fingerprint only in right is
// added. unchanged is the number of fingerprints in both. A duplicate
// fingerprint inside one file counts once. removed and added are non-nil.
func compareBundles(left, right []*x509.Certificate) (removed, added []bundleCert, unchanged int) {
	leftSet := indexBundle(left)
	rightSet := indexBundle(right)
	removed = bundleOnly(leftSet, rightSet)
	added = bundleOnly(rightSet, leftSet)
	for fp := range leftSet {
		if _, ok := rightSet[fp]; ok {
			unchanged++
		}
	}
	return removed, added, unchanged
}

// indexBundle keys certificates by SHA-256. The first copy of a fingerprint
// wins. Later copies in the same file are ignored.
func indexBundle(certs []*x509.Certificate) map[string]bundleCert {
	out := make(map[string]bundleCert, len(certs))
	for _, c := range certs {
		if c == nil {
			continue
		}
		fp := formatSHA256(c)
		if _, ok := out[fp]; ok {
			continue
		}
		out[fp] = bundleCert{Subject: bundleSubject(c), SHA256: fp}
	}
	return out
}

// bundleOnly returns certificates in have whose fingerprint is not in other,
// sorted by subject then fingerprint. The result is non-nil.
func bundleOnly(have, other map[string]bundleCert) []bundleCert {
	out := make([]bundleCert, 0)
	for fp, entry := range have {
		if _, ok := other[fp]; ok {
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].SHA256 < out[j].SHA256
	})
	return out
}

// bundleSubject is the name shown for a certificate in a bundle diff.
// StringifyPKIXName is the subject display used by list. chainDisplayName
// covers a certificate whose PKIX name string is empty.
func bundleSubject(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	if name := certutil.StringifyPKIXName(c.Subject); name != "" {
		return name
	}
	return chainDisplayName(c)
}

func formatBundleDiff(leftPath, rightPath, format string, verbose bool, removed, added []bundleCert, unchanged int) (string, error) {
	switch format {
	case diffFormatJSON:
		return formatBundleJSON(leftPath, rightPath, removed, added, unchanged)
	case diffFormatText:
		return formatBundleText(leftPath, rightPath, removed, added, unchanged, verbose), nil
	default:
		return "", fmt.Errorf("unknown format %q (formats: %s)", format, DiffFormats)
	}
}

// formatBundleText prints one line per changed certificate, then a summary.
// A certificate only in the left file is removed and starts with "-".
// A certificate only in the right file is added and starts with "+".
// Each line is the SHA-256 fingerprint, then the subject. Removed lines
// come first. Each group keeps compareBundles order (subject, then
// fingerprint). The summary is "removed N added N unchanged N".
// Identical bundles print "identical".
// When verbose is set, left: and right: path lines come first.
func formatBundleText(leftPath, rightPath string, removed, added []bundleCert, unchanged int, verbose bool) string {
	var b strings.Builder
	if verbose {
		b.WriteString("left: ")
		b.WriteString(leftPath)
		b.WriteByte('\n')
		b.WriteString("right: ")
		b.WriteString(rightPath)
		b.WriteByte('\n')
	}
	if len(removed) == 0 && len(added) == 0 {
		b.WriteString("identical\n")
		return b.String()
	}
	writeBundleChanges(&b, "-", removed)
	writeBundleChanges(&b, "+", added)
	b.WriteString("removed ")
	b.WriteString(strconv.Itoa(len(removed)))
	b.WriteString(" added ")
	b.WriteString(strconv.Itoa(len(added)))
	b.WriteString(" unchanged ")
	b.WriteString(strconv.Itoa(unchanged))
	b.WriteByte('\n')
	return b.String()
}

func writeBundleChanges(b *strings.Builder, mark string, entries []bundleCert) {
	for _, e := range entries {
		b.WriteString(mark)
		b.WriteByte(' ')
		b.WriteString(e.SHA256)
		b.WriteByte(' ')
		b.WriteString(e.Subject)
		b.WriteByte('\n')
	}
}

// formatBundleJSON formats a bundle diff as one JSON object.
// removed and added are empty arrays when nothing changed.
// The result ends with a newline. mode is "bundle".
func formatBundleJSON(leftPath, rightPath string, removed, added []bundleCert, unchanged int) (string, error) {
	if removed == nil {
		removed = []bundleCert{}
	}
	if added == nil {
		added = []bundleCert{}
	}
	doc := bundleDiffJSON{
		Identical: len(removed) == 0 && len(added) == 0,
		Left:      leftPath,
		Right:     rightPath,
		Mode:      "bundle",
		Removed:   removed,
		Added:     added,
		Unchanged: unchanged,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// readCertificates reads path once as PEM certificates or one DER certificate.
// A PEM file may contain comments and non-certificate blocks. Every
// CERTIFICATE block is returned. DER is the raw certificate encoding and is
// always one certificate. Zero certificates is an error.
func readCertificates(path string) ([]*x509.Certificate, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s does not exist", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return parseCertificates(path, body)
}

func parseCertificates(path string, body []byte) ([]*x509.Certificate, error) {
	if bytes.Contains(body, []byte("-----BEGIN")) {
		certs, err := parsePEMCertificates(body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("%s: no certificate", path)
		}
		return certs, nil
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("%s: no certificate", path)
	}
	// Parse the raw body. TrimSpace would drop a trailing signature byte
	// that is whitespace (0x09, 0x0a, 0x20, ...) and the certificate
	// would fail as malformed.
	cert, err := certutil.ParseCertificate(body)
	if err != nil {
		return nil, fmt.Errorf("%s: not a PEM or DER certificate: %w", path, err)
	}
	return []*x509.Certificate{cert}, nil
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
