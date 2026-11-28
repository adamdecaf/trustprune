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

// Package webscan builds a data-driven baseline allowlist of Mozilla
// roots that actually anchor TLS chains of popular websites.
package webscan

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

// Root is a Mozilla trusted-server root from certdata.txt.
type Root struct {
	Cert                *x509.Certificate
	SHA256              string
	Subject             string
	ServerDistrustAfter time.Time // CKA_NSS_SERVER_DISTRUST_AFTER; zero if unset
}

// LoadMozillaRoots parses a Mozilla certdata.txt document and returns the
// roots trusted for TLS server authentication, a pool for verification, and
// a map keyed by lowercase SHA-256 fingerprint. Only fingerprints from this
// set are ever recorded; unknown certificates are ignored.
func LoadMozillaRoots(certdata []byte) (*x509.CertPool, map[string]*Root, error) {
	if len(certdata) == 0 {
		return nil, nil, fmt.Errorf("empty certdata")
	}
	trusted, err := certutil.ParseTrustedServerCerts(bytes.NewReader(certdata))
	if err != nil {
		return nil, nil, err
	}
	if len(trusted) == 0 {
		return nil, nil, fmt.Errorf("no trusted server certificates in certdata")
	}
	pool := x509.NewCertPool()
	byFP := make(map[string]*Root, len(trusted))
	for i := range trusted {
		c := trusted[i].Cert
		if c == nil || len(c.Raw) == 0 {
			return nil, nil, fmt.Errorf("trusted server certificate %d has empty DER", i)
		}
		fp := certutil.GetHexSHA256Fingerprint(*c)
		pool.AddCert(c)
		byFP[fp] = &Root{
			Cert:                c,
			SHA256:              fp,
			Subject:             certutil.StringifyPKIXName(c.Subject),
			ServerDistrustAfter: trusted[i].ServerDistrustAfter,
		}
	}
	return pool, byFP, nil
}

// VerifiedRoot returns the Mozilla root that anchors leaf for dnsName,
// using intermediates and the Mozilla pool. It returns nil when
// verification fails, the verified root is not in known, or the leaf's
// NotBefore is after the root's ServerDistrustAfter cutoff. Verification
// uses the current time.
func VerifiedRoot(leaf *x509.Certificate, intermediates []*x509.Certificate, dnsName string, pool *x509.CertPool, known map[string]*Root) *Root {
	root, distrusted := VerifyChain(leaf, intermediates, dnsName, pool, known, time.Time{})
	if distrusted {
		return nil
	}
	return root
}

// VerifyChain is VerifiedRoot with an explicit verification time and a
// separate distrusted result. at is the verification time; a zero value
// uses the current time, the same as crypto/x509 when CurrentTime is unset.
// distrusted is true when a known Mozilla root chained but the leaf was
// issued after that root's ServerDistrustAfter cutoff. In that case root is
// still returned so the caller can count the site separately; it must not
// be added to site counts.
func VerifyChain(leaf *x509.Certificate, intermediates []*x509.Certificate, dnsName string, pool *x509.CertPool, known map[string]*Root, at time.Time) (root *Root, distrusted bool) {
	if leaf == nil || pool == nil || known == nil {
		return nil, false
	}
	intPool := x509.NewCertPool()
	for _, c := range intermediates {
		if c != nil {
			intPool.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{
		Intermediates: intPool,
		Roots:         pool,
		CurrentTime:   at,
	}
	if dnsName != "" {
		opts.DNSName = dnsName
	}
	chains, err := leaf.Verify(opts)
	if err != nil || len(chains) == 0 || len(chains[0]) == 0 {
		return nil, false
	}
	rootCert := chains[0][len(chains[0])-1]
	if rootCert == nil {
		return nil, false
	}
	fp := certutil.GetHexSHA256Fingerprint(*rootCert)
	root, ok := known[fp]
	if !ok {
		return nil, false
	}
	if DistrustedLeaf(root, leaf) {
		return root, true
	}
	return root, false
}

// DistrustedLeaf reports whether root has a ServerDistrustAfter cutoff and
// leaf was issued after that instant (leaf.NotBefore is strictly after the
// cutoff). A NotBefore equal to the cutoff is still accepted. A nil root
// or leaf, or a zero cutoff, is not distrusted.
func DistrustedLeaf(root *Root, leaf *x509.Certificate) bool {
	if root == nil || leaf == nil || root.ServerDistrustAfter.IsZero() {
		return false
	}
	return leaf.NotBefore.UTC().After(root.ServerDistrustAfter.UTC())
}

// Counts records how many sites each known Mozilla root anchored.
type Counts struct {
	byFP map[string]int
	root map[string]*Root
}

// NewCounts returns an empty count set.
func NewCounts() *Counts {
	return &Counts{
		byFP: make(map[string]int),
		root: make(map[string]*Root),
	}
}

// Add increments the site count for root. Unknown or nil roots are ignored
// so fingerprints are never invented.
func (c *Counts) Add(root *Root) {
	if c == nil || root == nil || root.SHA256 == "" {
		return
	}
	c.byFP[root.SHA256]++
	if _, ok := c.root[root.SHA256]; !ok {
		c.root[root.SHA256] = root
	}
}

// Sites returns how many sites fp anchored.
func (c *Counts) Sites(fp string) int {
	if c == nil {
		return 0
	}
	return c.byFP[fp]
}

// RootCount is one observed Mozilla root and the number of sites it anchored.
type RootCount struct {
	SHA256  string
	Subject string
	Sites   int
}

// Above returns observed roots with at least threshold sites, sorted by
// fingerprint for stable allowlist output. A threshold less than 1 is
// treated as 1.
func (c *Counts) Above(threshold int) []RootCount {
	if threshold < 1 {
		threshold = 1
	}
	return c.list(func(n int) bool { return n >= threshold }, byFingerprint)
}

// All returns every observed root, highest site count first, then fingerprint.
func (c *Counts) All() []RootCount {
	return c.list(func(n int) bool { return n > 0 }, byCountThenFingerprint)
}

func (c *Counts) list(keep func(int) bool, less func(a, b RootCount) bool) []RootCount {
	if c == nil {
		return nil
	}
	out := make([]RootCount, 0, len(c.byFP))
	for fp, n := range c.byFP {
		if !keep(n) {
			continue
		}
		subj := ""
		if r := c.root[fp]; r != nil {
			subj = r.Subject
		}
		out = append(out, RootCount{SHA256: fp, Subject: subj, Sites: n})
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

func byFingerprint(a, b RootCount) bool { return a.SHA256 < b.SHA256 }

func byCountThenFingerprint(a, b RootCount) bool {
	if a.Sites != b.Sites {
		return a.Sites > b.Sites
	}
	return a.SHA256 < b.SHA256
}

// Report is the metadata and counts written into a web baseline allowlist.
type Report struct {
	ListName       string
	ListID         string
	ListURL        string
	ListDate       string
	CertdataSource string
	N              int
	Success        int
	Distrusted     int // leaves issued after a root ServerDistrustAfter cutoff
	Threshold      int
	Roots          []RootCount // fingerprints that meet the threshold
	Observed       []RootCount // all observed roots, for header comments
}

// YAML renders a mozilla-included.yaml-style allowlist with provenance
// comments. Fingerprints are lowercase SHA-256, sorted, and quoted.
func (r Report) YAML() []byte {
	threshold := r.Threshold
	if threshold < 1 {
		threshold = 1
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# Baseline allowlist of Mozilla certdata.txt roots that anchored TLS
# chains of popular websites.
# Source list: %s
`, reportListLabel(r))
	if r.ListURL != "" {
		fmt.Fprintf(&b, "# List URL: %s\n", r.ListURL)
	}
	if r.ListDate != "" {
		fmt.Fprintf(&b, "# List date: %s\n", r.ListDate)
	}
	fmt.Fprintf(&b, `# Sites scanned: %d
# Successful verifications: %d
`, r.N, r.Success)
	if r.N > 0 {
		fmt.Fprintf(&b, "# Success rate: %.1f%%\n", 100*float64(r.Success)/float64(r.N))
	}
	fmt.Fprintf(&b, "# Distrusted (leaf NotBefore after root CKA_NSS_SERVER_DISTRUST_AFTER): %d\n", r.Distrusted)
	b.WriteString("# This is a large sample of the source list, not a full top-1-million scan.\n")
	if r.CertdataSource != "" {
		fmt.Fprintf(&b, "# Trust store: %s\n", r.CertdataSource)
	}
	if strings.Contains(strings.ToLower(r.ListName+" "+r.ListURL+" "+r.ListID), "tranco") {
		b.WriteString("# Cite: https://tranco-list.eu/ (V. Le Pochat et al., NDSS 2019)\n")
	}
	fmt.Fprintf(&b, `# Threshold: roots that anchored at least %d successful site`, threshold)
	if threshold != 1 {
		b.WriteString("s")
	}
	b.WriteString("\n")
	b.WriteString(`# Regenerate: make web-allowlist
#   or: CGO_ENABLED=0 go run pkg/allowlist/web_allowlist_gen.go -list <tranco.csv> -certdata testdata/certdata.txt.gz -out docs/downloads/allowlists/web.yaml
# Fingerprints are SHA-256 of the certificate DER.
# Applying this allowlist still honors trustprune's built-in denylist and the Chromium, Mozilla, Apple, and CCADB blocklists.
# This file has no Jekyll front matter so the docs site can serve it unchanged.
`)
	if len(r.Observed) > 0 {
		b.WriteString("#\n# Per-root site counts (successful verifications, highest first):\n")
		for _, rc := range r.Observed {
			subj := oneLine(rc.Subject)
			if subj == "" {
				subj = "(no subject)"
			}
			fmt.Fprintf(&b, "#   %s  %6d  %s\n", rc.SHA256, rc.Sites, subj)
		}
	}
	b.WriteString("fingerprints:\n")
	for _, rc := range r.Roots {
		fmt.Fprintf(&b, "  - \"%s\"\n", rc.SHA256)
	}
	return []byte(b.String())
}

// EncodeYAML returns the allowlist YAML. It returns an error, and does not
// render fingerprints, when no roots met the threshold, so callers cannot
// write an empty web.yaml.
func (r Report) EncodeYAML() ([]byte, error) {
	threshold := r.Threshold
	if threshold < 1 {
		threshold = 1
	}
	if len(r.Roots) == 0 {
		return nil, fmt.Errorf("no roots met threshold %d after scanning %d hosts (%d successful verifications)", threshold, r.N, r.Success)
	}
	return r.YAML(), nil
}

func reportListLabel(r Report) string {
	name := strings.TrimSpace(r.ListName)
	if name == "" {
		name = "top-sites list"
	}
	if r.ListID != "" {
		return name + " " + r.ListID
	}
	return name
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Join(strings.Fields(s), " ")
}

// ParseTopSitesCSV reads a Tranco-style rank,domain CSV (comments and
// blank lines skipped) and returns up to limit hostnames in list order.
// A limit less than 1 means the whole file.
func ParseTopSitesCSV(r io.Reader, limit int) ([]string, error) {
	br := bufio.NewScanner(r)
	// Some top-list rows can be long; raise the token size from the default.
	br.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var hosts []string
	lineNo := 0
	for br.Scan() {
		lineNo++
		line := strings.TrimSpace(br.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain, ok := parseRankDomain(line)
		if !ok {
			return nil, fmt.Errorf("line %d: want rank,domain, got %q", lineNo, line)
		}
		hosts = append(hosts, domain)
		if limit > 0 && len(hosts) >= limit {
			break
		}
	}
	if err := br.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}

func parseRankDomain(line string) (string, bool) {
	comma := strings.IndexByte(line, ',')
	if comma < 0 {
		return "", false
	}
	rank := strings.TrimSpace(line[:comma])
	domain := strings.ToLower(strings.TrimSpace(line[comma+1:]))
	if domain == "" {
		return "", false
	}
	if _, err := strconv.Atoi(rank); err != nil {
		return "", false
	}
	// A domain must not look like a URL or contain a space.
	if strings.Contains(domain, "://") || strings.ContainsAny(domain, " \t") {
		return "", false
	}
	return domain, true
}

const maxCertdataBytes = 32 << 20

// LoadMozillaRootsFile reads path (plain or gzip-compressed certdata.txt)
// and returns the trusted-server roots. The decompressed size is capped.
func LoadMozillaRootsFile(path string) (*x509.CertPool, map[string]*Root, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, fmt.Errorf("empty certdata path")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	plain, err := gunzipIfNeeded(path, body, maxCertdataBytes)
	if err != nil {
		return nil, nil, err
	}
	return LoadMozillaRoots(plain)
}

func gunzipIfNeeded(path string, body []byte, limit int64) ([]byte, error) {
	gzipName := strings.HasSuffix(strings.ToLower(path), ".gz")
	gzipMagic := len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b
	if !gzipName && !gzipMagic {
		return body, nil
	}
	if limit <= 0 {
		limit = maxCertdataBytes
	}
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gzip %s: %w", path, err)
	}
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	cerr := r.Close()
	if err != nil {
		return nil, fmt.Errorf("gzip %s: %w", path, err)
	}
	if cerr != nil {
		return nil, fmt.Errorf("gzip %s: %w", path, cerr)
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("gzip %s: decompressed size exceeds %d byte limit", path, limit)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("gzip %s is empty", path)
	}
	return out, nil
}
