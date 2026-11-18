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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

// chainRemoteTimeout is the deadline for a --remote TLS dial.
// The dial context and the TCP dialer both use it.
const chainRemoteTimeout = 30 * time.Second

// chainMaxCerts stops a walk that never reaches a self-signed certificate.
const chainMaxCerts = 16

// ChainOptions selects the store and which certificates may appear in a chain.
// The zero value reads the platform store, hides expired and blocklisted
// certificates, and does not dial the network.
type ChainOptions struct {
	// App is the application store. Empty is the platform store.
	App string
	// StorePath overrides discovery for java, certifi, and poppler.
	StorePath string
	// Bundle is an openssl PEM CA bundle. It requires App openssl.
	Bundle string
	// File is a PEM bundle or one DER certificate. The leaf is chosen
	// from this file when URL is nil.
	File string
	// URL is the host to match. Nil means File is the only input.
	URL *url.URL
	// Untrusted includes certificates that are not in the trusted store.
	Untrusted bool
	// Expired includes certificates whose NotAfter is before Now.
	Expired bool
	// Revoked includes certificates on the offline Chromium and Mozilla
	// blocklists. Included certificates are labeled blocklisted.
	// There is no OCSP or CRL lookup.
	Revoked bool
	// All includes untrusted, expired, and blocklisted certificates.
	// It does not enable Remote.
	All bool
	// Remote dials URL when no local leaf is found.
	Remote bool
	// Now is the time used for expiry. The zero value is time.Now.
	Now time.Time
	// Fetch overrides the TLS dial. Tests set it. Nil uses the default
	// dial with chainRemoteTimeout.
	Fetch func(*url.URL) ([]*x509.Certificate, error)
}

// errChainPresented stops the read-only handshake after PeerCertificates
// are recorded. It is not a successful connection.
var errChainPresented = errors.New("presented chain captured for display")

type chainInput struct {
	leaf      *x509.Certificate
	extras    []*x509.Certificate
	trusted   []*x509.Certificate
	untrusted []*x509.Certificate
	opts      ChainOptions
	blocked   func(*x509.Certificate) bool
}

type chainRow struct {
	subject  string
	issuer   string
	notAfter string
	sha      string
}

type skipReason struct {
	untrusted bool
	expired   bool
	revoked   bool
}

func (s *skipReason) add(o skipReason) {
	s.untrusted = s.untrusted || o.untrusted
	s.expired = s.expired || o.expired
	s.revoked = s.revoked || o.revoked
}

func (s skipReason) hint() string {
	var flags []string
	if s.untrusted {
		flags = append(flags, "--untrusted")
	}
	if s.expired {
		flags = append(flags, "--expired")
	}
	if s.revoked {
		flags = append(flags, "--revoked")
	}
	if len(flags) == 0 {
		return ""
	}
	return "pass " + strings.Join(flags, " ")
}

func (s skipReason) skipped() bool {
	return s.untrusted || s.expired || s.revoked
}

// ShowChain writes the certificate chain for opts to w.
// The store is only listed. Nothing is added, removed, or backed up.
// A nil writer uses os.Stdout.
//
// The default chain uses trusted, in-date certificates that are not on
// the offline Chromium or Mozilla blocklists. The leaf is shown when it
// passes the expiry and blocklist checks, even if it is not in the store.
// With no labels, the table matches connect's verified chain table.
func ShowChain(w io.Writer, opts ChainOptions) error {
	if w == nil {
		w = os.Stdout
	}
	opts = applyChainIncludes(opts)
	var fileCerts []*x509.Certificate
	if strings.TrimSpace(opts.File) != "" {
		certs, err := readChainFile(opts.File)
		if err != nil {
			return err
		}
		fileCerts = certs
	}
	if len(fileCerts) == 0 && opts.URL == nil {
		return errors.New("provide a certificate file (--file) or a URL")
	}
	if opts.Remote && opts.URL == nil {
		return errors.New("--remote requires a URL")
	}

	st, err := chainOpenStore(opts)
	if err != nil {
		return err
	}
	trusted, err := st.List(&store.ListOptions{Trusted: true})
	if err != nil {
		return fmt.Errorf("problem getting certs: %w", err)
	}
	var untrustedStore []*x509.Certificate
	if opts.Untrusted {
		// A second list is only done when the flag is set. Windows List
		// shells out, so the default path stays one read.
		listed, err := st.List(&store.ListOptions{Untrusted: true})
		if err != nil {
			return fmt.Errorf("problem getting untrusted certs: %w", err)
		}
		untrustedStore = listed
	}

	leaf, extras, err := resolveChainLeaf(opts, fileCerts, trusted, untrustedStore)
	if err != nil {
		return err
	}
	out, err := buildChain(chainInput{
		leaf:      leaf,
		extras:    extras,
		trusted:   trusted,
		untrusted: untrustedStore,
		opts:      opts,
		blocked:   allowlist.Blocklisted,
	})
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, out); err != nil {
		return fmt.Errorf("writing chain: %w", err)
	}
	return nil
}

func chainOpenStore(opts ChainOptions) (store.Store, error) {
	if bundle := strings.TrimSpace(opts.Bundle); bundle != "" {
		if strings.ToLower(strings.TrimSpace(opts.App)) != "openssl" {
			return nil, errors.New("--bundle requires --app openssl")
		}
		return store.OpenSSLBundleAt(bundle)
	}
	app := strings.TrimSpace(opts.App)
	if app == "" {
		if strings.TrimSpace(opts.StorePath) != "" {
			return nil, store.StoreOverrideNoAppError()
		}
		return store.Platform(), nil
	}
	return store.ForAppWithStore(app, opts.StorePath)
}

func resolveChainLeaf(opts ChainOptions, fileCerts, trusted, untrustedStore []*x509.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	if opts.URL == nil {
		leaf, extras := selectFileLeaf(fileCerts)
		if leaf == nil {
			return nil, nil, fmt.Errorf("%s: no certificate", opts.File)
		}
		return leaf, extras, nil
	}
	host := opts.URL.Hostname()
	if c := firstHostMatch(host, fileCerts); c != nil {
		return c, others(fileCerts, c), nil
	}
	if c := firstHostMatch(host, trusted); c != nil {
		return c, fileCerts, nil
	}
	if c := firstHostMatch(host, untrustedStore); c != nil {
		extras := append(append([]*x509.Certificate{}, fileCerts...), others(untrustedStore, c)...)
		return c, extras, nil
	}
	if !opts.Remote {
		return nil, nil, fmt.Errorf("no local chain for %s; pass --remote to look up the TLS chain", opts.URL.String())
	}
	presented, err := fetchPresented(opts)
	if err != nil {
		return nil, nil, err
	}
	if len(presented) == 0 || presented[0] == nil {
		return nil, nil, fmt.Errorf("remote lookup for %s: server presented no certificates", opts.URL.String())
	}
	extras := append(append([]*x509.Certificate{}, presented[1:]...), fileCerts...)
	return presented[0], extras, nil
}

func fetchPresented(opts ChainOptions) ([]*x509.Certificate, error) {
	if opts.Fetch != nil {
		certs, err := opts.Fetch(opts.URL)
		if err != nil {
			return nil, err
		}
		return certs, nil
	}
	return readChainCertificates(context.Background(), opts.URL, chainRemoteTimeout)
}

func applyChainIncludes(opts ChainOptions) ChainOptions {
	if opts.All {
		opts.Untrusted = true
		opts.Expired = true
		opts.Revoked = true
	}
	return opts
}

func buildChain(in chainInput) (string, error) {
	in.opts = applyChainIncludes(in.opts)
	if in.leaf == nil {
		return "", errors.New("no certificate")
	}
	now := in.opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	blocked := in.blocked
	if blocked == nil {
		blocked = allowlist.Blocklisted
	}
	if err := rejectLeaf(in.leaf, in.opts, now, blocked); err != nil {
		return "", err
	}
	trusted := chainTrustedSet(in.trusted)
	pool := chainPool([]*x509.Certificate{in.leaf}, in.trusted, in.untrusted, in.extras)
	rows, note, err := walkChain(in.leaf, pool, trusted, in.opts, now, blocked)
	if err != nil {
		return "", err
	}
	return formatChain(rows, note), nil
}

func rejectLeaf(leaf *x509.Certificate, opts ChainOptions, now time.Time, blocked func(*x509.Certificate) bool) error {
	var why []string
	var flags []string
	if chainExpired(leaf, now) && !opts.Expired {
		why = append(why, "expired "+leaf.NotAfter.UTC().Format(connectDateLayout))
		flags = append(flags, "--expired")
	}
	if chainIsBlocked(blocked, leaf) && !opts.Revoked {
		why = append(why, "is blocklisted")
		flags = append(flags, "--revoked")
	}
	if len(why) == 0 {
		return nil
	}
	return fmt.Errorf("leaf certificate %s; pass %s to include it", strings.Join(why, " and "), strings.Join(flags, " "))
}

func walkChain(leaf *x509.Certificate, pool []*x509.Certificate, trusted map[string]struct{}, opts ChainOptions, now time.Time, blocked func(*x509.Certificate) bool) ([]chainRow, string, error) {
	var rows []chainRow
	seen := map[string]struct{}{}
	current := leaf
	for {
		fp := chainFP(current)
		if _, ok := seen[fp]; ok {
			return rows, "incomplete: cycle at " + chainDisplayName(current), nil
		}
		if len(rows) >= chainMaxCerts {
			return rows, fmt.Sprintf("incomplete: chain is longer than %d certificates", chainMaxCerts), nil
		}
		seen[fp] = struct{}{}
		row, err := makeChainRow(current, len(rows) == 0, trusted, now, blocked)
		if err != nil {
			return nil, "", err
		}
		rows = append(rows, row)
		if chainSelfSigned(current) {
			return rows, "", nil
		}
		next, skip, ok := pickIssuer(current, pool, trusted, opts, now, blocked)
		if !ok {
			return rows, incompleteNote(current, skip), nil
		}
		current = next
	}
}

func makeChainRow(cert *x509.Certificate, isLeaf bool, trusted map[string]struct{}, now time.Time, blocked func(*x509.Certificate) bool) (chainRow, error) {
	sum, err := connectSHA256Prefix(cert)
	if err != nil {
		return chainRow{}, err
	}
	return chainRow{
		subject:  chainSubject(cert, isLeaf, chainInStore(cert, trusted), chainExpired(cert, now), chainIsBlocked(blocked, cert)),
		issuer:   connectName(cert.Issuer),
		notAfter: cert.NotAfter.UTC().Format(connectDateLayout),
		sha:      sum,
	}, nil
}

func chainSubject(cert *x509.Certificate, isLeaf, inStore, expired, blocked bool) string {
	name := chainDisplayName(cert)
	var tags []string
	// The leaf is the certificate the user asked about. It is shown even
	// when it is not in the store, and that is not labeled untrusted.
	if !isLeaf && !inStore {
		tags = append(tags, "untrusted")
	}
	if expired {
		tags = append(tags, "expired")
	}
	if blocked {
		tags = append(tags, "blocklisted")
	}
	if len(tags) == 0 {
		return name
	}
	return name + " (" + strings.Join(tags, ", ") + ")"
}

func chainDisplayName(cert *x509.Certificate) string {
	if cert == nil {
		return "certificate"
	}
	name := connectName(cert.Subject)
	if name == "" {
		return "certificate"
	}
	return name
}

func incompleteNote(current *x509.Certificate, skip skipReason) string {
	note := "incomplete: no issuer for " + chainDisplayName(current)
	if hint := skip.hint(); hint != "" {
		note += "; " + hint
	}
	return note
}

func formatChain(rows []chainRow, note string) string {
	headers := []string{"INDEX", "SUBJECT", "ISSUER", "NOT-AFTER", "SHA256"}
	body := make([][]string, len(rows))
	for i, row := range rows {
		body[i] = []string{strconv.Itoa(i), row.subject, row.issuer, row.notAfter, row.sha}
	}
	out := alignTable(headers, body)
	if note != "" {
		out += note + "\n"
	}
	return out
}

func pickIssuer(child *x509.Certificate, pool []*x509.Certificate, trusted map[string]struct{}, opts ChainOptions, now time.Time, blocked func(*x509.Certificate) bool) (*x509.Certificate, skipReason, bool) {
	var best *x509.Certificate
	var skipped skipReason
	found := false
	for _, parent := range pool {
		if !chainIssuedBy(child, parent) {
			continue
		}
		reason := issuerSkip(parent, trusted, opts, now, blocked)
		if reason.skipped() {
			skipped.add(reason)
			continue
		}
		if !found || chainBetterIssuer(parent, best, trusted, now, blocked) {
			best = parent
			found = true
		}
	}
	return best, skipped, found
}

func issuerSkip(parent *x509.Certificate, trusted map[string]struct{}, opts ChainOptions, now time.Time, blocked func(*x509.Certificate) bool) skipReason {
	var reason skipReason
	if !chainInStore(parent, trusted) && !opts.Untrusted {
		reason.untrusted = true
	}
	if chainExpired(parent, now) && !opts.Expired {
		reason.expired = true
	}
	if chainIsBlocked(blocked, parent) && !opts.Revoked {
		reason.revoked = true
	}
	return reason
}

func chainBetterIssuer(a, b *x509.Certificate, trusted map[string]struct{}, now time.Time, blocked func(*x509.Certificate) bool) bool {
	aTrust := chainInStore(a, trusted)
	bTrust := chainInStore(b, trusted)
	if aTrust != bTrust {
		return aTrust
	}
	aBlock := chainIsBlocked(blocked, a)
	bBlock := chainIsBlocked(blocked, b)
	if aBlock != bBlock {
		return !aBlock
	}
	aExp := chainExpired(a, now)
	bExp := chainExpired(b, now)
	if aExp != bExp {
		return !aExp
	}
	if !a.NotAfter.Equal(b.NotAfter) {
		return a.NotAfter.After(b.NotAfter)
	}
	return chainFP(a) < chainFP(b)
}

func chainIssuedBy(child, parent *x509.Certificate) bool {
	if child == nil || parent == nil || len(child.Raw) == 0 || len(parent.Raw) == 0 {
		return false
	}
	if bytes.Equal(child.Raw, parent.Raw) {
		return false
	}
	if len(child.RawIssuer) > 0 && len(parent.RawSubject) > 0 && !bytes.Equal(child.RawIssuer, parent.RawSubject) {
		return false
	}
	return child.CheckSignatureFrom(parent) == nil
}

func chainSelfSigned(cert *x509.Certificate) bool {
	if cert == nil || len(cert.Raw) == 0 {
		return false
	}
	if len(cert.RawSubject) > 0 && !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

func chainExpired(cert *x509.Certificate, now time.Time) bool {
	if cert == nil {
		return false
	}
	return now.After(cert.NotAfter)
}

func chainIsBlocked(fn func(*x509.Certificate) bool, cert *x509.Certificate) bool {
	if fn == nil || cert == nil {
		return false
	}
	return fn(cert)
}

func chainInStore(cert *x509.Certificate, trusted map[string]struct{}) bool {
	if cert == nil {
		return false
	}
	_, ok := trusted[chainFP(cert)]
	return ok
}

func chainTrustedSet(certs []*x509.Certificate) map[string]struct{} {
	set := make(map[string]struct{}, len(certs))
	for _, cert := range certs {
		fp := chainFP(cert)
		if fp == "" {
			continue
		}
		set[fp] = struct{}{}
	}
	return set
}

func chainFP(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	return certutil.GetHexSHA256Fingerprint(*cert)
}

func chainPool(groups ...[]*x509.Certificate) []*x509.Certificate {
	var all []*x509.Certificate
	for _, group := range groups {
		all = append(all, group...)
	}
	return chainDedupe(all)
}

func chainDedupe(certs []*x509.Certificate) []*x509.Certificate {
	seen := make(map[string]struct{}, len(certs))
	out := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		fp := chainFP(cert)
		if fp == "" {
			continue
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, cert)
	}
	return out
}

func selectFileLeaf(certs []*x509.Certificate) (*x509.Certificate, []*x509.Certificate) {
	certs = chainDedupe(certs)
	if len(certs) == 0 {
		return nil, nil
	}
	if len(certs) == 1 {
		return certs[0], nil
	}
	signs := map[string]bool{}
	for i := range certs {
		for j := range certs {
			if i == j {
				continue
			}
			if chainIssuedBy(certs[j], certs[i]) {
				signs[chainFP(certs[i])] = true
			}
		}
	}
	var leaves []*x509.Certificate
	for _, cert := range certs {
		if !signs[chainFP(cert)] {
			leaves = append(leaves, cert)
		}
	}
	if len(leaves) == 0 {
		leaves = []*x509.Certificate{certs[0]}
	}
	leaf := leaves[0]
	for _, cert := range leaves[1:] {
		if betterChainLeaf(cert, leaf) {
			leaf = cert
		}
	}
	return leaf, others(certs, leaf)
}

func betterChainLeaf(a, b *x509.Certificate) bool {
	if a.IsCA != b.IsCA {
		return !a.IsCA
	}
	aName := len(a.DNSNames) > 0 || len(a.IPAddresses) > 0
	bName := len(b.DNSNames) > 0 || len(b.IPAddresses) > 0
	if aName != bName {
		return aName
	}
	return false
}

func others(certs []*x509.Certificate, leaf *x509.Certificate) []*x509.Certificate {
	leafFP := chainFP(leaf)
	out := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		if chainFP(cert) == "" || chainFP(cert) == leafFP {
			continue
		}
		out = append(out, cert)
	}
	return out
}

func firstHostMatch(host string, certs []*x509.Certificate) *x509.Certificate {
	for _, cert := range certs {
		if chainHostname(cert, host) {
			return cert
		}
	}
	return nil
}

func chainHostname(cert *x509.Certificate, host string) bool {
	if cert == nil || strings.TrimSpace(host) == "" {
		return false
	}
	if cert.VerifyHostname(host) == nil {
		return true
	}
	// Go ignores the legacy CN once a SAN is present. A cert with only a
	// CN still matches that name, which is how a local leaf is found.
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 && len(cert.URIs) == 0 && len(cert.EmailAddresses) == 0 {
		return strings.EqualFold(cert.Subject.CommonName, host)
	}
	return false
}

func readChainFile(path string) ([]*x509.Certificate, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s does not exist", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
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

// readChainCertificates dials u once and returns the leaf-first peer chain.
// timeout applies to the dial context and the TCP dialer. A non-positive
// timeout uses chainRemoteTimeout. The handshake does not treat the server
// as trusted: VerifyConnection records the certificates and then fails.
func readChainCertificates(ctx context.Context, u *url.URL, timeout time.Duration) ([]*x509.Certificate, error) {
	if u == nil {
		return nil, errors.New("remote lookup: missing url")
	}
	if timeout <= 0 {
		timeout = chainRemoteTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	addr, err := connectDialAddr(u)
	if err != nil {
		return nil, fmt.Errorf("remote lookup for %s: %w", u.String(), err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var got []*x509.Certificate
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: u.Hostname(),
			// Skip the default check only so VerifyConnection can record
			// PeerCertificates. The callback always fails the handshake.
			InsecureSkipVerify: true, //nolint:gosec // G402: read-only handshake; VerifyConnection always returns an error
			VerifyConnection: func(cs tls.ConnectionState) error {
				got = append([]*x509.Certificate(nil), cs.PeerCertificates...)
				return errChainPresented
			},
		},
	}
	conn, dialErr := d.DialContext(ctx, "tcp", addr)
	if conn != nil {
		_ = conn.Close()
	}
	if len(got) > 0 {
		return got, nil
	}
	if dialErr != nil {
		return nil, fmt.Errorf("remote lookup for %s: %w", u.String(), dialErr)
	}
	return nil, fmt.Errorf("remote lookup for %s: server presented no certificates", u.String())
}
