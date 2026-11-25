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
	"encoding/json"
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

// ChainFormats is the chain --format list, in help text and errors.
const ChainFormats = "json, text"

const (
	chainFormatText = "text"
	chainFormatJSON = "json"
)

// ChainOptions selects the store and which certificates may appear in a chain.
// The zero value reads the platform store, hides expired, not-yet-valid,
// and blocklisted certificates, and does not dial the network.
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
	// Expired includes certificates outside their validity window:
	// NotAfter before Now, or NotBefore after Now. A future NotBefore
	// is labeled "not yet valid". A past NotAfter is labeled "expired".
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
	// Format is "text" (the default) or "json".
	// Empty means text. Matching is case-insensitive.
	Format string
	// Verbose prints the full 64-character SHA-256 in the text table.
	// The default table uses a 16-character prefix. JSON always uses
	// the full fingerprint.
	Verbose bool
	// Now is the time used for expiry. The zero value is time.Now.
	Now time.Time
	// Fetch overrides the TLS dial. Tests set it. Nil uses the default
	// dial with chainRemoteTimeout.
	Fetch func(*url.URL) ([]*x509.Certificate, error)
}

// NormalizeChainFormat accepts text (the default, including "") and json.
// Matching is case-insensitive. Any other value is an error that lists the
// valid formats. The returned name is lowercase. The error quotes format
// unchanged so the caller can show what was passed.
func NormalizeChainFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", chainFormatText:
		return chainFormatText, nil
	case chainFormatJSON:
		return chainFormatJSON, nil
	default:
		return "", fmt.Errorf("unknown format %q (formats: %s)", format, ChainFormats)
	}
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
	issuer   string
	notAfter string
	sha      string
	sha256   string
	name     string
	labels   []string
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

// chainNote is the walk result besides the rows. incomplete is the note
// the text table prints; it is empty when the chain is complete. JSON does
// not include that string.
// missingIssuer is the issuer display name of the last included certificate
// when the walk stopped because no issuer was found. It matches that
// certificate's issuer column (connectName of the Issuer). Cycle and
// too-long walks leave it empty.
// stoppedAt is the display name of the last included certificate when the
// chain is incomplete. It is empty when the chain is complete.
type chainNote struct {
	incomplete    string
	missingIssuer string
	stoppedAt     string
}

// incompleteChain is the chain command's incomplete-walk status.
// The report is already written. An empty message keeps finishRun from
// adding an ERROR: line. Exit code 1 matches other failures; an incomplete
// chain is told apart from a read error by the absence of ERROR:.
type incompleteChain struct{}

func (incompleteChain) Error() string { return "" }
func (incompleteChain) ExitCode() int { return 1 }

func isIncompleteChain(err error) bool {
	var ic incompleteChain
	return errors.As(err, &ic)
}

// ShowChain writes the certificate chain for opts to w.
// The store is only listed. Nothing is added, removed, or backed up.
// A nil writer uses os.Stdout.
//
// The default chain uses trusted, in-date certificates that are not on
// the offline Chromium or Mozilla blocklists. The leaf is shown when it
// passes the validity and blocklist checks, even if it is not in the store.
// With no labels, the table matches connect's verified chain table.
// Format json prints one object; text (the default) is unchanged.
// An incomplete chain is written first. ShowChain then returns
// incompleteChain: exit code 1 and an empty error string.
func ShowChain(w io.Writer, opts ChainOptions) error {
	if w == nil {
		w = os.Stdout
	}
	format, err := NormalizeChainFormat(opts.Format)
	if err != nil {
		return err
	}
	opts.Format = format
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
	out, note, err := renderChain(chainInput{
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
	if note.incomplete != "" {
		return incompleteChain{}
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
		return nil, nil, fmt.Errorf("no local chain for %s; pass --remote to look up the TLS chain", chainLookupURL(opts.URL))
	}
	presented, err := fetchPresented(opts)
	if err != nil {
		return nil, nil, err
	}
	if len(presented) == 0 || presented[0] == nil {
		return nil, nil, fmt.Errorf("remote lookup for %s: server presented no certificates", chainLookupURL(opts.URL))
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

// chainLookupURL is the host shown for a remote lookup. It is
// scheme://host[:port]. Userinfo, path, query, and fragment are omitted
// so a password or token passed in --url is not printed.
func chainLookupURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := u.Hostname()
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	return scheme + "://" + host
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
	out, _, err := renderChain(in)
	return out, err
}

func renderChain(in chainInput) (string, chainNote, error) {
	format, err := NormalizeChainFormat(in.opts.Format)
	if err != nil {
		return "", chainNote{}, err
	}
	in.opts = applyChainIncludes(in.opts)
	if in.leaf == nil {
		return "", chainNote{}, errors.New("no certificate")
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
		return "", chainNote{}, err
	}
	trusted := chainTrustedSet(in.trusted)
	pool := chainPool([]*x509.Certificate{in.leaf}, in.trusted, in.untrusted, in.extras)
	rows, note, err := walkChain(in.leaf, pool, trusted, in.opts, now, blocked)
	if err != nil {
		return "", chainNote{}, err
	}
	if format == chainFormatJSON {
		text, err := formatChainJSON(rows, note)
		if err != nil {
			return "", chainNote{}, err
		}
		return text, note, nil
	}
	return formatChain(rows, note.incomplete, in.opts.Verbose), note, nil
}

func rejectLeaf(leaf *x509.Certificate, opts ChainOptions, now time.Time, blocked func(*x509.Certificate) bool) error {
	var why []string
	var flags []string
	if chainExpired(leaf, now) && !opts.Expired {
		why = append(why, chainValidityReason(leaf, now))
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

func walkChain(leaf *x509.Certificate, pool []*x509.Certificate, trusted map[string]struct{}, opts ChainOptions, now time.Time, blocked func(*x509.Certificate) bool) ([]chainRow, chainNote, error) {
	var rows []chainRow
	seen := map[string]struct{}{}
	current := leaf
	for {
		fp := chainFP(current)
		if _, ok := seen[fp]; ok {
			return rows, chainNote{
				incomplete: "incomplete: cycle at " + chainDisplayName(current),
				stoppedAt:  lastIncludedName(rows),
			}, nil
		}
		if len(rows) >= chainMaxCerts {
			return rows, chainNote{
				incomplete: fmt.Sprintf("incomplete: chain is longer than %d certificates", chainMaxCerts),
				stoppedAt:  lastIncludedName(rows),
			}, nil
		}
		seen[fp] = struct{}{}
		row, err := makeChainRow(current, len(rows) == 0, trusted, now, blocked)
		if err != nil {
			return nil, chainNote{}, err
		}
		rows = append(rows, row)
		if chainSelfSigned(current) {
			return rows, chainNote{}, nil
		}
		next, skip, ok := pickIssuer(current, pool, trusted, opts, now, blocked)
		if !ok {
			return rows, incompleteNote(current, skip), nil
		}
		current = next
	}
}

func makeChainRow(cert *x509.Certificate, isLeaf bool, trusted map[string]struct{}, now time.Time, blocked func(*x509.Certificate) bool) (chainRow, error) {
	sum, err := connectSHA256(cert)
	if err != nil {
		return chainRow{}, err
	}
	inStore := chainInStore(cert, trusted)
	validity := chainValidityTag(cert, now)
	isBlocked := chainIsBlocked(blocked, cert)
	name := chainDisplayName(cert)
	labels := chainLabels(isLeaf, inStore, validity, isBlocked)
	return chainRow{
		issuer:   connectName(cert.Issuer),
		notAfter: cert.NotAfter.UTC().Format(connectDateLayout),
		sha:      sum[:16],
		sha256:   sum,
		name:     name,
		labels:   labels,
	}, nil
}

func chainLabels(isLeaf, inStore bool, validity string, blocked bool) []string {
	tags := make([]string, 0, 3)
	// The leaf is the certificate the user asked about. It is shown even
	// when it is not in the store, and that is not labeled untrusted.
	if !isLeaf && !inStore {
		tags = append(tags, "untrusted")
	}
	if validity != "" {
		tags = append(tags, validity)
	}
	if blocked {
		tags = append(tags, "blocklisted")
	}
	return tags
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

func incompleteNote(current *x509.Certificate, skip skipReason) chainNote {
	name := chainDisplayName(current)
	note := "incomplete: no issuer for " + name
	if hint := skip.hint(); hint != "" {
		note += "; " + hint
	}
	issuer := ""
	if current != nil {
		issuer = connectName(current.Issuer)
	}
	return chainNote{incomplete: note, missingIssuer: issuer, stoppedAt: name}
}

func lastIncludedName(rows []chainRow) string {
	if len(rows) == 0 {
		return ""
	}
	return rows[len(rows)-1].name
}

func formatChain(rows []chainRow, note string, verbose bool) string {
	headers := statusTableHeaders()
	body := make([][]string, len(rows))
	for i, row := range rows {
		sha := row.sha
		if verbose {
			sha = row.sha256
		}
		body[i] = []string{strconv.Itoa(i), row.name, row.issuer, row.notAfter, sha, formatLabelsCell(row.labels)}
	}
	out := alignTable(headers, body)
	if note != "" {
		out += note + "\n"
	}
	return out
}

// chainJSON is the document written by chain --format json.
// complete is always present. missing_issuer and stopped_at are omitted
// when empty. The text note is not a field.
type chainJSON struct {
	Chain         []chainJSONCert `json:"chain"`
	Complete      bool            `json:"complete"`
	MissingIssuer string          `json:"missing_issuer,omitempty"`
	StoppedAt     string          `json:"stopped_at,omitempty"`
}

// chainJSONCert is one certificate in the chain, leaf first.
// subject is the display name. sha256 is the full hex fingerprint.
// labels is never null.
type chainJSONCert struct {
	Index    int      `json:"index"`
	Subject  string   `json:"subject"`
	Issuer   string   `json:"issuer"`
	NotAfter string   `json:"not_after"`
	SHA256   string   `json:"sha256"`
	Labels   []string `json:"labels"`
}

// formatChainJSON formats the chain as one JSON object.
// chain is leaf-first. labels is an empty array when none apply.
// complete is always present. missing_issuer is the issuer name of the
// last certificate when the walk stopped because no issuer was found.
// Cycle and too-long walks omit it. stopped_at is the display name of
// the last certificate included. It is set whenever complete is false
// and omitted when the chain is complete. The human hint is not included.
// sha256 is the full hex fingerprint. not_after is the UTC date
// (YYYY-MM-DD). The result ends with a newline.
func formatChainJSON(rows []chainRow, note chainNote) (string, error) {
	entries := make([]chainJSONCert, len(rows))
	for i, row := range rows {
		labels := row.labels
		if labels == nil {
			labels = []string{}
		}
		entries[i] = chainJSONCert{
			Index:    i,
			Subject:  row.name,
			Issuer:   row.issuer,
			NotAfter: row.notAfter,
			SHA256:   row.sha256,
			Labels:   labels,
		}
	}
	doc := chainJSON{
		Chain:         entries,
		Complete:      note.incomplete == "",
		MissingIssuer: note.missingIssuer,
		StoppedAt:     note.stoppedAt,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	return buf.String(), nil
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

// chainSelfSigned reports whether cert was signed with its own key.
// CheckSignatureFrom rejects a non-CA, so a self-signed leaf would look
// like a missing issuer. Compare the raw names, then verify the signature
// directly. Links between two certificates still use CheckSignatureFrom.
func chainSelfSigned(cert *x509.Certificate) bool {
	if cert == nil || len(cert.Raw) == 0 {
		return false
	}
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// chainExpired reports whether cert is outside its validity window.
// NotBefore in the future is treated the same as NotAfter in the past:
// the certificate is left out unless --expired is set.
func chainExpired(cert *x509.Certificate, now time.Time) bool {
	return chainValidityTag(cert, now) != ""
}

// chainValidityTag is the row label for a certificate outside its
// validity window. An in-window certificate returns an empty string.
// NotBefore equal to now, and NotAfter equal to now, are in window.
func chainValidityTag(cert *x509.Certificate, now time.Time) string {
	if cert == nil {
		return ""
	}
	if now.Before(cert.NotBefore) {
		return "not yet valid"
	}
	if now.After(cert.NotAfter) {
		return "expired"
	}
	return ""
}

// chainValidityReason is the leaf error detail for chainExpired.
// cert is non-nil: rejectLeaf only calls this after chainExpired.
func chainValidityReason(cert *x509.Certificate, now time.Time) string {
	if now.Before(cert.NotBefore) {
		return "not yet valid until " + cert.NotBefore.UTC().Format(connectDateLayout)
	}
	return "expired " + cert.NotAfter.UTC().Format(connectDateLayout)
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

// readChainFile reads path as a PEM bundle or one DER certificate.
func readChainFile(path string) ([]*x509.Certificate, error) {
	return readCertificates(path)
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
		return nil, fmt.Errorf("remote lookup for %s: %w", chainLookupURL(u), err)
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
		return nil, fmt.Errorf("remote lookup for %s: %w", chainLookupURL(u), dialErr)
	}
	return nil, fmt.Errorf("remote lookup for %s: server presented no certificates", chainLookupURL(u))
}
