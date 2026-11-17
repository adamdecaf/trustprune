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

package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/httputil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

// ConnectFormats is the connect --format list, in help text and errors.
const ConnectFormats = "json, text"

const (
	connectFormatText = "text"
	connectFormatJSON = "json"
	connectDateLayout = "2006-01-02"
)

// ConnectOptions controls output from connect.
// The zero value prints only the one-line summary on success, and only the
// short error on failure.
type ConnectOptions struct {
	// Verbose prints the verified chain after the summary line.
	// When verification fails, it prints the chain the server presented.
	// It has no effect when Format is json.
	Verbose bool
	// Format is "text" (the default) or "json".
	// Empty means text. Matching is case-insensitive.
	Format string
}

// connectNotInStoreMark is appended to a presented-chain subject when that
// certificate's SHA-256 is not in the store selected for the handshake.
const connectNotInStoreMark = " (not in store)"

// errPresentedChainOnly is returned from the read-only handshake so that
// dial never succeeds. Callers use it only to obtain PeerCertificates.
var errPresentedChainOnly = errors.New("presented chain captured for display")

// NormalizeConnectFormat accepts text (the default, including "") and json.
// Matching is case-insensitive. Any other value is an error that lists the
// valid formats. The returned name is lowercase. The error quotes format
// unchanged so the caller can show what was passed.
func NormalizeConnectFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", connectFormatText:
		return connectFormatText, nil
	case connectFormatJSON:
		return connectFormatJSON, nil
	default:
		return "", fmt.Errorf("unknown format %q (formats: %s)", format, ConnectFormats)
	}
}

func ConnectWithPlatformStore(uri *url.URL, opts ConnectOptions) error {
	st := store.Platform()
	certs, err := st.List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return fmt.Errorf("problem getting certs: %w", err)
	}
	return connect(uri, certs, opts, "", "")
}

func ConnectWithAppStore(uri *url.URL, app string, opts ConnectOptions) error {
	return ConnectWithAppStoreFile(uri, app, "", opts)
}

func ConnectWithAppStoreFile(uri *url.URL, app, storePath string, opts ConnectOptions) error {
	st, err := store.ForAppWithStore(app, storePath)
	if err != nil {
		return err
	}
	certs, err := st.List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return fmt.Errorf("problem getting certs for %q: %w", app, err)
	}
	return connect(uri, certs, opts, app, storePath)
}

func connect(uri *url.URL, roots []*x509.Certificate, opts ConnectOptions, app, storePath string) error {
	// Reject a bad format before any dial. The CLI also checks this and
	// turns it into a usage error.
	format, err := NormalizeConnectFormat(opts.Format)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("HEAD", uri.String(), nil)
	if err != nil {
		return fmt.Errorf("unable to make request for %s: %w", uri.String(), err)
	}
	req.Close = true

	pool := x509.NewCertPool()
	for i := range roots {
		pool.AddCert(roots[i])
	}

	client := httputil.New()
	tr, ok := client.Transport.(*http.Transport)
	if ok {
		tr.TLSClientConfig.RootCAs = pool
	}
	client.Transport = tr

	resp, err := client.Do(req)
	if err != nil {
		if connectVerificationFailed(err) {
			if perr := connectPrintPresented(uri, roots, opts, format, err, app, storePath); perr != nil {
				return fmt.Errorf("%s: %w", uri.String(), perr)
			}
		}
		return shortConnectError(uri.String(), err, connectLeaf(err))
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	out, err := formatConnectResult(uri.String(), resp.TLS, opts)
	if err != nil {
		return fmt.Errorf("%s: %w", uri.String(), err)
	}
	fmt.Print(out)
	return nil
}

// presentedChain is the leaf-first certificate list from a read-only handshake.
type presentedChain struct {
	certs   []*x509.Certificate
	version uint16
}

// connectPrintPresented writes the chain the server sent when verification
// failed. Text output requires Verbose. JSON always includes presented_chain
// and ignores Verbose. A dial that is not a verification failure does not
// call this. The chain is taken from handshakeErr when it carries
// UnverifiedCertificates. A read-only probe is used only if that list is
// empty. The probe never decides whether connect succeeded.
func connectPrintPresented(u *url.URL, roots []*x509.Certificate, opts ConnectOptions, format string, handshakeErr error, app, storePath string) error {
	if format != connectFormatJSON && !opts.Verbose {
		return nil
	}
	presented := presentedChainFromError(handshakeErr)
	if len(presented.certs) == 0 {
		presented, _ = readPresentedCertificates(u)
	}
	if format == connectFormatJSON {
		out, err := formatConnectPresentedJSON(u.String(), presented.certs, presented.version, roots)
		if err != nil {
			return err
		}
		fmt.Print(out)
		return nil
	}
	if len(presented.certs) == 0 {
		return nil
	}
	out, err := formatConnectPresentedText(presented.certs, roots, app, storePath)
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

// readPresentedCertificates dials once with InsecureSkipVerify so
// VerifyConnection can read PeerCertificates. VerifyConnection always
// returns an error. That dial is not a successful connect.
func readPresentedCertificates(u *url.URL) (presentedChain, error) {
	addr, err := connectDialAddr(u)
	if err != nil {
		return presentedChain{}, err
	}
	var got presentedChain
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 30 * time.Second},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: u.Hostname(),
			// Skip the default check only so VerifyConnection runs and can
			// record PeerCertificates. The callback always fails the handshake.
			InsecureSkipVerify: true, //nolint:gosec // G402: read-only handshake; VerifyConnection always returns an error
			VerifyConnection: func(cs tls.ConnectionState) error {
				got.certs = append([]*x509.Certificate(nil), cs.PeerCertificates...)
				got.version = cs.Version
				return errPresentedChainOnly
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, dialErr := d.DialContext(ctx, "tcp", addr)
	if conn != nil {
		_ = conn.Close()
	}
	if len(got.certs) == 0 {
		if dialErr != nil {
			return presentedChain{}, dialErr
		}
		return presentedChain{}, errors.New("server presented no certificates")
	}
	return got, nil
}

func connectDialAddr(u *url.URL) (string, error) {
	host := u.Hostname()
	if host == "" {
		return "", errors.New("missing host")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port), nil
}

// connectVerificationFailed reports errors from certificate verification.
// Dial failures, DNS errors, and refused connections are not included.
func connectVerificationFailed(err error) bool {
	var ver *tls.CertificateVerificationError
	if errors.As(err, &ver) {
		return true
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return true
	}
	var host x509.HostnameError
	if errors.As(err, &host) {
		return true
	}
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid)
}

// presentedChainFromError returns the leaf-first peer chain from a
// *tls.CertificateVerificationError. The TLS version is left unset because
// that error does not include it. An empty result means the caller may try
// a read-only probe.
func presentedChainFromError(err error) presentedChain {
	var ver *tls.CertificateVerificationError
	if errors.As(err, &ver) && len(ver.UnverifiedCertificates) > 0 {
		return presentedChain{certs: append([]*x509.Certificate(nil), ver.UnverifiedCertificates...)}
	}
	return presentedChain{}
}

// formatConnectPresentedText prints the presented chain, leaf first, with
// the same columns as the verified chain. A certificate missing from roots
// has connectNotInStoreMark on its subject. When any certificate is missing,
// a hint tells the user to add that CA with add --file. The hint fingerprint
// is the last missing certificate (closest to the root). allowlist only
// keeps or removes certificates already in the store; after the CA is
// installed, its SHA-256 can go under fingerprints in an allowlist file.
func formatConnectPresentedText(chain, roots []*x509.Certificate, app, storePath string) (string, error) {
	if len(chain) == 0 {
		return "", errors.New("no presented certificate chain")
	}
	inStore := connectStoreFingerprints(roots)
	headers := []string{"INDEX", "SUBJECT", "ISSUER", "NOT-AFTER", "SHA256"}
	rows := make([][]string, len(chain))
	var hintFP string
	for i, cert := range chain {
		if cert == nil {
			return "", fmt.Errorf("presented chain certificate %d is nil", i)
		}
		full, err := connectSHA256(cert)
		if err != nil {
			return "", fmt.Errorf("presented chain certificate %d: %w", i, err)
		}
		subject := connectName(cert.Subject)
		if _, ok := inStore[full]; !ok {
			subject += connectNotInStoreMark
			hintFP = full
		}
		rows[i] = []string{
			strconv.Itoa(i),
			subject,
			connectName(cert.Issuer),
			cert.NotAfter.UTC().Format(connectDateLayout),
			full[:16],
		}
	}
	var b strings.Builder
	b.WriteString("presented chain:\n")
	b.WriteString(alignTable(headers, rows))
	if hintFP != "" {
		b.WriteString(connectTrustHint(hintFP, app, storePath))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// connectTrustHint tells the user how to install a CA that was not in the
// selected store. allowlist does not add a missing certificate.
func connectTrustHint(fp, app, storePath string) string {
	return "to add a missing CA, run: " + connectAddHintCmd(app, storePath) + "\nafter it is in the store, include sha256 " + fp + " under fingerprints in an allowlist file so a later allowlist run keeps it"
}

func connectAddHintCmd(app, storePath string) string {
	cmd := "trustprune add --file <cert>"
	app = strings.TrimSpace(app)
	if app != "" {
		cmd += " --app " + app
	}
	storePath = strings.TrimSpace(storePath)
	if storePath != "" {
		cmd += " --store " + connectShellQuote(storePath)
	}
	return cmd
}

// connectShellQuote quotes s for POSIX shells so a copied hint does not
// expand variables or run metacharacters.
func connectShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// connectFailJSON is the document written by connect --format json when
// verification fails. Success output does not use this type.
type connectFailJSON struct {
	URL            string                 `json:"url"`
	TLSVersion     string                 `json:"tls_version,omitempty"`
	Verified       bool                   `json:"verified"`
	PresentedChain []connectPresentedCert `json:"presented_chain"`
}

// connectPresentedCert is one certificate the server sent, leaf first.
// Fields match the verified chain entries, plus in_store.
type connectPresentedCert struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	SHA256   string `json:"sha256"`
	InStore  bool   `json:"in_store"`
}

// formatConnectPresentedJSON formats a verification failure. verified is
// false. presented_chain is leaf-first and may be empty when the server
// certificates could not be read. sha256 is the full fingerprint. in_store
// is false when the certificate is not in the selected store. The result
// ends with a newline. Verbose is not an input.
func formatConnectPresentedJSON(rawURL string, chain []*x509.Certificate, version uint16, roots []*x509.Certificate) (string, error) {
	inStore := connectStoreFingerprints(roots)
	entries := make([]connectPresentedCert, len(chain))
	for i, cert := range chain {
		if cert == nil {
			return "", fmt.Errorf("presented chain certificate %d is nil", i)
		}
		sum, err := connectSHA256(cert)
		if err != nil {
			return "", fmt.Errorf("presented chain certificate %d: %w", i, err)
		}
		_, ok := inStore[sum]
		entries[i] = connectPresentedCert{
			Subject:  connectName(cert.Subject),
			Issuer:   connectName(cert.Issuer),
			NotAfter: cert.NotAfter.UTC().Format(connectDateLayout),
			SHA256:   sum,
			InStore:  ok,
		}
	}
	doc := connectFailJSON{
		URL:            rawURL,
		Verified:       false,
		PresentedChain: entries,
	}
	if ver, err := connectTLSVersion(version); err == nil {
		doc.TLSVersion = ver
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// connectStoreFingerprints is the set of full SHA-256 fingerprints in the
// store selected for the handshake.
func connectStoreFingerprints(roots []*x509.Certificate) map[string]struct{} {
	set := make(map[string]struct{}, len(roots))
	for _, cert := range roots {
		fp, err := connectSHA256(cert)
		if err != nil {
			continue
		}
		set[fp] = struct{}{}
	}
	return set
}

// formatConnectResult renders a successful handshake.
// JSON ignores Verbose. Text is the one-line summary and, when Verbose,
// the chain table after it. The result ends with a newline.
func formatConnectResult(rawURL string, state *tls.ConnectionState, opts ConnectOptions) (string, error) {
	format, err := NormalizeConnectFormat(opts.Format)
	if err != nil {
		return "", err
	}
	if format == connectFormatJSON {
		return formatConnectJSON(rawURL, state)
	}
	summary, err := formatConnectOK(rawURL, state)
	if err != nil {
		return "", err
	}
	if !opts.Verbose {
		return summary + "\n", nil
	}
	chain, err := connectVerifiedChain(state)
	if err != nil {
		return "", err
	}
	table, err := formatConnectChainTable(chain)
	if err != nil {
		return "", err
	}
	return summary + "\n" + table, nil
}

// connectJSON is the document written by connect --format json.
type connectJSON struct {
	URL        string             `json:"url"`
	TLSVersion string             `json:"tls_version"`
	Verified   bool               `json:"verified"`
	Root       connectJSONRoot    `json:"root"`
	Leaf       connectJSONLeaf    `json:"leaf"`
	Chain      []connectJSONChain `json:"chain"`
}

type connectJSONRoot struct {
	Subject string `json:"subject"`
	SHA256  string `json:"sha256"`
}

type connectJSONLeaf struct {
	Subject  string `json:"subject"`
	NotAfter string `json:"not_after"`
}

type connectJSONChain struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	SHA256   string `json:"sha256"`
}

// formatConnectJSON formats a successful connect as one JSON object.
// Verified is always true: a missing chain is an error, not verified:false.
// sha256 is the full hex SHA-256. not_after is the UTC date (YYYY-MM-DD),
// the same day the text summary prints. chain is leaf-first and includes
// the trust anchor. The result ends with a newline.
// Verbose is not an input; JSON does not change when -v is set.
func formatConnectJSON(rawURL string, state *tls.ConnectionState) (string, error) {
	chain, err := connectVerifiedChain(state)
	if err != nil {
		return "", err
	}
	ver, err := connectTLSVersion(state.Version)
	if err != nil {
		return "", err
	}
	entries := make([]connectJSONChain, len(chain))
	for i, cert := range chain {
		if cert == nil {
			return "", fmt.Errorf("verified chain certificate %d is nil", i)
		}
		sum, err := connectSHA256(cert)
		if err != nil {
			return "", fmt.Errorf("verified chain certificate %d: %w", i, err)
		}
		entries[i] = connectJSONChain{
			Subject:  connectName(cert.Subject),
			Issuer:   connectName(cert.Issuer),
			NotAfter: cert.NotAfter.UTC().Format(connectDateLayout),
			SHA256:   sum,
		}
	}
	leaf := entries[0]
	root := entries[len(entries)-1]
	doc := connectJSON{
		URL:        rawURL,
		TLSVersion: ver,
		Verified:   true,
		Root: connectJSONRoot{
			Subject: root.Subject,
			SHA256:  root.SHA256,
		},
		Leaf: connectJSONLeaf{
			Subject:  leaf.Subject,
			NotAfter: leaf.NotAfter,
		},
		Chain: entries,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// formatConnectOK formats the one-line success summary from resp.TLS.
// VerifiedChains[0] is leaf-first and ends at the trust anchor.
// The line has no trailing newline:
//
//	ok <url> tls1.2|tls1.3 root=<CN or subject> sha256=<16 hex> leaf-expires=<YYYY-MM-DD>
func formatConnectOK(rawURL string, state *tls.ConnectionState) (string, error) {
	chain, err := connectVerifiedChain(state)
	if err != nil {
		return "", err
	}
	ver, err := connectTLSVersion(state.Version)
	if err != nil {
		return "", err
	}
	leaf := chain[0]
	root := chain[len(chain)-1]
	if leaf == nil || root == nil {
		return "", errors.New("verified chain certificate is nil")
	}
	sum, err := connectSHA256Prefix(root)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok %s %s root=%s sha256=%s leaf-expires=%s",
		rawURL,
		ver,
		connectName(root.Subject),
		sum,
		leaf.NotAfter.UTC().Format(connectDateLayout),
	), nil
}

// formatConnectChainTable formats the verified chain, leaf first, as an
// aligned table. Columns are index, subject, issuer, not-after, and the
// first 16 hex characters of each certificate's SHA-256. The result ends
// with a newline.
func formatConnectChainTable(chain []*x509.Certificate) (string, error) {
	if len(chain) == 0 {
		return "", errors.New("no verified certificate chain")
	}
	headers := []string{"INDEX", "SUBJECT", "ISSUER", "NOT-AFTER", "SHA256"}
	rows := make([][]string, len(chain))
	for i, cert := range chain {
		if cert == nil {
			return "", fmt.Errorf("verified chain certificate %d is nil", i)
		}
		sum, err := connectSHA256Prefix(cert)
		if err != nil {
			return "", fmt.Errorf("verified chain certificate %d: %w", i, err)
		}
		rows[i] = []string{
			strconv.Itoa(i),
			connectName(cert.Subject),
			connectName(cert.Issuer),
			cert.NotAfter.UTC().Format(connectDateLayout),
			sum,
		}
	}
	return alignTable(headers, rows), nil
}

func connectVerifiedChain(state *tls.ConnectionState) ([]*x509.Certificate, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return nil, errors.New("no verified certificate chain")
	}
	return state.VerifiedChains[0], nil
}

func connectTLSVersion(v uint16) (string, error) {
	switch v {
	case tls.VersionTLS12:
		return "tls1.2", nil
	case tls.VersionTLS13:
		return "tls1.3", nil
	default:
		return "", fmt.Errorf("unsupported TLS version 0x%04x", v)
	}
}

// connectName returns the common name, or the subject string when CN is empty.
func connectName(n pkix.Name) string {
	if n.CommonName != "" {
		return n.CommonName
	}
	return n.String()
}

// connectSHA256 is the full hex SHA-256 of the certificate.
func connectSHA256(c *x509.Certificate) (string, error) {
	if c == nil || len(c.Raw) == 0 {
		return "", errors.New("certificate is missing raw bytes")
	}
	return certutil.GetHexSHA256Fingerprint(*c), nil
}

// connectSHA256Prefix is the first 16 hex characters of the certificate SHA-256.
func connectSHA256Prefix(c *x509.Certificate) (string, error) {
	fp, err := connectSHA256(c)
	if err != nil {
		return "", err
	}
	return fp[:16], nil
}

// alignTable left-aligns cells and separates columns with two spaces.
// Each row, including the last, ends with a newline. No trailing spaces.
func alignTable(headers []string, rows [][]string) string {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		for i, cell := range row {
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
			if i == len(cells)-1 {
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

// NormalizeConnectURL parses a connect target. A value with no leading
// scheme is treated as https (host, host:port, or [::1]:port). A "://"
// later in the string, for example in a query, does not count as a
// scheme. Explicit http keeps the historical non-secure scheme error.
// Any other non-https scheme is rejected.
func NormalizeConnectURL(raw string) (*url.URL, error) {
	if i := strings.Index(raw, "://"); i <= 0 || strings.ContainsAny(raw[:i], "/?#") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		return nil, fmt.Errorf("non-secure url scheme used: %s", u.String())
	default:
		return nil, fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
}

// shortConnectError turns a connect failure into a single short line.
// leaf is a fallback for the failing certificate's dates when the
// x509 error does not carry one.
func shortConnectError(u string, err error, leaf *x509.Certificate) error {
	if err == nil {
		return nil
	}

	// x509 failures from the TLS handshake are wrapped in
	// tls.CertificateVerificationError. Unwrap before errors.As so the
	// fallback text is the inner error, and so a missing leaf can come
	// from the unverified chain.
	var ver *tls.CertificateVerificationError
	if errors.As(err, &ver) {
		if leaf == nil && len(ver.UnverifiedCertificates) > 0 {
			leaf = ver.UnverifiedCertificates[0]
		}
		if ver.Err != nil {
			err = ver.Err
		}
	}

	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		when := invalid.Cert
		if when == nil {
			when = leaf
		}
		if when != nil && time.Now().Before(when.NotBefore) {
			return fmt.Errorf("%s: certificate not yet valid until %s", u, when.NotBefore.UTC().Format("2006-01-02"))
		}
		if when != nil {
			return fmt.Errorf("%s: certificate expired %s", u, when.NotAfter.UTC().Format("2006-01-02"))
		}
		return fmt.Errorf("%s: certificate expired", u)
	}

	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return fmt.Errorf("%s: unknown authority", u)
	}

	var host x509.HostnameError
	if errors.As(err, &host) {
		return fmt.Errorf("%s: hostname mismatch", u)
	}

	// String form is intentional: the short line replaces the wrapped chain.
	return errors.New(u + ": " + err.Error())
}

func connectLeaf(err error) *x509.Certificate {
	var ver *tls.CertificateVerificationError
	if errors.As(err, &ver) && len(ver.UnverifiedCertificates) > 0 {
		return ver.UnverifiedCertificates[0]
	}
	return nil
}
