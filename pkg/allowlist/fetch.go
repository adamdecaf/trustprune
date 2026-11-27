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

package allowlist

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/httputil"
)

// DefaultMaxBytes is the maximum allowlist body accepted from an https URL.
const DefaultMaxBytes int64 = 1 << 20

// fetchTimeout matches httputil.Client. A caller-supplied client with a
// positive Timeout keeps that deadline.
const fetchTimeout = 30 * time.Second

// maxRedirects is the number of requests already sent before another
// redirect is refused. It counts the same way as net/http's default of 10.
const maxRedirects = 5

// HTTPClient, when non-nil, fetches allowlist URLs if FetchOptions.Client
// is nil. A nil HTTPClient uses httputil.New. Tests set this to an
// httptest server's Client.
var HTTPClient *http.Client

// FetchOptions controls FromPathOrURL.
// A nil Client uses HTTPClient, then httputil.New.
// MaxSize is the URL body cap in bytes. Zero uses DefaultMaxBytes.
// The cap applies to https responses, not to local allowlist files.
// SHA256 is an optional hex SHA-256 of the file bytes. Empty skips the check.
// Signature is an optional detached minisign signature, as a local path or
// an https URL. PubKey is the matching minisign public key: a local file
// or the key itself (the base64 line or a full minisign .pub file).
// A public key is never fetched from a URL. Signature and PubKey must
// both be set or both be empty. The signature is checked against the
// allowlist bytes before they are parsed. Signature downloads use the
// same https rules, timeout, redaction, and size cap as the allowlist.
type FetchOptions struct {
	Client    *http.Client
	MaxSize   int64
	SHA256    string
	Signature string
	PubKey    string
}

// FromPathOrURL loads ref and parses it with FromBytes.
// A value url.Parse treats as having a scheme is a URL: https is fetched,
// and any other scheme is refused. A one-letter scheme is a Windows volume
// path (C:\file or C:/file), which stays a local file. A value with no
// scheme is a local file, read the same way as FromFile.
// A value that looks like a URL (a scheme followed by "://") but fails
// url.Parse is rejected without putting the raw value or the parse
// error in the message.
// When SHA256 is set, the bytes are checked before they are parsed.
// When Signature and PubKey are set, the minisign signature is verified
// against those same bytes before they are parsed.
func FromPathOrURL(ref string, opts FetchOptions) (Allowlist, error) {
	if err := validateFetchOptions(opts); err != nil {
		return Allowlist{}, err
	}
	pin := strings.TrimSpace(opts.SHA256)
	remote, err := refIsURL(ref)
	if err != nil {
		return Allowlist{}, err
	}
	var body []byte
	if remote {
		body, err = fetchURL(ref, "allowlist", opts)
	} else {
		body, err = os.ReadFile(ref)
	}
	if err != nil {
		return Allowlist{}, err
	}
	if err := matchSHA256(ref, body, pin); err != nil {
		return Allowlist{}, err
	}
	if err := verifyAllowlistSignature(body, opts); err != nil {
		return Allowlist{}, err
	}
	al, err := FromBytes(body)
	if err != nil && remote {
		return Allowlist{}, fmt.Errorf("allowlist %s: %w", diagnosticRef(ref), err)
	}
	return al, err
}

func validateFetchOptions(opts FetchOptions) error {
	pin := strings.TrimSpace(opts.SHA256)
	if pin != "" {
		if err := ValidateSHA256Pin(pin); err != nil {
			return err
		}
	}
	sig := strings.TrimSpace(opts.Signature)
	pub := strings.TrimSpace(opts.PubKey)
	if sig == "" && pub == "" {
		return nil
	}
	if sig == "" {
		return errors.New("allowlist public key is set, but no signature was provided")
	}
	if pub == "" {
		return errors.New("allowlist signature is set, but no public key was provided")
	}
	if err := ValidateSignatureRef(sig); err != nil {
		return err
	}
	return ValidatePubKeyRef(pub)
}

// ValidateSignatureRef reports whether ref is a local path or an https URL
// for a detached minisign signature. An empty ref is not an error.
func ValidateSignatureRef(ref string) error {
	_, err := refKindIsURL(ref, "signature")
	return err
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ValidatePubKeyRef reports whether ref is a local minisign public key
// file or a minisign public key. A URL is refused. An empty ref is not
// an error.
func ValidatePubKeyRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	if looksLikeURL(ref) {
		return errMinisignPubKeyURL
	}
	u, err := url.Parse(ref)
	if err != nil {
		return nil
	}
	if u.Scheme != "" && (len(u.Scheme) != 1 || !isDriveLetter(u.Scheme[0])) {
		return errMinisignPubKeyURL
	}
	return nil
}

func verifyAllowlistSignature(body []byte, opts FetchOptions) error {
	sigRef := strings.TrimSpace(opts.Signature)
	pubRef := strings.TrimSpace(opts.PubKey)
	if sigRef == "" && pubRef == "" {
		return nil
	}
	pkData, err := readPubKey(pubRef, opts)
	if err != nil {
		return err
	}
	pk, err := parseMinisignPublicKey(pkData)
	if err != nil {
		return err
	}
	sigData, err := readSignature(sigRef, opts)
	if err != nil {
		return err
	}
	sig, err := parseMinisignSignature(sigData)
	if err != nil {
		return err
	}
	if err := verifyMinisign(body, sig, pk); err != nil {
		return fmt.Errorf("%w for %s", err, diagnosticRef(sigRef))
	}
	return nil
}

func readPubKey(ref string, opts FetchOptions) ([]byte, error) {
	if looksLikeURL(ref) {
		return nil, errMinisignPubKeyURL
	}
	// A full minisign .pub file pasted on the command line has a comment
	// line and a base64 line. The base64 often contains '/', so this is
	// not treated as a path.
	trimmed := strings.TrimSpace(ref)
	if strings.Contains(ref, "\n") || strings.HasPrefix(trimmed, minisignCommentPrefix) {
		return []byte(ref), nil
	}
	if st, err := os.Stat(ref); err == nil && !st.IsDir() {
		return readLocalLimited(ref, "public key", maxBytes(opts))
	}
	if looksLikePubKeyPath(ref) {
		return readLocalLimited(ref, "public key", maxBytes(opts))
	}
	// Literal minisign key (the base64 line).
	return []byte(ref), nil
}

func looksLikePubKeyPath(ref string) bool {
	if strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") {
		return true
	}
	if strings.HasPrefix(ref, `.\`) || strings.HasPrefix(ref, `..\`) {
		return true
	}
	if len(ref) >= 3 && ref[1] == ':' && (ref[2] == '\\' || ref[2] == '/') {
		return true
	}
	return strings.HasSuffix(strings.ToLower(ref), ".pub") && !strings.ContainsAny(ref, " \t")
}

func readSignature(ref string, opts FetchOptions) ([]byte, error) {
	remote, err := refKindIsURL(ref, "signature")
	if err != nil {
		return nil, err
	}
	if remote {
		return fetchURL(ref, "signature", opts)
	}
	return readLocalLimited(ref, "signature", maxBytes(opts))
}

func maxBytes(opts FetchOptions) int64 {
	if opts.MaxSize > 0 {
		return opts.MaxSize
	}
	return DefaultMaxBytes
}

func readLocalLimited(path, kind string, max int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- caller-selected allowlist signature or public key path
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", kind, path, err)
	}
	defer func() { _ = f.Close() }()
	body, err := readLimited(f, max)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return nil, fmt.Errorf("%s %s exceeds %d byte limit", kind, path, max)
		}
		return nil, fmt.Errorf("%s %s: %w", kind, path, err)
	}
	return body, nil
}

// ValidateRef reports whether ref is a local path or an https URL.
// An empty ref is not an error. A non-https scheme is an error.
// A URL-looking value that fails to parse is an error whose message
// does not include the raw value.
func ValidateRef(ref string) error {
	_, err := refIsURL(ref)
	return err
}

// ValidateSHA256Pin reports whether pin is 64 hex digits. Matching is
// case-insensitive. Empty is not a pin.
func ValidateSHA256Pin(pin string) error {
	pin = strings.TrimSpace(pin)
	if !sha256Hex(pin) {
		return fmt.Errorf("invalid allowlist SHA-256: want 64 hex digits")
	}
	return nil
}

// errInvalidAllowlistURL is returned when ref looks like a URL but
// url.Parse fails. The message must not include the raw value or the
// parse error, which can contain userinfo.
var errInvalidAllowlistURL = errors.New("invalid allowlist URL: the address could not be parsed")

func looksLikeURL(ref string) bool {
	i := strings.Index(ref, "://")
	if i < 1 {
		return false
	}
	scheme := ref[:i]
	for j := 0; j < len(scheme); j++ {
		c := scheme[j]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case j > 0 && ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

func refIsURL(ref string) (bool, error) {
	return refKindIsURL(ref, "allowlist")
}

func refKindIsURL(ref, kind string) (bool, error) {
	u, err := url.Parse(ref)
	if err != nil {
		if looksLikeURL(ref) {
			if kind == "signature" {
				return false, errInvalidSignatureURL
			}
			return false, errInvalidAllowlistURL
		}
		return false, nil
	}
	if u.Scheme == "" {
		return false, nil
	}
	if u.Scheme == "https" {
		return true, nil
	}
	// url.Parse lowercases the scheme and reports "c" for C:\path and C:/path.
	if len(u.Scheme) == 1 && u.Scheme[0] >= 'a' && u.Scheme[0] <= 'z' {
		return false, nil
	}
	return false, fmt.Errorf("%s URLs must be https, not %q", kind, u.Scheme)
}

func sha256Hex(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func matchSHA256(ref string, body []byte, pin string) error {
	if pin == "" {
		return nil
	}
	sum := sha256.Sum256(body)
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != len(sum) {
		return fmt.Errorf("invalid allowlist SHA-256: want 64 hex digits")
	}
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return fmt.Errorf("allowlist SHA-256 mismatch for %s: got %x", diagnosticRef(ref), sum[:])
	}
	return nil
}

// diagnosticRef is ref for error text. Userinfo passwords are masked
// with url.URL.Redacted. The original ref is still used to fetch.
func diagnosticRef(ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		if looksLikeURL(ref) {
			return "invalid allowlist URL"
		}
		return ref
	}
	if u.Scheme == "" {
		return ref
	}
	return u.Redacted()
}

var errBodyTooLarge = errors.New("allowlist body exceeds size limit")

func fetchURL(ref, kind string, opts FetchOptions) (body []byte, err error) {
	client := allowlistClient(opts.Client)
	req, err := http.NewRequest(http.MethodGet, ref, nil)
	if err != nil {
		return nil, fmt.Errorf("%s %s: invalid request", kind, diagnosticRef(ref))
	}
	req.Close = true

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer func() {
			cerr := resp.Body.Close()
			if err == nil && cerr != nil {
				err = sanitizeFetchErrorKind(kind, ref, cerr)
			}
		}()
	}
	if err != nil {
		return nil, sanitizeFetchErrorKind(kind, ref, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: response status %s", kind, diagnosticRef(ref), resp.Status)
	}
	max := maxBytes(opts)
	if resp.ContentLength > max {
		return nil, fmt.Errorf("%s %s exceeds %d byte limit (Content-Length %d)", kind, diagnosticRef(ref), max, resp.ContentLength)
	}
	body, err = readLimited(resp.Body, max)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return nil, fmt.Errorf("%s %s exceeds %d byte limit", kind, diagnosticRef(ref), max)
		}
		return nil, sanitizeFetchErrorKind(kind, ref, err)
	}
	return body, nil
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, errBodyTooLarge
	}
	return body, nil
}

func allowlistClient(base *http.Client) *http.Client {
	if base == nil {
		base = HTTPClient
	}
	if base == nil {
		base = httputil.New()
	}
	clone := *base
	clone.CheckRedirect = allowlistRedirect
	if clone.Timeout <= 0 {
		clone.Timeout = fetchTimeout
	}
	return &clone
}

var (
	errRedirectNotHTTPS = errors.New("redirect to non-https")
	errTooManyRedirects = errors.New("too many redirects")
)

func allowlistRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errTooManyRedirects
	}
	scheme := ""
	if req != nil && req.URL != nil {
		scheme = req.URL.Scheme
	}
	if scheme != "https" {
		return errRedirectNotHTTPS
	}
	return nil
}

// fetchTimeoutError is a fetch failure caused by a deadline. Error reports
// only the redacted request URL and "timeout". The original error is
// available to errors.Is and errors.As.
type fetchTimeoutError struct {
	msg string
	err error
}

func (e *fetchTimeoutError) Error() string { return e.msg }
func (e *fetchTimeoutError) Unwrap() error { return e.err }
func (e *fetchTimeoutError) Timeout() bool { return true }

// sanitizeFetchErrorKind turns a net/http client or I/O error into a
// message that uses the redacted original request URL and a safe
// description. The raw *url.Error, Location header, and client error
// text are never included in the returned Error string.
func sanitizeFetchErrorKind(kind, ref string, err error) error {
	if err == nil {
		return nil
	}
	var te *fetchTimeoutError
	if errors.As(err, &te) {
		return err
	}
	msg := fmt.Sprintf("%s %s: %s", kind, diagnosticRef(ref), fetchErrorDescription(err))
	if isTimeout(err) {
		return &fetchTimeoutError{msg: msg, err: err}
	}
	return errors.New(msg)
}

func fetchErrorDescription(err error) string {
	switch {
	case errors.Is(err, errTooManyRedirects):
		return "too many redirects"
	case errors.Is(err, errRedirectNotHTTPS):
		return "redirect to non-https"
	case isMalformedLocation(err):
		return "malformed redirect location"
	case isTimeout(err):
		return "timeout"
	case isTLSError(err):
		return "TLS failure"
	default:
		return "network error"
	}
}

func isMalformedLocation(err error) bool {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		err = uerr.Err
	}
	return strings.HasPrefix(err.Error(), "failed to parse Location header")
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

func isTLSError(err error) bool {
	var (
		ua x509.UnknownAuthorityError
		hn x509.HostnameError
		ci x509.CertificateInvalidError
		sr x509.SystemRootsError
		cv *tls.CertificateVerificationError
		rh tls.RecordHeaderError
	)
	if errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) || errors.As(err, &sr) || errors.As(err, &cv) || errors.As(err, &rh) {
		return true
	}
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		msg := uerr.Err.Error()
		if strings.HasPrefix(msg, "tls:") || strings.Contains(msg, "TLS handshake") {
			return true
		}
	}
	return false
}
