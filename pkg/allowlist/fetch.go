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
	"crypto/sha256"
	"crypto/subtle"
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
// The cap applies to https responses, not to local files.
// SHA256 is an optional hex SHA-256 of the file bytes. Empty skips the check.
type FetchOptions struct {
	Client  *http.Client
	MaxSize int64
	SHA256  string
}

// FromPathOrURL loads ref and parses it with FromBytes.
// A value url.Parse treats as having a scheme is a URL: https is fetched,
// and any other scheme is refused. A one-letter scheme is a Windows volume
// path (C:\file or C:/file), which stays a local file. A value with no
// scheme is a local file, read the same way as FromFile.
// When SHA256 is set, the bytes are checked before they are parsed.
func FromPathOrURL(ref string, opts FetchOptions) (Allowlist, error) {
	pin := strings.TrimSpace(opts.SHA256)
	if pin != "" {
		if err := ValidateSHA256Pin(pin); err != nil {
			return Allowlist{}, err
		}
	}
	remote, err := refIsURL(ref)
	if err != nil {
		return Allowlist{}, err
	}
	var body []byte
	if remote {
		body, err = fetchAllowlist(ref, opts)
	} else {
		body, err = os.ReadFile(ref)
	}
	if err != nil {
		return Allowlist{}, err
	}
	if err := matchSHA256(ref, body, pin); err != nil {
		return Allowlist{}, err
	}
	al, err := FromBytes(body)
	if err != nil && remote {
		return Allowlist{}, fmt.Errorf("allowlist %s: %w", diagnosticRef(ref), err)
	}
	return al, err
}

// ValidateRef reports whether ref is a local path or an https URL.
// An empty ref is not an error. A non-https scheme is an error.
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

func refIsURL(ref string) (bool, error) {
	u, err := url.Parse(ref)
	if err != nil || u.Scheme == "" {
		return false, nil
	}
	if u.Scheme == "https" {
		return true, nil
	}
	// url.Parse lowercases the scheme and reports "c" for C:\path and C:/path.
	if len(u.Scheme) == 1 && u.Scheme[0] >= 'a' && u.Scheme[0] <= 'z' {
		return false, nil
	}
	return false, fmt.Errorf("allowlist URLs must be https, not %q", u.Scheme)
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
	if err != nil || u.Scheme == "" {
		return ref
	}
	return u.Redacted()
}

var errBodyTooLarge = errors.New("allowlist body exceeds size limit")

func fetchAllowlist(ref string, opts FetchOptions) (body []byte, err error) {
	client := allowlistClient(opts.Client)
	req, err := http.NewRequest(http.MethodGet, ref, nil)
	if err != nil {
		return nil, fmt.Errorf("allowlist %s: %w", diagnosticRef(ref), err)
	}
	req.Close = true

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer func() {
			cerr := resp.Body.Close()
			if err == nil {
				err = cerr
			}
		}()
	}
	if err != nil {
		return nil, fmt.Errorf("allowlist %s: %w", diagnosticRef(ref), err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("allowlist %s: response status %s", diagnosticRef(ref), resp.Status)
	}
	max := opts.MaxSize
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if resp.ContentLength > max {
		return nil, fmt.Errorf("allowlist %s exceeds %d byte limit (Content-Length %d)", diagnosticRef(ref), max, resp.ContentLength)
	}
	body, err = readLimited(resp.Body, max)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return nil, fmt.Errorf("allowlist %s exceeds %d byte limit", diagnosticRef(ref), max)
		}
		return nil, fmt.Errorf("allowlist %s: %w", diagnosticRef(ref), err)
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

func allowlistRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("allowlist URL exceeded %d redirects", maxRedirects)
	}
	scheme := ""
	if req != nil && req.URL != nil {
		scheme = req.URL.Scheme
	}
	if scheme != "https" {
		if scheme == "" {
			scheme = "unknown"
		}
		return fmt.Errorf("allowlist URL redirected to %s: allowlist URLs must be https", scheme)
	}
	return nil
}
