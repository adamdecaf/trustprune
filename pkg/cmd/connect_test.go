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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

var (
	connectExampleApp = "java"
	connectExampleUrl *url.URL
)

func init() {
	raw := "https://example.com"
	u, err := url.Parse(raw)
	if err != nil {
		panic(fmt.Sprintf("problem parsing %s: %v", raw, err))
	}
	connectExampleUrl = u
}

func TestCmdConnect_platform(t *testing.T) {
	t.Skip("TODO(adam): fix")
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("windows isn't supported, yet")
	}

	if err := ConnectWithPlatformStore(connectExampleUrl, ConnectOptions{}); err != nil {
		t.Fatalf("problem with -connect on platform store: %v", err)
	}
}

func TestCmdConnect_app(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("java on windows isn't supported, yet")
	}

	if os.Getenv("JAVA_HOME") == "" {
		t.Skip("can't quickly find java")
	}

	if err := ConnectWithAppStore(connectExampleUrl, connectExampleApp, ConnectOptions{}); err != nil {
		t.Fatalf("problem with -connect on %s store: %v", connectExampleApp, err)
	}
}

func TestNormalizeConnectURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw     string
		want    string
		wantErr string
	}{
		{raw: "example.com", want: "https://example.com"},
		{raw: "example.com:8443", want: "https://example.com:8443"},
		{raw: "[::1]:443", want: "https://[::1]:443"},
		{raw: "localhost", want: "https://localhost"},
		{raw: "example.com/path", want: "https://example.com/path"},
		{raw: "https://example.com", want: "https://example.com"},
		{raw: "https://example.com/path?q=1", want: "https://example.com/path?q=1"},
		{raw: "https://[::1]:443", want: "https://[::1]:443"},
		{raw: "HTTPS://example.com", want: "https://example.com"},
		{raw: "http://example.com", wantErr: "non-secure url scheme used: http://example.com"},
		{raw: "HTTP://example.com", wantErr: "non-secure url scheme used: http://example.com"},
		{raw: "http://[::1]:443", wantErr: "non-secure url scheme used: http://[::1]:443"},
		{raw: "ftp://example.com", wantErr: `unsupported url scheme "ftp"`},
		{raw: "ssh://example.com/repo", wantErr: `unsupported url scheme "ssh"`},
		{raw: "file:///tmp/cert", wantErr: `unsupported url scheme "file"`},
		{raw: "https://[::1", wantErr: "missing ']'"},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeConnectURL(tc.raw)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("NormalizeConnectURL(%q) = %v, want error %q", tc.raw, got, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("NormalizeConnectURL(%q) url = %s, want nil", tc.raw, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("NormalizeConnectURL(%q) error %q, want substring %q", tc.raw, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeConnectURL(%q): %v", tc.raw, err)
			}
			if got == nil || got.String() != tc.want {
				t.Fatalf("NormalizeConnectURL(%q) = %v, want %s", tc.raw, got, tc.want)
			}
			if got.Scheme != "https" {
				t.Fatalf("scheme = %q", got.Scheme)
			}
		})
	}
}

func TestShortConnectError(t *testing.T) {
	t.Parallel()

	const target = "https://expired.example"
	leaf := &x509.Certificate{NotAfter: time.Date(2015, 4, 12, 23, 59, 59, 0, time.UTC)}
	other := &x509.Certificate{NotAfter: time.Date(1999, 1, 2, 0, 0, 0, 0, time.UTC)}
	expired := x509.CertificateInvalidError{Cert: other, Reason: x509.Expired, Detail: "current time after"}
	expiredNoCert := x509.CertificateInvalidError{Reason: x509.Expired}
	unknown := x509.UnknownAuthorityError{Cert: leaf}
	hostErr := x509.HostnameError{Certificate: leaf, Host: "expired.example"}
	incompatible := x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}
	plain := errors.New("dial tcp 127.0.0.1:443: connection refused")

	cases := []struct {
		name string
		err  error
		leaf *x509.Certificate
		want string
	}{
		{
			name: "expired uses leaf date",
			err:  expired,
			leaf: leaf,
			want: target + ": certificate expired 2015-04-12",
		},
		{
			name: "expired wrapped",
			err:  fmt.Errorf("verify: %w", expired),
			leaf: leaf,
			want: target + ": certificate expired 2015-04-12",
		},
		{
			name: "expired leaf nil uses cert on error",
			err:  expired,
			want: target + ": certificate expired 1999-01-02",
		},
		{
			name: "expired without cert",
			err:  expiredNoCert,
			want: target + ": certificate expired",
		},
		{
			name: "expired leaf from verification chain",
			err: &tls.CertificateVerificationError{
				UnverifiedCertificates: []*x509.Certificate{leaf},
				Err:                    expired,
			},
			want: target + ": certificate expired 2015-04-12",
		},
		{
			name: "explicit leaf wins over verification chain",
			err: &tls.CertificateVerificationError{
				UnverifiedCertificates: []*x509.Certificate{leaf},
				Err:                    expired,
			},
			leaf: other,
			want: target + ": certificate expired 1999-01-02",
		},
		{
			name: "unknown authority",
			err:  unknown,
			leaf: leaf,
			want: target + ": unknown authority",
		},
		{
			name: "unknown authority wrapped in verification error",
			err: &tls.CertificateVerificationError{
				UnverifiedCertificates: []*x509.Certificate{leaf},
				Err:                    fmt.Errorf("chain: %w", unknown),
			},
			want: target + ": unknown authority",
		},
		{
			name: "hostname mismatch",
			err:  hostErr,
			want: target + ": hostname mismatch",
		},
		{
			name: "hostname mismatch through url error",
			err: &url.Error{
				Op:  "Head",
				URL: target,
				Err: &tls.CertificateVerificationError{Err: hostErr},
			},
			want: target + ": hostname mismatch",
		},
		{
			name: "hostname with nil certificate does not panic",
			err:  x509.HostnameError{Host: "expired.example"},
			want: target + ": hostname mismatch",
		},
		{
			name: "other invalid reason keeps inner text",
			err:  &tls.CertificateVerificationError{Err: incompatible},
			want: target + ": " + incompatible.Error(),
		},
		{
			name: "plain error",
			err:  plain,
			want: target + ": " + plain.Error(),
		},
		{
			name: "connectLeaf supplies the peer leaf",
			err: &tls.CertificateVerificationError{
				UnverifiedCertificates: []*x509.Certificate{leaf},
				Err:                    expiredNoCert,
			},
			leaf: connectLeaf(&tls.CertificateVerificationError{
				UnverifiedCertificates: []*x509.Certificate{leaf},
				Err:                    expiredNoCert,
			}),
			want: target + ": certificate expired 2015-04-12",
		},
	}

	if err := shortConnectError(target, nil, leaf); err != nil {
		t.Fatalf("nil error: got %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := shortConnectError(target, tc.err, tc.leaf)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != tc.want {
				t.Fatalf("got %q\nwant %q", err.Error(), tc.want)
			}
		})
	}
}

func TestFormatConnectOK(t *testing.T) {
	t.Parallel()

	leafRaw := bytes.Repeat([]byte{0x11}, 16)
	rootRaw := bytes.Repeat([]byte{0x22}, 16)
	// 2027-03-04 01:00 at UTC+9 is 2027-03-03 16:00 UTC.
	leafExpires := time.Date(2027, 3, 4, 1, 0, 0, 0, time.FixedZone("EAST", 9*60*60))
	leaf := &x509.Certificate{
		Raw:      leafRaw,
		Subject:  pkix.Name{CommonName: "leaf.example"},
		NotAfter: leafExpires,
	}
	root := &x509.Certificate{
		Raw: rootRaw,
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Example Org"},
		},
	}
	orgRoot := &x509.Certificate{
		Raw:      rootRaw,
		Subject:  pkix.Name{Organization: []string{"Example Org"}},
		NotAfter: leafExpires,
	}
	const expires = "2027-03-03"
	rootSHA := sha256Prefix(rootRaw)
	leafSHA := sha256Prefix(leafRaw)

	cases := []struct {
		name    string
		url     string
		state   *tls.ConnectionState
		want    string
		wantErr string
	}{
		{
			name: "tls1.3 prefers root CN",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS13,
				VerifiedChains: [][]*x509.Certificate{{leaf, root}},
			},
			want: "ok https://example.com tls1.3 root=Root CA sha256=" + rootSHA + " leaf-expires=" + expires,
		},
		{
			name: "tls1.2 uses subject when CN is empty",
			url:  "https://example.com:8443/path",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS12,
				VerifiedChains: [][]*x509.Certificate{{leaf, orgRoot}},
			},
			want: "ok https://example.com:8443/path tls1.2 root=O=Example Org sha256=" + rootSHA + " leaf-expires=" + expires,
		},
		{
			name: "single certificate is root and leaf",
			url:  "https://[::1]",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS13,
				VerifiedChains: [][]*x509.Certificate{{leaf}},
			},
			want: "ok https://[::1] tls1.3 root=leaf.example sha256=" + leafSHA + " leaf-expires=" + expires,
		},
		{
			name:    "nil state",
			url:     "https://example.com",
			wantErr: "no verified certificate chain",
		},
		{
			name: "empty chains",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version: tls.VersionTLS13,
			},
			wantErr: "no verified certificate chain",
		},
		{
			name: "empty first chain",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS12,
				VerifiedChains: [][]*x509.Certificate{{}},
			},
			wantErr: "no verified certificate chain",
		},
		{
			name: "unsupported version",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS10,
				VerifiedChains: [][]*x509.Certificate{{leaf, root}},
			},
			wantErr: "unsupported TLS version",
		},
		{
			name: "missing raw",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version: tls.VersionTLS13,
				VerifiedChains: [][]*x509.Certificate{{
					leaf,
					{Subject: pkix.Name{CommonName: "no raw"}},
				}},
			},
			wantErr: "missing raw",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := formatConnectOK(tc.url, tc.state)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("formatConnectOK() error = %v, want substring %q", err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("formatConnectOK() = %q, want empty", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("formatConnectOK(): %v", err)
			}
			if got != tc.want {
				t.Fatalf("formatConnectOK() = %q\nwant %q", got, tc.want)
			}
			if strings.Contains(got, "\n") {
				t.Fatalf("summary contains a newline: %q", got)
			}
		})
	}
}

func TestFormatConnectChainTable(t *testing.T) {
	t.Parallel()

	leafRaw := bytes.Repeat([]byte{0x11}, 16)
	midRaw := bytes.Repeat([]byte{0x22}, 16)
	rootRaw := bytes.Repeat([]byte{0x33}, 16)
	// 2027-03-04 01:00 at UTC+9 is 2027-03-03 16:00 UTC.
	leafExpires := time.Date(2027, 3, 4, 1, 0, 0, 0, time.FixedZone("EAST", 9*60*60))
	midExpires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	rootExpires := time.Date(2035, 12, 31, 23, 59, 59, 0, time.UTC)
	leaf := &x509.Certificate{
		Raw:      leafRaw,
		Subject:  pkix.Name{CommonName: "leaf.example"},
		Issuer:   pkix.Name{CommonName: "Mid"},
		NotAfter: leafExpires,
	}
	mid := &x509.Certificate{
		Raw:      midRaw,
		Subject:  pkix.Name{CommonName: "Mid"},
		Issuer:   pkix.Name{Organization: []string{"Example Org"}},
		NotAfter: midExpires,
	}
	root := &x509.Certificate{
		Raw: rootRaw,
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Example Org"},
		},
		Issuer:   pkix.Name{CommonName: "Root CA"},
		NotAfter: rootExpires,
	}
	short := &x509.Certificate{
		Raw:      leafRaw,
		Subject:  pkix.Name{CommonName: "A"},
		Issuer:   pkix.Name{CommonName: "B"},
		NotAfter: leafExpires,
	}

	longWant := "" +
		"INDEX  SUBJECT       ISSUER         NOT-AFTER   SHA256\n" +
		"0      leaf.example  Mid            2027-03-03  " + sha256Prefix(leafRaw) + "\n" +
		"1      Mid           O=Example Org  2030-01-02  " + sha256Prefix(midRaw) + "\n" +
		"2      Root CA       Root CA        2035-12-31  " + sha256Prefix(rootRaw) + "\n"
	shortWant := "" +
		"INDEX  SUBJECT  ISSUER  NOT-AFTER   SHA256\n" +
		"0      A        B       2027-03-03  " + sha256Prefix(leafRaw) + "\n"

	cases := []struct {
		name    string
		chain   []*x509.Certificate
		want    string
		wantErr string
	}{
		{name: "leaf to root", chain: []*x509.Certificate{leaf, mid, root}, want: longWant},
		{name: "header wider than cells", chain: []*x509.Certificate{short}, want: shortWant},
		{name: "empty", wantErr: "no verified certificate chain"},
		{name: "nil cert", chain: []*x509.Certificate{leaf, nil}, wantErr: "certificate 1 is nil"},
		{
			name:    "missing raw",
			chain:   []*x509.Certificate{{Subject: pkix.Name{CommonName: "no raw"}}},
			wantErr: "missing raw",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := formatConnectChainTable(tc.chain)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("formatConnectChainTable() error = %v, want substring %q", err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("formatConnectChainTable() = %q, want empty", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("formatConnectChainTable(): %v", err)
			}
			if got != tc.want {
				t.Fatalf("formatConnectChainTable() =\n%s\nwant\n%s", got, tc.want)
			}
			for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
				if strings.TrimRight(line, " ") != line {
					t.Fatalf("trailing space on %q", line)
				}
			}
		})
	}
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func sha256Prefix(raw []byte) string {
	return sha256Hex(raw)[:16]
}

func TestNormalizeConnectFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{in: "", want: "text"},
		{in: "text", want: "text"},
		{in: "TEXT", want: "text"},
		{in: " json ", want: "json"},
		{in: "JSON", want: "json"},
		{in: "table", wantErr: `unknown format "table" (formats: json, text)`},
		{in: "Short", wantErr: `unknown format "Short" (formats: json, text)`},
		{in: "nope", wantErr: `unknown format "nope" (formats: json, text)`},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeConnectFormat(tc.in)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("NormalizeConnectFormat(%q) error = %v, want %q", tc.in, err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("NormalizeConnectFormat(%q) = %q, want empty", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeConnectFormat(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeConnectFormat(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFormatConnectJSON(t *testing.T) {
	t.Parallel()

	leafRaw := bytes.Repeat([]byte{0x11}, 16)
	midRaw := bytes.Repeat([]byte{0x22}, 16)
	rootRaw := bytes.Repeat([]byte{0x33}, 16)
	// 2027-03-04 01:00 at UTC+9 is 2027-03-03 16:00 UTC.
	leafExpires := time.Date(2027, 3, 4, 1, 0, 0, 0, time.FixedZone("EAST", 9*60*60))
	midExpires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	rootExpires := time.Date(2035, 12, 31, 23, 59, 59, 0, time.UTC)
	leaf := &x509.Certificate{
		Raw:      leafRaw,
		Subject:  pkix.Name{CommonName: "leaf.example"},
		Issuer:   pkix.Name{CommonName: "Mid"},
		NotAfter: leafExpires,
	}
	mid := &x509.Certificate{
		Raw:      midRaw,
		Subject:  pkix.Name{CommonName: "Mid"},
		Issuer:   pkix.Name{Organization: []string{"Example Org"}},
		NotAfter: midExpires,
	}
	root := &x509.Certificate{
		Raw: rootRaw,
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Example Org"},
		},
		Issuer:   pkix.Name{CommonName: "Root CA"},
		NotAfter: rootExpires,
	}
	orgRoot := &x509.Certificate{
		Raw:      rootRaw,
		Subject:  pkix.Name{Organization: []string{"Example Org"}},
		Issuer:   pkix.Name{CommonName: "Root CA"},
		NotAfter: rootExpires,
	}
	leafSHA := sha256Hex(leafRaw)
	midSHA := sha256Hex(midRaw)
	rootSHA := sha256Hex(rootRaw)

	chainState := &tls.ConnectionState{
		Version:        tls.VersionTLS13,
		VerifiedChains: [][]*x509.Certificate{{leaf, mid, root}},
	}

	cases := []struct {
		name    string
		url     string
		state   *tls.ConnectionState
		want    connectJSON
		wantErr string
	}{
		{
			name:  "tls1.3 chain",
			url:   "https://example.com",
			state: chainState,
			want: connectJSON{
				URL:        "https://example.com",
				TLSVersion: "tls1.3",
				Verified:   true,
				Root:       connectJSONRoot{Subject: "Root CA", SHA256: rootSHA},
				Leaf:       connectJSONLeaf{Subject: "leaf.example", NotAfter: "2027-03-03"},
				Chain: []connectJSONChain{
					{Subject: "leaf.example", Issuer: "Mid", NotAfter: "2027-03-03", SHA256: leafSHA},
					{Subject: "Mid", Issuer: "O=Example Org", NotAfter: "2030-01-02", SHA256: midSHA},
					{Subject: "Root CA", Issuer: "Root CA", NotAfter: "2035-12-31", SHA256: rootSHA},
				},
			},
		},
		{
			name: "tls1.2 subject when CN is empty",
			url:  "https://example.com:8443/path",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS12,
				VerifiedChains: [][]*x509.Certificate{{leaf, orgRoot}},
			},
			want: connectJSON{
				URL:        "https://example.com:8443/path",
				TLSVersion: "tls1.2",
				Verified:   true,
				Root:       connectJSONRoot{Subject: "O=Example Org", SHA256: rootSHA},
				Leaf:       connectJSONLeaf{Subject: "leaf.example", NotAfter: "2027-03-03"},
				Chain: []connectJSONChain{
					{Subject: "leaf.example", Issuer: "Mid", NotAfter: "2027-03-03", SHA256: leafSHA},
					{Subject: "O=Example Org", Issuer: "Root CA", NotAfter: "2035-12-31", SHA256: rootSHA},
				},
			},
		},
		{
			name: "single certificate is root and leaf",
			url:  "https://[::1]",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS13,
				VerifiedChains: [][]*x509.Certificate{{leaf}},
			},
			want: connectJSON{
				URL:        "https://[::1]",
				TLSVersion: "tls1.3",
				Verified:   true,
				Root:       connectJSONRoot{Subject: "leaf.example", SHA256: leafSHA},
				Leaf:       connectJSONLeaf{Subject: "leaf.example", NotAfter: "2027-03-03"},
				Chain: []connectJSONChain{
					{Subject: "leaf.example", Issuer: "Mid", NotAfter: "2027-03-03", SHA256: leafSHA},
				},
			},
		},
		{
			name:    "nil state",
			url:     "https://example.com",
			wantErr: "no verified certificate chain",
		},
		{
			name: "empty chains",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version: tls.VersionTLS13,
			},
			wantErr: "no verified certificate chain",
		},
		{
			name: "empty first chain",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS12,
				VerifiedChains: [][]*x509.Certificate{{}},
			},
			wantErr: "no verified certificate chain",
		},
		{
			name: "unsupported version",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS10,
				VerifiedChains: [][]*x509.Certificate{{leaf, root}},
			},
			wantErr: "unsupported TLS version",
		},
		{
			name: "nil cert",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version:        tls.VersionTLS13,
				VerifiedChains: [][]*x509.Certificate{{leaf, nil}},
			},
			wantErr: "certificate 1 is nil",
		},
		{
			name: "missing raw",
			url:  "https://example.com",
			state: &tls.ConnectionState{
				Version: tls.VersionTLS13,
				VerifiedChains: [][]*x509.Certificate{{
					leaf,
					{Subject: pkix.Name{CommonName: "no raw"}},
				}},
			},
			wantErr: "missing raw",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := formatConnectJSON(tc.url, tc.state)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("formatConnectJSON() error = %v, want substring %q", err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("formatConnectJSON() = %q, want empty", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("formatConnectJSON(): %v", err)
			}
			assertConnectJSON(t, got, tc.want)
			if !strings.HasSuffix(got, "\n") {
				t.Fatalf("json missing trailing newline: %q", got)
			}

			rendered, err := formatConnectResult(tc.url, tc.state, ConnectOptions{Format: "JSON", Verbose: true})
			if err != nil {
				t.Fatalf("formatConnectResult(json, verbose): %v", err)
			}
			if rendered != got {
				t.Fatalf("-v changed json\n got %q\nwant %q", rendered, got)
			}
			plain, err := formatConnectResult(tc.url, tc.state, ConnectOptions{Format: "json"})
			if err != nil {
				t.Fatalf("formatConnectResult(json): %v", err)
			}
			if plain != got {
				t.Fatalf("formatConnectResult(json) = %q\nwant %q", plain, got)
			}
		})
	}

	t.Run("text verbose still prints the table", func(t *testing.T) {
		t.Parallel()
		summary, err := formatConnectOK("https://example.com", chainState)
		if err != nil {
			t.Fatal(err)
		}
		text, err := formatConnectResult("https://example.com", chainState, ConnectOptions{Format: "TEXT"})
		if err != nil {
			t.Fatal(err)
		}
		if text != summary+"\n" {
			t.Fatalf("text = %q\nwant %q", text, summary+"\n")
		}
		table, err := formatConnectChainTable(chainState.VerifiedChains[0])
		if err != nil {
			t.Fatal(err)
		}
		verbose, err := formatConnectResult("https://example.com", chainState, ConnectOptions{Verbose: true})
		if err != nil {
			t.Fatal(err)
		}
		if verbose != summary+"\n"+table {
			t.Fatalf("verbose text =\n%s\nwant\n%s", verbose, summary+"\n"+table)
		}
		if verbose == text {
			t.Fatal("expected -v to add the chain table for text")
		}
	})
}

func TestConnectUnknownFormatDoesNotDial(t *testing.T) {
	t.Parallel()

	u, err := url.Parse("https://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	err = connect(u, nil, ConnectOptions{Format: "nope"})
	if err == nil || err.Error() != `unknown format "nope" (formats: json, text)` {
		t.Fatalf("connect() error = %v", err)
	}
}

// assertConnectJSON checks got is the pretty-printed form of want, with no
// extra fields and with sha256 values left as full hex.
func assertConnectJSON(t *testing.T, got string, want connectJSON) {
	t.Helper()

	dec := json.NewDecoder(strings.NewReader(got))
	dec.DisallowUnknownFields()
	var doc connectJSON
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode %q: %v", got, err)
	}
	if doc.URL != want.URL || doc.TLSVersion != want.TLSVersion || !doc.Verified || !want.Verified {
		t.Fatalf("header = %+v\nwant %+v", doc, want)
	}
	if doc.Root != want.Root {
		t.Fatalf("root = %+v\nwant %+v", doc.Root, want.Root)
	}
	if doc.Leaf != want.Leaf {
		t.Fatalf("leaf = %+v\nwant %+v", doc.Leaf, want.Leaf)
	}
	if len(doc.Chain) != len(want.Chain) {
		t.Fatalf("chain len = %d, want %d", len(doc.Chain), len(want.Chain))
	}
	for i := range want.Chain {
		if doc.Chain[i] != want.Chain[i] {
			t.Fatalf("chain[%d] = %+v\nwant %+v", i, doc.Chain[i], want.Chain[i])
		}
		if len(doc.Chain[i].SHA256) != 64 {
			t.Fatalf("chain[%d] sha256 = %q", i, doc.Chain[i].SHA256)
		}
	}
	if doc.Root.SHA256 != doc.Chain[len(doc.Chain)-1].SHA256 {
		t.Fatalf("root sha256 %s != chain anchor %s", doc.Root.SHA256, doc.Chain[len(doc.Chain)-1].SHA256)
	}
	if doc.Leaf.Subject != doc.Chain[0].Subject || doc.Leaf.NotAfter != doc.Chain[0].NotAfter {
		t.Fatalf("leaf %+v does not match chain[0] %+v", doc.Leaf, doc.Chain[0])
	}

	enc, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(enc)+"\n" {
		t.Fatalf("json =\n%s\nwant\n%s\n", got, string(enc)+"\n")
	}
}
