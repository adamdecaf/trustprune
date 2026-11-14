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
	"crypto/tls"
	"crypto/x509"
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

	if err := ConnectWithPlatformStore(connectExampleUrl); err != nil {
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

	if err := ConnectWithAppStore(connectExampleUrl, connectExampleApp); err != nil {
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
