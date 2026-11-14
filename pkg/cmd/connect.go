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
	"net/http"
	"net/url"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/httputil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

func ConnectWithPlatformStore(uri *url.URL) error {
	st := store.Platform()
	certs, err := st.List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return fmt.Errorf("problem getting certs: %w", err)
	}
	return connect(uri, certs)
}

func ConnectWithAppStore(uri *url.URL, app string) error {
	return ConnectWithAppStoreFile(uri, app, "")
}

func ConnectWithAppStoreFile(uri *url.URL, app, storePath string) error {
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
	return connect(uri, certs)
}

func connect(uri *url.URL, roots []*x509.Certificate) error {
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
		return shortConnectError(uri.String(), err, connectLeaf(err))
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	fmt.Printf("Connection to %s passed!\n", uri.String())
	return nil
}

// NormalizeConnectURL parses a connect target. A value with no "://" is
// treated as https (host, host:port, or [::1]:port). Explicit http keeps the
// historical non-secure scheme error. Any other non-https scheme is rejected.
func NormalizeConnectURL(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
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
// leaf supplies the expiry date for an expired certificate when non-nil.
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
		when := leaf
		if when == nil {
			when = invalid.Cert
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
