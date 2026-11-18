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

// Package certpool builds an x509.CertPool by applying an allowlist to
// trusted certificates. New reads the system store. FromFile reads a PEM
// bundle from a path. The system store is only read.
package certpool

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

// New returns an x509.CertPool which has had an allowlist applied.
// The initial set of certificates comes from the system's store.
//
// The store is only read. Certificates are listed with the platform
// store and filtered with allowlist.Allowlist.Matches. The returned pool
// is never nil when err is nil. An allowlist that matches nothing yields
// an empty pool.
func New(al allowlist.Allowlist) (*x509.CertPool, error) {
	certs, err := store.Platform().List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return nil, fmt.Errorf("list system certificates: %w", err)
	}
	return FromCertificates(al, certs), nil
}

// FromFile reads a PEM bundle at path and returns an x509.CertPool of the
// certificates al matches. Non-CERTIFICATE blocks are skipped. An
// unreadable file, a CERTIFICATE block that fails to parse, or a bundle
// with no certificates returns an error.
//
// The returned pool is never nil when err is nil. An allowlist that
// matches nothing yields an empty pool. No store is read or written.
func FromFile(al allowlist.Allowlist, path string) (*x509.CertPool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificates: %w", err)
	}
	certs, err := certificatesFromPEM(body)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return FromCertificates(al, certs), nil
}

// certificatesFromPEM returns the CERTIFICATE blocks in body.
// Other PEM types are ignored. A CERTIFICATE block that cannot be
// parsed is an error, as is a bundle that contains none.
func certificatesFromPEM(body []byte) ([]*x509.Certificate, error) {
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
			return nil, fmt.Errorf("certificate block %d: %w", n, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return certs, nil
}

// FromCertificates returns an x509.CertPool which has had an allowlist
// applied to certs. certs is the caller's certificate source (tests, a
// parsed bundle, or another store's list) and is not modified. No store
// is read or written.
//
// A certificate is included only when al.Matches reports a match. Nil
// entries are left out. The returned pool is never nil. An allowlist
// that matches nothing yields an empty pool.
func FromCertificates(al allowlist.Allowlist, certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for i := range certs {
		if certs[i] == nil || !al.Matches(certs[i]) {
			continue
		}
		pool.AddCert(certs[i])
	}
	return pool
}
