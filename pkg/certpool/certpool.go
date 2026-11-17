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
// trusted certificates. The system store is only read.
package certpool

import (
	"crypto/x509"
	"fmt"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
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

// FromFile reads an allowlist file at path and returns New applied to it.
// The system store is only read. The returned pool is never nil when err
// is nil. An allowlist that matches nothing yields an empty pool.
func FromFile(path string) (*x509.CertPool, error) {
	al, err := allowlist.FromFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist %s: %w", path, err)
	}
	pool, err := New(al)
	if err != nil {
		return nil, fmt.Errorf("apply allowlist %s: %w", path, err)
	}
	return pool, nil
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
