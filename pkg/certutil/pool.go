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

package certutil

import (
	"crypto/x509"
	"sync"
)

// cert is an internal object for pre-computing the fingerprint associated to a certificate
type cert struct {
	certificate *x509.Certificate
	fingerprint string
}

// Pool represents an append-only collection of x509 Certificates. There are no nessary connections
// between the certificates, except that each will only appear once in the pool.
type Pool struct {
	mu    sync.RWMutex // protects all fields
	certs []*cert
}

// Add will include the given certificate into the pool if it does
// not exist already
func (p *Pool) Add(c *x509.Certificate) {
	p.AddCertificates([]*x509.Certificate{c})
}

// AddCertificates includes multiple certificates into the pool.
// No duplicate certificates will be added.
func (p *Pool) AddCertificates(certs []*x509.Certificate) {
	var addable []*cert
	p.mu.RLock()
	for i := range certs {
		if certs[i] == nil {
			continue
		}

		needed := true
		fp := GetHexSHA256Fingerprint(*certs[i])
		for j := range p.certs {
			// collect certs which aren't
			if p.certs[j].fingerprint == fp {
				needed = false
				break
			}
		}
		if needed {
			for j := range addable {
				if addable[j].fingerprint == fp {
					needed = false
					break
				}
			}
		}
		if needed { // never found the cert existing
			addable = append(addable, &cert{
				certificate: certs[i],
				fingerprint: fp,
			})
		}
	}
	p.mu.RUnlock()

	p.mu.Lock() // write lock
	p.certs = append(p.certs, addable...)
	p.mu.Unlock()
}

// GetCertificates returns all x509.Certificate objects included in the pool
func (p *Pool) GetCertificates() []*x509.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()

	certs := make([]*x509.Certificate, len(p.certs))
	for i := range p.certs {
		certs[i] = p.certs[i].certificate
	}
	return certs
}
