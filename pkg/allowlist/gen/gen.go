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

package gen

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

var (
	debug      = os.Getenv("DEBUG") != ""
	maxWorkers = 25
	skipVerify = false
)

// CA holds the x509 certificate representing a signer of another x509
// certificate encountered.
type CA struct {
	Certificate *x509.Certificate

	// pre-computed sha256 fingerprint
	Fingerprint string

	mu sync.Mutex // protects DNSNames
	// DNSNames represents known fqdns (or wildcards) which this
	// CA has created a certificate for
	DNSNames []string
}

// signs checks if a given
func (c *CA) signs(dnsName string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	dnsName = strings.ToLower(dnsName)
	for i := range c.DNSNames {
		if c.DNSNames[i] == dnsName {
			return true
		}
		// crude wildcard match, it's probably wrong
		if strings.HasPrefix(c.DNSNames[i], "*.") {
			idx := strings.Index(dnsName, ".")
			if c.DNSNames[i][1:] == dnsName[idx:] {
				return true
			}
		}
	}
	return false
}
func (c *CA) addDNSName(dnsName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// lowercase incoming dnsNames
	dnsName = strings.ToLower(dnsName)

	for i := range c.DNSNames {
		if c.DNSNames[i] == dnsName {
			return
		}
	}

	c.DNSNames = append(c.DNSNames, dnsName)
}

type CAs struct {
	sync.RWMutex
	items []*CA
}

// find locates a CA certificate from our collection
// if the CA can't be found then a new CA is created
// and added for future lookups
//
// Never returns a nil CA value
func (c *CAs) find(inc *x509.Certificate) (ca *CA, exists bool) {
	// Hold the write lock for the whole find-or-create path. Releasing a
	// read lock before taking the write lock lets two workers both miss
	// and both append.
	c.Lock()
	defer c.Unlock()

	incfp := certutil.GetHexSHA256Fingerprint(*inc)
	for i := range c.items {
		if c.items[i].Fingerprint == incfp {
			return c.items[i], true
		}
	}

	ca = &CA{
		Certificate: inc,
		Fingerprint: incfp,
	}
	c.items = append(c.items, ca)
	return ca, false
}

// findSigners locates all CA records that have signed for a given dns name
//
// There's a bug with this code in that having the same dnsName signed by
// multiple chains won't record all those paths.
//
// 2018-01-21: I'm not sure how frequent that situation is, but I can see
// this happening when dnsNames change their CA.
func (c *CAs) findSigners(dnsName string) []*CA {
	// Write lock: we may record dnsName on a matching CA via addDNSName.
	c.Lock()
	defer c.Unlock()

	var out []*CA
	for i := range c.items {
		ca := c.items[i]
		if ca.signs(dnsName) {
			var exists bool
			for j := range out { // Add to accumulator only if we don't already have it
				if ca.Fingerprint == out[j].Fingerprint {
					exists = true
					break
				}
			}
			if !exists {
				out = append(out, ca)
				ca.addDNSName(dnsName)
			}
		}
	}
	return out
}

// chain represents a x509 certificate chain
type chain []*x509.Certificate

// Grab the stored root certificate
func (c chain) getRoot(dnsName string, sysRoots *x509.CertPool) *x509.Certificate {
	leaf := c.getLeaf()
	chains, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: c.asCertPool(),
		Roots:         sysRoots,
	})

	if err != nil {
		fmt.Printf("WARNING: Unable to find chain for %s, err=%v\n", dnsName, err)
		return nil
	}

	// return root from first chain
	chain := chains[0]
	return chain[len(chain)-1]
}

func (c chain) asCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	certs := c[:]
	for i := range certs {
		pool.AddCert(certs[i])
	}
	return pool
}

func (c chain) getLeaf() *x509.Certificate {
	if len(c) == 0 {
		return nil
	}
	return c[0]
}

// FindCAs accepts a slice of urls (expected to be "large") and
// finds all the CA certificates signing the urls.
//
// Only https:// urls are included
//
// URLs are grouped by their full hostname and a connection is established
// to retrieve a certificate, whose signer is looked up and retrieved.
func FindCAs(urls []*url.URL, sysRoots *x509.CertPool) ([]*CA, error) {
	// setup worker pool
	workers := newgate(maxWorkers)

	// Grab unique hostnames from urls
	authorities := CAs{}
	wg := sync.WaitGroup{}
	for i := range urls {
		wg.Add(1)

		go func(wrk *gate, u *url.URL, i int) {
			defer wg.Done()

			// skip non https:// addresses, such as ftp, http, etc
			// and invalid Host values
			if u.Scheme != "https" || u.Host == "" {
				return
			}
			// x509 names are hostnames, not host:port. --hosts accepts
			// example.com:8443; getChain still dials that full address.
			dnsName := u.Hostname()
			if dnsName == "" {
				return
			}

			workers.begin()
			defer workers.done()
			cas := authorities.findSigners(dnsName)
			if len(cas) == 0 {
				// We didn't find an existing CA, so we need to get one
				chain := getChain(u, sysRoots)
				if len(chain) == 0 {
					// didn't find chain, but that's not a huge deal as
					// the remote endpoint could be unreachable
					fmt.Printf("WARNING: Unable to get certificates for %s\n", dnsName)
					return
				}

				// With a new chain, find it's root and cache that
				root := chain.getRoot(dnsName, sysRoots)
				if root == nil {
					return
				}

				ca, exists := authorities.find(root)
				ca.addDNSName(dnsName)
				if debug && !exists {
					fmt.Printf("allowlist/gen: added %s root (%s)\n", dnsName, ca.Fingerprint[:16])
				}
			}

			// remind people we're still here
			if i >= 1000 && i%1000 == 0 {
				fmt.Printf("Processed %d/%d urls\n", i, len(urls))
			}
		}(workers, urls[i], i)
	}

	wg.Wait()
	return authorities.items, nil
}

// Make as little of a connection as needed to get TLS handshake complete and
// server certificates returned.
func getChain(u *url.URL, roots *x509.CertPool) chain {
	cfg := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}
	if roots != nil {
		cfg.RootCAs = roots
	}
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	// figure out host/port combo
	host, port := u.Host, u.Port()
	if strings.Contains(host, ":") {
		host, port, _ = net.SplitHostPort(u.Host)
	}
	if port == "" {
		port = "443" // total fallback
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	if debug {
		fmt.Printf("allowlist/gen: getChain: getting chain for addr=%q\n", addr)
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		if debug {
			fmt.Printf("allowlist/gen: getChain: error establishing tls conn with %q err=%v\n", addr, err)
		}
		return nil
	}
	defer func() { _ = conn.Close() }()

	return conn.ConnectionState().PeerCertificates
}

// gate is a worker pool impl
type gate struct { // TODO(adam): replace with go4.org/sync.Gate
	c chan struct{}
}

func (g gate) begin() {
	g.c <- struct{}{}
}
func (g gate) done() {
	select {
	case <-g.c:
	default:
		panic("invalid state") //nolint:forbidigo
	}
}
func newgate(n int) *gate {
	return &gate{
		c: make(chan struct{}, n),
	}
}
