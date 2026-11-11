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
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestGen__caSigns(t *testing.T) {
	certs, err := certutil.FromFile("../../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	ca := CA{
		Certificate: certs[0],
	}

	// we didn't tell ca that it signs anything, yet
	if ca.signs("") || ca.signs("google.com") {
		t.Error("nope, shouldn't say it signs anything yet")
	}

	// add signers
	ca.addDNSName("google.com")
	ca.addDNSName("*.gmail.com")
	ca.addDNSName("google.com")
	ca.addDNSName("*.gmail.com")

	// check we didn't add duplicates
	if len(ca.DNSNames) != 2 {
		t.Errorf("got %d", len(ca.DNSNames))
	}

	// Check signers now
	cases := []struct {
		dnsName string
		valid   bool
	}{
		{"yahoo.com", false},
		{"mail.yahoo.com", false},
		{"google.com", true},
		{"mail.gmail.com", true},
		{"foo.mail.google.com", false},
		{"foo.mail.gmail.com", false},
	}
	for i := range cases {
		if res := ca.signs(cases[i].dnsName); res != cases[i].valid {
			t.Errorf("%q got %v wanted %v", cases[i].dnsName, res, cases[i].valid)
		}
	}
}

func TestGen__caFind(t *testing.T) {
	certs, err := certutil.FromFile("../../../testdata/banno.com")
	if err != nil {
		t.Fatal(err)
	}
	authorities := CAs{}
	ca, exists := authorities.find(certs[0])
	if exists {
		t.Error("ca couldn't have existed")
	}
	if ca.Fingerprint != certutil.GetHexSHA256Fingerprint(*certs[0]) {
		t.Errorf("bad fingerprint, got %q", ca.Fingerprint)
	}

	if len(ca.DNSNames) != 0 {
		t.Errorf("somehow DNSNames were added..")
	}

	// manually call .addDNSName() and check
	ca.addDNSName("*.banno.com")
	ca.addDNSName("banno.com")

	ans := []string{"*.banno.com", "banno.com"}
	if !reflect.DeepEqual(ca.DNSNames, ans) {
		t.Errorf("got %q", ca.DNSNames)
	}

	// check .findSigners
	if res := authorities.findSigners("banno.com"); len(res) != 1 {
		t.Error("expectd to find signer")
	}
	if res := authorities.findSigners("api.banno.com"); len(res) != 1 {
		t.Error("expectd to find signer")
	}
	if res := authorities.findSigners("google.com"); len(res) != 0 {
		t.Error("shouldn't have found signer")
	}
}

func TestGen__getChain(t *testing.T) {
	cases := []string{
		"https://google.com",
		"https://google.com:443",
	}
	for i := range cases {
		u, _ := url.Parse(cases[i])
		c := getChain(u, nil)
		if len(c) == 0 {
			t.Error("expected cert chain")
		}
		for i := range c {
			if c[i] == nil {
				t.Fatalf("%v has nil-cert", c)
			}
		}
	}
}

func TestGen__gate(t *testing.T) {
	workers := newgate(2)

	// three timeslots, easy to fill in
	var w1 time.Time
	var w2 time.Time
	var w3 time.Time

	// start workers
	wg := sync.WaitGroup{}
	wg.Add(3)

	// first
	workers.begin()
	go func() {
		w1 = time.Now()
		time.Sleep(100 * time.Millisecond)
		workers.done()
		wg.Done()
	}()

	// second
	workers.begin()
	go func() {
		w2 = time.Now()
		time.Sleep(100 * time.Millisecond)
		workers.done()
		wg.Done()
	}()

	// third
	go func() {
		workers.begin()
		w3 = time.Now()
		workers.done()
		wg.Done()
	}()

	wg.Wait()
	// check (w3 should come last)
	if w1.After(w3) || w2.After(w3) {
		t.Errorf("w1=%q > w3=%q", w1, w3)
	}
	if w2.After(w3) {
		t.Errorf("w2=%q > w3=%q", w2, w3)
	}
	if w1.IsZero() || w2.IsZero() || w3.IsZero() {
		t.Errorf("can't be zero: w1=%q, w2=%q, w3=%q", w1, w2, w3)
	}
}

// FindCAs must verify and record the hostname, not host:port. httptest's URL
// always includes a non-443 port; dialing still uses that port.
func TestFindCAsRecordsHostnameWithoutPort(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Port() == "" || u.Port() == "443" {
		t.Fatalf("server URL %s must include a non-443 port", ts.URL)
	}
	if strings.Contains(u.Hostname(), ":") {
		t.Fatalf("hostname %q still contains a port", u.Hostname())
	}

	tr, ok := ts.Client().Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("test server client has no certificate pool")
	}
	cas, err := FindCAs([]*url.URL{u}, tr.TLSClientConfig.RootCAs)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 {
		t.Fatalf("got %d CAs, want 1", len(cas))
	}
	if len(cas[0].DNSNames) != 1 || cas[0].DNSNames[0] != u.Hostname() {
		t.Fatalf("DNSNames = %#v, want [%q]", cas[0].DNSNames, u.Hostname())
	}
}

// getRoot verifies DNSName as a certificate name. host:port is not a DNS name
// and used to drop CAs after a successful dial to a non-443 port.
func TestGetRootRejectsHostPortDNSName(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("tls server has no certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	if got := (chain{cert}).getRoot(u.Host, roots); got != nil {
		t.Fatalf("getRoot(%q) returned a root; host:port must not verify", u.Host)
	}
	if got := (chain{cert}).getRoot(u.Hostname(), roots); got == nil {
		t.Fatalf("getRoot(%q) rejected the hostname without a port", u.Hostname())
	}
}

// Concurrent find / addDNSName / findSigners on shared CAs. Under -race this
// fails without the locks in find, addDNSName, and findSigners.
func TestCAsConcurrentFindAndAddDNSName(t *testing.T) {
	example, err := certutil.FromFile("../../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	banno, err := certutil.FromFile("../../../testdata/banno.com")
	if err != nil {
		t.Fatal(err)
	}
	certA, certB := example[0], banno[0]

	authorities := CAs{}
	const workers = 16
	const perWorker = 40

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for n := 0; n < perWorker; n++ {
				cert := certA
				if n%2 == 1 {
					cert = certB
				}
				ca, _ := authorities.find(cert)
				name := fmt.Sprintf("host-%d-%d.example", w, n)
				ca.addDNSName(name)
				ca.addDNSName(name) // duplicate must be ignored
				_ = authorities.findSigners(name)
				_ = authorities.findSigners("missing.example")
			}
		}(w)
	}
	wg.Wait()

	if got := len(authorities.items); got != 2 {
		t.Fatalf("got %d CAs, want 2 (find-or-create raced)", got)
	}

	seen := make(map[string]bool, 2)
	wantNames := workers * (perWorker / 2)
	for _, ca := range authorities.items {
		if seen[ca.Fingerprint] {
			t.Errorf("duplicate CA fingerprint %s", ca.Fingerprint)
		}
		seen[ca.Fingerprint] = true

		names := make(map[string]int, len(ca.DNSNames))
		for _, dns := range ca.DNSNames {
			names[dns]++
			if names[dns] > 1 {
				t.Errorf("duplicate DNS name %q on %s", dns, ca.Fingerprint)
			}
		}
		if len(ca.DNSNames) != wantNames {
			t.Errorf("CA %s: got %d DNS names, want %d", ca.Fingerprint[:16], len(ca.DNSNames), wantNames)
		}
	}
}
