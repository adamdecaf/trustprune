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

package gen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
)

// ScanStats counts HTTPS dials while CA certificates are discovered.
// Methods are safe for concurrent use. A nil *ScanStats records nothing.
type ScanStats struct {
	mu sync.Mutex

	urls        int
	uniqueHosts int

	attempted int
	succeeded int
	failed    int
	// failedHosts is unique, insertion order. Printing sorts and caps it.
	failedHosts []string
	failedSeen  map[string]struct{}

	// reused is hosts answered from a CA already recorded for that name.
	reused int

	dnsTotal   time.Duration
	dnsLookups int

	handshakeTotal time.Duration
	handshakes     int

	roots int
	wall  time.Duration
}

// ScanSnapshot is a stable copy of ScanStats for printing.
type ScanSnapshot struct {
	URLs        int
	UniqueHosts int

	Attempted   int
	Succeeded   int
	Failed      int
	FailedHosts []string

	Reused int

	DNSTotal   time.Duration
	DNSLookups int

	HandshakeTotal time.Duration
	Handshakes     int

	Roots int
	Wall  time.Duration
}

// SetInput records how many URLs and unique hosts were read from the input.
func (s *ScanStats) SetInput(urls, hosts int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.urls = urls
	s.uniqueHosts = hosts
	s.mu.Unlock()
}

// SetWall records total elapsed time for generation.
func (s *ScanStats) SetWall(d time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.wall = d
	s.mu.Unlock()
}

// Snapshot returns a copy of the counters.
func (s *ScanStats) Snapshot() ScanSnapshot {
	if s == nil {
		return ScanSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hosts := make([]string, len(s.failedHosts))
	copy(hosts, s.failedHosts)
	return ScanSnapshot{
		URLs:           s.urls,
		UniqueHosts:    s.uniqueHosts,
		Attempted:      s.attempted,
		Succeeded:      s.succeeded,
		Failed:         s.failed,
		FailedHosts:    hosts,
		Reused:         s.reused,
		DNSTotal:       s.dnsTotal,
		DNSLookups:     s.dnsLookups,
		HandshakeTotal: s.handshakeTotal,
		Handshakes:     s.handshakes,
		Roots:          s.roots,
		Wall:           s.wall,
	}
}

func (s *ScanStats) setRoots(n int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.roots = n
	s.mu.Unlock()
}

func (s *ScanStats) noteSuccess() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.attempted++
	s.succeeded++
	s.mu.Unlock()
}

func (s *ScanStats) noteFailure(host string) {
	if s == nil {
		return
	}
	host = strings.ToLower(strings.TrimSpace(host))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempted++
	s.failed++
	if host == "" {
		return
	}
	if s.failedSeen == nil {
		s.failedSeen = make(map[string]struct{})
	}
	if _, ok := s.failedSeen[host]; ok {
		return
	}
	s.failedSeen[host] = struct{}{}
	s.failedHosts = append(s.failedHosts, host)
}

func (s *ScanStats) noteReuse() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.reused++
	s.mu.Unlock()
}

func (s *ScanStats) noteDNS(total time.Duration, n int) {
	if s == nil || n <= 0 {
		return
	}
	s.mu.Lock()
	s.dnsTotal += total
	s.dnsLookups += n
	s.mu.Unlock()
}

func (s *ScanStats) noteHandshake(d time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.handshakeTotal += d
	s.handshakes++
	s.mu.Unlock()
}

// dialTiming records one TLS dial. DNS hooks and the TCP dial can run
// on other goroutines, so the fields are locked.
type dialTiming struct {
	mu             sync.Mutex
	dnsStart       time.Time
	dnsTotal       time.Duration
	dnsLookups     int
	connectStart   time.Time
	connectStarted bool
}

func (t *dialTiming) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			t.mu.Lock()
			t.dnsStart = time.Now()
			t.mu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			t.mu.Lock()
			if !t.dnsStart.IsZero() {
				t.dnsTotal += time.Since(t.dnsStart)
				t.dnsStart = time.Time{}
			}
			t.dnsLookups++
			t.mu.Unlock()
		},
		ConnectStart: func(string, string) {
			t.mu.Lock()
			if !t.connectStarted {
				t.connectStart = time.Now()
				t.connectStarted = true
			}
			t.mu.Unlock()
		},
	}
}

func (t *dialTiming) result() (dns time.Duration, lookups int, handshake time.Duration, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connectStarted {
		handshake = time.Since(t.connectStart)
		ok = true
	}
	return t.dnsTotal, t.dnsLookups, handshake, ok
}

// dialTLSStats dials like tls.DialWithDialer and records timing on stats.
// DNS time is the lookup only. Connect+TLS time starts at the TCP dial and
// ends when the TLS dial returns, including a dial that fails.
func dialTLSStats(dialer *net.Dialer, addr string, cfg *tls.Config, stats *ScanStats) (*tls.Conn, error) {
	timing := &dialTiming{}
	ctx := httptrace.WithClientTrace(context.Background(), timing.trace())
	raw, err := (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", addr)
	dns, lookups, handshake, haveHandshake := timing.result()
	stats.noteDNS(dns, lookups)
	if haveHandshake {
		stats.noteHandshake(handshake)
	}
	if err != nil {
		return nil, err
	}
	conn, isTLS := raw.(*tls.Conn)
	if !isTLS {
		_ = raw.Close()
		return nil, fmt.Errorf("tls dial returned %T", raw)
	}
	return conn, nil
}
