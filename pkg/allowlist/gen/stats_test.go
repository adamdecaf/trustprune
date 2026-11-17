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
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"testing"
	"time"
)

func TestFindCAsWithStatsRecordsRoot(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := ts.Client().Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("test server client has no certificate pool")
	}
	roots := tr.TLSClientConfig.RootCAs

	plain, err := url.Parse("http://example.com/skip")
	if err != nil {
		t.Fatal(err)
	}
	stats := &ScanStats{}
	cas, err := FindCAsWithStats([]*url.URL{u, plain}, roots, stats)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 {
		t.Fatalf("got %d CAs, want 1", len(cas))
	}
	snap := stats.Snapshot()
	if snap.Roots != 1 || snap.Attempted != 1 || snap.Succeeded != 1 || snap.Failed != 0 || snap.Reused != 0 {
		t.Fatalf("snapshot %+v", snap)
	}
	if snap.Handshakes != 1 || snap.HandshakeTotal <= 0 {
		t.Fatalf("handshake timing %+v", snap)
	}
	if snap.DNSLookups != 0 {
		t.Fatalf("IP dial recorded DNS: %+v", snap)
	}
}

func TestFindCAsWithStatsSkipsNonHTTPS(t *testing.T) {
	u, err := url.Parse("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	stats := &ScanStats{}
	cas, err := FindCAsWithStats([]*url.URL{u}, nil, stats)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 0 {
		t.Fatalf("got %d CAs", len(cas))
	}
	snap := stats.Snapshot()
	if snap.Attempted != 0 || snap.Reused != 0 || snap.Roots != 0 || snap.Handshakes != 0 {
		t.Fatalf("%+v", snap)
	}
}

func TestScanHTTPSHostReusesRecordedName(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := ts.Client().Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("test server client has no certificate pool")
	}

	var authorities CAs
	stats := &ScanStats{}
	if !scanHTTPSHost(&authorities, u, u.Hostname(), tr.TLSClientConfig.RootCAs, stats) {
		t.Fatal("first scan did not record a CA")
	}
	if !scanHTTPSHost(&authorities, u, u.Hostname(), tr.TLSClientConfig.RootCAs, stats) {
		t.Fatal("second scan did not hit the recorded CA")
	}
	snap := stats.Snapshot()
	if snap.Attempted != 1 || snap.Succeeded != 1 || snap.Failed != 0 || snap.Reused != 1 {
		t.Fatalf("snapshot %+v", snap)
	}
	if snap.Handshakes != 1 || snap.HandshakeTotal <= 0 {
		t.Fatalf("handshake timing %+v", snap)
	}
	if len(authorities.items) != 1 {
		t.Fatalf("got %d CAs", len(authorities.items))
	}
}

func TestScanHTTPSHostIPFailureSkipsDNS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("https://" + addr)
	if err != nil {
		t.Fatal(err)
	}

	var authorities CAs
	stats := &ScanStats{}
	if scanHTTPSHost(&authorities, u, u.Hostname(), nil, stats) {
		t.Fatal("refused dial recorded a CA")
	}
	snap := stats.Snapshot()
	if snap.Attempted != 1 || snap.Failed != 1 || snap.Succeeded != 0 || snap.Reused != 0 {
		t.Fatalf("%+v", snap)
	}
	if snap.DNSLookups != 0 {
		t.Fatalf("IP dial recorded DNS: %+v", snap)
	}
	if snap.Handshakes != 1 || snap.HandshakeTotal <= 0 {
		t.Fatalf("connect timing %+v", snap)
	}
	if len(snap.FailedHosts) != 1 || snap.FailedHosts[0] != "127.0.0.1" {
		t.Fatalf("failed hosts %v", snap.FailedHosts)
	}
}

func TestScanHTTPSHostFailedNameRecordsDNS(t *testing.T) {
	var authorities CAs
	stats := &ScanStats{}
	u, err := url.Parse("https://localhost:1")
	if err != nil {
		t.Fatal(err)
	}
	if scanHTTPSHost(&authorities, u, u.Hostname(), nil, stats) {
		t.Fatal("localhost:1 recorded a CA")
	}
	snap := stats.Snapshot()
	if snap.Attempted != 1 || snap.Failed != 1 || snap.Succeeded != 0 {
		t.Fatalf("%+v", snap)
	}
	if snap.DNSLookups < 1 || snap.DNSTotal < 0 {
		t.Fatalf("expected a DNS lookup, %+v", snap)
	}
	if len(snap.FailedHosts) != 1 || snap.FailedHosts[0] != "localhost" {
		t.Fatalf("failed hosts %v", snap.FailedHosts)
	}
}

func TestScanStatsFailureListIsUnique(t *testing.T) {
	s := &ScanStats{}
	s.noteFailure("B.Example")
	s.noteFailure("b.example")
	s.noteFailure("other.example")
	s.noteFailure("  ")
	snap := s.Snapshot()
	if snap.Failed != 4 || snap.Attempted != 4 || snap.Succeeded != 0 {
		t.Fatalf("%+v", snap)
	}
	if len(snap.FailedHosts) != 2 {
		t.Fatalf("failed hosts %v", snap.FailedHosts)
	}
}

func TestDialTimingRecordsDNSAndConnect(t *testing.T) {
	timing := &dialTiming{}
	tr := timing.trace()
	tr.DNSStart(httptrace.DNSStartInfo{Host: "example.com"})
	time.Sleep(5 * time.Millisecond)
	tr.DNSDone(httptrace.DNSDoneInfo{})
	tr.ConnectStart("tcp", "127.0.0.1:443")
	time.Sleep(5 * time.Millisecond)
	dns, n, handshake, ok := timing.result()
	if n != 1 || dns <= 0 || !ok || handshake <= 0 {
		t.Fatalf("dns=%s lookups=%d handshake=%s ok=%v", dns, n, handshake, ok)
	}

	// A second lookup adds to the total. ConnectStart keeps the first stamp.
	tr.DNSStart(httptrace.DNSStartInfo{Host: "example.com"})
	time.Sleep(5 * time.Millisecond)
	tr.DNSDone(httptrace.DNSDoneInfo{})
	tr.ConnectStart("tcp", "127.0.0.1:443")
	dns2, n2, handshake2, ok2 := timing.result()
	if n2 != 2 || dns2 <= dns || !ok2 || handshake2 < handshake {
		t.Fatalf("dns=%s lookups=%d handshake=%s ok=%v (first dns=%s handshake=%s)", dns2, n2, handshake2, ok2, dns, handshake)
	}
}
