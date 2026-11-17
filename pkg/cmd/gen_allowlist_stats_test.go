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

package cmd

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist/gen"
)

func TestFormatAllowlistStats(t *testing.T) {
	got := formatAllowlistStats(gen.ScanSnapshot{
		URLs:           4,
		UniqueHosts:    3,
		Attempted:      2,
		Succeeded:      1,
		Failed:         2,
		Reused:         1,
		DNSTotal:       30 * time.Millisecond,
		DNSLookups:     2,
		HandshakeTotal: 100 * time.Millisecond,
		Handshakes:     2,
		Roots:          1,
		Wall:           250 * time.Millisecond,
		FailedHosts:    []string{"b.example", "a.example"},
	})
	want := `stats:
urls: 4
unique hosts: 3
tls attempted: 2
tls succeeded: 1
tls failed: 2
reused hosts: 1
dns: total 30ms, avg 15ms, lookups 2
connect+tls: total 100ms, avg 50ms, handshakes 2
roots: 1
wall: 250ms
failed hosts: a.example, b.example
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestFormatAllowlistStatsOmitsEmptyFailures(t *testing.T) {
	got := formatAllowlistStats(gen.ScanSnapshot{})
	want := `stats:
urls: 0
unique hosts: 0
tls attempted: 0
tls succeeded: 0
tls failed: 0
reused hosts: 0
dns: total 0s, avg 0s, lookups 0
connect+tls: total 0s, avg 0s, handshakes 0
roots: 0
wall: 0s
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, "failed hosts:") {
		t.Fatalf("empty failure list should be omitted:\n%s", got)
	}
}

func TestFormatAllowlistStatsCapsFailedHosts(t *testing.T) {
	hosts := make([]string, 23)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%02d.example", 22-i)
	}
	got := formatAllowlistStats(gen.ScanSnapshot{FailedHosts: hosts})
	shown := make([]string, allowlistStatsFailedHostLimit)
	for i := range shown {
		shown[i] = fmt.Sprintf("h%02d.example", i)
	}
	wantLine := "failed hosts: " + strings.Join(shown, ", ") + " (+3 more)\n"
	if !strings.HasSuffix(got, wantLine) {
		t.Fatalf("failed-host line:\n%s\nwant suffix:\n%s", got, wantLine)
	}
	if strings.Contains(got, "h20.example") || strings.Contains(got, "h21.example") || strings.Contains(got, "h22.example") {
		t.Fatalf("capped hosts leaked:\n%s", got)
	}
}

func TestCountAllowlistInput(t *testing.T) {
	must := func(s string) *url.URL {
		t.Helper()
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	n, hosts := countAllowlistInput([]*url.URL{
		must("https://Example.com/a"),
		must("https://example.com/b"),
		must("https://api.example.com:8443/x"),
		must("http://other.example"),
		nil,
		must("https:///no-host"),
	})
	if n != 4 || hosts != 3 {
		t.Fatalf("urls=%d hosts=%d", n, hosts)
	}
}

func TestGenerateAllowlistStats(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	hosts := fmt.Sprintf("127.0.0.1:%d,127.0.0.1:%d", port, port)

	t.Run("off leaves stats empty", func(t *testing.T) {
		var buf bytes.Buffer
		out := filepath.Join(t.TempDir(), "allowlist.yaml")
		err := GenerateAllowlist(GenerateAllowlistOptions{
			Output:    out,
			Hosts:     hosts,
			NoPresets: true,
			GOOS:      "freebsd",
			statsOut:  &buf,
		})
		if err == nil || !strings.Contains(err.Error(), "unable to find any") {
			t.Fatalf("err=%v", err)
		}
		if buf.Len() != 0 {
			t.Fatalf("stats written without --stats:\n%s", buf.String())
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Fatalf("wrote %s: %v", out, statErr)
		}
	})

	t.Run("on reports the refused dial", func(t *testing.T) {
		var buf bytes.Buffer
		out := filepath.Join(t.TempDir(), "allowlist.yaml")
		err := GenerateAllowlist(GenerateAllowlistOptions{
			Output:    out,
			Hosts:     hosts,
			NoPresets: true,
			GOOS:      "freebsd",
			Stats:     true,
			statsOut:  &buf,
		})
		if err == nil || !strings.Contains(err.Error(), "unable to find any") {
			t.Fatalf("err=%v", err)
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Fatalf("wrote %s: %v", out, statErr)
		}
		got := buf.String()
		for _, line := range []string{
			"stats:\n",
			"urls: 2\n",
			"unique hosts: 1\n",
			"tls attempted: 1\n",
			"tls succeeded: 0\n",
			"tls failed: 1\n",
			"reused hosts: 0\n",
			"roots: 0\n",
			"failed hosts: 127.0.0.1\n",
		} {
			if !strings.Contains(got, line) {
				t.Fatalf("missing %q in:\n%s", line, got)
			}
		}
		if !strings.Contains(got, "connect+tls: total ") || !strings.Contains(got, "handshakes 1\n") {
			t.Fatalf("handshake line:\n%s", got)
		}
		if !strings.Contains(got, "dns: total 0s, avg 0s, lookups 0\n") {
			t.Fatalf("dns line:\n%s", got)
		}
		if !strings.Contains(got, "wall: ") || strings.Contains(got, "wall: 0s\n") {
			t.Fatalf("wall line:\n%s", got)
		}
	})
}

func TestGenerateAllowlistStatsBeforeScan(t *testing.T) {
	var buf bytes.Buffer
	err := GenerateAllowlist(GenerateAllowlistOptions{
		Output:    filepath.Join(t.TempDir(), "allowlist.yaml"),
		NoPresets: true,
		GOOS:      "freebsd",
		Stats:     true,
		statsOut:  &buf,
	})
	if err == nil || !strings.Contains(err.Error(), "no urls") {
		t.Fatalf("err=%v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("stats printed before a dial:\n%s", buf.String())
	}
}
