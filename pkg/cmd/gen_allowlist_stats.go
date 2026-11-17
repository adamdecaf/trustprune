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
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist/gen"
)

// allowlistStatsFailedHostLimit caps the failed-host list in --stats.
const allowlistStatsFailedHostLimit = 20

func writeAllowlistStats(w io.Writer, snap gen.ScanSnapshot) {
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprint(w, formatAllowlistStats(snap))
}

func formatAllowlistStats(snap gen.ScanSnapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "stats:\n")
	fmt.Fprintf(&b, "urls: %d\n", snap.URLs)
	fmt.Fprintf(&b, "unique hosts: %d\n", snap.UniqueHosts)
	fmt.Fprintf(&b, "tls attempted: %d\n", snap.Attempted)
	fmt.Fprintf(&b, "tls succeeded: %d\n", snap.Succeeded)
	fmt.Fprintf(&b, "tls failed: %d\n", snap.Failed)
	fmt.Fprintf(&b, "reused hosts: %d\n", snap.Reused)
	fmt.Fprintf(&b, "dns: total %s, avg %s, lookups %d\n",
		snap.DNSTotal, durationAvg(snap.DNSTotal, snap.DNSLookups), snap.DNSLookups)
	fmt.Fprintf(&b, "connect+tls: total %s, avg %s, handshakes %d\n",
		snap.HandshakeTotal, durationAvg(snap.HandshakeTotal, snap.Handshakes), snap.Handshakes)
	fmt.Fprintf(&b, "roots: %d\n", snap.Roots)
	fmt.Fprintf(&b, "wall: %s\n", snap.Wall)
	if line := formatFailedHosts(snap.FailedHosts); line != "" {
		b.WriteString(line)
	}
	return b.String()
}

func formatFailedHosts(hosts []string) string {
	if len(hosts) == 0 {
		return ""
	}
	sorted := append([]string(nil), hosts...)
	sort.Strings(sorted)
	extra := 0
	if len(sorted) > allowlistStatsFailedHostLimit {
		extra = len(sorted) - allowlistStatsFailedHostLimit
		sorted = sorted[:allowlistStatsFailedHostLimit]
	}
	line := "failed hosts: " + strings.Join(sorted, ", ")
	if extra > 0 {
		line += fmt.Sprintf(" (+%d more)", extra)
	}
	return line + "\n"
}

func durationAvg(total time.Duration, n int) time.Duration {
	if n <= 0 {
		return 0
	}
	return total / time.Duration(n)
}

// countAllowlistInput counts URL entries with a host, and distinct
// hostnames. Comparison ignores case. The count is before dedupe.
func countAllowlistInput(urls []*url.URL) (n, hosts int) {
	seen := make(map[string]struct{})
	for _, u := range urls {
		if u == nil || u.Host == "" {
			continue
		}
		n++
		h := strings.ToLower(u.Hostname())
		if h == "" {
			continue
		}
		seen[h] = struct{}{}
	}
	return n, len(seen)
}
