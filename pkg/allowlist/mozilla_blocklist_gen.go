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

//go:build ignore
// +build ignore

// Generates mozilla_blocklist.go from Mozilla certdata.txt.
//
// Entries are certificates certdata.txt marks CKT_NSS_NOT_TRUSTED for server
// authentication, and roots whose CKA_NSS_SERVER_DISTRUST_AFTER date has
// passed. The date is recorded on those entries. A future distrust-after
// date is left out. Run from the repository root:
//
//	CGO_ENABLED=0 go run pkg/allowlist/mozilla_blocklist_gen.go
//	CGO_ENABLED=0 go run pkg/allowlist/mozilla_blocklist_gen.go -file /path/to/certdata.txt
//
// -file reads a local certdata.txt. When -file is empty, MOZILLA_CERTDATA_FILE
// is the same override. When both are empty, the generator downloads
// mozillaCertDataURL. That URL stays the default: it is the Firefox
// certdata.txt already cited by `trustprune list --url`. The client
// disables HTTP/2 and has a deadline (a leftover workaround from when
// this fetched hg.mozilla.org, which redirected to an HTTP/1.1 hg-edge
// host that stalled Go's default HTTP/2 stack).
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"go/format"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

const mozillaCertDataTimeout = 2 * time.Minute

var (
	// mozillaCertDataURL is the certdata.txt already used by `trustprune list --url`.
	mozillaCertDataURL = "https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/nss/lib/ckfw/builtins/certdata.txt"

	outputFilename = "pkg/allowlist/mozilla_blocklist.go"
)

func main() {
	fileFlag := flag.String("file", os.Getenv("MOZILLA_CERTDATA_FILE"), "local certdata.txt to read instead of downloading (default: $MOZILLA_CERTDATA_FILE, otherwise the Mozilla URL)")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}

	when := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	who, err := user.Current()
	if err != nil {
		log.Fatalf("Unable to get user on %s", runtime.GOOS)
	}
	userName := oneLine(who.Username)
	if userName == "" {
		userName = "unknown"
	}

	body, srcLabel, err := loadMozillaCertData(*fileFlag)
	if err != nil {
		log.Fatalf("error getting mozilla certdata from %s, err=%v", srcLabel, err)
	}
	now := time.Now().UTC()
	entries, err := certutil.ParseDistrustedServerCerts(bytes.NewReader(body), now)
	if err != nil {
		log.Fatalf("error parsing mozilla certdata, err=%v", err)
	}
	if len(entries) == 0 {
		log.Fatalf("no distrusted certificates found in %s", srcLabel)
	}
	for i := range entries {
		e := entries[i]
		if !e.DistrustAfter.IsZero() && e.DistrustAfter.After(now) {
			log.Fatalf("refusing to block %s: distrust-after %s is still in the future", oneLine(e.Cert.Subject.String()), e.DistrustAfter.UTC().Format(time.RFC3339))
		}
	}
	skipped, err := countFutureDistrustAfter(body, entries)
	if err != nil {
		log.Fatalf("error counting future distrust-after certificates, err=%v", err)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, `// Copyright 2026 Adam Shannon
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

// Fingerprints are derived from Mozilla certdata.txt,
// %s
// Mozilla Public License, v. 2.0. See NOTICE.
// A certificate is included when CKA_TRUST_SERVER_AUTH is CKT_NSS_NOT_TRUSTED,
// or when CKA_NSS_SERVER_DISTRUST_AFTER had passed at generation time.
// The distrust-after date is recorded on that entry.
// Generated on %s by %s, any modifications will be overwritten
package allowlist
`, mozillaCertDataURL, when, userName)

	explicit := 0
	passed := 0
	fmt.Fprintf(&buf, "var mozillaBlocklistedFingerprints = []string{\n")
	for i := range entries {
		e := entries[i]
		fmt.Fprintf(&buf, "// %s\n", oneLine(e.Cert.Subject.String()))
		if e.NotTrusted {
			explicit++
			fmt.Fprintf(&buf, "// CKT_NSS_NOT_TRUSTED\n")
		}
		if !e.DistrustAfter.IsZero() {
			passed++
			fmt.Fprintf(&buf, "// CKA_NSS_SERVER_DISTRUST_AFTER %s\n", e.DistrustAfter.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(&buf, "`%s`,\n", certutil.GetHexSHA256Fingerprint(*e.Cert))
	}
	fmt.Fprintf(&buf, "}\n")

	fmt.Fprintf(&buf, "\n// mozillaServerDistrustAfter is CKA_NSS_SERVER_DISTRUST_AFTER for\n")
	fmt.Fprintf(&buf, "// fingerprints in mozillaBlocklistedFingerprints that have a date.\n")
	fmt.Fprintf(&buf, "// Values are UTC RFC 3339 instants recorded at generation time.\n")
	fmt.Fprintf(&buf, "var mozillaServerDistrustAfter = map[string]string{\n")
	for i := range entries {
		e := entries[i]
		if e.DistrustAfter.IsZero() {
			continue
		}
		fmt.Fprintf(&buf, "\t\"%s\": \"%s\",\n", certutil.GetHexSHA256Fingerprint(*e.Cert), e.DistrustAfter.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&buf, "}\n")

	out, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatalf("error formatting output code, err=%v", err)
	}
	if err := os.WriteFile(outputFilename, out, 0644); err != nil {
		log.Fatalf("error writing file, err=%v", err)
	}
	fmt.Fprintf(os.Stderr, "mozilla blocklist: %d certificates written to %s (%d explicitly distrusted, %d passed distrust-after, %d future distrust-after skipped) from %s\n", len(entries), outputFilename, explicit, passed, skipped, srcLabel)
}

// loadMozillaCertData reads path when it is set, and otherwise downloads the
// Mozilla URL. The returned label is the path or URL, for error messages.
func loadMozillaCertData(path string) ([]byte, string, error) {
	path = strings.TrimSpace(path)
	if path != "" {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, path, err
		}
		if len(body) == 0 {
			return nil, path, fmt.Errorf("empty certdata file %s", path)
		}
		return body, path, nil
	}
	body, err := getMozillaCertData(mozillaCertDataURL)
	if err != nil {
		return nil, mozillaCertDataURL, err
	}
	return body, mozillaCertDataURL, nil
}

// countFutureDistrustAfter reports certificates whose only reason to be
// blocked would be a CKA_NSS_SERVER_DISTRUST_AFTER instant that has not
// arrived. included is the list written at the generation cutoff.
func countFutureDistrustAfter(body []byte, included []certutil.DistrustedServerCert) (int, error) {
	far := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	all, err := certutil.ParseDistrustedServerCerts(bytes.NewReader(body), far)
	if err != nil {
		return 0, err
	}
	have := make(map[string]struct{}, len(included))
	for i := range included {
		have[certutil.GetHexSHA256Fingerprint(*included[i].Cert)] = struct{}{}
	}
	skipped := 0
	for i := range all {
		fp := certutil.GetHexSHA256Fingerprint(*all[i].Cert)
		if _, ok := have[fp]; !ok {
			skipped++
		}
	}
	return skipped, nil
}

func getMozillaCertData(u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("getMozillaCertData: can't build request for %s: %w", u, err)
	}
	req.Close = true

	// An empty TLSNextProto map disables HTTP/2. That workaround was needed
	// when this fetched hg.mozilla.org, which redirected to an HTTP/1.1
	// hg-edge host that stalled Go's default HTTP/2 client while waiting
	// for response headers. mozillaCertDataTimeout bounds the whole
	// exchange, including the body.
	client := &http.Client{
		Timeout: mozillaCertDataTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: time.Minute,
			IdleConnTimeout:       time.Minute,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			if cerr := resp.Body.Close(); cerr != nil {
				log.Println(cerr)
			}
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getMozillaCertData: unexpected status %s for %s", resp.Status, u)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getMozillaCertData: reading body: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("getMozillaCertData: empty body for %s", u)
	}
	return body, nil
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
