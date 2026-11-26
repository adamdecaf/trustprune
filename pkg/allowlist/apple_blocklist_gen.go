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

// Generates apple_blocklist.go from Apple's published blocked-certificate
// list at https://support.apple.com/en-us/103255 (the current page for the
// blocked certificates previously described via HT204132).
//
// Only the "Blocked Certificates" table is used. Constrained certificates
// on the same page are left out. Fingerprints are the SHA-256 values Apple
// published; they are not invented. Run from the repository root:
//
//	make generate
//	CGO_ENABLED=0 go run pkg/allowlist/apple_blocklist_gen.go -file pkg/allowlist/testdata/apple-blocked-certificates.html
//
// -file reads a local HTML document (also honors APPLE_BLOCKLIST_FILE).
// make generate passes the checked-in excerpt so it does not download.
// When -file and APPLE_BLOCKLIST_FILE are empty, the generator downloads
// appleBlockedCertsURL.
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
	"sort"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

const appleBlocklistTimeout = 2 * time.Minute

var (
	appleBlockedCertsURL = "https://support.apple.com/en-us/103255"
	outputFilename       = "pkg/allowlist/apple_blocklist.go"
)

func main() {
	fileFlag := flag.String("file", os.Getenv("APPLE_BLOCKLIST_FILE"), "local HTML to read instead of downloading (default: $APPLE_BLOCKLIST_FILE, otherwise the Apple support URL)")
	outFlag := flag.String("out", outputFilename, "Go source file to write")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}
	outPath := strings.TrimSpace(*outFlag)
	if outPath == "" {
		log.Fatal("-out is empty")
	}

	body, srcLabel, err := loadAppleBlockedPage(*fileFlag)
	if err != nil {
		log.Fatalf("error getting Apple blocked-certificate list from %s, err=%v", srcLabel, err)
	}
	certs, err := allowlist.ParseAppleBlockedCertificates(bytes.NewReader(body))
	if err != nil {
		log.Fatalf("error parsing Apple blocked-certificate list, err=%v", err)
	}

	sort.Slice(certs, func(i, j int) bool {
		if certs[i].Fingerprint == certs[j].Fingerprint {
			return certs[i].Name < certs[j].Name
		}
		return certs[i].Fingerprint < certs[j].Fingerprint
	})

	when := time.Now().UTC().Format("2006-01-02T15:04:05Z")
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

// Fingerprints are the SHA-256 values Apple published in the
// "Blocked Certificates" table of:
// %s
// Constrained certificates on that page are not included.
// HT204132 is the earlier Apple support article that described these lists.
// Generated on %s, any modifications will be overwritten
package allowlist

var appleBlocklistedFingerprints = []string{
`, appleBlockedCertsURL, when)

	for _, c := range certs {
		fmt.Fprintf(&buf, "\t// %s\n", oneLine(c.Name))
		fmt.Fprintf(&buf, "\t`%s`,\n", c.Fingerprint)
	}
	fmt.Fprintf(&buf, "}\n")

	out, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatalf("error formatting output code, err=%v", err)
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		log.Fatalf("error writing %s, err=%v", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "apple blocklist: %d fingerprints written to %s from %s\n", len(certs), outPath, srcLabel)
}

func loadAppleBlockedPage(path string) ([]byte, string, error) {
	path = strings.TrimSpace(path)
	if path != "" {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, path, err
		}
		if len(body) == 0 {
			return nil, path, fmt.Errorf("empty Apple blocked-certificate file %s", path)
		}
		return body, path, nil
	}
	body, err := getAppleBlockedPage(appleBlockedCertsURL)
	if err != nil {
		return nil, appleBlockedCertsURL, err
	}
	return body, appleBlockedCertsURL, nil
}

func getAppleBlockedPage(u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("getAppleBlockedPage: can't build request for %s: %w", u, err)
	}
	req.Header.Set("User-Agent", "trustprune-apple-blocklist-gen")
	req.Close = true
	client := &http.Client{
		Timeout: appleBlocklistTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
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
		return nil, fmt.Errorf("getAppleBlockedPage: unexpected status %s for %s", resp.Status, u)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getAppleBlockedPage: reading body: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("getAppleBlockedPage: empty body for %s", u)
	}
	return body, nil
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "*/", "* /")
	return strings.TrimSpace(s)
}
