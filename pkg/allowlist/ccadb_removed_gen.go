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

// Generates ccadb_removed_blocklist.go from the CCADB Mozilla Removed CA
// Certificate Report CSV.
//
// The report has no structured removal-reason column. Comments is free text.
// Every row is included except those whose Comments indicate the removal is
// only expiry or a voluntary / CA-requested withdrawal. A row is excluded
// when Comments matches (case-insensitive): expir, voluntar, asking for the
// removal, requested (the )?removal, or at the (ca|certificate authority).{0,40}request.
// Empty comments are kept. Fingerprints are the SHA-256 Fingerprint column,
// lowercase hex. Run from the repository root:
//
//	make denylists
//	CGO_ENABLED=0 go run pkg/allowlist/ccadb_removed_gen.go -file pkg/allowlist/testdata/ccadb-removed-ca-certificates.csv
//
// -file reads a local CSV. When -file is empty, CCADB_REMOVED_FILE is the
// same override. When both are empty, the generator downloads
// ccadbRemovedCSVURL. make denylists and make generate pass the checked-in
// CSV so they do not download.
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

const ccadbRemovedTimeout = 2 * time.Minute

var (
	// ccadbRemovedCSVURL is the official Mozilla Removed CA Certificate Report
	// listed from https://wiki.mozilla.org/CA/Removed_Certificates
	ccadbRemovedCSVURL = "https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportCSVFormat"

	defaultCCADBRemovedOut = "pkg/allowlist/ccadb_removed_blocklist.go"
)

func main() {
	fileFlag := flag.String("file", os.Getenv("CCADB_REMOVED_FILE"), "local CCADB Removed CA Certificate Report CSV (default: $CCADB_REMOVED_FILE, otherwise the official URL)")
	outFlag := flag.String("out", defaultCCADBRemovedOut, "Go source to write")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}
	outPath := strings.TrimSpace(*outFlag)
	if outPath == "" {
		log.Fatal("-out is empty")
	}

	body, srcLabel, err := loadCCADBRemovedCSV(*fileFlag)
	if err != nil {
		log.Fatalf("error getting CCADB removed CA report from %s, err=%v", srcLabel, err)
	}
	fps, err := allowlist.ParseCCADBRemovedRoots(bytes.NewReader(body))
	if err != nil {
		log.Fatalf("error parsing CCADB removed CA report, err=%v", err)
	}
	if len(fps) == 0 {
		log.Fatalf("no fingerprints found in %s", srcLabel)
	}
	sort.Strings(fps)

	when := time.Now().UTC().Format(time.RFC3339)

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

// Fingerprints are derived from the Common CA Database (CCADB) Mozilla
// Removed CA Certificate Report,
// %s
// listed from https://wiki.mozilla.org/CA/Removed_Certificates
// See NOTICE (CDLA-2.0 Permissive).
// The report has no structured removal-reason column. Comments is free text.
// Every row is included except those whose Comments indicate the removal is
// only expiry or a voluntary / CA-requested withdrawal. A row is excluded
// when Comments matches (case-insensitive):
//
//	expir
//	voluntar
//	asking for the removal
//	requested (the )?removal
//	at the (ca|certificate authority).{0,40}request
//
// Empty comments are kept. "Trust bit turned off" and other non-matching
// comments are kept. Fingerprints are the SHA-256 Fingerprint column,
// lowercase hex. The Subject + SPKI SHA256 column is not used.
// Generated on %s, any modifications will be overwritten
package allowlist
`, ccadbRemovedCSVURL, when)

	fmt.Fprintf(&buf, "var ccadbRemovedBlocklistedFingerprints = []string{\n")
	for _, fp := range fps {
		fmt.Fprintf(&buf, "\t`%s`,\n", fp)
	}
	fmt.Fprintf(&buf, "}\n")

	out, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatalf("error formatting output code, err=%v", err)
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		log.Fatalf("error writing file, err=%v", err)
	}
	fmt.Fprintf(os.Stderr, "ccadb removed CA blocklist: %d fingerprints written to %s from %s\n", len(fps), outPath, srcLabel)
}

// loadCCADBRemovedCSV reads path when it is set, and otherwise downloads the
// official report URL. The returned label is the path or URL, for error messages.
func loadCCADBRemovedCSV(path string) ([]byte, string, error) {
	path = strings.TrimSpace(path)
	if path != "" {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, path, err
		}
		if len(body) == 0 {
			return nil, path, fmt.Errorf("empty CCADB removed CA report %s", path)
		}
		return body, path, nil
	}
	body, err := getCCADBRemovedCSV(ccadbRemovedCSVURL)
	if err != nil {
		return nil, ccadbRemovedCSVURL, err
	}
	return body, ccadbRemovedCSVURL, nil
}

func getCCADBRemovedCSV(u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("getCCADBRemovedCSV: can't build request for %s: %w", u, err)
	}
	req.Close = true

	client := &http.Client{
		Timeout: ccadbRemovedTimeout,
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
		return nil, fmt.Errorf("getCCADBRemovedCSV: unexpected status %s for %s", resp.Status, u)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getCCADBRemovedCSV: reading body: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("getCCADBRemovedCSV: empty body for %s", u)
	}
	return body, nil
}
