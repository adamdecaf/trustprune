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

//go:build ignore
// +build ignore

// Generates blocklist.go from Chromium's net/data/ssl/blocklist.
//
// CERTIFICATE PEM files become certificate SHA-256 fingerprints. PUBLIC KEY
// .key files become SPKI SHA-256 hashes. Hashes are computed from the file
// bytes; filenames are never used as fingerprints.
//
// Run from the repository root:
//
//	make generate
//	CGO_ENABLED=0 go run pkg/allowlist/blocklist_gen.go -file pkg/allowlist/testdata/chromium-ssl-blocklist.tar.gz
//
// -file reads a local tarball (also honors CHROMIUM_BLOCKLIST_FILE). When
// -file and CHROMIUM_BLOCKLIST_FILE are empty, the generator downloads the
// Chromium archive. make generate passes the checked-in tarball so it does
// not download.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

const chromiumBlocklistTimeout = 2 * time.Minute

var (
	chromiumBlocklistBase = "https://chromium.googlesource.com/chromium/src"

	defaultChromiumBlocklistOut = "pkg/allowlist/blocklist.go"
)

func main() {
	fileFlag := flag.String("file", os.Getenv("CHROMIUM_BLOCKLIST_FILE"), "local Chromium net/data/ssl/blocklist tarball (default: $CHROMIUM_BLOCKLIST_FILE, otherwise the Chromium archive URL)")
	outFlag := flag.String("out", defaultChromiumBlocklistOut, "Go source to write")
	commitFlag := flag.String("commit", "", "Chromium src commit hash recorded in the generated header")
	dateFlag := flag.String("date", "", "source date recorded in the generated header (UTC RFC 3339 or YYYY-MM-DD)")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}
	outPath := strings.TrimSpace(*outFlag)
	if outPath == "" {
		log.Fatal("-out is empty")
	}
	commit := strings.TrimSpace(*commitFlag)
	date := strings.TrimSpace(*dateFlag)

	body, srcLabel, err := loadChromiumBlocklist(*fileFlag, commit)
	if err != nil {
		log.Fatalf("error getting chromium blocklist from %s, err=%v", srcLabel, err)
	}
	parsed, err := allowlist.ParseChromiumBlocklistArchive(bytes.NewReader(body), srcLabel)
	if err != nil {
		log.Fatalf("error parsing chromium blocklist from %s, err=%v", srcLabel, err)
	}
	if len(parsed.Certs) == 0 && len(parsed.SPKIs) == 0 {
		log.Fatalf("no certificates or public keys found in %s", srcLabel)
	}

	fps := make([]string, len(parsed.Certs))
	for i, it := range parsed.Certs {
		fps[i] = it.SHA256
	}
	appleN, ccadbN, bothN, eitherN := allowlist.ChromiumFingerprintOverlap(fps)

	when := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	sourceURL := chromiumBlocklistBase + "/+/main/net/data/ssl/blocklist/"
	if commit != "" {
		sourceURL = chromiumBlocklistBase + "/+/" + commit + "/net/data/ssl/blocklist/"
	}

	var buf strings.Builder
	fmt.Fprintf(&buf, `// Copyright 2018 Adam Shannon
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

// Certificate SHA-256 fingerprints and SPKI SHA-256 hashes from Chromium's
// net/data/ssl/blocklist, Copyright The Chromium Authors, used under a
// BSD-style license. See NOTICE.
// Source: %s
// Source archive: %s
`, sourceURL, srcLabel)
	if commit != "" {
		fmt.Fprintf(&buf, "// Chromium src commit: %s\n", commit)
	}
	if date != "" {
		fmt.Fprintf(&buf, "// Chromium list date: %s\n", date)
	}
	fmt.Fprintf(&buf, `// Generated on %s, any modifications will be overwritten
// Certificate PEMs are matched by certificate SHA-256. Standalone public
// key files (.key) are matched by the SHA-256 of the SubjectPublicKeyInfo.
// Hashes are computed from the file bytes, never from the filename.
// %d certificate fingerprints also appear on the Apple or CCADB blocklists
// (%d Apple, %d CCADB, %d on both). Those entries are kept so BlocklistNames
// can report the Chromium source.
package allowlist

var blocklistedFingerprints = []string{
`, when, eitherN, appleN, ccadbN, bothN)

	for _, it := range parsed.Certs {
		fmt.Fprintf(&buf, "\t// %s\n", it.Comment)
		fmt.Fprintf(&buf, "\t`%s`,\n", it.SHA256)
	}
	fmt.Fprintf(&buf, "}\n\n")
	fmt.Fprintf(&buf, "// blocklistedSPKIs is the SHA-256 of each standalone PUBLIC KEY\n")
	fmt.Fprintf(&buf, "// in Chromium's net/data/ssl/blocklist. A certificate matches when\n")
	fmt.Fprintf(&buf, "// the SHA-256 of its SubjectPublicKeyInfo is in this list.\n")
	fmt.Fprintf(&buf, "var blocklistedSPKIs = []string{\n")
	for _, it := range parsed.SPKIs {
		fmt.Fprintf(&buf, "\t// %s\n", it.Comment)
		fmt.Fprintf(&buf, "\t`%s`,\n", it.SHA256)
	}
	fmt.Fprintf(&buf, "}\n")

	out, err := format.Source([]byte(buf.String()))
	if err != nil {
		log.Fatalf("error formatting output code, err=%v", err)
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		log.Fatalf("error writing %s, err=%v", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "chromium blocklist: %d certificate fingerprints, %d SPKIs written to %s from %s (overlap Apple=%d CCADB=%d both=%d either=%d)\n",
		len(parsed.Certs), len(parsed.SPKIs), outPath, srcLabel, appleN, ccadbN, bothN, eitherN)
}

func loadChromiumBlocklist(path, commit string) ([]byte, string, error) {
	path = strings.TrimSpace(path)
	if path != "" {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, path, err
		}
		if len(body) == 0 {
			return nil, path, fmt.Errorf("empty chromium blocklist file %s", path)
		}
		return body, path, nil
	}
	ref := "main"
	if commit != "" {
		ref = commit
	}
	u := chromiumBlocklistBase + "/+archive/" + ref + "/net/data/ssl/blocklist.tar.gz"
	body, err := getChromiumBlocklist(u)
	if err != nil {
		return nil, u, err
	}
	return body, u, nil
}

func getChromiumBlocklist(u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("getChromiumBlocklist: can't build request for %s: %w", u, err)
	}
	req.Close = true
	client := &http.Client{Timeout: chromiumBlocklistTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getChromiumBlocklist: unexpected status %s for %s", resp.Status, u)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20+1))
}
