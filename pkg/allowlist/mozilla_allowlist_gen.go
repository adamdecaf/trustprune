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

// Generates a baseline allowlist of Mozilla certdata.txt roots trusted for
// TLS server authentication.
//
// Fingerprints are SHA-256 of each certificate's DER, lowercase hex, sorted
// ascending. Run from the repository root:
//
//	make allowlists
//	CGO_ENABLED=0 go run pkg/allowlist/mozilla_allowlist_gen.go -file testdata/certdata.txt.gz
//
// -file reads a local certdata.txt or a gzip-compressed .gz. When -file is
// empty, MOZILLA_CERTDATA_FILE is the same override. When both are empty,
// the generator downloads mozillaCertDataURL. make allowlists and make
// generate pass testdata/certdata.txt.gz so they do not download.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

const mozillaCertDataTimeout = 2 * time.Minute

var (
	// mozillaCertDataURL is the certdata.txt tip already used by `trustprune list --url`.
	mozillaCertDataURL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

	defaultAllowlistOut = "docs/downloads/allowlists/mozilla-included.yaml"
)

func main() {
	fileFlag := flag.String("file", os.Getenv("MOZILLA_CERTDATA_FILE"), "local certdata.txt or certdata.txt.gz (default: $MOZILLA_CERTDATA_FILE, otherwise the Mozilla URL)")
	outFlag := flag.String("out", defaultAllowlistOut, "allowlist YAML to write")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}
	outPath := strings.TrimSpace(*outFlag)
	if outPath == "" {
		log.Fatal("-out is empty")
	}

	body, srcLabel, err := loadMozillaCertData(*fileFlag)
	if err != nil {
		log.Fatalf("error getting mozilla certdata from %s, err=%v", srcLabel, err)
	}
	certs, err := certutil.ParseTrustedServerCerts(bytes.NewReader(body))
	if err != nil {
		log.Fatalf("error parsing mozilla certdata, err=%v", err)
	}
	if len(certs) == 0 {
		log.Fatalf("no trusted server certificates found in %s", srcLabel)
	}

	fps := make([]string, 0, len(certs))
	dated := 0
	for i := range certs {
		c := certs[i].Cert
		if c == nil || len(c.Raw) == 0 {
			subj := ""
			if c != nil {
				subj = oneLine(c.Subject.String())
			}
			log.Fatalf("certificate %d has empty DER (%s)", i, subj)
		}
		if !certs[i].ServerDistrustAfter.IsZero() {
			dated++
		}
		sum := sha256.Sum256(c.Raw)
		fp := hex.EncodeToString(sum[:])
		if !hexFingerprint(fp) {
			log.Fatalf("certificate %d fingerprint %q is not lowercase hex", i, fp)
		}
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, `# Baseline allowlist of Mozilla certdata.txt roots trusted for TLS server authentication.
# Source: %s
# Upstream: %s
# Regenerate: make allowlists
#   or: CGO_ENABLED=0 go run pkg/allowlist/mozilla_allowlist_gen.go -file testdata/certdata.txt.gz
# Fingerprints are SHA-256 of the certificate DER.
# Applying this allowlist still honors trustprune's built-in denylist and the Chromium and Mozilla blocklists.
# certdata.txt is MPL-2.0. NOTICE already credits it.
# This file has no Jekyll front matter so the docs site can serve it unchanged.
fingerprints:
`, srcLabel, mozillaCertDataURL)
	for _, fp := range fps {
		fmt.Fprintf(&buf, "  - \"%s\"\n", fp)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		log.Fatalf("error creating %s, err=%v", filepath.Dir(outPath), err)
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		log.Fatalf("error writing %s, err=%v", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "mozilla allowlist: %d fingerprints written to %s (%d with server distrust-after still included) from %s\n", len(fps), outPath, dated, srcLabel)
}

// loadMozillaCertData reads path when it is set, and otherwise downloads the
// Mozilla URL. A .gz path, or a body with a gzip header, is decompressed.
// The returned label is the path or URL, for error messages and the file header.
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
		plain, err := gunzipIfNeeded(path, body)
		if err != nil {
			return nil, path, err
		}
		return plain, path, nil
	}
	body, err := getMozillaCertData(mozillaCertDataURL)
	if err != nil {
		return nil, mozillaCertDataURL, err
	}
	plain, err := gunzipIfNeeded(mozillaCertDataURL, body)
	if err != nil {
		return nil, mozillaCertDataURL, err
	}
	return plain, mozillaCertDataURL, nil
}

func gunzipIfNeeded(path string, body []byte) ([]byte, error) {
	gzipName := strings.HasSuffix(strings.ToLower(path), ".gz")
	gzipMagic := len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b
	if !gzipName && !gzipMagic {
		return body, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("reading gzip certdata %s: %w", path, err)
	}
	out, err := io.ReadAll(r)
	cerr := r.Close()
	if err != nil {
		return nil, fmt.Errorf("reading gzip certdata %s: %w", path, err)
	}
	if cerr != nil {
		return nil, fmt.Errorf("closing gzip certdata %s: %w", path, cerr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty certdata after gzip decompress %s", path)
	}
	return out, nil
}

func getMozillaCertData(u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("getMozillaCertData: can't build request for %s: %w", u, err)
	}
	req.Close = true

	// hg.mozilla.org redirects to hg-edge.mozilla.org. That edge host answers
	// HTTP/1.1 and stalls the default Go HTTP/2 client while it waits for
	// response headers. An empty TLSNextProto map disables HTTP/2.
	// mozillaCertDataTimeout bounds the whole exchange, including the body.
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

func hexFingerprint(fp string) bool {
	if len(fp) != sha256.Size*2 {
		return false
	}
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
