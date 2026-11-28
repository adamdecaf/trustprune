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

// Generates a baseline allowlist of Mozilla certdata.txt roots that
// actually anchor TLS chains of popular websites.
//
// The scan dials the network. make allowlists and make generate stay
// offline and do not run this tool. From the repository root:
//
//	make web-allowlist LIST=/path/to/tranco.csv LIST_ID=947L2 N=50000 \
//	  LIST_URL=https://tranco-list.eu/download/947L2/100000 \
//	  LIST_DATE='2026-11-27 (window 2026-10-29 to 2026-11-27)'
//	CGO_ENABLED=0 go run pkg/allowlist/web_allowlist_gen.go -list /path/to/tranco.csv \
//	  -certdata testdata/certdata.txt.gz -out docs/downloads/allowlists/web.yaml
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist/webscan"
)

const (
	defaultOut      = "docs/downloads/allowlists/web.yaml"
	defaultCertdata = "testdata/certdata.txt.gz"
)

func main() {
	listFlag := flag.String("list", "", "local top-sites CSV (rank,domain), as published by Tranco")
	nFlag := flag.Int("n", 0, "max sites to scan from the list (0 means the whole file)")
	thresholdFlag := flag.Int("threshold", 1, "include roots that anchored at least this many successful sites")
	certdataFlag := flag.String("certdata", defaultCertdata, "Mozilla certdata.txt or certdata.txt.gz used as the only trust store")
	outFlag := flag.String("out", defaultOut, "allowlist YAML to write")
	workersFlag := flag.Int("workers", 64, "concurrent TLS handshakes")
	timeoutFlag := flag.Duration("timeout", 8*time.Second, "per-site dial and handshake timeout")
	listNameFlag := flag.String("list-name", "Tranco", "source list name for the YAML header")
	listIDFlag := flag.String("list-id", "", "source list ID for the YAML header")
	listURLFlag := flag.String("list-url", "", "source list URL for the YAML header")
	listDateFlag := flag.String("list-date", "", "source list date or date window for the YAML header")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}

	listPath := strings.TrimSpace(*listFlag)
	if listPath == "" {
		log.Fatal("-list is required")
	}
	outPath := strings.TrimSpace(*outFlag)
	if outPath == "" {
		log.Fatal("-out is empty")
	}
	certdataPath := strings.TrimSpace(*certdataFlag)
	if certdataPath == "" {
		log.Fatal("-certdata is empty")
	}
	if *workersFlag < 1 {
		log.Fatal("-workers must be at least 1")
	}
	if *timeoutFlag <= 0 {
		log.Fatal("-timeout must be greater than 0")
	}
	threshold := *thresholdFlag
	if threshold < 1 {
		threshold = 1
	}

	hosts, err := loadHosts(listPath, *nFlag)
	if err != nil {
		log.Fatalf("reading %s: %v", listPath, err)
	}
	if len(hosts) == 0 {
		log.Fatalf("no hosts in %s", listPath)
	}

	pool, known, err := webscan.LoadMozillaRootsFile(certdataPath)
	if err != nil {
		log.Fatalf("loading mozilla roots from %s: %v", certdataPath, err)
	}
	log.Printf("loaded %d mozilla trusted-server roots from %s; scanning %d hosts with %d workers, timeout %s, threshold %d",
		len(known), certdataPath, len(hosts), *workersFlag, *timeoutFlag, threshold)

	counts, success, dialFail, verifyFail, distrusted := scanHosts(hosts, pool, known, *workersFlag, *timeoutFlag)
	rep := webscan.Report{
		ListName:       strings.TrimSpace(*listNameFlag),
		ListID:         strings.TrimSpace(*listIDFlag),
		ListURL:        strings.TrimSpace(*listURLFlag),
		ListDate:       strings.TrimSpace(*listDateFlag),
		CertdataSource: certdataPath,
		N:              len(hosts),
		Success:        success,
		Distrusted:     distrusted,
		Threshold:      threshold,
		Roots:          counts.Above(threshold),
		Observed:       counts.All(),
	}
	body, err := rep.EncodeYAML()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(outPath, body, 0o644); err != nil {
		log.Fatalf("writing %s: %v", outPath, err)
	}

	log.Printf("wrote %s: success=%d/%d (%.1f%%) dial_fail=%d verify_fail=%d distrusted=%d roots_observed=%d roots_in_allowlist=%d (threshold >= %d)",
		outPath, success, len(hosts), 100*float64(success)/float64(len(hosts)), dialFail, verifyFail, distrusted, len(rep.Observed), len(rep.Roots), threshold)
	for i, rc := range rep.Observed {
		if i >= 10 {
			break
		}
		log.Printf("  %6d  %s  %s", rc.Sites, rc.SHA256, rc.Subject)
	}
}

func loadHosts(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := webscan.ParseTopSitesCSV(f, limit)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, h := range raw {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out, nil
}

func scanHosts(hosts []string, pool *x509.CertPool, known map[string]*webscan.Root, workers int, timeout time.Duration) (counts *webscan.Counts, success, dialFail, verifyFail, distrusted int) {
	counts = webscan.NewCounts()
	jobs := make(chan string)
	var (
		mu        sync.Mutex
		done      atomic.Int32
		succA     atomic.Int32
		dialA     atomic.Int32
		verifyA   atomic.Int32
		distrustA atomic.Int32
	)
	total := len(hosts)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				root, kind := scanHost(host, pool, known, timeout)
				switch kind {
				case resultSuccess:
					succA.Add(1)
					mu.Lock()
					counts.Add(root)
					mu.Unlock()
				case resultDialFail:
					dialA.Add(1)
				case resultDistrusted:
					distrustA.Add(1)
				default:
					verifyA.Add(1)
				}
				n := int(done.Add(1))
				if n%1000 == 0 || n == total {
					s, d, v, x := succA.Load(), dialA.Load(), verifyA.Load(), distrustA.Load()
					log.Printf("progress %d/%d success=%d dial_fail=%d verify_fail=%d distrusted=%d", n, total, s, d, v, x)
				}
			}
		}()
	}
	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)
	wg.Wait()
	return counts, int(succA.Load()), int(dialA.Load()), int(verifyA.Load()), int(distrustA.Load())
}

type resultKind int

const (
	resultSuccess resultKind = iota
	resultDialFail
	resultVerifyFail
	resultDistrusted
)

func scanHost(host string, pool *x509.CertPool, known map[string]*webscan.Root, timeout time.Duration) (*webscan.Root, resultKind) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addr := net.JoinHostPort(host, "443")
	d := &net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, resultDialFail
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // verification is against the pinned Mozilla roots below
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, resultDialFail
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, resultVerifyFail
	}
	leaf := state.PeerCertificates[0]
	intermediates := state.PeerCertificates[1:]
	root, distrusted := webscan.VerifyChain(leaf, intermediates, host, pool, known, time.Time{})
	if distrusted {
		return root, resultDistrusted
	}
	if root == nil {
		return nil, resultVerifyFail
	}
	return root, resultSuccess
}
