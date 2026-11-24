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

package cmd

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/allowlist/gen"
	"github.com/adamdecaf/trustprune/pkg/allowlist/preset"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

var (
	debug = os.Getenv("DEBUG") != ""

	exampleDNSNamesLength = 3
)

// allowlistFingerprintPreview is the default summary fingerprint width.
const allowlistFingerprintPreview = 16

// GenerateAllowlistOptions is the input to GenerateAllowlist.
type GenerateAllowlistOptions struct {
	Output    string
	From      string
	File      string
	Hosts     string
	Presets   string
	NoPresets bool
	// GOOS selects the default platform preset when Presets is empty and
	// NoPresets is false. Empty means runtime.GOOS.
	GOOS string
	// Verbose prints full fingerprints in the summary table. The default
	// summary keeps the first allowlistFingerprintPreview characters.
	Verbose bool
	// Stats prints connection and timing details after generation.
	Stats bool
	// statsOut receives the stats block. Nil writes to stderr.
	statsOut io.Writer
}

func GenerateAllowlist(opts GenerateAllowlistOptions) error {
	if opts.Output == "" {
		return errors.New("you need to specify --out <path>")
	}
	output, err := filepath.Abs(opts.Output)
	if err != nil {
		return err
	}

	started := time.Now()
	var stats *gen.ScanStats
	if opts.Stats {
		stats = &gen.ScanStats{}
		// Report after at least one TLS dial, including on a later error or panic.
		defer func() {
			if stats.Snapshot().Attempted == 0 {
				return
			}
			stats.SetWall(time.Since(started))
			writeAllowlistStats(opts.statsOut, stats.Snapshot())
		}()
	}

	choiceURLs, err := urlsFromChoices(opts.From, opts.File)
	if err != nil {
		return err
	}
	raw, err := collectAllowlistURLs(choiceURLs, opts)
	if err != nil {
		return err
	}
	if stats != nil {
		n, hosts := countAllowlistInput(raw)
		stats.SetInput(n, hosts)
	}
	accum := dedupeURLs(raw)

	if debug {
		fmt.Printf("getting chains for %d urls\n", len(accum))
	}

	if len(accum) == 0 {
		return errors.New("no urls found to generate allowlist from")
	}

	// Generate allowlist and write to file.
	authorities, err := gen.FindCAsWithStats(accum, nil, stats)
	if err != nil {
		return err
	}

	if len(authorities) == 0 {
		return fmt.Errorf("unable to find any CA's from %d urls retrieved", len(accum))
	}

	// prep summary. Denylisted CAs are omitted from the table and the file.
	sortCAs(authorities)
	nFound := len(authorities)
	authorities, err = dropDenylisted(os.Stdout, authorities)
	if err != nil {
		return err
	}
	if len(authorities) == 0 {
		return fmt.Errorf("all %d discovered CAs are denylisted and were skipped", nFound)
	}
	if err := writeAllowlistSummary(os.Stdout, authorities, opts.Verbose); err != nil {
		return err
	}

	acc := certutil.Pool{}
	for i := range authorities {
		acc.Add(authorities[i].Certificate)
	}

	al := allowlist.FromCertificates(acc.GetCertificates())
	return al.ToFile(output)
}

// writeAllowlistSummary prints the CA summary table. Columns are separated
// by at least two spaces, so a CA name that contains spaces stays in its
// column. verbose shows each full fingerprint; otherwise fingerprints are
// truncated to allowlistFingerprintPreview characters. A fingerprint shorter
// than that width is printed whole.
func writeAllowlistSummary(w io.Writer, authorities []*gen.CA, verbose bool) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CA\tSHA256-FINGERPRINT\tCOUNT\tEXAMPLE-DNS-NAMES")
	for i := range authorities {
		dnsNames := authorities[i].DNSNames
		if len(dnsNames) > exampleDNSNamesLength {
			dnsNames = authorities[i].DNSNames[:exampleDNSNamesLength]
		}
		row := fmt.Sprintf("%s\t%s\t%d\t%s",
			certutil.StringifyPKIXName(authorities[i].Certificate.Issuer),
			previewAllowlistFingerprint(authorities[i].Fingerprint, verbose),
			len(authorities[i].DNSNames),
			strings.Join(dnsNames, ", "),
		)
		fmt.Fprintln(tw, row)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("problem flushing output: %w", err)
	}
	return nil
}

func previewAllowlistFingerprint(fp string, verbose bool) string {
	if verbose || len(fp) <= allowlistFingerprintPreview {
		return fp
	}
	return fp[:allowlistFingerprintPreview]
}

// dropDenylisted removes CAs on the built-in denylist and writes a note for
// each one. Nil entries are dropped without a note.
func dropDenylisted(w io.Writer, cas []*gen.CA) ([]*gen.CA, error) {
	if w == nil {
		w = io.Discard
	}
	kept := make([]*gen.CA, 0, len(cas))
	for _, ca := range cas {
		if ca == nil || ca.Certificate == nil {
			continue
		}
		denied, name := allowlist.Denied(ca.Certificate)
		if !denied {
			kept = append(kept, ca)
			continue
		}
		fp := ca.Fingerprint
		if fp == "" {
			fp = certutil.GetHexSHA256Fingerprint(*ca.Certificate)
		}
		if _, err := fmt.Fprintf(w, "NOTE: skipping denylisted certificate %s sha256=%s (%s)\n",
			certutil.StringifyPKIXName(ca.Certificate.Subject), fp, name); err != nil {
			return nil, err
		}
	}
	return kept, nil
}

func getChoices(from, file string) []string {
	if !strings.Contains(from, "file") && file != "" {
		if from != "" {
			from += ","
		}
		from += "file"
	}
	if from == "" {
		return nil
	}
	return strings.Split(from, ",")
}

func urlsFromChoices(from, file string) ([]*url.URL, error) {
	choices := getChoices(from, file)
	if len(choices) == 0 {
		return nil, nil
	}

	var accum []*url.URL
	var mu sync.Mutex
	uacc := make(chan []*url.URL)
	eacc := make(chan error)

	pool := x509.NewCertPool()

	debugLog("running %d choices", len(choices))
	for i := range choices {
		opt := strings.ToLower(strings.TrimSpace(choices[i]))
		switch opt {
		case "browser", "browsers":
			debugLog("starting browser url retrieval")
			go accumulateUrls(gen.FromAllBrowsers, uacc, eacc)
			addCertsToPool(pool, gen.BrowserCAs)

		case "file":
			debugLog("grabbing urls from %s", file)
			go accumulateUrls(func() ([]*url.URL, error) {
				return gen.FromFile(file)
			}, uacc, eacc)
			list := func() ([]*x509.Certificate, error) {
				return store.Platform().List(&store.ListOptions{
					Trusted: true,
				})
			}
			addCertsToPool(pool, list)

		default:
			debugLog("starting %s url retrieval", opt)
			go accumulateUrls(func() ([]*url.URL, error) {
				return gen.FromBrowser(opt)
			}, uacc, eacc)
			addCertsToPoolForApp(pool, opt)
		}
	}

	for range choices {
		select {
		case urls := <-uacc:
			mu.Lock()
			debugLog("accumulating %d urls", len(urls))
			accum = append(accum, urls...)
			mu.Unlock()
		case err := <-eacc:
			return nil, err
		}
	}
	debugLog("cleaning up from url retrieval")
	close(uacc)
	close(eacc)
	return accum, nil
}

// assembleAllowlistURLs merges URLs already collected from --from/--file
// with --hosts and preset URLs. It does not dial TLS.
func assembleAllowlistURLs(choiceURLs []*url.URL, opts GenerateAllowlistOptions) ([]*url.URL, error) {
	raw, err := collectAllowlistURLs(choiceURLs, opts)
	if err != nil {
		return nil, err
	}
	return dedupeURLs(raw), nil
}

// collectAllowlistURLs is assembleAllowlistURLs before duplicate hosts
// are collapsed. Stats count this list.
func collectAllowlistURLs(choiceURLs []*url.URL, opts GenerateAllowlistOptions) ([]*url.URL, error) {
	extra, err := hostAndPresetURLs(opts)
	if err != nil {
		return nil, err
	}
	out := make([]*url.URL, 0, len(choiceURLs)+len(extra))
	out = append(out, choiceURLs...)
	out = append(out, extra...)
	return out, nil
}

func hostAndPresetURLs(opts GenerateAllowlistOptions) ([]*url.URL, error) {
	var out []*url.URL
	if strings.TrimSpace(opts.Hosts) != "" {
		urls, err := preset.ParseHosts(opts.Hosts)
		if err != nil {
			return nil, err
		}
		out = append(out, urls...)
	}
	names, err := resolvePresetNames(opts.Presets, opts.NoPresets, opts.GOOS)
	if err != nil {
		return nil, err
	}
	if len(names) > 0 {
		urls, err := preset.URLs(names)
		if err != nil {
			return nil, err
		}
		out = append(out, urls...)
	}
	return out, nil
}

func resolvePresetNames(presets string, noPresets bool, goos string) ([]string, error) {
	presets = strings.TrimSpace(presets)
	if noPresets && presets != "" {
		return nil, fmt.Errorf("--presets and --no-presets cannot be used together")
	}
	if noPresets {
		return nil, nil
	}
	if presets != "" {
		return preset.ParseNames(presets)
	}
	if goos == "" {
		goos = runtime.GOOS
	}
	if def := preset.DefaultName(goos); def != "" {
		return []string{def}, nil
	}
	return nil, nil
}

func dedupeURLs(urls []*url.URL) []*url.URL {
	seen := make(map[string]struct{})
	out := make([]*url.URL, 0, len(urls))
	for _, u := range urls {
		if u == nil || u.Host == "" {
			continue
		}
		key := u.Scheme + "://" + u.Host
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, u)
	}
	return out
}

func accumulateUrls(f func() ([]*url.URL, error), u chan []*url.URL, e chan error) {
	urls, err := f() // often long blocking call
	if err != nil {
		e <- err
	} else {
		debugLog("adding %d urls", len(urls))
		u <- urls
	}
}

func addCertsToPool(pool *x509.CertPool, f func() ([]*x509.Certificate, error)) {
	certs, err := f()
	if err == nil {
		for i := range certs {
			pool.AddCert(certs[i])
		}
	}
}

func addCertsToPoolForApp(pool *x509.CertPool, appName string) {
	st, err := store.ForApp(appName)
	if err != nil {
		st = store.Platform() // try and give something as a root store
	}
	list := func() ([]*x509.Certificate, error) {
		return st.List(&store.ListOptions{
			Trusted: true,
		})
	}
	addCertsToPool(pool, list)
}

func debugLog(msg string, args ...interface{}) {
	if debug {
		fmt.Printf("cmd/gen-allowlist: "+msg+"\n", args...)
	}
}

// sortableCAs defines a sorting order on gen.CA by len(CA.DNSNames) in descending order
type sortableCAs []*gen.CA

func (c sortableCAs) Len() int {
	return len(c)
}
func (c sortableCAs) Less(i, j int) bool {
	return len(c[i].DNSNames) > len(c[j].DNSNames)
}
func (c sortableCAs) Swap(i, j int) {
	c[i].DNSNames, c[j].DNSNames = c[j].DNSNames, c[i].DNSNames
}
func sortCAs(c []*gen.CA) {
	sort.Sort(sortableCAs(c))
}
