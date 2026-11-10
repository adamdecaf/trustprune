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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/allowlist/gen"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

var (
	debug = os.Getenv("DEBUG") != ""

	exampleDNSNamesLength = 3
)

func GenerateAllowlist(output string, from, file string) error {
	if output == "" || (from == "" && file == "") {
		return errors.New("you need to specify --out <path> and either --from or --file")
	}
	output, err := filepath.Abs(output)
	if err != nil {
		return err
	}

	var accum []*url.URL
	var mu sync.Mutex
	uacc := make(chan []*url.URL)
	eacc := make(chan error)

	pool := x509.NewCertPool()

	choices := getChoices(from, file)
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
			return err
		}
	}
	debugLog("cleaning up from url retrieval")
	close(uacc)
	close(eacc)

	if debug {
		fmt.Printf("getting chains for %d urls\n", len(accum))
	}

	if len(accum) == 0 {
		return errors.New("no urls found to generate allowlist from")
	}

	// Generate allowlist and write to file
	authorities, err := gen.FindCAs(accum, nil)
	if err != nil {
		return err
	}

	if len(authorities) == 0 {
		return fmt.Errorf("unable to find any CA's from %d urls retrieved", len(accum))
	}

	// prep summary
	sortCAs(authorities)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "CA\tFingerprint\tCount\tExample DNSNames")

	acc := certutil.Pool{}
	for i := range authorities {
		acc.Add(authorities[i].Certificate)

		// print sumamry
		dnsNames := authorities[i].DNSNames
		if len(dnsNames) > exampleDNSNamesLength {
			dnsNames = authorities[i].DNSNames[:exampleDNSNamesLength]
		}

		row := fmt.Sprintf("%s\t%s\t%d\t%s",
			certutil.StringifyPKIXName(authorities[i].Certificate.Issuer),
			authorities[i].Fingerprint[:16],
			len(authorities[i].DNSNames),
			strings.Join(dnsNames, ", "),
		)
		fmt.Fprintln(w, row)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("problem flushing output: %w", err)
	}

	al := allowlist.FromCertificates(acc.GetCertificates())
	return al.ToFile(output)
}

func getChoices(from, file string) []string {
	if !strings.Contains(from, "file") && file != "" {
		if from != "" {
			from += ","
		}
		from += "file"
	}
	return strings.Split(from, ",")
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
