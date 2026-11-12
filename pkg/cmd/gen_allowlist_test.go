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
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist/gen"
)

func TestGenAllowlist_getChoices(t *testing.T) {
	t.Parallel()

	// left off '-from file'
	choices := getChoices("", "/dev/null")
	if !reflect.DeepEqual(choices, []string{"file"}) {
		t.Errorf("got %q", choices)
	}

	// has '-from file'
	choices = getChoices("file", "/dev/null")
	if !reflect.DeepEqual(choices, []string{"file"}) {
		t.Errorf("got %q", choices)
	}

	// browser
	choices = getChoices("browser", "")
	if !reflect.DeepEqual(choices, []string{"browser"}) {
		t.Errorf("got %q", choices)
	}

	// comma separated list
	choices = getChoices("browser,file", "")
	if !reflect.DeepEqual(choices, []string{"browser", "file"}) {
		t.Errorf("got %q", choices)
	}

	// neither --from nor --file
	choices = getChoices("", "")
	if choices != nil {
		t.Errorf("got %q", choices)
	}
}

func TestGenAllowlist_accumulateUrls(t *testing.T) {
	t.Parallel()

	uacc := make(chan []*url.URL)
	eacc := make(chan error)
	wg := sync.WaitGroup{}

	// happy path
	fn := func() ([]*url.URL, error) {
		defer wg.Done()
		u, _ := url.Parse("https://github.com")
		return []*url.URL{u}, nil
	}
	wg.Add(1)
	go accumulateUrls(fn, uacc, eacc)
	wg.Wait() // just so we ensure the code finished

	select {
	case urls := <-uacc:
		if len(urls) != 1 {
			t.Errorf("got %q", urls)
		}
	case err := <-eacc:
		t.Error(err)
	}

	// unhappy path
	fn = func() ([]*url.URL, error) {
		defer wg.Done()
		return nil, errors.New("whoops")
	}
	wg.Add(1)
	go accumulateUrls(fn, uacc, eacc)
	wg.Wait() // just so we ensure the code finished

	select {
	case urls := <-uacc:
		t.Errorf("expected error, got %q", urls)
	case err := <-eacc:
		if !strings.Contains(err.Error(), "whoops") {
			t.Errorf("got %q", err)
		}
	}
}

func TestAssembleAllowlistURLs(t *testing.T) {
	t.Parallel()

	mustURL := func(s string) *url.URL {
		t.Helper()
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	fileURLs := []*url.URL{
		mustURL("https://google.com"),
		mustURL("https://yahoo.com"),
	}

	t.Run("hosts plus default GOOS linux", func(t *testing.T) {
		got, err := assembleAllowlistURLs(fileURLs, GenerateAllowlistOptions{
			Hosts: "example.com,api.example.com",
			GOOS:  "linux",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !hasURL(got, "https://google.com") || !hasURL(got, "https://example.com") || !hasURL(got, "https://archive.ubuntu.com") {
			t.Errorf("missing expected urls: %q", urlStrings(got))
		}
		if !hasURL(got, "https://api.example.com") {
			t.Errorf("missing host: %q", urlStrings(got))
		}
	})

	t.Run("explicit presets ignore GOOS", func(t *testing.T) {
		got, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Hosts:   "example.com",
			Presets: "linux",
			GOOS:    "darwin",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !hasURL(got, "https://example.com") || !hasURL(got, "https://archive.ubuntu.com") {
			t.Errorf("got %q", urlStrings(got))
		}
		if hasURL(got, "https://apple.com") {
			t.Errorf("darwin hosts leaked into linux presets: %q", urlStrings(got))
		}
	})

	t.Run("no-presets skips default GOOS", func(t *testing.T) {
		got, err := assembleAllowlistURLs(fileURLs, GenerateAllowlistOptions{
			Hosts:     "example.com",
			NoPresets: true,
			GOOS:      "linux",
		})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"https://google.com", "https://yahoo.com", "https://example.com"}
		if !reflect.DeepEqual(urlStrings(got), want) {
			t.Errorf("got %q want %q", urlStrings(got), want)
		}
	})

	t.Run("freebsd has no default preset", func(t *testing.T) {
		got, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Hosts: "example.com",
			GOOS:  "freebsd",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(urlStrings(got), []string{"https://example.com"}) {
			t.Errorf("got %q", urlStrings(got))
		}
	})

	t.Run("overlapping host is not duplicated", func(t *testing.T) {
		got, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Hosts:   "archive.ubuntu.com,https://archive.ubuntu.com/ubuntu",
			Presets: "linux",
		})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, u := range got {
			if u.Host == "archive.ubuntu.com" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("archive.ubuntu.com count=%d in %q", n, urlStrings(got))
		}
	})

	t.Run("conflicting flags", func(t *testing.T) {
		_, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Presets:   "linux",
			NoPresets: true,
		})
		if err == nil || !strings.Contains(err.Error(), "--presets") {
			t.Errorf("got %v", err)
		}
	})

	t.Run("unknown preset", func(t *testing.T) {
		_, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Presets: "nope",
		})
		if err == nil || !strings.Contains(err.Error(), "unknown preset") {
			t.Errorf("got %v", err)
		}
	})
}

func TestResolvePresetNames(t *testing.T) {
	t.Parallel()

	got, err := resolvePresetNames("", false, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"linux"}) {
		t.Errorf("got %q", got)
	}

	got, err = resolvePresetNames("", true, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("no-presets got %q", got)
	}

	got, err = resolvePresetNames("apple", false, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"apple"}) {
		t.Errorf("got %q", got)
	}
}

const (
	allowlistSummaryGoldenPath        = "testdata/allowlist-summary.golden"
	allowlistSummaryVerboseGoldenPath = "testdata/allowlist-summary-verbose.golden"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

func allowlistSummaryFixture() []*gen.CA {
	return []*gen.CA{
		{
			Certificate: &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Example CA"}}},
			Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			DNSNames:    []string{"a.example", "b.example", "c.example", "d.example"},
		},
		{
			Certificate: &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Second CA"}}},
			Fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			DNSNames:    []string{"only.example"},
		},
		{
			Certificate: &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Third CA"}}},
			Fingerprint: "fedcba9876543210ffff",
			DNSNames:    []string{"one.example", "two.example"},
		},
	}
}

func compareGolden(t *testing.T, path, out string) {
	t.Helper()
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// #nosec G304 -- path is a testdata golden selected by the test
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if out != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Fatalf("output differs from %s (run with -update):\n%s", path, out)
	}
}

func TestWriteAllowlistSummaryGolden(t *testing.T) {
	cas := allowlistSummaryFixture()
	var buf bytes.Buffer
	if err := writeAllowlistSummary(&buf, cas, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	compareGolden(t, allowlistSummaryGoldenPath, out)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if got := strings.Fields(lines[0]); !reflect.DeepEqual(got, []string{"CA", "FINGERPRINT", "COUNT", "EXAMPLE-DNS-NAMES"}) {
		t.Fatalf("header=%q", lines[0])
	}
	if strings.Contains(out, "Fingerprint") || strings.Contains(out, "Example DNSNames") || strings.Contains(out, "Count") {
		t.Fatalf("old headers still present:\n%s", out)
	}
	if strings.Contains(out, cas[0].Fingerprint) || strings.Contains(out, cas[2].Fingerprint) || !strings.Contains(out, cas[0].Fingerprint[:16]) {
		t.Fatalf("default should preview the first 16 fingerprint characters:\n%s", out)
	}
	if strings.Contains(out, "d.example") || !strings.Contains(out, "a.example, b.example, c.example") {
		t.Fatalf("example DNS names:\n%s", out)
	}

	buf.Reset()
	if err := writeAllowlistSummary(&buf, cas, true); err != nil {
		t.Fatal(err)
	}
	verbose := buf.String()
	compareGolden(t, allowlistSummaryVerboseGoldenPath, verbose)
	if got := strings.Fields(strings.Split(verbose, "\n")[0]); !reflect.DeepEqual(got, []string{"CA", "FINGERPRINT", "COUNT", "EXAMPLE-DNS-NAMES"}) {
		t.Fatalf("verbose header=%q", strings.Split(verbose, "\n")[0])
	}
	for _, ca := range cas {
		if !strings.Contains(verbose, ca.Fingerprint) {
			t.Fatalf("verbose missing full fingerprint %s\n%s", ca.Fingerprint, verbose)
		}
	}
}

func TestWriteAllowlistSummary(t *testing.T) {
	t.Parallel()

	full := "0123456789abcdefFULL"
	cas := []*gen.CA{
		{
			Certificate: &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Example CA"}}},
			Fingerprint: full,
			DNSNames:    []string{"a.example", "b.example", "c.example", "d.example"},
		},
		{
			Certificate: &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Short CA"}}},
			Fingerprint: "zz",
			DNSNames:    []string{"only.example"},
		},
		{
			Certificate: &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Exact CA"}}},
			Fingerprint: "1234567890abcdef",
			DNSNames:    nil,
		},
		{
			Certificate: &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Empty CA"}}},
			Fingerprint: "",
			DNSNames:    []string{"empty.example"},
		},
	}

	var buf bytes.Buffer
	if err := writeAllowlistSummary(&buf, cas, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("lines=%d\n%s", len(lines), out)
	}
	if got := strings.Fields(lines[0]); !reflect.DeepEqual(got, []string{"CA", "FINGERPRINT", "COUNT", "EXAMPLE-DNS-NAMES"}) {
		t.Fatalf("header=%q", lines[0])
	}
	if strings.Contains(out, "Fingerprint") || strings.Contains(out, "Example DNSNames") {
		t.Fatalf("old headers still present:\n%s", out)
	}
	if !strings.Contains(out, full[:16]) || strings.Contains(out, full) {
		t.Fatalf("default fingerprint truncation:\n%s", out)
	}
	if !strings.Contains(out, "zz") || !strings.Contains(out, "1234567890abcdef") {
		t.Fatalf("short fingerprints should print whole:\n%s", out)
	}
	if !strings.Contains(out, "a.example, b.example, c.example") || strings.Contains(out, "d.example") {
		t.Fatalf("example DNS names:\n%s", out)
	}

	buf.Reset()
	if err := writeAllowlistSummary(&buf, cas, true); err != nil {
		t.Fatal(err)
	}
	verbose := buf.String()
	if !strings.Contains(verbose, full) {
		t.Fatalf("verbose missing full fingerprint:\n%s", verbose)
	}
	if got := strings.Fields(strings.Split(verbose, "\n")[0]); !reflect.DeepEqual(got, []string{"CA", "FINGERPRINT", "COUNT", "EXAMPLE-DNS-NAMES"}) {
		t.Fatalf("verbose header=%q", verbose)
	}
}

func urlStrings(urls []*url.URL) []string {
	out := make([]string, len(urls))
	for i, u := range urls {
		out[i] = u.String()
	}
	return out
}

func hasURL(urls []*url.URL, want string) bool {
	for _, u := range urls {
		if u.String() == want {
			return true
		}
	}
	return false
}
