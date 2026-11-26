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

package allowlist

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestMozillaIncludedAllowlistMatchesFixture(t *testing.T) {
	t.Parallel()

	const (
		fixturePath = "../../testdata/certdata.txt.gz"
		allowPath   = "../../docs/downloads/allowlists/mozilla-included.yaml"
	)
	rawYAML, err := os.ReadFile(allowPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(rawYAML, []byte("---")) {
		t.Fatal("mozilla-included.yaml must not start with Jekyll front matter")
	}
	for _, phrase := range []string{
		"Baseline allowlist of Mozilla certdata.txt roots trusted for TLS server authentication.",
		"https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt",
		"make allowlists",
		"testdata/certdata.txt.gz",
		"SHA-256 of the certificate DER",
		"built-in denylist",
		"Chromium and Mozilla blocklists",
		"MPL-2.0",
		"NOTICE",
	} {
		if !bytes.Contains(rawYAML, []byte(phrase)) {
			t.Errorf("allowlist header missing %q", phrase)
		}
	}
	if bytes.Contains(rawYAML, []byte("\ncountries:")) || bytes.Contains(rawYAML, []byte("\nCountries:")) {
		t.Fatal("allowlist must not set countries")
	}

	al, err := FromFile(allowPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Countries) != 0 {
		t.Fatalf("countries = %v", al.Countries)
	}
	for _, fp := range al.Fingerprints {
		if len(fp) != 64 {
			t.Fatalf("fingerprint %q is not 64 hex digits", fp)
		}
		for _, c := range fp {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("fingerprint %q is not lowercase hex", fp)
			}
		}
	}

	certs, err := certutil.ParseTrustedServerCerts(bytes.NewReader(readGzip(t, fixturePath)))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 132 {
		t.Fatalf("fixture has %d trusted server certs, want 132", len(certs))
	}
	if certs[0].Cert == nil || certs[0].Cert.Subject.CommonName != "GlobalSign Root CA" {
		cn := ""
		if certs[0].Cert != nil {
			cn = certs[0].Cert.Subject.CommonName
		}
		t.Fatalf("first cert %q", cn)
	}

	want := make([]string, 0, len(certs))
	for i := range certs {
		c := certs[i].Cert
		if c == nil || len(c.Raw) == 0 {
			t.Fatalf("cert %d has empty DER", i)
		}
		want = append(want, certutil.GetHexSHA256Fingerprint(*c))
	}
	sort.Strings(want)
	if !sort.StringsAreSorted(al.Fingerprints) {
		t.Fatal("committed fingerprints are not sorted")
	}
	if reflect.DeepEqual(al.Fingerprints, want) {
		return
	}
	missing, extra := diffFingerprints(al.Fingerprints, want)
	t.Fatalf("committed allowlist fingerprints != fixture (file %d, fixture %d, missing %d, extra %d)\nmissing: %v\nextra: %v", len(al.Fingerprints), len(want), len(missing), len(extra), missing, extra)
}

func readGzip(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	bs, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

func diffFingerprints(got, want []string) (missing, extra []string) {
	g := make(map[string]int, len(got))
	w := make(map[string]int, len(want))
	for _, s := range got {
		g[s]++
	}
	for _, s := range want {
		w[s]++
	}
	for s, n := range w {
		if g[s] < n {
			missing = append(missing, s)
		}
	}
	for s, n := range g {
		if w[s] < n {
			extra = append(extra, s)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}
