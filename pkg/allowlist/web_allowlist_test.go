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
	"os"
	"sort"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist/webscan"
)

func TestWebAllowlistIsSubsetOfMozillaRoots(t *testing.T) {
	t.Parallel()

	const (
		fixturePath = "../../testdata/certdata.txt.gz"
		allowPath   = "../../docs/downloads/allowlists/web.yaml"
	)
	rawYAML, err := os.ReadFile(allowPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(rawYAML, []byte("---")) {
		t.Fatal("web.yaml must not start with Jekyll front matter")
	}
	for _, phrase := range []string{
		"Baseline allowlist of Mozilla certdata.txt roots that anchored TLS",
		"Source list: Tranco",
		"List URL: https://tranco-list.eu/",
		"List date:",
		"Sites scanned:",
		"Successful verifications:",
		"Distrusted (leaf NotBefore after root CKA_NSS_SERVER_DISTRUST_AFTER):",
		"not a full top-1-million scan",
		"Trust store: testdata/certdata.txt.gz",
		"Cite: https://tranco-list.eu/",
		"Threshold:",
		"make web-allowlist",
		"SHA-256 of the certificate DER",
		"built-in denylist",
		"Per-root site counts",
		"This file has no Jekyll front matter",
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
	if len(al.Fingerprints) == 0 {
		t.Fatal("web allowlist has no fingerprints")
	}
	if !sort.StringsAreSorted(al.Fingerprints) {
		t.Fatal("fingerprints are not sorted")
	}

	_, known, err := webscan.LoadMozillaRootsFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, len(al.Fingerprints))
	for _, fp := range al.Fingerprints {
		if len(fp) != 64 {
			t.Fatalf("fingerprint %q is not 64 hex digits", fp)
		}
		for _, c := range fp {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("fingerprint %q is not lowercase hex", fp)
			}
		}
		if _, ok := known[fp]; !ok {
			t.Fatalf("fingerprint %q is not a testdata Mozilla trusted-server root", fp)
		}
		if _, dup := seen[fp]; dup {
			t.Fatalf("duplicate fingerprint %q", fp)
		}
		seen[fp] = struct{}{}
	}

	// Every fingerprint in the YAML body must also appear in the header
	// site-count comments, so the checked-in file stays self-describing.
	for _, fp := range al.Fingerprints {
		if !bytes.Contains(rawYAML, []byte("#   "+fp)) {
			t.Errorf("missing per-root count for %s", fp)
		}
	}
}
