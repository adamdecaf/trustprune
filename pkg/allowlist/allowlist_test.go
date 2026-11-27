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

package allowlist

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestAllowlist_nocert(t *testing.T) {
	cases := []Allowlist{
		{},
		{
			Fingerprints: []string{"a"},
		},
		{
			Countries: []string{"US"},
		},
	}
	for i := range cases {
		al := cases[i]
		if al.Matches(nil) {
			t.Errorf("shouldn't have matched, al=%#v", al)
		}
	}
}

func TestAllowlist_emptyallowlist(t *testing.T) {
	al := Allowlist{}
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	for i := range certs {
		if al.Matches(certs[i]) {
			t.Fatalf("err, empty allowlist shouldn't match")
		}
	}
}

func TestAllowlist_remove(t *testing.T) {
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	// test fingerprint
	al := Allowlist{
		Fingerprints: []string{
			"05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030",
		},
	}
	for i := range certs {
		if !al.Matches(certs[i]) {
			t.Fatalf("should have matched")
		}
	}

	// test country
	al = Allowlist{
		Countries: []string{"US"},
	}
	for i := range certs {
		if !al.Matches(certs[i]) {
			t.Fatalf("should have matched")
		}
	}
}

func TestAllowlist__jsonFile(t *testing.T) {
	al, err := FromFile("../../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 1 {
		t.Errorf("Wrong number of parsed fingerprints in allowlist, found=%d", len(al.Fingerprints))
	}

	if !reflect.DeepEqual(al.Fingerprints, []string{"a"}) {
		t.Errorf("got %q", al.Fingerprints)
	}

	if !reflect.DeepEqual(al.Countries, []string{"US", "GB"}) {
		t.Errorf("got %q", al.Countries)
	}
}

func TestAllowlist__emptyJson(t *testing.T) {
	al, err := FromFile("../../testdata/empty-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 0 {
		t.Errorf("empty allowlist had fingerprints: %q", al.Fingerprints)
	}
	if len(al.Countries) != 0 {
		t.Errorf("empty allowlist had countries: %q", al.Countries)
	}
}

func TestAllowlist__yamlFile(t *testing.T) {
	al, err := FromFile("../../testdata/complete-whitelist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 1 {
		t.Errorf("Wrong number of parsed fingerprints in allowlist, found=%d", len(al.Fingerprints))
	}

	if !reflect.DeepEqual(al.Fingerprints, []string{"a"}) {
		t.Errorf("got %q", al.Fingerprints)
	}

	if !reflect.DeepEqual(al.Countries, []string{"US", "GB"}) {
		t.Errorf("got %q", al.Countries)
	}
}

func TestAllowlist__emptyYaml(t *testing.T) {
	al, err := FromFile("../../testdata/empty-whitelist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 0 {
		t.Errorf("empty allowlist had fingerprints: %q", al.Fingerprints)
	}
	if len(al.Countries) != 0 {
		t.Errorf("empty allowlist had countries: %q", al.Countries)
	}
}

func TestAllowlist__globalsignJson(t *testing.T) {
	al, err := FromFile("../../testdata/globalsign-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 6 {
		t.Errorf("Wrong number of parsed fingerprints in allowlist, found=%d", len(al.Fingerprints))
	}
	if len(al.Countries) != 0 {
		t.Errorf("got countries %q", al.Countries)
	}
}

func TestAllowlist__usYaml(t *testing.T) {
	al, err := FromFile("../../testdata/us-whitelist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(al.Countries, []string{"US"}) {
		t.Errorf("got %q", al.Countries)
	}
	if len(al.Fingerprints) != 0 {
		t.Errorf("got fingerprints %q", al.Fingerprints)
	}
}

func TestAllowlist__testJson(t *testing.T) {
	al, err := FromFile("../../testdata/test-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) < 1 {
		t.Errorf("expected fingerprints in testdata/test-whitelist.json, got %q", al.Fingerprints)
	}
}

func TestAllowlist_cycle(t *testing.T) {
	al, err := FromFile("../../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	where := "../../test-allowlist.json"
	defer os.Remove(where)
	if err = al.ToFile(where); err != nil {
		t.Fatal(err)
	}
	al2, err := FromFile(where)
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != len(al2.Fingerprints) {
		t.Errorf("%d != %d", len(al.Fingerprints), len(al2.Fingerprints))
	}
}

func TestAllowlist__matching(t *testing.T) {
	certificates, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 1 {
		t.Errorf("got %d certs", len(certificates))
	}
	if certificates[0] == nil {
		t.Error("Unable to read first cert")
	}

	al := Allowlist{}
	if al.Matches(certificates[0]) {
		t.Error("empty allowlist and cert shouldn't match")
	}

	// Fingerprints
	al.Fingerprints = []string{"abc"}
	if al.Matches(certificates[0]) {
		t.Error("shouldn't match")
	}

	al.Fingerprints = []string{"05a6db38939"}
	if al.Matches(certificates[0]) {
		t.Errorf("%q shouldn't mattch, (short fingerprints not allowed)", al.Fingerprints)
	}

	al.Fingerprints = []string{"05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030"}
	if !al.Matches(certificates[0]) {
		t.Error("should have matched")
	}

	// Country
	al.Fingerprints = []string{}
	al.Countries = []string{"US"}
	if !al.Matches(certificates[0]) {
		t.Error("should have matched")
	}
}

func TestBlocklisted(t *testing.T) {
	if Blocklisted(nil) {
		t.Fatal("nil certificate is not blocklisted")
	}
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 || certs[0] == nil {
		t.Fatal("expected example.crt")
	}
	if Blocklisted(certs[0]) {
		t.Fatal("example.crt should not be on the embedded blocklists")
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])
	origChrome := blocklistedFingerprints
	origMozilla := mozillaBlocklistedFingerprints
	origApple := appleBlocklistedFingerprints
	origCCADB := ccadbRemovedBlocklistedFingerprints
	t.Cleanup(func() {
		blocklistedFingerprints = origChrome
		mozillaBlocklistedFingerprints = origMozilla
		appleBlocklistedFingerprints = origApple
		ccadbRemovedBlocklistedFingerprints = origCCADB
	})

	blocklistedFingerprints = append([]string{fp}, blocklistedFingerprints...)
	if !Blocklisted(certs[0]) {
		t.Fatal("chromium blocklist should match the certificate SHA-256")
	}
	blocklistedFingerprints = origChrome
	mozillaBlocklistedFingerprints = append([]string{fp}, mozillaBlocklistedFingerprints...)
	if !Blocklisted(certs[0]) {
		t.Fatal("mozilla blocklist should match the certificate SHA-256")
	}
	mozillaBlocklistedFingerprints = origMozilla
	appleBlocklistedFingerprints = append([]string{fp}, appleBlocklistedFingerprints...)
	if !Blocklisted(certs[0]) {
		t.Fatal("Apple blocklist should match the certificate SHA-256")
	}
	appleBlocklistedFingerprints = origApple
	ccadbRemovedBlocklistedFingerprints = append([]string{fp}, ccadbRemovedBlocklistedFingerprints...)
	if !Blocklisted(certs[0]) {
		t.Fatal("ccadb removed CA blocklist should match the certificate SHA-256")
	}
}

func TestAllowlist_blocklistedFingerprintsLoad(t *testing.T) {
	if len(blocklistedFingerprints) == 0 {
		t.Fatal("blocklistedFingerprints is empty")
	}
	// Qaznet Trust Network fingerprint from Chromium's current blocklist.
	const refreshed = "00309c736dd661da6f1eb24173aa849944c168a43a15bffd192eecfdb6f8dbd2"
	for i := range blocklistedFingerprints {
		if blocklistedFingerprints[i] == refreshed {
			return
		}
	}
	t.Fatalf("refreshed Chromium fingerprint %q is missing", refreshed)
}

func TestAllowlist_blocklistRejectsMatch(t *testing.T) {
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 || certs[0] == nil {
		t.Fatal("expected example.crt")
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	orig := blocklistedFingerprints
	t.Cleanup(func() { blocklistedFingerprints = orig })
	blocklistedFingerprints = append([]string{fp}, blocklistedFingerprints...)

	al := Allowlist{Fingerprints: []string{fp}}
	if al.Matches(certs[0]) {
		t.Fatal("blocklisted fingerprint should not match even if it is on the allowlist")
	}
}

func TestAllowlist_mozillaBlocklistedFingerprintsLoad(t *testing.T) {
	if len(mozillaBlocklistedFingerprints) == 0 {
		t.Fatal("mozillaBlocklistedFingerprints is empty")
	}
	for _, fp := range mozillaBlocklistedFingerprints {
		if len(fp) != 64 {
			t.Fatalf("fingerprint %q is not 64 hex digits", fp)
		}
		for _, c := range fp {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("fingerprint %q is not lowercase hex", fp)
			}
		}
	}
	// Entrust Root Certification Authority - G2, server distrust after
	// 2024-11-30 from Mozilla certdata.txt.
	const entrustG2 = "43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339"
	found := false
	for _, fp := range mozillaBlocklistedFingerprints {
		if fp == entrustG2 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Entrust Root Certification Authority - G2 fingerprint %s is missing", entrustG2)
	}

	src, err := os.ReadFile("mozilla_blocklist.go")
	if err != nil {
		t.Fatal(err)
	}
	const sourceURL = "https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/nss/lib/ckfw/builtins/certdata.txt"
	if !bytes.Contains(src, []byte(sourceURL)) {
		t.Fatal("generated file is missing the certdata.txt source URL")
	}
	if !bytes.Contains(src, []byte("CKA_NSS_SERVER_DISTRUST_AFTER 2024-11-30T23:59:59Z")) {
		t.Fatal("generated file does not record a passed server distrust-after date")
	}
	dates := regexp.MustCompile(`CKA_NSS_SERVER_DISTRUST_AFTER (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)`).FindAllSubmatch(src, -1)
	if len(dates) == 0 {
		t.Fatal("generated file records no server distrust-after dates")
	}
	now := time.Now().UTC()
	for _, m := range dates {
		got, err := time.Parse(time.RFC3339, string(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		if got.After(now) {
			t.Fatalf("future distrust-after %s is blocklisted", got.Format(time.RFC3339))
		}
	}
}

func TestAllowlist_mozillaBlocklistRejectsMatch(t *testing.T) {
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 || certs[0] == nil {
		t.Fatal("expected example.crt")
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	orig := mozillaBlocklistedFingerprints
	t.Cleanup(func() { mozillaBlocklistedFingerprints = orig })
	mozillaBlocklistedFingerprints = append([]string{fp}, mozillaBlocklistedFingerprints...)

	al := Allowlist{Fingerprints: []string{fp}, Countries: []string{"US"}}
	if al.Matches(certs[0]) {
		t.Fatal("mozilla blocklisted fingerprint should not match even if it is on the allowlist")
	}
}

func TestAllowlist_ccadbRemovedBlocklistedFingerprintsLoad(t *testing.T) {
	if len(ccadbRemovedBlocklistedFingerprints) == 0 {
		t.Fatal("ccadbRemovedBlocklistedFingerprints is empty")
	}
	if len(ccadbRemovedBlocklistedFingerprints) != 105 {
		t.Fatalf("ccadbRemovedBlocklistedFingerprints has %d entries, want 105", len(ccadbRemovedBlocklistedFingerprints))
	}
	if !sort.StringsAreSorted(ccadbRemovedBlocklistedFingerprints) {
		t.Fatal("ccadbRemovedBlocklistedFingerprints is not sorted")
	}
	for _, fp := range ccadbRemovedBlocklistedFingerprints {
		if len(fp) != 64 {
			t.Fatalf("fingerprint %q is not 64 hex digits", fp)
		}
		for _, c := range fp {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("fingerprint %q is not lowercase hex", fp)
			}
		}
	}

	src, err := os.ReadFile("ccadb_removed_blocklist.go")
	if err != nil {
		t.Fatal(err)
	}
	const sourceURL = "https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportCSVFormat"
	if !bytes.Contains(src, []byte(sourceURL)) {
		t.Fatal("generated file is missing the CCADB Removed CA Certificate Report URL")
	}
	for _, phrase := range []string{
		"expir",
		"voluntar",
		"asking for the removal",
		"requested (the )?removal",
		"at the (ca|certificate authority).{0,40}request",
		"Generated on ",
	} {
		if !bytes.Contains(src, []byte(phrase)) {
			t.Errorf("generated file is missing %q", phrase)
		}
	}
	if regexp.MustCompile(`Generated on [^\n]* by `).Match(src) {
		t.Fatal("generated file must not include a username on the Generated on line")
	}

	f, err := os.Open(ccadbRemovedCSV)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	parsed, err := ParseCCADBRemovedRoots(f)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(parsed)
	if !reflect.DeepEqual(ccadbRemovedBlocklistedFingerprints, parsed) {
		t.Fatal("generated CCADB blocklist does not match ParseCCADBRemovedRoots of the checked-in CSV")
	}
}

func TestAllowlist_ccadbRemovedBlocklistRejectsMatch(t *testing.T) {
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 || certs[0] == nil {
		t.Fatal("expected example.crt")
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	orig := ccadbRemovedBlocklistedFingerprints
	t.Cleanup(func() { ccadbRemovedBlocklistedFingerprints = orig })
	ccadbRemovedBlocklistedFingerprints = append([]string{fp}, ccadbRemovedBlocklistedFingerprints...)

	al := Allowlist{Fingerprints: []string{fp}, Countries: []string{"US"}}
	if al.Matches(certs[0]) {
		t.Fatal("ccadb removed CA fingerprint should not match even if it is on the allowlist")
	}
}

func TestAllowlist_ToFileFormat(t *testing.T) {
	al := Allowlist{Fingerprints: []string{"abc"}}
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "out.json")
	if err := al.ToFile(jsonPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != '{' {
		t.Fatalf("expected JSON object, got %q", raw)
	}
	var decoded Allowlist
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json decode: %v\n%s", err, raw)
	}
	if len(decoded.Fingerprints) != 1 || decoded.Fingerprints[0] != "abc" {
		t.Fatalf("decoded=%+v", decoded)
	}

	yamlPath := filepath.Join(dir, "out.yaml")
	if err := al.ToFile(yamlPath); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		t.Fatalf("expected YAML, got %q", raw)
	}
	al2, err := FromFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(al2.Fingerprints) != 1 {
		t.Fatalf("yaml round-trip: %+v", al2)
	}
}

func TestAllowlist_JSONFingerprintsKey(t *testing.T) {
	al := Allowlist{Fingerprints: []string{"abc"}, Countries: []string{"US"}}
	raw, err := json.Marshal(al)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"fingerprints"`)) || bytes.Contains(raw, []byte(`"Fingerprints"`)) {
		t.Fatalf("marshal = %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"Countries"`)) {
		t.Fatalf("Countries key changed: %s", raw)
	}

	path := filepath.Join(t.TempDir(), "out.json")
	if err := al.ToFile(path); err != nil {
		t.Fatal(err)
	}
	fileRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(fileRaw, []byte(`"fingerprints"`)) || bytes.Contains(fileRaw, []byte(`"Fingerprints"`)) {
		t.Fatalf("ToFile = %s", fileRaw)
	}
	if !bytes.Contains(fileRaw, []byte(`"Countries"`)) {
		t.Fatalf("Countries key changed: %s", fileRaw)
	}
}

func TestAllowlist_LegacyFingerprintsKey(t *testing.T) {
	const old = `{"Fingerprints":["abc"],"Countries":["US"]}`
	var decoded Allowlist
	if err := json.Unmarshal([]byte(old), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Fingerprints, []string{"abc"}) {
		t.Fatalf("unmarshal = %+v", decoded)
	}
	if !reflect.DeepEqual(decoded.Countries, []string{"US"}) {
		t.Fatalf("countries = %q", decoded.Countries)
	}

	path := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	fromFile, err := FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromFile, decoded) {
		t.Fatalf("FromFile = %+v", fromFile)
	}

	var both Allowlist
	if err := json.Unmarshal([]byte(`{"fingerprints":[],"Fingerprints":["abc"]}`), &both); err != nil {
		t.Fatal(err)
	}
	if both.Fingerprints == nil || len(both.Fingerprints) != 0 {
		t.Fatalf("empty fingerprints should win, got %#v", both.Fingerprints)
	}

	var nullKey Allowlist
	if err := json.Unmarshal([]byte(`{"fingerprints":null,"Fingerprints":["abc"]}`), &nullKey); err != nil {
		t.Fatal(err)
	}
	if nullKey.Fingerprints != nil {
		t.Fatalf("null fingerprints should win, got %#v", nullKey.Fingerprints)
	}

	var onlyNew Allowlist
	if err := json.Unmarshal([]byte(`{"fingerprints":["def"]}`), &onlyNew); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(onlyNew.Fingerprints, []string{"def"}) {
		t.Fatalf("got %#v", onlyNew.Fingerprints)
	}
}
