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
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestMozillaServerDistrustAfterMatchesComments(t *testing.T) {
	t.Parallel()

	if len(mozillaServerDistrustAfter) == 0 {
		t.Fatal("no recorded Mozilla distrust-after dates")
	}
	inList := make(map[string]struct{}, len(mozillaBlocklistedFingerprints))
	for _, fp := range mozillaBlocklistedFingerprints {
		inList[fp] = struct{}{}
	}
	for fp, raw := range mozillaServerDistrustAfter {
		if _, ok := inList[fp]; !ok {
			t.Errorf("distrust-after date for %s is not on the mozilla blocklist", fp)
		}
		if _, err := time.Parse(time.RFC3339, raw); err != nil {
			t.Errorf("distrust-after for %s: %v", fp, err)
		}
	}

	// DigiCert Trusted Root G4 and emSign Root CA - G1, as recorded in
	// mozilla_blocklist.go from certdata.txt.
	want := map[string]string{
		"552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988": "2026-09-14T23:59:59Z",
		"40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367": "2026-11-16T23:59:59Z",
	}
	for fp, date := range want {
		if mozillaServerDistrustAfter[fp] != date {
			t.Errorf("%s: got %q want %q", fp, mozillaServerDistrustAfter[fp], date)
		}
	}
}

func TestListLabelsFromEmbeddedData(t *testing.T) {
	now := time.Date(2026, 11, 27, 18, 0, 0, 0, time.UTC)
	certs := loadTestdataCerts(t, "lots.crt")
	g2 := certByFPPrefix(t, certs, "43df5774b03e7fef")
	ec1 := certByFPPrefix(t, certs, "02ed0eb28c14da45")

	for _, cert := range []*x509.Certificate{g2, ec1} {
		after := MozillaDistrustAfter(cert)
		if after.IsZero() || after.Format(time.RFC3339) != "2024-11-30T23:59:59Z" {
			t.Fatalf("%s distrust_after=%s", certutil.StringifyPKIXName(cert.Subject), after)
		}
		got := ListLabels(cert, now)
		want := []string{ListLabelDistrusted, ListBlocklistPrefix + "mozilla"}
		if !slices.Equal(got, want) {
			t.Fatalf("%s labels=%q want %q", certutil.StringifyPKIXName(cert.Subject), got, want)
		}
		if !slices.Equal(BlocklistIDs(cert), []string{"mozilla"}) {
			t.Fatalf("%s blocklists=%q", certutil.StringifyPKIXName(cert.Subject), BlocklistIDs(cert))
		}
	}

	example := loadTestdataCerts(t, "example.crt")
	if len(example) == 0 {
		t.Fatal("no example.crt")
	}
	if got := ListLabels(example[0], now); len(got) != 0 {
		t.Fatalf("example.crt labels=%q", got)
	}
	if !MozillaDistrustAfter(example[0]).IsZero() {
		t.Fatal("example.crt has a distrust-after date")
	}

	before := time.Date(2024, 11, 30, 23, 59, 58, 0, time.UTC)
	if got := ListLabels(g2, before); !slices.Equal(got, []string{ListBlocklistPrefix + "mozilla"}) {
		t.Fatalf("before labels=%q", got)
	}
}

func TestListLabelsDenyAndBlocklists(t *testing.T) {
	now := time.Date(2026, 11, 27, 18, 0, 0, 0, time.UTC)
	certs := loadTestdataCerts(t, "example.crt")
	if len(certs) == 0 {
		t.Fatal("no example.crt")
	}
	cert := certs[0]
	fp := certutil.GetHexSHA256Fingerprint(*cert)

	t.Cleanup(AddDeniedForTest("test deny", fp, ""))
	t.Cleanup(AddBlocklistedForTest("chromium", fp))
	t.Cleanup(AddBlocklistedForTest("apple", fp))

	got := ListLabels(cert, now)
	want := []string{ListLabelDeny, ListBlocklistPrefix + "chromium", ListBlocklistPrefix + "apple"}
	if !slices.Equal(got, want) {
		t.Fatalf("labels=%q want %q", got, want)
	}
	if !slices.Equal(BlocklistIDs(cert), []string{"chromium", "apple"}) {
		t.Fatalf("blocklists=%q", BlocklistIDs(cert))
	}
}

func TestListLabelsCertdataDigiCertAndEmSign(t *testing.T) {
	now := time.Date(2026, 11, 27, 18, 0, 0, 0, time.UTC)
	certs := loadTestdataCerts(t, "certdata.txt.gz")
	want := map[string]string{
		"552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988": "2026-09-14T23:59:59Z",
		"40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367": "2026-11-16T23:59:59Z",
	}
	found := 0
	for _, c := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*c)
		date, ok := want[fp]
		if !ok {
			continue
		}
		found++
		after := MozillaDistrustAfter(c)
		if after.Format(time.RFC3339) != date {
			t.Errorf("%s distrust_after=%s want %s", fp, after.Format(time.RFC3339), date)
		}
		got := ListLabels(c, now)
		if !slices.Equal(got, []string{ListLabelDistrusted, ListBlocklistPrefix + "mozilla"}) {
			t.Errorf("%s (%s) labels=%q", certutil.StringifyPKIXName(c.Subject), fp, got)
		}
	}
	if found != len(want) {
		t.Fatalf("found %d of %d certdata certs with recorded distrust-after dates", found, len(want))
	}
}

func loadTestdataCerts(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	bs, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if len(name) >= 3 && name[len(name)-3:] == ".gz" {
		plain, err := gunzipTestdata(bs)
		if err != nil {
			t.Fatal(err)
		}
		bs = plain
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatalf("no certs in %s", name)
	}
	return certs
}

func gunzipTestdata(bs []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(r)
	cerr := r.Close()
	if err != nil {
		return nil, err
	}
	if cerr != nil {
		return nil, cerr
	}
	return out, nil
}

func certByFPPrefix(t *testing.T, certs []*x509.Certificate, prefix string) *x509.Certificate {
	t.Helper()
	for _, c := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*c)
		if len(fp) >= len(prefix) && fp[:len(prefix)] == prefix {
			return c
		}
	}
	t.Fatalf("no certificate with fingerprint prefix %s", prefix)
	return nil
}
