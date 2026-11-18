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

package ui

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"html"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestWritePrinterFailureIncludesClose(t *testing.T) {
	var buf bytes.Buffer
	writePrinterFailure(&buf, errors.New("openssl unavailable"))
	out := buf.String()
	if !strings.Contains(out, "ERROR: openssl unavailable") {
		t.Fatalf("missing error text:\n%s", out)
	}
	if !strings.Contains(out, `href="/done"`) || !strings.Contains(out, "Close") {
		t.Fatalf("missing Close action:\n%s", out)
	}
}

func TestWebTitleUsesTrustprune(t *testing.T) {
	var buf bytes.Buffer
	if err := write(&buf, head, struct{ Operation string }{Operation: "list certificates"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<title>trustprune list certificates</title>") {
		t.Fatalf("expected trustprune title, got:\n%s", out)
	}
	if strings.Contains(out, "cert-mange") || strings.Contains(out, "cert-manage") {
		t.Fatalf("legacy/typo title still present:\n%s", out)
	}
}

func TestWebCertSummaryFields(t *testing.T) {
	cert := mustTestCert(t)
	view := webCertFromX509(cert, "RAW DUMP")
	var buf bytes.Buffer
	if err := write(&buf, list, webListData{Certificates: []webCert{view}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	wantSubject := certutil.StringifyPKIXName(cert.Subject)
	wantIssuer := certutil.StringifyPKIXName(cert.Issuer)
	wantFP := certutil.GetHexSHA256Fingerprint(*cert)
	for _, want := range []string{
		"Subject: " + wantSubject,
		"Issuer: " + wantIssuer,
		"SHA256: " + wantFP,
		"Serial: " + cert.SerialNumber.String(),
		"NotBefore: " + cert.NotBefore.UTC().Format("2006-01-02"),
		"NotAfter: " + cert.NotAfter.UTC().Format("2006-01-02"),
		"RAW DUMP",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func mustTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "web-ui-test"},
		Issuer:       pkix.Name{CommonName: "web-ui-issuer"},
		NotBefore:    time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 3, 4, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustNamedCert(t *testing.T, cn, country string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{CommonName: cn}
	if country != "" {
		subject.Country = []string{country}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      subject,
		Issuer:       pkix.Name{CommonName: cn + "-issuer"},
		NotBefore:    time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 3, 4, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func renderChecklistPage(t *testing.T, data webListData) string {
	t.Helper()
	var buf bytes.Buffer
	if err := write(&buf, head, struct{ Operation string }{Operation: "list certificates"}); err != nil {
		t.Fatal(err)
	}
	if err := write(&buf, list, data); err != nil {
		t.Fatal(err)
	}
	if err := write(&buf, footer, nil); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func textareaByID(t *testing.T, page, id string) string {
	t.Helper()
	marker := `id="` + id + `"`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("page missing %s\n%s", id, page)
	}
	rest := page[i:]
	gt := strings.Index(rest, ">")
	if gt < 0 {
		t.Fatalf("unclosed tag %s", id)
	}
	endRel := strings.Index(rest[gt+1:], "</textarea>")
	if endRel < 0 {
		t.Fatalf("page missing textarea end for %s\n%s", id, page)
	}
	return html.UnescapeString(rest[gt+1 : gt+1+endRel])
}

func assertKeepBox(t *testing.T, page, fp string, keep bool) {
	t.Helper()
	needle := `class="cert-keep" value="` + fp + `"`
	i := strings.Index(page, needle)
	if i < 0 {
		t.Fatalf("missing checkbox for %s\n%s", fp, page)
	}
	start := strings.LastIndex(page[:i], "<input")
	end := strings.Index(page[i:], ">")
	if start < 0 || end < 0 {
		t.Fatalf("broken checkbox tag for %s\n%s", fp, page)
	}
	tag := page[start : i+end+1]
	if !strings.Contains(tag, `type="checkbox"`) {
		t.Fatalf("checkbox tag = %s", tag)
	}
	checked := strings.HasSuffix(tag, " checked>")
	if keep != checked {
		t.Fatalf("keep=%v tag=%s", keep, tag)
	}
}

func parseAllowlistJSON(t *testing.T, body string) allowlist.Allowlist {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := allowlist.FromFile(path)
	if err != nil {
		t.Fatalf("FromFile: %v\n%s", err, body)
	}
	return got
}

func assertFingerprints(t *testing.T, got allowlist.Allowlist, want []string) {
	t.Helper()
	if len(got.Countries) != 0 {
		t.Fatalf("countries = %q", got.Countries)
	}
	if len(got.Fingerprints) != len(want) {
		t.Fatalf("fingerprints = %q, want %q", got.Fingerprints, want)
	}
	for i := range want {
		if got.Fingerprints[i] != want[i] {
			t.Fatalf("fingerprints = %q, want %q", got.Fingerprints, want)
		}
	}
}

func TestChecklistAllowlistJSONRoundTrip(t *testing.T) {
	one, err := checklistAllowlistJSON([]string{"abc"})
	if err != nil {
		t.Fatal(err)
	}
	const wantOne = "{\n  \"Fingerprints\": [\n    \"abc\"\n  ]\n}\n"
	if string(one) != wantOne {
		t.Fatalf("one fingerprint =\n%s", one)
	}
	empty, err := checklistAllowlistJSON(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(empty) != "{}\n" {
		t.Fatalf("empty = %q", empty)
	}

	cases := [][]string{nil, {}, {"abc"}, {"bbb", "aaa"}}
	for _, fps := range cases {
		got, err := checklistAllowlistJSON(fps)
		if err != nil {
			t.Fatal(err)
		}
		al := allowlist.Allowlist{}
		if len(fps) > 0 {
			al.Fingerprints = append([]string(nil), fps...)
		}
		path := filepath.Join(t.TempDir(), "allowlist.json")
		if err := al.ToFile(path); err != nil {
			t.Fatal(err)
		}
		// #nosec G304 -- path is the allowlist this test just wrote with ToFile
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("checklist JSON\n%s\nallowlist.ToFile\n%s", got, want)
		}
		assertFingerprints(t, parseAllowlistJSON(t, string(got)), fps)
	}
}

func TestChecklistScriptIsLocal(t *testing.T) {
	for _, banned := range []string{"fetch(", "XMLHttpRequest", "https://", "http://", "<script src=", "cdn."} {
		if strings.Contains(head, banned) || strings.Contains(list, banned) || strings.Contains(footer, banned) {
			t.Fatalf("web view references %q", banned)
		}
	}
	for _, want := range []string{
		"renderAllowlistJSON",
		"Fingerprints",
		"checklist-fingerprints",
		"checklist-allowlist",
		"download-allowlist",
		"createObjectURL",
	} {
		if !strings.Contains(footer, want) {
			t.Fatalf("footer script missing %q", want)
		}
	}
}

func TestWebChecklistPrecheck(t *testing.T) {
	alpha := mustNamedCert(t, "alpha", "US", 1)
	zulu := mustNamedCert(t, "zulu", "DE", 2)
	certs := []*x509.Certificate{zulu, alpha}
	certutil.Sort(certs)
	alphaFP := certutil.GetHexSHA256Fingerprint(*alpha)
	zuluFP := certutil.GetHexSHA256Fingerprint(*zulu)

	render := func(t *testing.T, al *allowlist.Allowlist) string {
		t.Helper()
		data, err := applyChecklist(certs, []string{"ALPHA", "ZULU"}, al)
		if err != nil {
			t.Fatal(err)
		}
		page := renderChecklistPage(t, data)
		if !strings.Contains(page, `id="download-allowlist"`) || !strings.Contains(page, "Download allowlist") {
			t.Fatalf("missing download button:\n%s", page)
		}
		if !strings.Contains(page, "leaves the trust store unchanged") {
			t.Fatalf("missing read-only note:\n%s", page)
		}
		body := textareaByID(t, page, "checklist-allowlist")
		if body != data.AllowlistJSON {
			t.Fatalf("embedded allowlist\n%s\nbuilt\n%s", body, data.AllowlistJSON)
		}
		var decoded []string
		if err := json.Unmarshal([]byte(textareaByID(t, page, "checklist-fingerprints")), &decoded); err != nil {
			t.Fatalf("fingerprints json: %v\n%s", err, page)
		}
		if len(decoded) != 2 || decoded[0] != alphaFP || decoded[1] != zuluFP {
			t.Fatalf("embedded fingerprints = %q", decoded)
		}
		return page
	}

	t.Run("no allowlist", func(t *testing.T) {
		al, err := prepareWebAllowlist(nil)
		if err != nil {
			t.Fatal(err)
		}
		page := render(t, al)
		assertKeepBox(t, page, alphaFP, true)
		assertKeepBox(t, page, zuluFP, true)
		got := parseAllowlistJSON(t, textareaByID(t, page, "checklist-allowlist"))
		assertFingerprints(t, got, []string{alphaFP, zuluFP})
	})

	t.Run("fingerprint allowlist", func(t *testing.T) {
		const stale = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		body, err := checklistAllowlistJSON([]string{alphaFP, stale})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "allowlist.json")
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		al, err := prepareWebAllowlist(&Config{AllowlistPath: path})
		if err != nil {
			t.Fatal(err)
		}
		page := render(t, al)
		assertKeepBox(t, page, alphaFP, true)
		assertKeepBox(t, page, zuluFP, false)
		got := parseAllowlistJSON(t, textareaByID(t, page, "checklist-allowlist"))
		assertFingerprints(t, got, []string{alphaFP})
		if strings.Contains(textareaByID(t, page, "checklist-allowlist"), stale) {
			t.Fatal("download included a fingerprint that is not a checked certificate")
		}
	})

	t.Run("country allowlist", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "allowlist.yaml")
		if err := os.WriteFile(path, []byte("countries:\n  - US\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		al, err := prepareWebAllowlist(&Config{AllowlistPath: path})
		if err != nil {
			t.Fatal(err)
		}
		page := render(t, al)
		assertKeepBox(t, page, alphaFP, true)
		assertKeepBox(t, page, zuluFP, false)
		body := textareaByID(t, page, "checklist-allowlist")
		if strings.Contains(body, "Countries") || strings.Contains(body, "countries") {
			t.Fatalf("download kept country filters:\n%s", body)
		}
		got := parseAllowlistJSON(t, body)
		assertFingerprints(t, got, []string{alphaFP})
	})

	t.Run("empty allowlist", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "allowlist.json")
		if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		al, err := prepareWebAllowlist(&Config{AllowlistPath: path})
		if err != nil {
			t.Fatal(err)
		}
		page := render(t, al)
		assertKeepBox(t, page, alphaFP, false)
		assertKeepBox(t, page, zuluFP, false)
		body := textareaByID(t, page, "checklist-allowlist")
		if body != "{}\n" {
			t.Fatalf("empty selection = %q", body)
		}
		got := parseAllowlistJSON(t, body)
		assertFingerprints(t, got, nil)
	})
}

func TestPrepareWebAllowlistMissing(t *testing.T) {
	al, err := prepareWebAllowlist(nil)
	if err != nil || al != nil {
		t.Fatalf("nil cfg err=%v al=%v", err, al)
	}
	al, err = prepareWebAllowlist(&Config{})
	if err != nil || al != nil {
		t.Fatalf("empty path err=%v al=%v", err, al)
	}
	_, err = prepareWebAllowlist(&Config{AllowlistPath: filepath.Join(t.TempDir(), "missing.json")})
	if err == nil {
		t.Fatal("expected an error for a missing allowlist")
	}
}
