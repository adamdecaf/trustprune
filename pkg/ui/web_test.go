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
	"crypto/ecdsa"
	"crypto/elliptic"
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
		"cert-search",
		"cert-sort",
		"select-all",
		"select-none",
		"copyFingerprint",
		"applyView",
		"setVisibleKeep",
		"is-dropped",
		"data-status",
		"data-self",
	} {
		if !strings.Contains(footer, want) {
			t.Fatalf("footer script missing %q", want)
		}
	}
	if strings.Contains(head, "@import") || strings.Contains(head, "url(") || strings.Contains(head, "<link") || strings.Contains(head, "<script src=") {
		t.Fatal("stylesheet or head references an external resource")
	}
	for _, want := range []string{
		"prefers-color-scheme",
		"position: sticky",
		"-apple-system",
		"BlinkMacSystemFont",
		"Segoe UI",
		":focus-visible",
	} {
		if !strings.Contains(head, want) {
			t.Fatalf("head stylesheet missing %q", want)
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
		if !strings.Contains(page, "2 certificates, 2 kept, 0 to drop") {
			t.Fatalf("missing count line:\n%s", page)
		}
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
		if !strings.Contains(page, "2 certificates, 1 kept, 1 to drop") {
			t.Fatalf("missing count line:\n%s", page)
		}
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
		if !strings.Contains(page, "2 certificates, 1 kept, 1 to drop") {
			t.Fatalf("missing count line:\n%s", page)
		}
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
		if !strings.Contains(page, "2 certificates, 0 kept, 2 to drop") {
			t.Fatalf("missing count line:\n%s", page)
		}
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

func TestCertValidity(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	window := 90 * 24 * time.Hour
	cases := []struct {
		name                string
		notBefore, notAfter time.Time
		label, class        string
	}{
		{
			name:      "valid beyond the window",
			notBefore: now.AddDate(-2, 0, 0),
			notAfter:  now.Add(window + time.Nanosecond),
			label:     "Valid",
			class:     "valid",
		},
		{
			name:      "expiring at the 90 day boundary",
			notBefore: now.AddDate(-1, 0, 0),
			notAfter:  now.Add(window),
			label:     "Expiring soon",
			class:     "expiring",
		},
		{
			name:      "expiring inside the window",
			notBefore: now.AddDate(-1, 0, 0),
			notAfter:  now.Add(24 * time.Hour),
			label:     "Expiring soon",
			class:     "expiring",
		},
		{
			name:      "still valid at NotAfter",
			notBefore: now.AddDate(-1, 0, 0),
			notAfter:  now,
			label:     "Expiring soon",
			class:     "expiring",
		},
		{
			name:      "expired one nanosecond later",
			notBefore: now.AddDate(-2, 0, 0),
			notAfter:  now.Add(-time.Nanosecond),
			label:     "Expired",
			class:     "expired",
		},
		{
			name:      "not yet valid",
			notBefore: now.Add(time.Nanosecond),
			notAfter:  now.AddDate(1, 0, 0),
			label:     "Not yet valid",
			class:     "notyet",
		},
		{
			name:      "valid at NotBefore",
			notBefore: now,
			notAfter:  now.Add(window + time.Hour),
			label:     "Valid",
			class:     "valid",
		},
		{
			name:      "expired wins when NotAfter is already past",
			notBefore: now.Add(time.Hour),
			notAfter:  now.Add(-time.Hour),
			label:     "Expired",
			class:     "expired",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			label, class := certValidity(tc.notBefore, tc.notAfter, now)
			if label != tc.label || class != tc.class {
				t.Fatalf("got %s/%s, want %s/%s", label, class, tc.label, tc.class)
			}
		})
	}
}

func TestChecklistCountText(t *testing.T) {
	cases := []struct {
		total, kept int
		want        string
	}{
		{0, 0, "0 certificates, 0 kept, 0 to drop"},
		{1, 1, "1 certificate, 1 kept, 0 to drop"},
		{1, 0, "1 certificate, 0 kept, 1 to drop"},
		{8, 5, "8 certificates, 5 kept, 3 to drop"},
	}
	for _, tc := range cases {
		got := checklistCountText(tc.total, tc.kept)
		if got != tc.want {
			t.Fatalf("checklistCountText(%d, %d) = %q, want %q", tc.total, tc.kept, got, tc.want)
		}
	}
}

func TestShortFingerprint(t *testing.T) {
	if shortFingerprint("") != "" {
		t.Fatal("empty fingerprint")
	}
	if shortFingerprint("abcd") != "abcd" {
		t.Fatal("short fingerprint should stay whole")
	}
	fp := strings.Repeat("ab", 32)
	got := shortFingerprint(fp)
	want := fp[:8] + "…" + fp[len(fp)-8:]
	if got != want {
		t.Fatalf("short = %q, want %q", got, want)
	}
	if strings.Contains(got, fp) {
		t.Fatal("short form still contains the full fingerprint")
	}
}

func TestCertSelfSigned(t *testing.T) {
	if certSelfSigned(nil) {
		t.Fatal("nil certificate is not self-signed")
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	self := mustUICert(t, "Root CA", "Root CA", now.AddDate(-1, 0, 0), now.AddDate(5, 0, 0), 11)
	cross := mustUICert(t, "Leaf CA", "Other Root", now.AddDate(-1, 0, 0), now.AddDate(5, 0, 0), 12)
	if !certSelfSigned(self) {
		t.Fatal("matching subject and issuer should be self-signed")
	}
	if certSelfSigned(cross) {
		t.Fatal("cross-signed certificate should not be self-signed")
	}
}

func TestWebPageControlsAndStatus(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	window := 90 * 24 * time.Hour
	valid := mustUICert(t, "Valid Root", "Valid Root", now.AddDate(-2, 0, 0), now.AddDate(3, 0, 0), 21)
	expiring := mustUICert(t, "Soon CA", "Soon Issuer", now.AddDate(-1, 0, 0), now.Add(30*24*time.Hour), 22)
	expired := mustUICert(t, "Old CA", "Old Issuer", now.AddDate(-4, 0, 0), now.AddDate(-1, 0, 0), 23)
	notYet := mustUICert(t, "Future CA", "Future Issuer", now.AddDate(0, 0, 20), now.AddDate(2, 0, 0), 24)
	boundary := mustUICert(t, "Boundary CA", "Boundary Issuer", now.AddDate(-1, 0, 0), now.Add(window), 25)

	rows := []webCert{
		webCertFromX509At(valid, "VALID RAW", now),
		webCertFromX509At(expiring, "SOON RAW", now),
		webCertFromX509At(expired, "OLD RAW", now),
		webCertFromX509At(notYet, "FUTURE RAW", now),
		webCertFromX509At(boundary, "BOUNDARY RAW", now),
	}
	rows[0].Keep = true
	rows[1].Keep = false
	rows[2].Keep = false
	rows[3].Keep = true
	rows[4].Keep = true

	if rows[0].Status != "Valid" || rows[0].StatusClass != "valid" || !rows[0].SelfSigned {
		t.Fatalf("valid row = %+v", rows[0])
	}
	if rows[1].Status != "Expiring soon" || rows[1].SelfSigned {
		t.Fatalf("expiring row = %+v", rows[1])
	}
	if rows[2].Status != "Expired" || rows[2].StatusClass != "expired" {
		t.Fatalf("expired row = %+v", rows[2])
	}
	if rows[3].Status != "Not yet valid" || rows[3].StatusClass != "notyet" {
		t.Fatalf("not yet row = %+v", rows[3])
	}
	if rows[4].Status != "Expiring soon" || rows[4].StatusClass != "expiring" {
		t.Fatalf("boundary row = %+v", rows[4])
	}
	if rows[0].FingerprintShort == rows[0].Fingerprint || !strings.Contains(rows[0].Fingerprint, rows[0].FingerprintShort[:8]) {
		t.Fatalf("short fingerprint = %q full %q", rows[0].FingerprintShort, rows[0].Fingerprint)
	}

	data := webListData{
		Certificates: rows,
		CountLine:    checklistCountText(len(rows), 3),
	}
	page := renderChecklistPage(t, data)

	for _, want := range []string{
		"5 certificates, 3 kept, 2 to drop",
		`<label for="cert-search">Search</label>`,
		`id="cert-search"`,
		`placeholder="Subject, issuer, or SHA256"`,
		`<label for="cert-sort">Sort</label>`,
		`<option value="subject" selected>Subject</option>`,
		`<option value="notafter">NotAfter</option>`,
		`<option value="issuer">Issuer</option>`,
		`id="select-all"`,
		"Select all",
		`id="select-none"`,
		"Select none",
		"Expiring within 90 days",
		"Self-signed",
		`data-filter="kept"`,
		`data-filter="dropped"`,
		`data-filter="expired"`,
		`data-filter="expiring"`,
		`data-filter="selfsigned"`,
		`aria-pressed="true"`,
		"<details",
		"<summary>Details</summary>",
		"leaves the trust store unchanged",
		`href="/done"`,
		">Close</a>",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("page missing %q", want)
		}
	}

	tags := articleOpenTags(t, page)
	if len(tags) != len(rows) {
		t.Fatalf("articles = %d, want %d\n%s", len(tags), len(rows), page)
	}
	for i, row := range rows {
		tag := tags[i]
		if row.Keep && strings.Contains(tag, "is-dropped") {
			t.Fatalf("kept row tagged dropped: %s", tag)
		}
		if !row.Keep && !strings.Contains(tag, "is-dropped") {
			t.Fatalf("dropped row missing is-dropped: %s", tag)
		}
		for _, want := range []string{
			`data-status="` + row.StatusClass + `"`,
			`data-fp="` + row.Fingerprint + `"`,
			`data-notafter="` + row.NotAfter + `"`,
		} {
			if !strings.Contains(tag, want) {
				t.Fatalf("article missing %q in %s", want, tag)
			}
		}
		self := `data-self="0"`
		if row.SelfSigned {
			self = `data-self="1"`
		}
		if !strings.Contains(tag, self) {
			t.Fatalf("article missing %s in %s", self, tag)
		}
		if !strings.Contains(page, `<span class="badge badge-`+row.StatusClass+`">`+row.Status+`</span>`) {
			t.Fatalf("missing badge %s/%s", row.Status, row.StatusClass)
		}
		if !strings.Contains(page, `<code>`+row.FingerprintShort+`</code>`) {
			t.Fatalf("missing short fingerprint %s", row.FingerprintShort)
		}
		if !strings.Contains(page, `data-fp="`+row.Fingerprint+`"`) {
			t.Fatalf("missing copy target for %s", row.Fingerprint)
		}
	}
	if strings.Count(page, `<span class="pill">Self-signed</span>`) != 1 {
		t.Fatalf("self-signed pills:\n%s", page)
	}
}

func articleOpenTags(t *testing.T, page string) []string {
	t.Helper()
	var tags []string
	rest := page
	for {
		i := strings.Index(rest, "<article")
		if i < 0 {
			break
		}
		rest = rest[i:]
		end := strings.Index(rest, ">")
		if end < 0 {
			t.Fatal("unclosed article tag")
		}
		tags = append(tags, rest[:end+1])
		rest = rest[end+1:]
	}
	return tags
}

func mustUICert(t *testing.T, subjectCN, issuerCN string, notBefore, notAfter time.Time, serial int64) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: subjectCN},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	parent := leaf
	signer := leafKey
	if subjectCN != issuerCN {
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial + 1000),
			Subject:               pkix.Name{CommonName: issuerCN},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		parent, err = x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		signer = caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
