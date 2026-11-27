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

package certutil

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: fixture trust records use the NSS SHA-1 key
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// mozillaDistrustOctal is the CKA_NSS_SERVER_DISTRUST_AFTER value for
// "Sat Nov 30 23:59:59 2024" in current Mozilla certdata.txt, split the way
// MULTILINE_OCTAL values are wrapped.
const mozillaDistrustOctal = "\\062\\064\\061\\061\\063\\060\n\\062\\063\\065\\071\\065\\071\\132"

func TestParseCertData_distrustAfter(t *testing.T) {
	der := testSelfSignedDER(t, "Distrust After Root")
	doc := certDataDocument(t, der, "CKT_NSS_TRUSTED_DELEGATOR", mozillaDistrustOctal)
	entries, err := parseCertData(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d certs", len(entries))
	}
	if !bytes.Equal(entries[0].cert.Raw, der) {
		t.Fatal("parsed certificate DER does not match the fixture")
	}
	want := time.Date(2024, time.November, 30, 23, 59, 59, 0, time.UTC)
	if !entries[0].serverDistrustAfter.Equal(want) {
		t.Fatalf("distrust-after = %s, want %s", entries[0].serverDistrustAfter.Format(time.RFC3339), want.Format(time.RFC3339))
	}

	// The root stays trusted for server auth. Decode only returns certificates.
	certs, err := Decode([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "Distrust After Root" {
		t.Fatalf("Decode got %+v", certs)
	}
}

func TestParseCertData_distrustAfterAbsent(t *testing.T) {
	der := testSelfSignedDER(t, "No Date Root")
	for _, dateOctal := range []string{"", "false"} {
		doc := certDataDocument(t, der, "CKT_NSS_TRUSTED_DELEGATOR", dateOctal)
		entries, err := parseCertData(strings.NewReader(doc))
		if err != nil {
			t.Fatalf("date %q: %v", dateOctal, err)
		}
		if len(entries) != 1 {
			t.Fatalf("date %q: got %d certs", dateOctal, len(entries))
		}
		if !entries[0].serverDistrustAfter.IsZero() {
			t.Fatalf("date %q: got %s", dateOctal, entries[0].serverDistrustAfter)
		}
	}
}

func TestParseCertData_serverAuthTrust(t *testing.T) {
	der := testSelfSignedDER(t, "Trust Root")
	cases := []struct {
		trust string
		want  int
	}{
		{"CKT_NSS_TRUSTED_DELEGATOR", 1},
		{"CKT_NSS_NOT_TRUSTED", 0},
		{"CKT_NSS_MUST_VERIFY_TRUST", 0},
		{"CKT_NSS_TRUST_UNKNOWN", 0},
		{"(CKT_NSS_MUST_VERIFY_TRUST|CKT_NSS_NOT_TRUSTED)", 0},
	}
	for _, tc := range cases {
		doc := certDataDocument(t, der, tc.trust, "")
		entries, err := parseCertData(strings.NewReader(doc))
		if err != nil {
			t.Fatalf("%s: %v", tc.trust, err)
		}
		if len(entries) != tc.want {
			t.Fatalf("%s: got %d certs, want %d", tc.trust, len(entries), tc.want)
		}
	}
}

func TestServerAuthExplicitDistrustWinsOverDelegator(t *testing.T) {
	der := testSelfSignedDER(t, "Conflicting Trust")
	orders := [][]string{
		{"CKT_NSS_NOT_TRUSTED", "CKT_NSS_TRUSTED_DELEGATOR"},
		{"CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_NOT_TRUSTED"},
	}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for _, order := range orders {
		var doc strings.Builder
		doc.WriteString("BEGINDATA\n")
		writeCertObject(&doc, der, "")
		for _, trust := range order {
			writeServerAuthTrust(&doc, der, trust)
		}
		name := strings.Join(order, " then ")

		entries, err := parseCertData(strings.NewReader(doc.String()))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(entries) != 0 {
			t.Fatalf("%s: trusted %d certs, want 0", name, len(entries))
		}

		blocked, err := ParseDistrustedServerCerts(strings.NewReader(doc.String()), now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(blocked) != 1 {
			t.Fatalf("%s: distrusted %d certs, want 1", name, len(blocked))
		}
		if !blocked[0].NotTrusted {
			t.Fatalf("%s: NotTrusted=false, want true", name)
		}
		if blocked[0].Cert.Subject.CommonName != "Conflicting Trust" {
			t.Fatalf("%s: blocked %q", name, blocked[0].Cert.Subject.CommonName)
		}
	}
}

func TestParseCertData_skipsUnparsedCertificate(t *testing.T) {
	good := testSelfSignedDER(t, "Good Root")
	var doc strings.Builder
	doc.WriteString("BEGINDATA\n")
	writeCertPair(&doc, []byte{0x30, 0x03, 0x01, 0x01, 0x00}, "CKT_NSS_TRUSTED_DELEGATOR", "")
	writeCertPair(&doc, good, "CKT_NSS_TRUSTED_DELEGATOR", "")
	entries, err := parseCertData(strings.NewReader(doc.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].cert.Subject.CommonName != "Good Root" {
		t.Fatalf("got %#v", entries)
	}
}

func TestParseCertData_multilineOctalErrors(t *testing.T) {
	missingEnd := "BEGINDATA\nCKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n\\060\\061\n"
	if _, err := parseCertData(strings.NewReader(missingEnd)); err == nil {
		t.Fatal("expected missing END to fail")
	}
	badDigit := "BEGINDATA\nCKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n\\999\nEND\n"
	if _, err := parseCertData(strings.NewReader(badDigit)); err == nil {
		t.Fatal("expected invalid octal to fail")
	}
	badDate := certDataDocument(t, testSelfSignedDER(t, "Bad Date"), "CKT_NSS_TRUSTED_DELEGATOR", "\\060\\061")
	if _, err := parseCertData(strings.NewReader(badDate)); err == nil {
		t.Fatal("expected invalid distrust-after timestamp to fail")
	}
	if _, err := parseCertData(strings.NewReader("not certdata\n")); err == nil {
		t.Fatal("expected missing BEGINDATA to fail")
	}
}

func TestDistrustedServerCerts(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	past := time.Date(2024, 11, 30, 23, 59, 59, 0, time.UTC)
	future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		cn            string
		trust         string
		date          string
		trusted       bool
		blocked       bool
		notTrusted    bool
		distrustAfter time.Time
	}{
		{cn: "Explicitly Distrusted", trust: "CKT_NSS_NOT_TRUSTED", blocked: true, notTrusted: true},
		{cn: "Passed Distrust After", trust: "CKT_NSS_TRUSTED_DELEGATOR", date: nssDistrustOctal(past), trusted: true, blocked: true, distrustAfter: past},
		{cn: "Future Distrust After", trust: "CKT_NSS_TRUSTED_DELEGATOR", date: nssDistrustOctal(future), trusted: true},
		{cn: "Still Trusted", trust: "CKT_NSS_TRUSTED_DELEGATOR", trusted: true},
		{cn: "Distrust After At Cutoff", trust: "CKT_NSS_TRUSTED_DELEGATOR", date: nssDistrustOctal(now), trusted: true, blocked: true, distrustAfter: now},
		{cn: "Combined Not Trusted", trust: "(CKT_NSS_MUST_VERIFY_TRUST|CKT_NSS_NOT_TRUSTED)", blocked: true, notTrusted: true},
		{cn: "Must Verify", trust: "CKT_NSS_MUST_VERIFY_TRUST"},
		{cn: "False Date Root", trust: "CKT_NSS_TRUSTED_DELEGATOR", date: "false", trusted: true},
		{cn: "Explicit And Passed", trust: "CKT_NSS_NOT_TRUSTED", date: nssDistrustOctal(past), blocked: true, notTrusted: true, distrustAfter: past},
	}

	var doc strings.Builder
	doc.WriteString("BEGINDATA\n")
	for i := range cases {
		writeCertPair(&doc, testSelfSignedDER(t, cases[i].cn), cases[i].trust, cases[i].date)
	}

	entries, err := parseCertData(strings.NewReader(doc.String()))
	if err != nil {
		t.Fatal(err)
	}
	trustedNames := map[string]bool{}
	for _, entry := range entries {
		trustedNames[entry.cert.Subject.CommonName] = true
	}
	blocked, err := ParseDistrustedServerCerts(strings.NewReader(doc.String()), now)
	if err != nil {
		t.Fatal(err)
	}
	blockedByName := map[string]DistrustedServerCert{}
	for _, entry := range blocked {
		cn := entry.Cert.Subject.CommonName
		if _, ok := blockedByName[cn]; ok {
			t.Fatalf("duplicate blocked certificate %s", cn)
		}
		blockedByName[cn] = entry
	}

	for _, tc := range cases {
		if trustedNames[tc.cn] != tc.trusted {
			t.Errorf("%s trusted=%v, want %v", tc.cn, trustedNames[tc.cn], tc.trusted)
		}
		got, ok := blockedByName[tc.cn]
		if ok != tc.blocked {
			t.Errorf("%s blocked=%v, want %v", tc.cn, ok, tc.blocked)
			continue
		}
		if !tc.blocked {
			continue
		}
		if got.NotTrusted != tc.notTrusted {
			t.Errorf("%s NotTrusted=%v, want %v", tc.cn, got.NotTrusted, tc.notTrusted)
		}
		if !got.DistrustAfter.Equal(tc.distrustAfter) {
			t.Errorf("%s distrust-after=%s, want %s", tc.cn, got.DistrustAfter.Format(time.RFC3339), tc.distrustAfter.Format(time.RFC3339))
		}
	}
	wantBlocked := 0
	for _, tc := range cases {
		if tc.blocked {
			wantBlocked++
		}
	}
	if len(blockedByName) != wantBlocked {
		t.Fatalf("blocked %d certificates, want %d", len(blockedByName), wantBlocked)
	}
}

func nssDistrustOctal(t time.Time) string {
	return octalEncode([]byte(t.UTC().Format("060102150405Z")))
}

func TestDistrustedServerCerts_badDate(t *testing.T) {
	doc := certDataDocument(t, testSelfSignedDER(t, "Bad Date"), "CKT_NSS_TRUSTED_DELEGATOR", "\\060\\061")
	if _, err := ParseDistrustedServerCerts(strings.NewReader(doc), time.Now()); err == nil {
		t.Fatal("expected invalid distrust-after timestamp to fail")
	}
}

func TestDistrustedServerCerts_fixture(t *testing.T) {
	bs := readCertDataFixture(t)
	cutoff := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	got, err := ParseDistrustedServerCerts(bytes.NewReader(bs), cutoff)
	if err != nil {
		t.Fatal(err)
	}
	// Fingerprints are SHA-256 of the certificate DER from the pinned
	// certdata.txt snapshot. These seven have a passed
	// CKA_NSS_SERVER_DISTRUST_AFTER at the cutoff.
	want := map[string]string{
		"6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177": "Entrust.net Certification Authority (2048)",
		"2530cc8e98321502bad96f9b1fba1b099e2d299e0f4548bb914f363bc0d4531f": "Izenpe.com",
		"552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988": "DigiCert Trusted Root G4",
		"43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339": "Entrust Root Certification Authority - G2",
		"02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5": "Entrust Root Certification Authority - EC1",
		"40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367": "emSign Root CA - G1",
		"57de0583efd2b26e0361da99da9df4648def7ee8441c3b728afa9bcde0f9b26a": "Autoridad de Certificacion Firmaprofesional CIF A62634068",
	}
	if len(got) != len(want) {
		names := make([]string, 0, len(got))
		for _, entry := range got {
			names = append(names, entry.Cert.Subject.String())
		}
		t.Fatalf("got %d distrusted certs, want %d: %s", len(got), len(want), strings.Join(names, "; "))
	}
	for _, entry := range got {
		fp := GetHexSHA256Fingerprint(*entry.Cert)
		cn, ok := want[fp]
		if !ok {
			t.Fatalf("unexpected distrusted fingerprint %s (%s)", fp, entry.Cert.Subject.String())
		}
		if entry.Cert.Subject.CommonName != cn {
			t.Fatalf("%s CommonName %q, want %q", fp, entry.Cert.Subject.CommonName, cn)
		}
		if entry.NotTrusted || entry.DistrustAfter.IsZero() || !entry.DistrustAfter.Before(cutoff) {
			t.Fatalf("%s NotTrusted=%v date=%s", entry.Cert.Subject.CommonName, entry.NotTrusted, entry.DistrustAfter)
		}
	}
}

func readCertDataFixture(t *testing.T) []byte {
	t.Helper()
	f, err := os.Open("../../testdata/certdata.txt.gz")
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

func TestDecodeNSS_fixture(t *testing.T) {
	bs := readCertDataFixture(t)
	entries, err := parseCertData(bytes.NewReader(bs))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 113 {
		t.Fatalf("got %d certs, want 113", len(entries))
	}
	if entries[0].cert.Subject.CommonName != "COMODO ECC Certification Authority" {
		t.Fatalf("first cert %q", entries[0].cert.Subject.CommonName)
	}
	// Four roots in the pinned snapshot have a CKA_NSS_SERVER_DISTRUST_AFTER date.
	wantDated := map[string]time.Time{
		"Izenpe.com":               time.Date(2026, 4, 15, 23, 59, 59, 0, time.UTC),
		"DigiCert Trusted Root G4": time.Date(2026, 9, 14, 23, 59, 59, 0, time.UTC),
		"emSign Root CA - G1":      time.Date(2026, 11, 16, 23, 59, 59, 0, time.UTC),
		"Autoridad de Certificacion Firmaprofesional CIF A62634068": time.Date(2026, 8, 6, 7, 1, 0, 0, time.UTC),
	}
	dated := 0
	for _, entry := range entries {
		cn := entry.cert.Subject.CommonName
		if want, ok := wantDated[cn]; ok {
			dated++
			if !entry.serverDistrustAfter.Equal(want) {
				t.Fatalf("%s distrust-after %s, want %s", cn, entry.serverDistrustAfter.UTC().Format(time.RFC3339), want.Format(time.RFC3339))
			}
			continue
		}
		if !entry.serverDistrustAfter.IsZero() {
			t.Fatalf("%s has unexpected distrust-after %s", cn, entry.serverDistrustAfter)
		}
	}
	if dated != len(wantDated) {
		t.Fatalf("dated certs %d, want %d", dated, len(wantDated))
	}
	sum := sha256.New()
	for _, entry := range entries {
		if _, err := sum.Write(entry.cert.Raw); err != nil {
			t.Fatal(err)
		}
	}
	// SHA-256 of the 113 certificate DERs in parse order, from the pinned snapshot.
	const want = "73b5aca636a138bad80104e5b388b617b7c72ba490d653d3feab1db5622740a8"
	if got := hex.EncodeToString(sum.Sum(nil)); got != want {
		t.Fatalf("fixture digest %s", got)
	}

	trusted, err := ParseTrustedServerCerts(bytes.NewReader(bs))
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted) != len(entries) {
		t.Fatalf("ParseTrustedServerCerts returned %d certs, parseCertData returned %d", len(trusted), len(entries))
	}
	for i := range entries {
		if trusted[i].Cert == nil {
			t.Fatalf("cert %d is nil", i)
		}
		if trusted[i].Cert.Subject.CommonName != entries[i].cert.Subject.CommonName {
			t.Fatalf("cert %d CN %q, want %q", i, trusted[i].Cert.Subject.CommonName, entries[i].cert.Subject.CommonName)
		}
		if !bytes.Equal(trusted[i].Cert.Raw, entries[i].cert.Raw) {
			t.Fatalf("cert %d DER differs from parseCertData", i)
		}
		if !trusted[i].ServerDistrustAfter.Equal(entries[i].serverDistrustAfter) {
			t.Fatalf("cert %d ServerDistrustAfter=%s, want %s", i, trusted[i].ServerDistrustAfter, entries[i].serverDistrustAfter)
		}
	}
}

func TestParseTrustedServerCerts(t *testing.T) {
	t.Parallel()
	der := testSelfSignedDER(t, "Distrust After Root")
	doc := certDataDocument(t, der, "CKT_NSS_TRUSTED_DELEGATOR", mozillaDistrustOctal)
	got, err := ParseTrustedServerCerts(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d certs", len(got))
	}
	if !bytes.Equal(got[0].Cert.Raw, der) {
		t.Fatal("parsed certificate DER does not match the fixture")
	}
	want := time.Date(2024, time.November, 30, 23, 59, 59, 0, time.UTC)
	if !got[0].ServerDistrustAfter.Equal(want) {
		t.Fatalf("ServerDistrustAfter = %s, want %s", got[0].ServerDistrustAfter.Format(time.RFC3339), want.Format(time.RFC3339))
	}

	future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	futureDoc := certDataDocument(t, der, "CKT_NSS_TRUSTED_DELEGATOR", nssDistrustOctal(future))
	got, err = ParseTrustedServerCerts(strings.NewReader(futureDoc))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("future distrust-after: got %d certs", len(got))
	}
	if !got[0].ServerDistrustAfter.Equal(future) {
		t.Fatalf("future ServerDistrustAfter = %s, want %s", got[0].ServerDistrustAfter.Format(time.RFC3339), future.Format(time.RFC3339))
	}

	absent := certDataDocument(t, der, "CKT_NSS_TRUSTED_DELEGATOR", "")
	got, err = ParseTrustedServerCerts(strings.NewReader(absent))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].ServerDistrustAfter.IsZero() {
		t.Fatalf("absent date: %+v", got)
	}

	for _, trust := range []string{
		"CKT_NSS_NOT_TRUSTED",
		"(CKT_NSS_MUST_VERIFY_TRUST|CKT_NSS_NOT_TRUSTED)",
		"CKT_NSS_MUST_VERIFY_TRUST",
	} {
		rejected := certDataDocument(t, der, trust, "")
		got, err := ParseTrustedServerCerts(strings.NewReader(rejected))
		if err != nil {
			t.Fatalf("%s: %v", trust, err)
		}
		if len(got) != 0 {
			t.Fatalf("%s: got %d certs, want 0", trust, len(got))
		}
	}

	if _, err := ParseTrustedServerCerts(strings.NewReader("not certdata\n")); err == nil {
		t.Fatal("expected missing BEGINDATA to fail")
	}
}

func testSelfSignedDER(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// certDataDocument builds a minimal certdata.txt object pair.
// dateOctal is a MULTILINE_OCTAL body, "false" for CK_BBOOL CK_FALSE, or
// empty to omit CKA_NSS_SERVER_DISTRUST_AFTER.
func certDataDocument(t *testing.T, der []byte, serverAuth, dateOctal string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("BEGINDATA\n")
	// Unknown classes are ignored, matching the builtin root-list object.
	b.WriteString("CKA_CLASS CK_OBJECT_CLASS CKO_NSS_BUILTIN_ROOT_LIST\n")
	b.WriteString("CKA_LABEL UTF8 \"Mozilla Builtin Roots\"\n")
	writeCertPair(&b, der, serverAuth, dateOctal)
	return b.String()
}

func writeCertPair(b *strings.Builder, der []byte, serverAuth, dateOctal string) {
	writeCertObject(b, der, dateOctal)
	writeServerAuthTrust(b, der, serverAuth)
}

func writeServerAuthTrust(b *strings.Builder, der []byte, serverAuth string) {
	sum := sha1.Sum(der) //nolint:gosec // G401: fixture uses the NSS trust-record key
	b.WriteString("CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\n")
	b.WriteString("CKA_CERT_SHA1_HASH MULTILINE_OCTAL\n")
	b.WriteString(octalEncode(sum[:]))
	b.WriteString("\nEND\n")
	b.WriteString("CKA_TRUST_SERVER_AUTH CK_TRUST ")
	b.WriteString(serverAuth)
	b.WriteString("\n")
}

func writeCertObject(b *strings.Builder, der []byte, dateOctal string) {
	b.WriteString("CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n")
	b.WriteString("CKA_VALUE MULTILINE_OCTAL\n")
	b.WriteString(octalEncode(der))
	b.WriteString("\nEND\n")
	switch dateOctal {
	case "":
	case "false":
		b.WriteString("CKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_FALSE\n")
	default:
		b.WriteString("CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL\n")
		b.WriteString(dateOctal)
		b.WriteString("\nEND\n")
	}
}

func octalEncode(in []byte) string {
	var b strings.Builder
	for i, c := range in {
		if i > 0 && i%16 == 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "\\%03o", c)
	}
	return b.String()
}
