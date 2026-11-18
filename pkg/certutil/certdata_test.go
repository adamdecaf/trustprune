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

func TestDistrustedServerCerts_historicalFixture(t *testing.T) {
	bs := readCertDataFixture(t)
	got, err := ParseDistrustedServerCerts(bytes.NewReader(bs), time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	// The fixture has no CKA_NSS_SERVER_DISTRUST_AFTER dates. The two
	// explicitly distrusted certificates that include a DER are DigiNotar.
	if len(got) != 2 {
		names := make([]string, 0, len(got))
		for _, entry := range got {
			names = append(names, entry.Cert.Subject.String())
		}
		t.Fatalf("got %d distrusted certs: %s", len(got), strings.Join(names, "; "))
	}
	for _, entry := range got {
		if !entry.NotTrusted || !entry.DistrustAfter.IsZero() {
			t.Fatalf("%s NotTrusted=%v date=%s", entry.Cert.Subject.CommonName, entry.NotTrusted, entry.DistrustAfter)
		}
		if !strings.Contains(entry.Cert.Subject.String(), "DigiNotar") {
			t.Fatalf("subject %s", entry.Cert.Subject.String())
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

func TestDecodeNSS_historicalFixture(t *testing.T) {
	bs := readCertDataFixture(t)
	entries, err := parseCertData(bytes.NewReader(bs))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 132 {
		t.Fatalf("got %d certs", len(entries))
	}
	if entries[0].cert.Subject.CommonName != "GlobalSign Root CA" {
		t.Fatalf("first cert %q", entries[0].cert.Subject.CommonName)
	}
	// The historical fixture has no CKA_NSS_SERVER_DISTRUST_AFTER dates.
	for i, entry := range entries {
		if !entry.serverDistrustAfter.IsZero() {
			t.Fatalf("cert %d has distrust-after %s", i, entry.serverDistrustAfter)
		}
	}
	sum := sha256.New()
	for _, entry := range entries {
		if _, err := sum.Write(entry.cert.Raw); err != nil {
			t.Fatal(err)
		}
	}
	const want = "e68e03a1d1d4532b86fe113857f10b1c00bd450a5137cf5c5024b00f349e19e2"
	if got := hex.EncodeToString(sum.Sum(nil)); got != want {
		t.Fatalf("fixture digest %s", got)
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
	sum := sha1.Sum(der) //nolint:gosec // G401: fixture uses the NSS trust-record key
	writeCertObject(b, der, dateOctal)
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
