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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestParseChromiumBlocklistArchiveSelfMinted(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	cert, key := mintChromiumTestCA(t, "Test Blocked Root", now.Add(10*365*24*time.Hour))
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	spkiDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER})

	// Name the cert file with a fake hash so a filename-based generator
	// would emit the wrong value.
	archive := makeChromiumTarGz(t, map[string][]byte{
		"README.md": []byte("# Certificate Blocklist\n"),
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.pem": certPEM,
		hex.EncodeToString(sha256Sum(spkiDER)) + ".key":                        keyPEM,
	})

	got, err := ParseChromiumBlocklistArchive(bytes.NewReader(archive), "self-minted.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	wantCert := certutil.GetHexSHA256Fingerprint(*cert)
	wantSPKI := hex.EncodeToString(sha256Sum(spkiDER))
	if len(got.Certs) != 1 || got.Certs[0].SHA256 != wantCert {
		t.Fatalf("certs = %+v, want %s", got.Certs, wantCert)
	}
	if got.Certs[0].SHA256 == strings.Repeat("f", 64) {
		t.Fatal("used the filename as the certificate fingerprint")
	}
	if !strings.Contains(got.Certs[0].Comment, "Test Blocked Root") {
		t.Fatalf("comment = %q", got.Certs[0].Comment)
	}
	if len(got.SPKIs) != 1 || got.SPKIs[0].SHA256 != wantSPKI {
		t.Fatalf("spkis = %+v, want %s", got.SPKIs, wantSPKI)
	}
}

func TestParseChromiumBlocklistArchiveEmpty(t *testing.T) {
	t.Parallel()

	archive := makeChromiumTarGz(t, map[string][]byte{"README.md": []byte("hi\n")})
	_, err := ParseChromiumBlocklistArchive(bytes.NewReader(archive), "empty.tar.gz")
	if err == nil || !strings.Contains(err.Error(), "no certificates or public keys") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseChromiumBlocklistArchiveRejectsInventedKey(t *testing.T) {
	t.Parallel()

	archive := makeChromiumTarGz(t, map[string][]byte{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.key": []byte("not a pem key\n"),
	})
	_, err := ParseChromiumBlocklistArchive(bytes.NewReader(archive), "bad-key.tar.gz")
	if err == nil || !strings.Contains(err.Error(), "no CERTIFICATE or PUBLIC KEY") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseChromiumBlocklistTestdata(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "chromium-ssl-blocklist.tar.gz")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, err := ParseChromiumBlocklistArchive(f, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Certs) != 115 {
		t.Fatalf("certs = %d, want 115", len(got.Certs))
	}
	if len(got.SPKIs) != 4 {
		t.Fatalf("spkis = %d, want 4", len(got.SPKIs))
	}
	// Qaznet Trust Network, a known Chromium blocklist certificate.
	const qaznet = "00309c736dd661da6f1eb24173aa849944c168a43a15bffd192eecfdb6f8dbd2"
	if !chromiumHas(got.Certs, qaznet) {
		t.Fatalf("missing Qaznet certificate fingerprint %s", qaznet)
	}
	const keySPKI = "32ecc96f912f96d889e73088cd031c7ded2c651c805016157a23b6f32f798a3b"
	if !chromiumHas(got.SPKIs, keySPKI) {
		t.Fatalf("missing public-key SPKI %s", keySPKI)
	}
	// This file is named by its SPKI hash, not the certificate hash.
	// The certificate fingerprint must still come from the DER.
	const iscaFile = "3472e4f16c570e0dd388aaaa4a64a34a4b939f1ca770996b5be0037c1aded9c1"
	const iscaCert = "235150de7df7db2e538d461bc4d210c4e0819be2c4c76969476e3cbe67b723dd"
	if chromiumHas(got.Certs, iscaFile) {
		t.Fatalf("used the SPKI filename %s as a certificate fingerprint", iscaFile)
	}
	if !chromiumHas(got.Certs, iscaCert) {
		t.Fatalf("missing ISCA certificate fingerprint %s", iscaCert)
	}
	if len(blocklistedFingerprints) != len(got.Certs) {
		t.Fatalf("blocklistedFingerprints = %d, testdata certs = %d", len(blocklistedFingerprints), len(got.Certs))
	}
	for i, it := range got.Certs {
		if blocklistedFingerprints[i] != it.SHA256 {
			t.Fatalf("blocklistedFingerprints[%d] = %s, testdata %s", i, blocklistedFingerprints[i], it.SHA256)
		}
	}
	if len(blocklistedSPKIs) != len(got.SPKIs) {
		t.Fatalf("blocklistedSPKIs = %d, testdata SPKIs = %d", len(blocklistedSPKIs), len(got.SPKIs))
	}
	for i, it := range got.SPKIs {
		if blocklistedSPKIs[i] != it.SHA256 {
			t.Fatalf("blocklistedSPKIs[%d] = %s, testdata %s", i, blocklistedSPKIs[i], it.SHA256)
		}
	}
}

func TestChromiumBlocklistMatchesSPKI(t *testing.T) {
	now := time.Now().UTC()
	cert, key := mintChromiumTestCA(t, "SPKI Blocked Root", now.Add(10*365*24*time.Hour))
	spkiDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	spki := hex.EncodeToString(sha256Sum(spkiDER))

	prevFP := blocklistedFingerprints
	prevSPKI := blocklistedSPKIs
	t.Cleanup(func() {
		blocklistedFingerprints = prevFP
		blocklistedSPKIs = prevSPKI
	})
	blocklistedFingerprints = nil
	blocklistedSPKIs = []string{spki}

	if !Blocklisted(cert) {
		t.Fatal("Blocklisted did not match a Chromium SPKI")
	}
	names := BlocklistNames(cert)
	if len(names) != 1 || names[0] != BlocklistChromium {
		t.Fatalf("BlocklistNames = %v", names)
	}
	// A different key must not match.
	other, _ := mintChromiumTestCA(t, "Other Root", now.Add(10*365*24*time.Hour))
	if Blocklisted(other) {
		t.Fatal("Blocklisted matched a certificate with a different SPKI")
	}
}

func TestChromiumFingerprintOverlap(t *testing.T) {
	t.Parallel()

	if len(appleBlocklistedFingerprints) == 0 || len(ccadbRemovedBlocklistedFingerprints) == 0 {
		t.Fatal("apple or CCADB blocklist is empty")
	}
	appleOnly := appleBlocklistedFingerprints[0]
	var both, ccadbOnly string
	inApple := map[string]struct{}{}
	for _, fp := range appleBlocklistedFingerprints {
		inApple[fp] = struct{}{}
	}
	for _, fp := range ccadbRemovedBlocklistedFingerprints {
		if _, ok := inApple[fp]; ok {
			both = fp
			break
		}
	}
	for _, fp := range ccadbRemovedBlocklistedFingerprints {
		if _, ok := inApple[fp]; !ok {
			ccadbOnly = fp
			break
		}
	}
	if both == "" || ccadbOnly == "" {
		t.Fatal("need shared and CCADB-only fingerprints in the fixtures")
	}
	a, c, b, e := ChromiumFingerprintOverlap([]string{appleOnly, both, ccadbOnly, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if a != 2 || c != 2 || b != 1 || e != 3 {
		t.Fatalf("overlap apple=%d ccadb=%d both=%d either=%d", a, c, b, e)
	}
}

func chromiumHas(items []ChromiumItem, fp string) bool {
	for _, it := range items {
		if it.SHA256 == fp {
			return true
		}
	}
	return false
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func makeChromiumTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mintChromiumTestCA(t *testing.T, cn string, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"trustprune test"}},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
