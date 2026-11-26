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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestDenylist_committedEntries(t *testing.T) {
	if len(deniedCerts) == 0 {
		t.Fatal("denylist is empty")
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	wantFP := []string{
		"0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217", // DigiNotar Root CA
		"e28393773da845a679f2080cc7fb44a3b7a1c3792cb7eb7729fdcb6a8d99aea7", // CNNIC ROOT
		"4b22d5a6aec99f3cdb79aa5ec06838479cd5ecba7164f7f22dc1d65f63d85708", // WoSign
		"c766a9bef2d4071c863a31aa4920e813b2d198608cb7b7cfe21143b836df09ea", // StartCom
		"9acfab7e43c8d880d06b262a94deeee4b4659989c3d0caf19baf6405e41ab7df", // VeriSign Class 3 G5
	}
	byFP := make(map[string]deniedCert, len(deniedCerts))
	for _, e := range deniedCerts {
		if e.name == "" {
			t.Errorf("entry %s has an empty name", e.fingerprint)
		}
		if !hex64.MatchString(e.fingerprint) {
			t.Errorf("%s fingerprint %q is not lowercase sha256 hex", e.name, e.fingerprint)
		}
		if !hex64.MatchString(e.spki) {
			t.Errorf("%s spki %q is not lowercase sha256 hex", e.name, e.spki)
		}
		if prev, ok := byFP[e.fingerprint]; ok {
			t.Errorf("duplicate fingerprint %s (%s and %s)", e.fingerprint, prev.name, e.name)
		}
		byFP[e.fingerprint] = e
	}
	for _, fp := range wantFP {
		if _, ok := byFP[fp]; !ok {
			t.Errorf("missing denylisted fingerprint %s", fp)
		}
	}

	// Three DigiNotar Root CA certificates were re-issued on one key.
	shared := "a903af8c07bb91b0d9e3f3a30c6d53339fc5bd47e5d6bdb476598860c068a024"
	for _, fp := range []string{
		"0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217",
		"4fee0163686ecbd65db968e7494f55d84b25486d438e9de558d629d28cd4d176",
		"8a1bd21661c60015065212cc98b1abb50dfd14c872a208e66bae890f25c448af",
	} {
		e, ok := byFP[fp]
		if !ok {
			t.Fatalf("missing DigiNotar Root CA %s", fp)
		}
		if e.spki != shared {
			t.Errorf("%s spki=%s, want shared DigiNotar Root CA key %s", fp, e.spki, shared)
		}
	}
}

func TestAllowlist_denylistRejectsNamedCert(t *testing.T) {
	cert := mustDeniedTestCert(t, nil, "Named Root", "US", 1)
	fp := certutil.GetHexSHA256Fingerprint(*cert)

	al := Allowlist{
		Fingerprints: []string{fp},
		Countries:    []string{"US"},
	}
	if !al.Matches(cert) {
		t.Fatal("certificate should match before it is denylisted")
	}

	// Upper case and colons still identify the certificate.
	var colon string
	for i := 0; i < len(fp); i += 2 {
		if i > 0 {
			colon += ":"
		}
		colon += fp[i : i+2]
	}
	t.Cleanup(AddDeniedForTest("fixture root", strings.ToUpper(colon), ""))

	if al.Matches(cert) {
		t.Fatal("denylisted certificate must not match even when the allowlist names it")
	}
	if denied, name := Denied(cert); !denied || name != "fixture root" {
		t.Fatalf("Denied=%v %q", denied, name)
	}
	if al.MatchesAll([]*x509.Certificate{cert}) {
		t.Fatal("MatchesAll must reject a denylisted certificate")
	}
}

func TestAllowlist_denylistSPKICatchesReissue(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := mustDeniedTestCert(t, key, "Original Root", "US", 1)
	reissued := mustDeniedTestCert(t, key, "Reissued Root", "US", 2)
	other := mustDeniedTestCert(t, nil, "Other Root", "US", 3)

	origFP := certutil.GetHexSHA256Fingerprint(*original)
	reFP := certutil.GetHexSHA256Fingerprint(*reissued)
	otherFP := certutil.GetHexSHA256Fingerprint(*other)
	if origFP == reFP {
		t.Fatal("re-issued certificate must have a different fingerprint")
	}
	if spkiSHA256(original) != spkiSHA256(reissued) {
		t.Fatal("re-issued certificate must keep the same SPKI")
	}
	if spkiSHA256(original) == spkiSHA256(other) {
		t.Fatal("unrelated certificate must not share the SPKI")
	}

	// Fingerprint-only entry rejects the original certificate and not the re-issue.
	t.Cleanup(AddDeniedForTest("fingerprint only", origFP, ""))
	alRe := Allowlist{Fingerprints: []string{reFP}, Countries: []string{"US"}}
	if !alRe.Matches(reissued) {
		t.Fatal("fingerprint denylist entry must not reject a re-issued certificate")
	}
	alOrig := Allowlist{Fingerprints: []string{origFP}, Countries: []string{"US"}}
	if alOrig.Matches(original) {
		t.Fatal("fingerprint denylist entry must reject the named certificate")
	}

	// SPKI entry rejects the re-issue even though the allowlist names it.
	t.Cleanup(AddDeniedForTest("shared key", "", spkiSHA256(original)))
	if alRe.Matches(reissued) {
		t.Fatal("SPKI denylist entry must reject a re-issued certificate named by the allowlist")
	}
	if alOrig.Matches(original) {
		t.Fatal("SPKI denylist entry must reject the original certificate")
	}
	if denied, name := Denied(reissued); !denied || name == "" {
		t.Fatalf("Denied(reissued)=%v %q", denied, name)
	}
	alOther := Allowlist{Fingerprints: []string{otherFP}}
	if !alOther.Matches(other) {
		t.Fatal("unrelated certificate must still match")
	}
}

func TestDenylist_eMudhraG3Intermediates(t *testing.T) {
	want := []deniedCert{
		{
			name:        "EM DV TLS CA - G3C",
			fingerprint: "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19",
			spki:        "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
		},
		{
			name:        "EM DV TLS CA - G3B",
			fingerprint: "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493",
			spki:        "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
		},
		{
			name:        "EM EV TLS CA - G3C",
			fingerprint: "432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3",
			spki:        "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
		},
		{
			name:        "EM EV TLS CA - G3B",
			fingerprint: "e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838",
			spki:        "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
		},
		{
			name:        "EM OV TLS CA - G3C",
			fingerprint: "cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f",
			spki:        "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
		},
		{
			name:        "EM OV TLS CA - G3B",
			fingerprint: "98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b",
			spki:        "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
		},
		{
			name:        "EM OV CS CA - G3C",
			fingerprint: "4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1",
			spki:        "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
		},
		{
			name:        "EM OV CS CA - G3B",
			fingerprint: "9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4",
			spki:        "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
		},
	}
	if len(want) != 8 {
		t.Fatalf("eMudhra G3 case list has %d entries, want 8", len(want))
	}
	byFP := make(map[string]deniedCert, len(deniedCerts))
	for _, e := range deniedCerts {
		byFP[e.fingerprint] = e
	}
	seenSPKI := make(map[string]string, len(want))
	for _, w := range want {
		e, ok := byFP[w.fingerprint]
		if !ok {
			t.Errorf("missing eMudhra G3 fingerprint %s (%s)", w.fingerprint, w.name)
			continue
		}
		if e.spki != w.spki {
			t.Errorf("%s spki=%s, want %s", w.name, e.spki, w.spki)
		}
		if e.name != w.name {
			t.Errorf("fingerprint %s name=%q, want %q", w.fingerprint, e.name, w.name)
		}
		if prev, ok := seenSPKI[w.spki]; ok {
			t.Errorf("duplicate eMudhra SPKI %s (%s and %s)", w.spki, prev, w.name)
		}
		seenSPKI[w.spki] = w.name
	}
}

func TestDenied_eMudhraG3SPKIRejectsNewCert(t *testing.T) {
	const (
		wantFP   = "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19"
		wantSPKI = "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f"
		wantName = "EM DV TLS CA - G3C"
	)
	// #nosec G304 -- testdata fixture, not user input
	raw, err := os.ReadFile(filepath.Join("testdata", "em-dv-tls-ca-g3c.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("testdata PEM has no CERTIFICATE block")
	}
	original, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := certutil.GetHexSHA256Fingerprint(*original); got != wantFP {
		t.Fatalf("fixture fingerprint %s, want %s", got, wantFP)
	}
	if got := spkiSHA256(original); got != wantSPKI {
		t.Fatalf("fixture SPKI %s, want %s", got, wantSPKI)
	}
	if denied, name := Denied(original); !denied || name != wantName {
		t.Fatalf("Denied(fixture)=%v %q", denied, name)
	}

	parentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Parent",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Reissued EM DV TLS CA - G3C",
			Country:    []string{"US"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		PublicKey:             original.PublicKey,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, tmpl.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	reissued, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if certutil.GetHexSHA256Fingerprint(*reissued) == wantFP {
		t.Fatal("reissued certificate must not keep the denylisted certificate fingerprint")
	}
	if spkiSHA256(reissued) != wantSPKI {
		t.Fatalf("reissued SPKI %s, want %s", spkiSHA256(reissued), wantSPKI)
	}
	if denied, name := Denied(reissued); !denied || name != wantName {
		t.Fatalf("Denied(reissued)=%v %q", denied, name)
	}
}

func TestDenied_DYMORootCA(t *testing.T) {
	const (
		wantFP   = "b6281afb8dbfc71515f9573e26d92b47c70f8b6d821c2065cd358f8658b75389"
		wantSPKI = "481c702ef267378036c7d5cc157d7e8b3a8eb65946dfc1c5402770439a508e09"
		wantName = "DYMO Root CA (for localhost)"
	)
	// #nosec G304 -- testdata fixture, not user input
	raw, err := os.ReadFile(filepath.Join("testdata", "dymo-root-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("testdata PEM has no CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := certutil.GetHexSHA256Fingerprint(*cert); got != wantFP {
		t.Fatalf("fixture fingerprint %s, want %s", got, wantFP)
	}
	if got := spkiSHA256(cert); got != wantSPKI {
		t.Fatalf("fixture SPKI %s, want %s", got, wantSPKI)
	}
	if denied, name := Denied(cert); !denied || name != wantName {
		t.Fatalf("Denied(fixture)=%v %q", denied, name)
	}
}

func TestDenied_SennheiserHeadSetupRoots(t *testing.T) {
	cases := []struct {
		file     string
		wantFP   string
		wantSPKI string
		wantName string
	}{
		{
			file:     "senncomcccert.pem",
			wantFP:   "ddd8ab9178c99cbd9685ea4ae66dc28bfdc9a5a8a166f7f69ad0b5042ad6eb28",
			wantSPKI: "8f591f7aa4dc3efe9490c38a4692c9011ed128f1de595569406d77b6fa1f6b4c",
			wantName: "SennComCCCert",
		},
		{
			file:     "senncomrootca.pem",
			wantFP:   "91e5cc32910686c5cac25c18cc805696c7b33868c280caf0c72844a2a8eb91e2",
			wantSPKI: "0c43ea8bcde9fc3bca165664ac8215567e3489d5393a0c81e1a79141992e1953",
			wantName: "SenncomRootCA",
		},
	}
	for _, tc := range cases {
		t.Run(tc.wantName, func(t *testing.T) {
			// #nosec G304 -- testdata fixture, not user input
			raw, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE" {
				t.Fatal("testdata PEM has no CERTIFICATE block")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if got := certutil.GetHexSHA256Fingerprint(*cert); got != tc.wantFP {
				t.Fatalf("fixture fingerprint %s, want %s", got, tc.wantFP)
			}
			if got := spkiSHA256(cert); got != tc.wantSPKI {
				t.Fatalf("fixture SPKI %s, want %s", got, tc.wantSPKI)
			}
			if denied, name := Denied(cert); !denied || name != tc.wantName {
				t.Fatalf("Denied(fixture)=%v %q", denied, name)
			}

			parentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			parent := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "Test Parent",
				},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageCertSign,
				IsCA:                  true,
				BasicConstraintsValid: true,
			}
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject: pkix.Name{
					CommonName: "Reissued " + tc.wantName,
					Country:    []string{"DK"},
				},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageCertSign,
				IsCA:                  true,
				BasicConstraintsValid: true,
				PublicKey:             cert.PublicKey,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, tmpl.PublicKey, parentKey)
			if err != nil {
				t.Fatal(err)
			}
			reissued, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if certutil.GetHexSHA256Fingerprint(*reissued) == tc.wantFP {
				t.Fatal("reissued certificate must not keep the denylisted certificate fingerprint")
			}
			if spkiSHA256(reissued) != tc.wantSPKI {
				t.Fatalf("reissued SPKI %s, want %s", spkiSHA256(reissued), tc.wantSPKI)
			}
			if denied, name := Denied(reissued); !denied || name != tc.wantName {
				t.Fatalf("Denied(reissued)=%v %q", denied, name)
			}
		})
	}
}

func TestDenied_SuperfishAndEDellRoot(t *testing.T) {
	cases := []struct {
		file     string
		wantFP   string
		wantSPKI string
		wantName string
	}{
		{
			file:     "superfish.pem",
			wantFP:   "b6fe9151402bad1c06d7e66db67a26aa7356f2e6c644dbcf9f98968ff632e1b7",
			wantSPKI: "4bb8f35ba1e126f8dde1b0c420625ed86dce61a7bddadbdea9aba578ff13145e",
			wantName: "Superfish",
		},
		{
			file:     "edellroot.pem",
			wantFP:   "ec30c9c3065a06bb07dc5b1c6b497f370c1ca65c0f30c08e042ba6bcecc78f2c",
			wantSPKI: "cdee9f3305572a677e1a6c82dc1e02a35b11cae6a684338c9f37fe1ac8daec23",
			wantName: "eDellRoot",
		},
	}
	for _, tc := range cases {
		t.Run(tc.wantName, func(t *testing.T) {
			// #nosec G304 -- testdata fixture, not user input
			raw, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE" {
				t.Fatal("testdata PEM has no CERTIFICATE block")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if got := certutil.GetHexSHA256Fingerprint(*cert); got != tc.wantFP {
				t.Fatalf("fixture fingerprint %s, want %s", got, tc.wantFP)
			}
			if got := spkiSHA256(cert); got != tc.wantSPKI {
				t.Fatalf("fixture SPKI %s, want %s", got, tc.wantSPKI)
			}
			if denied, name := Denied(cert); !denied || name != tc.wantName {
				t.Fatalf("Denied(fixture)=%v %q", denied, name)
			}

			parentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			parent := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "Test Parent",
				},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageCertSign,
				IsCA:                  true,
				BasicConstraintsValid: true,
			}
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject: pkix.Name{
					CommonName: "Reissued " + tc.wantName,
					Country:    []string{"US"},
				},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageCertSign,
				IsCA:                  true,
				BasicConstraintsValid: true,
				PublicKey:             cert.PublicKey,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, tmpl.PublicKey, parentKey)
			if err != nil {
				t.Fatal(err)
			}
			reissued, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if certutil.GetHexSHA256Fingerprint(*reissued) == tc.wantFP {
				t.Fatal("reissued certificate must not keep the denylisted certificate fingerprint")
			}
			if spkiSHA256(reissued) != tc.wantSPKI {
				t.Fatalf("reissued SPKI %s, want %s", spkiSHA256(reissued), tc.wantSPKI)
			}
			if denied, name := Denied(reissued); !denied || name != tc.wantName {
				t.Fatalf("Denied(reissued)=%v %q", denied, name)
			}
		})
	}
}

func TestDenied_DSDTestProvider(t *testing.T) {
	const (
		wantFP   = "0f912fd7be760be25afbc56bdc09cd9e5dcc9c6f6a55a778aefcb6aa30e31554"
		wantSPKI = "130ad4e0633521290531b6651f5759b0bc7bc656709ff8f365c2143b0389b6f6"
		wantName = "DSDTestProvider"
	)
	// #nosec G304 -- testdata fixture, not user input
	raw, err := os.ReadFile(filepath.Join("testdata", "dsdtestprovider.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("testdata PEM has no CERTIFICATE block")
	}
	// Negative serial: crypto/x509 rejects this certificate. The cryptobyte
	// fallback fills Raw and RawSubjectPublicKeyInfo so Denied can match
	// both the certificate fingerprint and a reissue of the same key.
	if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		t.Fatal("crypto/x509.ParseCertificate must reject DSDTestProvider")
	} else if !strings.Contains(err.Error(), "negative serial") {
		t.Fatalf("expected negative serial parse error, got %v", err)
	}
	cert, err := certutil.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := certutil.GetHexSHA256Fingerprint(*cert); got != wantFP {
		t.Fatalf("fixture fingerprint %s, want %s", got, wantFP)
	}
	if got := spkiSHA256(cert); got != wantSPKI {
		t.Fatalf("fixture SPKI %s, want %s", got, wantSPKI)
	}
	if denied, name := Denied(cert); !denied || name != wantName {
		t.Fatalf("Denied(fixture)=%v %q", denied, name)
	}

	pub, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	parentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Parent"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Reissued DSDTestProvider", Country: []string{"US"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		PublicKey:             pub,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	reissued, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if certutil.GetHexSHA256Fingerprint(*reissued) == wantFP {
		t.Fatal("reissued certificate must not keep the denylisted certificate fingerprint")
	}
	if spkiSHA256(reissued) != wantSPKI {
		t.Fatalf("reissued SPKI %s, want %s", spkiSHA256(reissued), wantSPKI)
	}
	if denied, name := Denied(reissued); !denied || name != wantName {
		t.Fatalf("Denied(reissued)=%v %q", denied, name)
	}
}

func TestDenied_negativeSerialSPKI(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	positive := mustDeniedTestCert(t, key, "positive.example", "US", 1)
	t.Cleanup(AddDeniedForTest("test negative serial key", "", spkiSHA256(positive)))

	der := negativeSerialDER(t, positive.Raw)
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Skip("crypto/x509 accepted a negative serial; cannot exercise fallback on this toolchain")
	} else if !strings.Contains(err.Error(), "negative serial") {
		t.Fatalf("expected negative serial parse error, got %v", err)
	}
	cert, err := certutil.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() >= 0 {
		t.Fatalf("serial=%v, want negative", cert.SerialNumber)
	}
	if got := spkiSHA256(cert); got != spkiSHA256(positive) {
		t.Fatalf("fallback SPKI %s, want %s", got, spkiSHA256(positive))
	}
	if denied, name := Denied(cert); !denied || name != "test negative serial key" {
		t.Fatalf("Denied(negative serial)=%v %q", denied, name)
	}
}

func TestDenied_missingSPKI(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
	if denied, name := Denied(cert); !denied || name != "missing SPKI" {
		t.Fatalf("Denied(empty SPKI)=%v %q", denied, name)
	}
}

func TestDenied_nil(t *testing.T) {
	if denied, name := Denied(nil); denied || name != "" {
		t.Fatalf("Denied(nil)=%v %q", denied, name)
	}
}

// negativeSerialDER copies der and sets the serial INTEGER's high bit so
// crypto/x509 rejects it and ParseCertificate uses the fallback. The SPKI
// bytes are left unchanged. CreateCertificate cannot emit a negative serial.
func negativeSerialDER(t *testing.T, der []byte) []byte {
	t.Helper()
	out := append([]byte(nil), der...)
	rest := cryptobyte.String(out)
	var certSeq cryptobyte.String
	if !rest.ReadASN1(&certSeq, cryptobyte_asn1.SEQUENCE) || !rest.Empty() {
		t.Fatal("expected one certificate SEQUENCE")
	}
	var tbs cryptobyte.String
	if !certSeq.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		t.Fatal("unwrap tbs")
	}
	if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		t.Fatal("version")
	}
	var serial cryptobyte.String
	if !tbs.ReadASN1Element(&serial, cryptobyte_asn1.INTEGER) {
		t.Fatal("serial")
	}
	if len(serial) < 3 || serial[0] != byte(cryptobyte_asn1.INTEGER) || serial[1]&0x80 != 0 {
		t.Fatalf("serial encoding = %x", serial)
	}
	if serial[2]&0x80 != 0 {
		t.Fatal("serial already negative")
	}
	serial[2] |= 0x80
	return out
}

func mustDeniedTestCert(t *testing.T, key *ecdsa.PrivateKey, cn, country string, serial int64) *x509.Certificate {
	t.Helper()
	var err error
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: cn,
			Country:    []string{country},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
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
