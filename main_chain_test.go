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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestChainCLI(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	bundle := writeChainCLICert(t)

	t.Run("help", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--help")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		for _, needle := range []string{
			"trustprune chain --file leaf.pem",
			"--untrusted",
			"--expired",
			"--revoked",
			"--all",
			"--remote",
			"labeled blocklisted",
			"no OCSP or CRL",
			"30s timeout",
			"INDEX, SUBJECT, ISSUER, NOT-AFTER, SHA256",
			"--app openssl --bundle",
			"trustprune chain --url example.com --remote",
			"trustprune chain --url example.com --remote --format json",
			"default: text",
			"options: json, text",
			"--format text|json",
		} {
			if !strings.Contains(res.stdout, needle) {
				t.Fatalf("chain help missing %q:\n%s", needle, res.stdout)
			}
		}
		if strings.Contains(res.stdout, "(revoked)") {
			t.Fatalf("help used revoked as the row label:\n%s", res.stdout)
		}
		top := runCLI(t, bin, home, "--help")
		if top.code != 0 {
			t.Fatalf("root help code=%d stdout=%s stderr=%s", top.code, top.stdout, top.stderr)
		}
		if !strings.Contains(top.stdout, "chain") || !strings.Contains(top.stdout, "Show the certificate chain") {
			t.Fatalf("root help missing chain:\n%s", top.stdout)
		}
	})

	t.Run("missing file and url", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain")
		assertUsageError(t, res, "provide a certificate file (--file) or a URL (--url)")
	})

	t.Run("remote without url", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--file", bundle, "--remote")
		assertUsageError(t, res, "--remote requires a URL")
	})

	t.Run("file and bundle", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle)
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "INDEX") || !strings.Contains(res.stdout, "SUBJECT") || !strings.Contains(res.stdout, "SHA256") {
			t.Fatalf("missing table:\n%s", res.stdout)
		}
		if strings.Contains(res.stdout, "(untrusted)") || strings.Contains(res.stdout, "(expired)") || strings.Contains(res.stdout, "(blocklisted)") {
			t.Fatalf("default chain labeled:\n%s", res.stdout)
		}
		if strings.Contains(res.stdout, "incomplete:") {
			t.Fatalf("self-signed roots marked incomplete:\n%s", res.stdout)
		}
	})

	t.Run("all accepted", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle, "--all")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "INDEX") {
			t.Fatalf("missing table:\n%s", res.stdout)
		}
	})

	t.Run("unknown format", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--format", "nope")
		assertUsageError(t, res, `unknown format "nope" (formats: json, text)`)
		if strings.Contains(res.stdout+res.stderr, "provide a certificate file") {
			t.Fatalf("format check ran after file/url: stdout=%q stderr=%q", res.stdout, res.stderr)
		}
	})

	t.Run("json", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle, "--format", "JSON")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.HasSuffix(res.stdout, "\n") {
			t.Fatalf("json missing trailing newline: %q", res.stdout)
		}
		var doc struct {
			Chain []struct {
				Index    int      `json:"index"`
				Subject  string   `json:"subject"`
				Issuer   string   `json:"issuer"`
				NotAfter string   `json:"not_after"`
				SHA256   string   `json:"sha256"`
				Labels   []string `json:"labels"`
			} `json:"chain"`
			Incomplete string `json:"incomplete"`
		}
		if err := json.Unmarshal([]byte(res.stdout), &doc); err != nil {
			t.Fatalf("json: %v\n%s", err, res.stdout)
		}
		if doc.Incomplete != "" {
			t.Fatalf("incomplete = %q\n%s", doc.Incomplete, res.stdout)
		}
		if len(doc.Chain) != 1 {
			t.Fatalf("chain len = %d\n%s", len(doc.Chain), res.stdout)
		}
		if doc.Chain[0].Index != 0 || doc.Chain[0].Subject != "chain-cli.example" {
			t.Fatalf("cert = %+v", doc.Chain[0])
		}
		if doc.Chain[0].Labels == nil || len(doc.Chain[0].Labels) != 0 {
			t.Fatalf("labels = %#v", doc.Chain[0].Labels)
		}
		if len(doc.Chain[0].SHA256) != 64 {
			t.Fatalf("sha256 = %q", doc.Chain[0].SHA256)
		}
		if !strings.Contains(res.stdout, `"labels": []`) {
			t.Fatalf("empty labels not encoded as []:\n%s", res.stdout)
		}
		if strings.Contains(res.stdout, "INDEX") {
			t.Fatalf("text table in json output:\n%s", res.stdout)
		}
	})

	t.Run("http url", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--url", "http://example.com")
		if res.code == 2 || strings.Contains(res.stderr, "unknown flag") {
			t.Fatalf("http treated as usage: code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if res.code != 1 || !strings.Contains(res.stdout+res.stderr, "non-secure") {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
	})

	t.Run("local url does not dial", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--url", "https://chain-no-local.invalid")
		if res.code != 1 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "pass --remote") {
			t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
		}
	})
}

func TestChainCLIRemote(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	bin := cliBinary(t)
	home := t.TempDir()
	lots := filepath.Join("testdata", "lots.crt")

	quiet := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", lots, "--url", srv.URL)
	if quiet.code != 1 || !strings.Contains(quiet.stdout, "pass --remote") {
		t.Fatalf("code=%d stdout=%s stderr=%s", quiet.code, quiet.stdout, quiet.stderr)
	}
	if strings.Contains(quiet.stdout, "INDEX") {
		t.Fatalf("wrote a table without --remote:\n%s", quiet.stdout)
	}

	res := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", lots, "--url", srv.URL, "--remote")
	if res.code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "INDEX") || !strings.Contains(res.stdout, "SHA256") {
		t.Fatalf("remote chain:\n%s", res.stdout)
	}
	if strings.Contains(res.stdout, "incomplete:") {
		t.Fatalf("self-signed httptest leaf marked incomplete:\n%s", res.stdout)
	}
}

func writeChainCLICert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "chain-cli.example"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
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
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := certutil.ToFile(path, []*x509.Certificate{cert}); err != nil {
		t.Fatal(err)
	}
	return path
}
