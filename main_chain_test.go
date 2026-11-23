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
			"(--file <path> | <path> | --url <url> | <url>)",
			"one positional argument",
			"existing regular file",
			"treated as https",
			"trustprune chain leaf.pem --app openssl --bundle",
			"trustprune chain example.com --remote",
			"--untrusted",
			"--expired",
			"--revoked",
			"--all",
			"--remote",
			"labeled blocklisted",
			"no OCSP or CRL",
			"30s timeout",
			"INDEX, SUBJECT, ISSUER, NOT-AFTER, SHA256",
			"16-character prefix",
			"full 64-character SHA-256",
			"--app openssl --bundle",
			"trustprune chain --url example.com --remote",
			"trustprune chain --url example.com --remote --format json",
			"default: text",
			"options: json, text",
			"--format text|json",
			"instead of a positional path",
			"instead of a positional URL",
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
			Complete      bool   `json:"complete"`
			Incomplete    string `json:"incomplete"`
			MissingIssuer string `json:"missing_issuer"`
		}
		if err := json.Unmarshal([]byte(res.stdout), &doc); err != nil {
			t.Fatalf("json: %v\n%s", err, res.stdout)
		}
		if !doc.Complete {
			t.Fatalf("complete = false\n%s", res.stdout)
		}
		if !strings.Contains(res.stdout, `"complete": true`) {
			t.Fatalf("complete not encoded as true:\n%s", res.stdout)
		}
		if doc.Incomplete != "" {
			t.Fatalf("incomplete = %q\n%s", doc.Incomplete, res.stdout)
		}
		if strings.Contains(res.stdout, `"incomplete"`) {
			t.Fatalf("incomplete present when chain is complete:\n%s", res.stdout)
		}
		if doc.MissingIssuer != "" {
			t.Fatalf("missing_issuer = %q\n%s", doc.MissingIssuer, res.stdout)
		}
		if strings.Contains(res.stdout, `"missing_issuer"`) {
			t.Fatalf("missing_issuer present when chain is complete:\n%s", res.stdout)
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

	t.Run("json incomplete", func(t *testing.T) {
		file := writeChainCLILeafAndCA(t)
		res := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", file, "--format", "json")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		var doc struct {
			Chain []struct {
				Subject string `json:"subject"`
			} `json:"chain"`
			Complete      bool   `json:"complete"`
			Incomplete    string `json:"incomplete"`
			MissingIssuer string `json:"missing_issuer"`
		}
		if err := json.Unmarshal([]byte(res.stdout), &doc); err != nil {
			t.Fatalf("json: %v\n%s", err, res.stdout)
		}
		if doc.Complete {
			t.Fatalf("complete = true\n%s", res.stdout)
		}
		if !strings.Contains(res.stdout, `"complete": false`) {
			t.Fatalf("complete not encoded as false:\n%s", res.stdout)
		}
		wantNote := "incomplete: no issuer for leaf.example; pass --untrusted"
		if doc.Incomplete != wantNote {
			t.Fatalf("incomplete = %q, want %q\n%s", doc.Incomplete, wantNote, res.stdout)
		}
		if doc.MissingIssuer != "leaf.example" {
			t.Fatalf("missing_issuer = %q\n%s", doc.MissingIssuer, res.stdout)
		}
		if !strings.Contains(res.stdout, `"missing_issuer": "leaf.example"`) {
			t.Fatalf("missing_issuer not encoded:\n%s", res.stdout)
		}
		if len(doc.Chain) != 1 || doc.Chain[0].Subject != "leaf.example" {
			t.Fatalf("chain = %+v\n%s", doc.Chain, res.stdout)
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

	t.Run("positional file matches --file", func(t *testing.T) {
		flagged := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle)
		pos := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, bundle)
		if pos.code != 0 || flagged.code != 0 {
			t.Fatalf("positional code=%d stdout=%s stderr=%s\nflag code=%d stdout=%s stderr=%s", pos.code, pos.stdout, pos.stderr, flagged.code, flagged.stdout, flagged.stderr)
		}
		if pos.stdout != flagged.stdout {
			t.Fatalf("positional file output differs\npositional:\n%s\n--file:\n%s", pos.stdout, flagged.stdout)
		}
	})

	t.Run("positional host matches --url without remote", func(t *testing.T) {
		host := "chain-no-local.invalid"
		flagged := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--url", host)
		pos := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, host)
		if pos.code != flagged.code || pos.stdout != flagged.stdout {
			t.Fatalf("positional host\ncode=%d stdout=%q stderr=%q\n--url code=%d stdout=%q stderr=%q", pos.code, pos.stdout, pos.stderr, flagged.code, flagged.stdout, flagged.stderr)
		}
		if pos.code != 1 || !strings.Contains(pos.stdout, "pass --remote") {
			t.Fatalf("code=%d stdout=%q stderr=%q", pos.code, pos.stdout, pos.stderr)
		}
	})

	t.Run("missing path matches --url", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing.pem")
		flagged := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--url", missing)
		pos := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, missing)
		if pos.code != flagged.code || pos.stdout != flagged.stdout {
			t.Fatalf("missing path\ncode=%d stdout=%q stderr=%q\n--url code=%d stdout=%q stderr=%q", pos.code, pos.stdout, pos.stderr, flagged.code, flagged.stdout, flagged.stderr)
		}
		if pos.code != 1 || !strings.Contains(pos.stdout, "pass --remote") {
			t.Fatalf("code=%d stdout=%q stderr=%q", pos.code, pos.stdout, pos.stderr)
		}
	})

	t.Run("positional directory matches --url", func(t *testing.T) {
		dir := t.TempDir()
		flagged := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--url", dir)
		pos := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, dir)
		if pos.code != flagged.code || pos.stdout != flagged.stdout {
			t.Fatalf("directory\ncode=%d stdout=%q stderr=%q\n--url code=%d stdout=%q stderr=%q", pos.code, pos.stdout, pos.stderr, flagged.code, flagged.stdout, flagged.stderr)
		}
		if pos.code != 1 || !strings.Contains(pos.stdout, "pass --remote") {
			t.Fatalf("code=%d stdout=%q stderr=%q", pos.code, pos.stdout, pos.stderr)
		}
		if strings.Contains(pos.stdout+pos.stderr, "directory") {
			t.Fatalf("directory opened as --file:\nstdout=%s\nstderr=%s", pos.stdout, pos.stderr)
		}
	})

	t.Run("positional file with remote", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", bundle, "--remote")
		assertUsageError(t, res, "--remote requires a URL")
	})

	t.Run("positional and url", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--url", "example.com", bundle)
		assertUsageError(t, res, "not both")
	})

	t.Run("positional and file", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", "--file", bundle, "example.com")
		assertUsageError(t, res, "not both")
	})

	t.Run("two positionals", func(t *testing.T) {
		res := runCLI(t, bin, home, "chain", bundle, "example.com")
		assertUsageError(t, res, "unexpected argument")
		if !strings.Contains(res.stderr, bundle) || !strings.Contains(res.stderr, "example.com") {
			t.Fatalf("stderr=%q", res.stderr)
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
	quietPos := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", lots, srv.URL)
	if quietPos.code != quiet.code || quietPos.stdout != quiet.stdout {
		t.Fatalf("positional without --remote\ncode=%d stdout=%s stderr=%s\n--url stdout=%s", quietPos.code, quietPos.stdout, quietPos.stderr, quiet.stdout)
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
	pos := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", lots, srv.URL, "--remote")
	if pos.code != res.code || pos.stdout != res.stdout {
		t.Fatalf("positional --remote\ncode=%d stdout=%s stderr=%s\n--url stdout=%s", pos.code, pos.stdout, pos.stderr, res.stdout)
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

func writeChainCLILeafAndCA(t *testing.T) string {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "priv.example"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "leaf.example"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"leaf.example"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "leaf.pem")
	if err := certutil.ToFile(path, []*x509.Certificate{leaf, ca}); err != nil {
		t.Fatal(err)
	}
	return path
}
