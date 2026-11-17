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

package main

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestParseConnectURL(t *testing.T) {
	t.Run("positional", func(t *testing.T) {
		u, err := parseConnectURL("", []string{"https://example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if u.String() != "https://example.com" {
			t.Fatalf("got %s", u)
		}
	})

	t.Run("flagURL", func(t *testing.T) {
		u, err := parseConnectURL("https://example.com/via-flag", nil)
		if err != nil {
			t.Fatal(err)
		}
		if u.String() != "https://example.com/via-flag" {
			t.Fatalf("got %s", u)
		}
	})

	t.Run("both rejected", func(t *testing.T) {
		_, err := parseConnectURL("https://example.com/flag", []string{"https://example.com/pos"})
		if err == nil || !strings.Contains(err.Error(), "not both") {
			t.Fatalf("expected both-rejected error, got %v", err)
		}
		if !isUsageErr(err) {
			t.Fatalf("expected usage error, got %v", err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		_, err := parseConnectURL("", nil)
		if err == nil || !strings.Contains(err.Error(), "no url") {
			t.Fatalf("expected missing url error, got %v", err)
		}
		if !isUsageErr(err) {
			t.Fatalf("expected usage error, got %v", err)
		}
	})
}

func TestConnectFormatUsage(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()

	t.Run("unknown format", func(t *testing.T) {
		// http would be rejected before any dial. A format error must win.
		res := runCLI(t, bin, home, "connect", "--format", "nope", "http://example.com")
		assertUsageError(t, res, `unknown format "nope" (formats: json, text)`)
		if strings.Contains(res.stdout+res.stderr, "non-secure") {
			t.Fatalf("format check ran after URL parse: stdout=%q stderr=%q", res.stdout, res.stderr)
		}
	})

	t.Run("list format rejected", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "--format", "table", "https://example.com")
		assertUsageError(t, res, `unknown format "table" (formats: json, text)`)
	})

	t.Run("case preserved", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "--format", "Short", "google.com")
		assertUsageError(t, res, `unknown format "Short" (formats: json, text)`)
	})

	t.Run("json accepted", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "--format", "JSON", "http://example.com")
		if res.code == 2 || strings.Contains(res.stderr, "unknown format") {
			t.Fatalf("json treated as unknown: code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if res.code != 1 || !strings.Contains(res.stdout+res.stderr, "non-secure") {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
	})

	t.Run("text accepted", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "--format", "TEXT", "http://example.com")
		if res.code == 2 || strings.Contains(res.stderr, "unknown format") {
			t.Fatalf("text treated as unknown: code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if res.code != 1 || !strings.Contains(res.stdout+res.stderr, "non-secure") {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
	})

	t.Run("help", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "--help")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		for _, needle := range []string{
			"trustprune connect google.com",
			"ok https://google.com tls1.3 root=<name> sha256=<16 hex> leaf-expires=<YYYY-MM-DD>",
			"trustprune connect -v google.com",
			"trustprune connect --format json google.com",
			"ERROR: https://expired.badssl.com: certificate expired 2015-04-12",
			"default: text",
			"options: json, text",
			"no effect with --format json",
			"to add a missing CA, run: trustprune add --file <cert>",
		} {
			if !strings.Contains(res.stdout, needle) {
				t.Fatalf("connect help missing %q:\n%s", needle, res.stdout)
			}
		}
	})
}

func TestConnectPresentedChainExitCode(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("missing server certificate")
	}
	fp := certutil.GetHexSHA256Fingerprint(*cert)
	bin := cliBinary(t)
	home := t.TempDir()

	t.Run("verbose", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "-v", srv.URL)
		if res.code != 1 {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "presented chain:") || !strings.Contains(res.stdout, connectNotInStoreSubject(cert)) {
			t.Fatalf("stdout =\n%s", res.stdout)
		}
		if !strings.Contains(res.stdout, "to add a missing CA, run: trustprune add --file <cert>") || !strings.Contains(res.stdout, "include sha256 "+fp+" under fingerprints") {
			t.Fatalf("missing hint:\n%s", res.stdout)
		}
		if !strings.Contains(res.stdout, "ERROR: "+srv.URL+": unknown authority") {
			t.Fatalf("stdout =\n%s", res.stdout)
		}
		if strings.Contains(res.stdout, "--sha256") {
			t.Fatalf("invented flag:\n%s", res.stdout)
		}
	})

	t.Run("quiet", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", srv.URL)
		if res.code != 1 {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if strings.Contains(res.stdout, "presented chain:") || strings.Contains(res.stdout, "INDEX") {
			t.Fatalf("quiet connect printed a chain:\n%s", res.stdout)
		}
		if !strings.Contains(res.stdout, "ERROR: "+srv.URL+": unknown authority") {
			t.Fatalf("stdout =\n%s", res.stdout)
		}
	})

	t.Run("json", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "--format", "json", srv.URL)
		if res.code != 1 {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, `"presented_chain"`) || !strings.Contains(res.stdout, fp) || !strings.Contains(res.stdout, `"in_store": false`) {
			t.Fatalf("stdout =\n%s", res.stdout)
		}
		if !strings.Contains(res.stdout, "ERROR: "+srv.URL+": unknown authority") {
			t.Fatalf("missing error:\n%s", res.stdout)
		}
		if strings.Contains(res.stdout, "presented chain:") {
			t.Fatalf("json included the text table:\n%s", res.stdout)
		}
	})
}

func connectNotInStoreSubject(cert *x509.Certificate) string {
	name := cert.Subject.CommonName
	if name == "" {
		name = cert.Subject.String()
	}
	return name + " (not in store)"
}
