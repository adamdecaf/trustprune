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

package cmd

import (
	"compress/gzip"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/adamdecaf/trustprune/pkg/ui"
)

func TestCmdList__file(t *testing.T) {
	t.Parallel()

	cfg := ui.Config{
		Count: true,
	}
	err := ListCertsFromFile("../../testdata/example.crt", &cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCmdList__url(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, err := os.Open("../../testdata/certdata.txt.gz")
		if err != nil {
			t.Fatal(err)
		}
		r, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(w, r)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("no bytes written")
		}
	}))
	defer ts.Close()

	// Read certs from url
	out := filepath.Join(t.TempDir(), "count.txt")
	cfg := ui.Config{
		Count:   true,
		Outfile: out,
	}
	err := ListCertsFromURL(fmt.Sprintf("http://%s", ts.Listener.Addr().String()), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(got)))
	if err != nil || n < 1 {
		t.Fatalf("count = %q", got)
	}
}

func TestListCertsFromURLPEM(t *testing.T) {
	t.Parallel()

	pem, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(pem); err != nil {
			t.Errorf("write pem: %v", err)
		}
	}))
	defer ts.Close()

	out := filepath.Join(t.TempDir(), "count.txt")
	err = ListCertsFromURL(ts.URL, &ui.Config{Count: true, Outfile: out})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1\n" {
		t.Fatalf("count = %q", got)
	}
}

func TestListCertsFromURLDER(t *testing.T) {
	t.Parallel()

	pemBytes, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || len(block.Bytes) == 0 {
		t.Fatal("no DER certificate in testdata/example.crt")
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(block.Bytes); err != nil {
			t.Errorf("write der: %v", err)
		}
	}))
	defer ts.Close()

	out := filepath.Join(t.TempDir(), "count.txt")
	err = ListCertsFromURL(ts.URL, &ui.Config{Count: true, Outfile: out})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1\n" {
		t.Fatalf("count = %q", got)
	}
}

func TestListCertsFromURLNotBundle(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{name: "html", body: "<!DOCTYPE html><html><body>not a certificate</body></html>"},
		{name: "text", body: "not a certificate bundle"},
		{name: "empty", body: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := tc.body
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if _, err := io.WriteString(w, body); err != nil {
					t.Errorf("write body: %v", err)
				}
			}))
			defer ts.Close()

			for _, count := range []bool{false, true} {
				out := filepath.Join(t.TempDir(), "out.txt")
				err := ListCertsFromURL(ts.URL, &ui.Config{Count: count, Outfile: out})
				if err == nil {
					t.Fatal("expected error")
				}
				msg := err.Error()
				if !strings.Contains(msg, "no PEM/DER certificates at "+ts.URL) {
					t.Fatalf("error = %q", msg)
				}
				u, perr := url.Parse(ts.URL)
				if perr != nil {
					t.Fatal(perr)
				}
				wantHint := "trustprune chain " + u.Hostname() + " --remote"
				if !strings.Contains(msg, wantHint) {
					t.Fatalf("error = %q, want %q", msg, wantHint)
				}
				if strings.Contains(msg, "no certificates to display") {
					t.Fatalf("fell through to empty list: %q", msg)
				}
				if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
					t.Fatalf("list wrote output for a non-bundle (count=%v): %v", count, statErr)
				}
			}
		})
	}
}

func TestListCertsFromURLReturnsError(t *testing.T) {
	t.Parallel()
	err := ListCertsFromURL("http://127.0.0.1:1/", &ui.Config{Count: true})
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
	if strings.Contains(err.Error(), "no PEM/DER certificates at") {
		t.Fatalf("dial failure reported as an empty bundle: %v", err)
	}
}

func TestListURLNoCertsError(t *testing.T) {
	t.Parallel()
	err := listURLNoCertsError("https://example.com/bundle.pem")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no PEM/DER certificates at https://example.com/bundle.pem") {
		t.Fatalf("error = %q", msg)
	}
	if !strings.Contains(msg, "trustprune chain example.com --remote") {
		t.Fatalf("error = %q", msg)
	}
	if strings.Contains(msg, "no certificates to display") {
		t.Fatalf("error = %q", msg)
	}

	err = listURLNoCertsError(":")
	if err == nil {
		t.Fatal("expected error")
	}
	msg = err.Error()
	if !strings.Contains(msg, "no PEM/DER certificates at :") {
		t.Fatalf("error = %q", msg)
	}
	if !strings.Contains(msg, "trustprune chain <host> --remote") {
		t.Fatalf("unparseable URL should keep the placeholder: %q", msg)
	}
}

func TestListCertsForAppWithFileMissingStore(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing.pem")
	err := ListCertsForAppWithFile("certifi", missing, &ui.Config{Count: true})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("got %v", err)
	}
}

func TestListCertsForAppOkularReportsBackend(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CONFIG_DIRS", t.TempDir())
	t.Setenv("POPPLER_SIGNATURE_BACKEND", "")
	t.Setenv("APPDATA", "")
	t.Setenv("MOZ_LEGACY_HOME", "")

	cfgDir := filepath.Join(home, ".config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rc := filepath.Join(cfgDir, "okular-generator-popplerrc")
	if err := os.WriteFile(rc, []byte("[Signatures]\nSignatureBackend=GPG\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := ListCertsForApp("okular", &ui.Config{Count: true})
	if !errors.Is(err, store.ErrOkularGPG) {
		t.Fatalf("GPG list: %v", err)
	}

	custom := filepath.Join(t.TempDir(), "okular-nssdb")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(custom, "cert9.db"), []byte("certdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rc, []byte("[Signatures]\nSignatureBackend=NSS\nUseDefaultCertDB=false\nDBCertificatePath="+custom+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.ForApp("okular")
	if err != nil {
		t.Fatal(err)
	}
	info := st.GetInfo()
	if info == nil || info.Path != custom {
		t.Fatalf("list meta path %#v, want %q", info, custom)
	}
}

func TestListCertsForAppReturnsStoreError(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("ssl store is available on darwin")
	}
	err := ListCertsForApp("ssl", &ui.Config{Count: true})
	if err == nil || !strings.Contains(err.Error(), "Darwin") {
		t.Fatalf("got %v", err)
	}
}

func TestListCertsForAppPlatformOSName(t *testing.T) {
	got, err := store.ForApp(runtime.GOOS)
	if err != nil {
		t.Fatalf("ForApp(%s): %v", runtime.GOOS, err)
	}
	gi, wi := got.GetInfo(), store.Platform().GetInfo()
	if gi == nil || wi == nil || gi.Name != wi.Name || gi.Path != wi.Path || gi.Version != wi.Version {
		t.Fatalf("ForApp(%s) info %#v, platform %#v", runtime.GOOS, gi, wi)
	}
}

func TestListURLSourceRedactsUserinfo(t *testing.T) {
	t.Parallel()
	got := listURLSource("https://alice:s3cret-url@example.com/bundle.pem")
	if strings.Contains(got, "s3cret-url") {
		t.Fatalf("password leaked: %q", got)
	}
	if !strings.Contains(got, "xxxxx") || !strings.Contains(got, "alice") {
		t.Fatalf("redacted URL = %q", got)
	}
}

func TestListCertsFromURLJSONStoreAndPath(t *testing.T) {
	t.Parallel()
	pem, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(pem); err != nil {
			t.Errorf("write pem: %v", err)
		}
	}))
	t.Cleanup(ts.Close)

	out := filepath.Join(t.TempDir(), "certs.json")
	if err := ListCertsFromURL(ts.URL, &ui.Config{Format: "json", Outfile: out}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Store string `json:"store"`
		Path  string `json:"path"`
	}
	if err := json.Unmarshal(got, &rows); err != nil {
		t.Fatalf("json: %v\n%s", err, got)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	if rows[0].Store != "url" {
		t.Fatalf("store = %q, want url", rows[0].Store)
	}
	if rows[0].Path != ts.URL {
		t.Fatalf("path = %q, want %q", rows[0].Path, ts.URL)
	}
}

func TestListCertsFromURLJSONRedactsUserinfo(t *testing.T) {
	t.Parallel()
	pem, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(pem); err != nil {
			t.Errorf("write pem: %v", err)
		}
	}))
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	const password = "s3cret-url"
	u.User = url.UserPassword("alice", password)
	out := filepath.Join(t.TempDir(), "certs.json")
	if err := ListCertsFromURL(u.String(), &ui.Config{Format: "json", Outfile: out}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), password) {
		t.Fatalf("password leaked:\n%s", got)
	}
	var rows []struct {
		Store string `json:"store"`
		Path  string `json:"path"`
	}
	if err := json.Unmarshal(got, &rows); err != nil {
		t.Fatalf("json: %v\n%s", err, got)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	if rows[0].Store != "url" {
		t.Fatalf("store = %q, want url", rows[0].Store)
	}
	if !strings.Contains(rows[0].Path, "xxxxx") || !strings.Contains(rows[0].Path, "alice") {
		t.Fatalf("path = %q", rows[0].Path)
	}
}

func TestListCertsFromURLVerbosePath(t *testing.T) {
	t.Parallel()
	pem, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(pem); err != nil {
			t.Errorf("write pem: %v", err)
		}
	}))
	t.Cleanup(ts.Close)

	out := filepath.Join(t.TempDir(), "table.txt")
	cfg := &ui.Config{Format: ui.DefaultFormat(), UI: ui.DefaultUI(), Verbose: true, Outfile: out}
	if err := ListCertsFromURL(ts.URL, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if strings.Contains(text, "PATH: -") {
		t.Fatalf("verbose path still empty:\n%s", text)
	}
	if !strings.Contains(text, "PATH: "+ts.URL) {
		t.Fatalf("missing PATH line:\n%s", text)
	}
}
