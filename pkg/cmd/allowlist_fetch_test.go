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

package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

func TestCreateFromStoreAllowlistURL(t *testing.T) {
	keep := mustCreateCert(t, "Keep", "US", 1)
	drop := mustCreateCert(t, "Drop", "DE", 2)
	body := allowlistFileBytes(t, allowlist.Allowlist{
		Fingerprints: []string{certutil.GetHexSHA256Fingerprint(*keep)},
	})
	sum := sha256.Sum256(body)
	pin := hex.EncodeToString(sum[:])
	var hits int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	prev := allowlist.HTTPClient
	allowlist.HTTPClient = srv.Client()
	t.Cleanup(func() { allowlist.HTTPClient = prev })

	dir := t.TempDir()
	st := &fakeCreateStore{
		info:  &store.Info{Name: "fake", Path: filepath.Join(dir, "store.pem")},
		certs: []*x509.Certificate{keep, drop},
	}
	out := filepath.Join(dir, "out.pem")
	err := CreateFromStore(st, CreateOptions{
		AllowlistPath: srv.URL + "/allowlist.yaml",
		SHA256:        strings.ToUpper(pin),
		Out:           out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.mutated || st.listCalls != 1 {
		t.Fatalf("mutated=%v listCalls=%d", st.mutated, st.listCalls)
	}
	got, err := certutil.FromFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || certutil.GetHexSHA256Fingerprint(*got[0]) != certutil.GetHexSHA256Fingerprint(*keep) {
		t.Fatalf("kept %#v", got)
	}

	before := st.listCalls
	err = CreateFromStore(st, CreateOptions{
		AllowlistPath: srv.URL + "/allowlist.yaml",
		SHA256:        strings.Repeat("ab", 32),
		Out:           filepath.Join(dir, "nope.pem"),
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("err = %v", err)
	}
	if st.listCalls != before {
		t.Fatal("pin mismatch still read the store")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "nope.pem")); !os.IsNotExist(statErr) {
		t.Fatalf("mismatch wrote output: %v", statErr)
	}
	if hits < 2 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestAllowlistStorePinMismatchDoesNotApply(t *testing.T) {
	body := []byte("[\n")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	prev := allowlist.HTTPClient
	allowlist.HTTPClient = srv.Client()
	t.Cleanup(func() { allowlist.HTTPClient = prev })

	g := &noWriteStore{}
	err := allowlistStore(g, "", srv.URL+"/bad.yaml", allowlist.FetchOptions{SHA256: strings.Repeat("cd", 32)}, nil)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "unable to read allowlist") {
		t.Fatalf("mismatch parsed the body: %v", err)
	}
	if g.removed {
		t.Fatal("pin mismatch applied the allowlist")
	}
}

func allowlistFileBytes(t *testing.T, al allowlist.Allowlist) []byte {
	t.Helper()
	path := writeCreateAllowlist(t, al)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
