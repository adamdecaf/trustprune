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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
	cfg := ui.Config{
		Count: true,
	}
	err := ListCertsFromURL(fmt.Sprintf("http://%s", ts.Listener.Addr().String()), &cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestListCertsFromURLReturnsError(t *testing.T) {
	t.Parallel()
	err := ListCertsFromURL("http://127.0.0.1:1/", &ui.Config{Count: true})
	if err == nil {
		t.Fatal("expected dial error, got nil")
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
