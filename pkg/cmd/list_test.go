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
