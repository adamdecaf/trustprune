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
	"os"
	"path/filepath"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/adamdecaf/trustprune/pkg/ui"
)

func TestCreateMetaFromStore(t *testing.T) {
	t.Parallel()
	meta := createMeta(store.Platform())
	// Platform GetInfo is never nil on supported OSes; Name should be set.
	if meta.Name == "" {
		t.Fatalf("expected platform meta name, got %#v", meta)
	}
}

func TestListCertsForAppWithFileCertifi(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	bundle := filepath.Join(t.TempDir(), "cacert.pem")
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, src, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &ui.Config{Count: true}
	if err := ListCertsForAppWithFile("certifi", bundle, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestListAppsRuns(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// XDG cache under temp home when possible.
	cache := filepath.Join(home, "cache")
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LOCALAPPDATA", cache) // Windows UserCacheDir
	if err := ListApps(""); err != nil {
		t.Fatal(err)
	}
	if err := ListApps("json"); err != nil {
		t.Fatal(err)
	}
}
