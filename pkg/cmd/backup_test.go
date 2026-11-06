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
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/store"
)

func TestBackupForAppUnknown(t *testing.T) {
	t.Parallel()
	err := BackupForApp("nope-not-an-app")
	if err == nil {
		t.Fatal("expected error for unknown app")
	}
	if !strings.Contains(err.Error(), "unknown app nope-not-an-app (apps:") || !strings.Contains(err.Error(), "java") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBackupForAppWithFileCertifiDryRun(t *testing.T) {
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

	store.SetDryRun(true)
	t.Cleanup(func() { store.SetDryRun(false) })
	if err := BackupForAppWithFile("certifi", bundle); err != nil {
		t.Fatal(err)
	}
	// Dry-run must not create a backup tree under the temp HOME.
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "trustprune") || strings.Contains(e.Name(), "cert-manage") {
			t.Fatalf("dry-run wrote under HOME: %s", e.Name())
		}
	}
}

func TestBackupForPlatformDryRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store.SetDryRun(true)
	t.Cleanup(func() { store.SetDryRun(false) })
	if err := BackupForPlatform(); err != nil {
		t.Fatal(err)
	}
}
