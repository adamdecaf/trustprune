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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

func TestRestoreArgs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		app        string
		file       string
		backup     string
		storeFile  string
		backupPath string
		wantErr    string
	}{
		{name: "java file is store", app: "java", file: "/ks", backup: "/b.bck", storeFile: "/ks", backupPath: "/b.bck"},
		{name: "certifi file is store", app: "certifi", file: "/venv/cacert.pem", storeFile: "/venv/cacert.pem"},
		{name: "platform file is backup", file: "/linux-backup", backupPath: "/linux-backup"},
		{name: "platform backup flag", backup: "/linux-backup", backupPath: "/linux-backup"},
		{name: "platform both same", file: "/p", backup: "/p", backupPath: "/p"},
		{name: "platform both different", file: "/a", backup: "/b", wantErr: "-file and -backup both set"},
		{name: "firefox file is backup", app: "firefox", file: "/nss-backup", backupPath: "/nss-backup"},
		{name: "ssl both different", app: "ssl", file: "/a", backup: "/b", wantErr: "-file and -backup both set"},
		{name: "java case insensitive", app: "Java", file: "/ks", storeFile: "/ks"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storeFile, backupPath, err := restoreArgs(tt.app, tt.file, tt.backup)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if storeFile != tt.storeFile || backupPath != tt.backupPath {
				t.Fatalf("storeFile=%q backupPath=%q want %q %q", storeFile, backupPath, tt.storeFile, tt.backupPath)
			}
		})
	}
}

func TestRestore_FileIsStoreTargetForCertifi(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store.SetDryRun(false)
	store.SetForceRestore(false)
	t.Cleanup(func() {
		store.SetDryRun(false)
		store.SetForceRestore(false)
	})

	certsA, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certsA) < 2 {
		t.Fatalf("lots.crt: len=%d err=%v", len(certsA), err)
	}
	certsB, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil || len(certsB) == 0 {
		t.Fatalf("example.crt: %v", err)
	}
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a", "cacert.pem")
	pathB := filepath.Join(dir, "b", "cacert.pem")
	for _, p := range []string{pathA, pathB} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(filepath.Clean(p), "/etc/") || strings.HasPrefix(filepath.Clean(p), "/usr/") {
			t.Fatalf("refusing system path in tests: %s", p)
		}
	}
	if err := certutil.ToFile(pathA, certsA); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(pathB, certsB); err != nil {
		t.Fatal(err)
	}
	originalA, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	originalB, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}

	if err := BackupForAppWithFile("certifi", pathA); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathA, []byte("MUTATED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// -file is the store to restore into, not the backup source.
	if err := Restore("certifi", pathA, ""); err != nil {
		t.Fatalf("same-path restore via -file: %v", err)
	}
	gotA, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, originalA) {
		t.Fatal("restore -file did not restore into the overridden store")
	}

	st := store.CertifiStoreAt(pathA)
	backupA, err := st.GetLatestBackup()
	if err != nil || backupA == "" {
		t.Fatalf("latest backup: %q err=%v", backupA, err)
	}

	err = Restore("certifi", pathB, backupA)
	if err == nil || !strings.Contains(err.Error(), "refusing restore") {
		t.Fatalf("expected cross-path refusal, got %v", err)
	}
	gotB, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, originalB) {
		t.Fatal("cross-path restore mutated target")
	}

	store.SetForceRestore(true)
	if err := Restore("certifi", pathB, backupA); err != nil {
		t.Fatalf("forced restore: %v", err)
	}
	gotB, err = os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, originalA) {
		t.Fatal("forced restore did not copy backup into -file store")
	}
}
