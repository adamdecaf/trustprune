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
	// storePath is the store to restore into, not the backup source.
	if err := Restore("certifi", pathA, ""); err != nil {
		t.Fatalf("same-path restore via --store: %v", err)
	}
	gotA, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, originalA) {
		t.Fatal("restore --store did not restore into the overridden store")
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
		t.Fatal("forced restore did not copy backup into --store store")
	}
}

func TestRestorePrintsLivePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store.SetDryRun(false)
	store.SetForceRestore(false)
	t.Cleanup(func() {
		store.SetDryRun(false)
		store.SetForceRestore(false)
	})

	bundle := writeLotsBundle(t, filepath.Join(t.TempDir(), "cacert.pem"))
	if err := BackupForAppWithFile("certifi", bundle); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, []byte("MUTATED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() error {
		return RestoreForAppWithFile("certifi", bundle, "")
	})
	info := store.CertifiStoreAt(bundle).GetInfo()
	if info == nil || info.Path == "" {
		t.Fatalf("certifi info %#v", info)
	}
	if out != "Restore completed successfully: "+info.Path+"\n" {
		t.Fatalf("restore output %q", out)
	}

	store.SetDryRun(true)
	out = captureStdout(t, func() error {
		return RestoreForAppWithFile("certifi", bundle, "")
	})
	if !strings.Contains(out, "dry-run: no changes made\n") || strings.Contains(out, "Restore completed successfully") {
		t.Fatalf("dry-run output %q", out)
	}
}

// TestRestore_StoreRejectedForUnsupportedApp checks that --store is only a
// restore target for java and certifi; other apps must error, not treat it as
// a backup source.
func TestRestore_StoreRejectedForUnsupportedApp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	storePath := filepath.Join(t.TempDir(), "cert9.db")
	err := Restore("firefox", storePath, "")
	const want = "--store with --app firefox is only supported for java (keystore override) and certifi (cacert.pem override)"
	if err == nil || err.Error() != want {
		t.Fatalf("error %v, want %q", err, want)
	}
	if _, err := os.Stat(storePath); !os.IsNotExist(err) {
		t.Fatalf("store path should not be created: %v", err)
	}
}

// TestRestore_EmptyAppWithStoreRejected checks that a store path with no app
// does not fall through to the platform store. RestoreForPlatform can replace
// the host CA directory, so this must fail before any write.
func TestRestore_EmptyAppWithStoreRejected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store.SetDryRun(false)
	store.SetForceRestore(false)
	t.Cleanup(func() {
		store.SetDryRun(false)
		store.SetForceRestore(false)
	})

	// Empty backup on purpose. A non-empty backup handed to RestoreForPlatform
	// can rewrite the host CA directory. This case must fail before that call.
	dir := t.TempDir()
	storePath := filepath.Join(dir, "nested", "cacerts")
	const want = "--store overrides the trust store path and is only supported with --app java or --app certifi"

	for _, app := range []string{"", "   "} {
		err := Restore(app, storePath, "")
		if err == nil || err.Error() != want {
			t.Fatalf("Restore(%q) error %v, want %q", app, err, want)
		}
	}
	if _, err := os.Stat(storePath); !os.IsNotExist(err) {
		t.Fatalf("store path should not be created: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(storePath)); !os.IsNotExist(err) {
		t.Fatalf("store parent should not be created: %v", err)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("HOME not empty: %v", entries)
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("store dir not empty: %v", entries)
	}

	// A blank store path still restores the platform store (no backup here).
	err = Restore("", "  ", "")
	if err == nil || err.Error() == want || !strings.Contains(err.Error(), "no backup for") {
		t.Fatalf("blank store path should reach the platform store, got %v", err)
	}
	entries, err = os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("platform no-backup path wrote under HOME: %v", entries)
	}
}
