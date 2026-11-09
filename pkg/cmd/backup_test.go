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
	"runtime"
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
	out := captureStdout(t, func() error {
		return BackupForAppWithFile("certifi", bundle)
	})
	if !strings.Contains(out, "dry-run: no changes made\n") {
		t.Fatalf("dry-run output %q", out)
	}
	if strings.Contains(out, "Backup completed successfully") {
		t.Fatalf("dry-run printed a backup path: %q", out)
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
	out := captureStdout(t, func() error {
		return BackupForPlatform()
	})
	if !strings.Contains(out, "dry-run: no changes made\n") || strings.Contains(out, "Backup completed successfully") {
		t.Fatalf("dry-run output %q", out)
	}
}

func TestBackupForAppAcceptsPlatformOSName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store.SetDryRun(true)
	t.Cleanup(func() { store.SetDryRun(false) })
	out := captureStdout(t, func() error {
		return BackupForApp(runtime.GOOS)
	})
	if !strings.Contains(out, "dry-run: no changes made\n") || strings.Contains(out, "Backup completed successfully") {
		t.Fatalf("dry-run output %q", out)
	}
}

func TestBackupSuccessPrintsWrittenPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store.SetDryRun(false)
	t.Cleanup(func() { store.SetDryRun(false) })

	certifiBundle := writeLotsBundle(t, filepath.Join(t.TempDir(), "cacert.pem"))
	out := captureStdout(t, func() error {
		return BackupForAppWithFile("certifi", certifiBundle)
	})
	st, err := store.ForAppWithStore("certifi", certifiBundle)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := st.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("latest backup: %q err=%v", latest, err)
	}
	if out != "Backup completed successfully: "+latest+"\n" {
		t.Fatalf("certifi backup output %q", out)
	}

	pem := writeLotsBundle(t, filepath.Join(t.TempDir(), "ca-bundle.pem"))
	out = captureStdout(t, func() error {
		return BackupForBundle(pem)
	})
	ost, err := store.OpenSSLBundleAt(pem)
	if err != nil {
		t.Fatal(err)
	}
	latest, err = ost.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("openssl backup: %q err=%v", latest, err)
	}
	if out != "Backup completed successfully: "+latest+"\n" {
		t.Fatalf("bundle backup output %q", out)
	}

	// Windows GetLatestBackup is a stub ("", nil). FreeBSD Backup returns
	// "not implemented". Only Linux and Darwin write a platform backup.
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return
	}

	out = captureStdout(t, func() error {
		return BackupForPlatform()
	})
	latest, err = store.Platform().GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("platform backup: %q err=%v", latest, err)
	}
	if out != "Backup completed successfully: "+latest+"\n" {
		t.Fatalf("platform backup output %q", out)
	}

	out = captureStdout(t, func() error {
		return BackupForApp(runtime.GOOS)
	})
	latest, err = store.Platform().GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("second platform backup: %q err=%v", latest, err)
	}
	if out != "Backup completed successfully: "+latest+"\n" {
		t.Fatalf("ForApp(%s) backup output %q", runtime.GOOS, out)
	}
}
