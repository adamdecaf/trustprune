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

//go:build linux
// +build linux

package store

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// linuxTestStore builds a linuxStore whose CA paths and backup destination
// all live under t.TempDir(). HOME is pointed at a separate temp dir so
// backups land in $HOME/.trustprune/linux/... rather than the real home.
//
// Restore always runs rebundleCerts, which prefixes the refresh command with
// sudo unless the process is already root. Tests install a PATH-shadowing
// passthrough sudo so `sudo /bin/true` succeeds without touching the host
// (this environment's real sudo requires a password).
func linuxTestStore(t *testing.T) linuxStore {
	t.Helper()

	caRoot := t.TempDir()
	caDir := filepath.Join(caRoot, "ca")
	caAdd := filepath.Join(caRoot, "add")
	caAll := filepath.Join(caRoot, "all.pem")
	if err := os.MkdirAll(caDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(caAdd, 0755); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	installPassthroughSudo(t)

	example, err := os.ReadFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "example.crt"), example, 0644); err != nil {
		t.Fatal(err)
	}
	extra := []byte("extra-ca-file-for-backup-tests\n")
	if err := os.WriteFile(filepath.Join(caDir, "extra.crt"), extra, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caAll, example, 0644); err != nil {
		t.Fatal(err)
	}

	s := linuxStore{
		ca: cadir{
			add:     caAdd,
			dir:     caDir,
			all:     caAll,
			refresh: "/bin/true",
		},
	}
	refuseSystemCAPaths(t, s)
	return s
}

func installPassthroughSudo(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "sudo")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec \"$@\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func refuseSystemCAPaths(t *testing.T, s linuxStore) {
	t.Helper()
	for _, p := range []string{s.ca.dir, s.ca.add, s.ca.all} {
		cleaned := filepath.Clean(p)
		if strings.HasPrefix(cleaned, "/etc/") || strings.HasPrefix(cleaned, "/usr/") {
			t.Fatalf("refusing to run against system CA path %s", p)
		}
	}
}

func snapshotDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[rel] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertDirSnapshotEqual(t *testing.T, gotDir string, want map[string][]byte) {
	t.Helper()
	got := snapshotDir(t, gotDir)
	if len(got) != len(want) {
		t.Errorf("file count: got %d want %d", len(got), len(want))
	}
	for name, wantb := range want {
		gotb, ok := got[name]
		if !ok {
			t.Errorf("missing file %s", name)
			continue
		}
		if !bytes.Equal(gotb, wantb) {
			t.Errorf("file %s: content mismatch", name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected file %s", name)
		}
	}
}

func TestBackupProducesCompleteCopy(t *testing.T) {
	s := linuxTestStore(t)
	want := snapshotDir(t, s.ca.dir)
	if len(want) < 2 {
		t.Fatalf("expected multiple files in ca.dir, got %d", len(want))
	}

	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil {
		t.Fatalf("GetLatestBackup: %v", err)
	}
	if latest == "" {
		t.Fatal("GetLatestBackup returned empty path")
	}
	st, err := os.Stat(latest)
	if err != nil {
		t.Fatalf("stat backup dir: %v", err)
	}
	if !st.IsDir() {
		t.Fatalf("latest backup %s is not a directory", latest)
	}

	assertDirSnapshotEqual(t, latest, want)
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	s := linuxTestStore(t)
	want := snapshotDir(t, s.ca.dir)

	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	if err := os.Remove(filepath.Join(s.ca.dir, "extra.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.ca.dir, "example.crt"), []byte("mutated-live-ca\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	assertDirSnapshotEqual(t, s.ca.dir, want)
}

func TestLinuxRestore_HonorsWherePath(t *testing.T) {
	// Restore(where) must use the provided path (CLI -file), not only GetLatestBackup().
	s := linuxTestStore(t)

	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}

	if err := os.Remove(filepath.Join(s.ca.dir, "extra.crt")); err != nil {
		t.Fatal(err)
	}

	alternate := t.TempDir()
	if err := os.WriteFile(filepath.Join(alternate, "only-in-alternate.crt"), []byte("ALTERNATE-BACKUP-MARKER\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if alternate == latest {
		t.Fatal("alternate path unexpectedly equals latest backup")
	}

	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore(alternate): %v", err)
	}

	got := snapshotDir(t, s.ca.dir)
	if _, ok := got["only-in-alternate.crt"]; !ok {
		t.Fatal("Restore did not use the `where` path; expected only-in-alternate.crt in ca.dir")
	}
	if _, ok := got["extra.crt"]; ok {
		t.Error("ca.dir still has extra.crt; Restore(where) should have replaced live with the alternate tree")
	}
	if bytes.Equal(mustRead(t, filepath.Join(s.ca.dir, "only-in-alternate.crt")), mustRead(t, filepath.Join(latest, "example.crt"))) {
		t.Error("unexpected content match against latest backup")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLinuxRestore_FailedRestoreLeavesLiveDirIntact(t *testing.T) {
	s := linuxTestStore(t)
	want := snapshotDir(t, s.ca.dir)

	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}

	if err := os.RemoveAll(latest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(latest, []byte("not-a-directory\n"), 0644); err != nil {
		t.Fatal(err)
	}
	gotLatest, err := s.GetLatestBackup()
	if err != nil {
		t.Fatalf("GetLatestBackup after corrupting backup: %v", err)
	}
	if gotLatest != latest {
		t.Fatalf("GetLatestBackup=%s want %s", gotLatest, latest)
	}

	err = s.Restore("")
	if err == nil {
		t.Fatal("expected Restore to fail after backup was replaced with a file")
	}
	assertDirSnapshotEqual(t, s.ca.dir, want)
	if fileExists(t, s.ca.dir+".restore-tmp") {
		t.Errorf("restore-tmp left behind after failed MirrorDir: %s", s.ca.dir+".restore-tmp")
	}
}

func fileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	t.Fatalf("stat %s: %v", path, err)
	return false
}

func TestLinuxRestore_RestoreTmpCleanedOnMirrorFailure(t *testing.T) {
	// *.restore-tmp must be removed when MirrorDir fails (backup is not a dir).
	s := linuxTestStore(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}
	if err := os.RemoveAll(latest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(latest, []byte("not-a-directory\n"), 0644); err != nil {
		t.Fatal(err)
	}
	tmp := s.ca.dir + ".restore-tmp"
	_ = os.MkdirAll(tmp, 0755) // leftover from a previous crash
	if err := s.Restore(""); err == nil {
		t.Fatal("expected Restore to fail")
	}
	if fileExists(t, tmp) {
		t.Fatalf("expected %s to be cleaned up after MirrorDir failure", tmp)
	}
}

func TestLinuxRestore_RebundleFailureRollsBackAside(t *testing.T) {
	// Aside is kept until refresh succeeds; a failed rebundle swaps live back.
	s := linuxTestStore(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Mutate live after backup. Restore will swap in the backup, then fail
	// rebundle and roll back to this pre-swap live snapshot.
	if err := os.WriteFile(filepath.Join(s.ca.dir, "extra.crt"), []byte("pre-restore-mutation\n"), 0644); err != nil {
		t.Fatal(err)
	}
	liveBeforeRestore := snapshotDir(t, s.ca.dir)
	s.ca.refresh = "/bin/false"

	err := s.Restore("")
	if err == nil {
		t.Fatal("expected Restore to fail when refresh returns non-zero")
	}
	assertDirSnapshotEqual(t, s.ca.dir, liveBeforeRestore)
	if fileExists(t, s.ca.dir+".restore-old") {
		t.Errorf("restore-old should be consumed by rollback, still at %s", s.ca.dir+".restore-old")
	}
	if fileExists(t, s.ca.dir+".restore-tmp") {
		t.Errorf("restore-tmp left behind: %s", s.ca.dir+".restore-tmp")
	}
	if fileExists(t, s.ca.dir+".restore-failed") {
		t.Errorf("restore-failed left behind: %s", s.ca.dir+".restore-failed")
	}
}

func TestLinuxRestore_LogsAsidePath(t *testing.T) {
	// Successful restore deletes *.restore-old, so do not print the path.
	s := linuxTestStore(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	aside := s.ca.dir + ".restore-old"

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	err = s.Restore("")
	_ = w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("moved aside")) {
		t.Fatalf("successful restore must not log moved-aside path, got %q", out)
	}
	if fileExists(t, aside) {
		t.Errorf("aside should be removed after successful rebundle: %s", aside)
	}
}

func TestLinuxRestore_LogsAsidePathWhenKept(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory mode 0555; rollback cannot be blocked by permissions")
	}
	// When refresh fails and rollback cannot move live aside, *.restore-old
	// is kept and must be printed for the operator.
	s := linuxTestStore(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	aside := s.ca.dir + ".restore-old"
	parent := filepath.Dir(s.ca.dir)

	script := filepath.Join(t.TempDir(), "refresh-fail.sh")
	body := "#!/bin/sh\nchmod 555 \"$PARENT\"\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PARENT", parent)
	s.ca.refresh = script
	t.Cleanup(func() { _ = os.Chmod(parent, 0755) })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	err = s.Restore("")
	_ = w.Close()
	os.Stdout = old
	if err == nil {
		t.Fatal("expected Restore to fail when refresh returns non-zero")
	}
	out, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Contains(out, []byte(aside)) || !bytes.Contains(out, []byte("moved aside")) {
		t.Fatalf("expected stdout to mention kept aside path %s, got %q", aside, out)
	}
	if !fileExists(t, aside) {
		t.Errorf("aside should be kept when rollback cannot move live: %s", aside)
	}
}

func TestLinuxRestore_AsideCleanupFailureWarns(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory mode 0555; aside cleanup cannot be blocked by permissions")
	}
	// After a successful restore, a leftover *.restore-old is a warning, not an error.
	s := linuxTestStore(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	aside := s.ca.dir + ".restore-old"
	parent := filepath.Dir(s.ca.dir)

	script := filepath.Join(t.TempDir(), "refresh-ok-lock.sh")
	body := "#!/bin/sh\nchmod 555 \"$PARENT\"\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	s.ca.refresh = script
	t.Setenv("PARENT", parent)
	t.Cleanup(func() { _ = os.Chmod(parent, 0755) })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	err = s.Restore("")
	_ = w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("Restore should succeed despite aside cleanup failure: %v", err)
	}
	out, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Contains(out, []byte("warning")) || !bytes.Contains(out, []byte(aside)) {
		t.Fatalf("expected warning naming kept aside %s, got %q", aside, out)
	}
	if !fileExists(t, aside) {
		t.Errorf("aside should remain when cleanup fails: %s", aside)
	}
}

// snapshotTreeMeta records every path under root (with size and mode) so tests can
// assert a call made no filesystem writes.
func snapshotTreeMeta(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		out[p] = fmt.Sprintf("%v:%v:%d", info.Mode(), info.ModTime().UnixNano(), info.Size())
		return nil
	})
	return out
}

func TestLinuxRestore_NoBackupRefusesBeforeWrite(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(map[bool]string{false: "real", true: "dry-run"}[dry], func(t *testing.T) {
			s := linuxTestStore(t) // HOME is an empty temp dir
			home := os.Getenv("HOME")
			caParent := filepath.Dir(s.ca.dir)
			if dry {
				SetDryRun(true)
				defer SetDryRun(false)
			}
			beforeCA := snapshotTreeMeta(t, caParent)
			beforeHome := snapshotTreeMeta(t, home)

			err := s.Restore("")
			if err == nil {
				t.Fatal("expected error with no backup")
			}
			want := "no backup for linux in ~/.trustprune/linux; run: trustprune backup"
			if err.Error() != want {
				t.Fatalf("got %q, want %q", err.Error(), want)
			}
			if got := snapshotTreeMeta(t, caParent); len(got) != len(beforeCA) {
				t.Fatalf("CA tree changed: before=%v after=%v", beforeCA, got)
			} else {
				for k, v := range beforeCA {
					if got[k] != v {
						t.Fatalf("CA path %s changed", k)
					}
				}
			}
			if got := snapshotTreeMeta(t, home); len(got) != len(beforeHome) {
				t.Fatalf("HOME changed: before=%v after=%v", beforeHome, got)
			} else {
				for k, v := range beforeHome {
					if got[k] != v {
						t.Fatalf("HOME path %s changed", k)
					}
				}
			}
			if _, err := os.Stat(s.ca.dir + ".restore-tmp"); !os.IsNotExist(err) {
				t.Fatalf("restore-tmp created: %v", err)
			}
		})
	}
}
