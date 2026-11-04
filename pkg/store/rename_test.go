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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func withRename(t *testing.T, fn func(string, string) error) {
	t.Helper()
	orig := osRename
	osRename = fn
	t.Cleanup(func() { osRename = orig })
}

func exdev(old, new string) error {
	return &os.LinkError{Op: "rename", Old: old, New: new, Err: syscall.EXDEV}
}

func TestRenameDir_EXDEVFallback(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "ca")
	dst := filepath.Join(root, "ca.restore-old")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "a.crt"), []byte("A"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub/a.crt", filepath.Join(src, "link.crt")); err != nil {
		t.Fatal(err)
	}
	withRename(t, exdev)

	if err := renameDir(src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(src); !os.IsNotExist(err) {
		t.Fatalf("source still exists: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dst, "sub", "a.crt"))
	if err != nil || string(b) != "A" {
		t.Fatalf("content: %q %v", b, err)
	}
	fi, _ := os.Stat(filepath.Join(dst, "sub", "a.crt"))
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("file mode %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Join(dst, "sub"))
	if di.Mode().Perm() != 0o750 {
		t.Errorf("dir mode %v", di.Mode().Perm())
	}
	link, err := os.Readlink(filepath.Join(dst, "link.crt"))
	if err != nil || link != "sub/a.crt" {
		t.Errorf("symlink %q %v", link, err)
	}
}

func TestRenameDir_OtherErrorNoFallback(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "ca")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	withRename(t, func(string, string) error { return boom })
	if err := renameDir(src, filepath.Join(root, "x")); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("source removed: %v", err)
	}
}

func TestRenameDir_EXDEVDestExists(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "ca")
	dst := filepath.Join(root, "dst")
	for _, d := range []string{src, dst} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	withRename(t, exdev)
	if err := renameDir(src, dst); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("source removed: %v", err)
	}
}

func ebusyFor(busy string) func(string, string) error {
	return func(old, new string) error {
		if old == busy || new == busy {
			return &os.LinkError{Op: "rename", Old: old, New: new, Err: syscall.EBUSY}
		}
		return os.Rename(old, new)
	}
}

func TestRenameDir_EBUSYMovesContents(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "ca") // pretend mount point
	aside := filepath.Join(root, "ca.restore-old")
	tmp := filepath.Join(root, "ca.restore-tmp")
	for _, d := range []string{live, tmp} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(live, "old.crt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "new.crt"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	withRename(t, ebusyFor(live))

	if err := renameDir(live, aside); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("mount point removed: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(aside, "old.crt")); string(b) != "old" {
		t.Fatalf("aside content %q", b)
	}
	if err := renameDir(tmp, live); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(live, "new.crt")); string(b) != "new" {
		t.Fatalf("live content %q", b)
	}
	if _, err := os.Stat(filepath.Join(live, "old.crt")); !os.IsNotExist(err) {
		t.Fatalf("old entry still live: %v", err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("tmp left behind: %v", err)
	}
}

func TestRenameDir_EBUSYRollsBack(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "ca")
	aside := filepath.Join(root, "aside")
	if err := os.Mkdir(live, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a.crt", "b.crt"} {
		if err := os.WriteFile(filepath.Join(live, n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	boom := errors.New("boom")
	withRename(t, func(old, new string) error {
		if old == live {
			return &os.LinkError{Op: "rename", Old: old, New: new, Err: syscall.EBUSY}
		}
		if filepath.Base(old) == "b.crt" && filepath.Dir(old) == live {
			return boom
		}
		return os.Rename(old, new)
	})
	if err := renameDir(live, aside); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	for _, n := range []string{"a.crt", "b.crt"} {
		if _, err := os.Stat(filepath.Join(live, n)); err != nil {
			t.Fatalf("%s not rolled back: %v", n, err)
		}
	}
	if _, err := os.Stat(aside); !os.IsNotExist(err) {
		t.Fatalf("aside left behind: %v", err)
	}
}

func TestRenameDir_EXDEVRemoveFailsKeepsCopy(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "ca")
	dst := filepath.Join(root, "aside")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.crt"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	withRename(t, exdev)
	origRm := osRemoveAll
	osRemoveAll = func(p string) error {
		if p == src {
			_ = os.Remove(filepath.Join(src, "a.crt")) // partial removal
			return errors.New("remove failed")
		}
		return origRm(p)
	}
	t.Cleanup(func() { osRemoveAll = origRm })

	err := renameDir(src, dst)
	if err == nil || !strings.Contains(err.Error(), "intact copy is at "+dst) {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "a.crt")); string(b) != "A" {
		t.Fatalf("copy not intact: %q", b)
	}
}

func TestVerifyTree_DetectsMismatch(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	for _, d := range []string{a, b} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(a, "x"), []byte("1"), 0o644)
	_ = os.WriteFile(filepath.Join(b, "x"), []byte("2"), 0o644)
	if err := verifyTree(a, b); err == nil {
		t.Fatal("expected mismatch")
	}
}

func setupPartialRemove(t *testing.T, src string) {
	t.Helper()
	origRm := osRemoveAll
	osRemoveAll = func(p string) error {
		if p == src {
			_ = os.Remove(filepath.Join(src, "sub", "a.crt"))
			_ = os.Remove(filepath.Join(src, "link.crt"))
			return errors.New("remove failed")
		}
		return origRm(p)
	}
	t.Cleanup(func() { osRemoveAll = origRm })
}

func makeCATree(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "a.crt"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub/a.crt", filepath.Join(dir, "link.crt")); err != nil {
		t.Fatal(err)
	}
}

func TestRenameAside_RestoresLiveAfterPartialRemove(t *testing.T) {
	root := t.TempDir()
	live, aside := filepath.Join(root, "ca"), filepath.Join(root, "ca.restore-old")
	makeCATree(t, live)
	withRename(t, exdev)
	setupPartialRemove(t, live)

	err := renameAside(live, aside)
	if err == nil || !strings.Contains(err.Error(), "restored from the copy") {
		t.Fatalf("got %v", err)
	}
	if err := verifyTree(aside, live); err != nil {
		t.Fatalf("live not restored: %v", err)
	}
}

func TestRenameAside_CopyBackFailsNamesCopy(t *testing.T) {
	root := t.TempDir()
	live, aside := filepath.Join(root, "ca"), filepath.Join(root, "ca.restore-old")
	makeCATree(t, live)
	withRename(t, exdev)
	origRm := osRemoveAll
	osRemoveAll = func(p string) error {
		if p == live {
			// Partial removal, then make live unusable for copy-back.
			_ = os.RemoveAll(live)
			_ = os.WriteFile(live, []byte("x"), 0o644)
			return errors.New("remove failed")
		}
		return origRm(p)
	}
	t.Cleanup(func() { osRemoveAll = origRm })

	err := renameAside(live, aside)
	if err == nil || !strings.Contains(err.Error(), "intact copy is at "+aside) || strings.Contains(err.Error(), "restored from the copy") {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(aside, "sub", "a.crt")); string(b) != "A" {
		t.Fatalf("copy not intact: %q", b)
	}
}

func TestRenameDir_EXDEVKeepsSpecialModes(t *testing.T) {
	root := t.TempDir()
	src, dst := filepath.Join(root, "ca"), filepath.Join(root, "aside")
	sub := filepath.Join(src, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	want := os.ModeDir | os.ModeSetgid | os.ModeSticky | 0o775
	if err := os.Chmod(sub, want&keepModeBits); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(sub); fi.Mode() != want {
		t.Skipf("filesystem does not keep special bits: %v", fi.Mode())
	}
	withRename(t, exdev)
	if err := renameDir(src, dst); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(filepath.Join(dst, "sub")); fi.Mode() != want {
		t.Fatalf("mode %v, want %v", fi.Mode(), want)
	}
}
