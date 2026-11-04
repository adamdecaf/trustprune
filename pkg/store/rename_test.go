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
