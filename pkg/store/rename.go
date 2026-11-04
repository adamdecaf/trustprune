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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// osRename is swappable in tests to simulate cross-device (EXDEV) errors.
var osRename = os.Rename

// renameDir renames src to dst. When the rename crosses filesystems
// (EXDEV, common with overlay or bind mounts), it copies the tree keeping
// modes and symlinks, then removes src.
func renameDir(src, dst string) error {
	err := osRename(src, dst)
	if err == nil || !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if _, statErr := os.Lstat(dst); statErr == nil {
		return fmt.Errorf("rename %s -> %s: destination exists: %w", src, dst, err)
	}
	if cerr := copyTree(src, dst); cerr != nil {
		_ = os.RemoveAll(dst)
		return fmt.Errorf("cross-device copy %s -> %s: %w", src, dst, cerr)
	}
	if rerr := os.RemoveAll(src); rerr != nil {
		return fmt.Errorf("cross-device copy %s -> %s: removing source: %w", src, dst, rerr)
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target) //nolint:gosec // root-owned CA dir; links are copied, never followed
		case info.IsDir():
			if err := os.Mkdir(target, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(target, info.Mode().Perm())
		case info.Mode().IsRegular():
			return copyRegular(path, target, info.Mode().Perm())
		default:
			return fmt.Errorf("unsupported file type %s at %s", info.Mode().Type(), path)
		}
	})
}

func copyRegular(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm)
}
