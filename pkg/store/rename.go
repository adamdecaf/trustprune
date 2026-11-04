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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// keepModeBits are the mode bits copied for files and directories.
const keepModeBits = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky

// osRename and osRemoveAll are swappable in tests to simulate EXDEV,
// EBUSY, and removal failures.
var (
	osRename    = os.Rename
	osRemoveAll = os.RemoveAll
)

// renameDir renames src to dst.
//
// On EXDEV (crossing filesystems, common with overlay or bind mounts) it
// copies the tree keeping modes and symlinks, verifies the copy, then
// removes src. If removing src fails, the verified copy at dst is kept
// and the error names it.
//
// On EBUSY (src or dst is a mount point) it moves the directory's
// entries instead, never renaming or deleting the mount point itself.
func renameDir(src, dst string) error {
	err := osRename(src, dst)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.EBUSY):
		return moveContents(src, dst, err)
	case !errors.Is(err, syscall.EXDEV):
		return err
	}
	if _, statErr := os.Lstat(dst); statErr == nil {
		return fmt.Errorf("rename %s -> %s: destination exists: %w", src, dst, err)
	}
	if cerr := copyTree(src, dst); cerr != nil {
		_ = osRemoveAll(dst)
		return fmt.Errorf("cross-device copy %s -> %s: %w", src, dst, cerr)
	}
	if verr := verifyTree(src, dst); verr != nil {
		_ = osRemoveAll(dst)
		return fmt.Errorf("cross-device copy %s -> %s: verify: %w", src, dst, verr)
	}
	if rerr := osRemoveAll(src); rerr != nil {
		return &partialMoveError{src: src, copy: dst, err: rerr}
	}
	return nil
}

// partialMoveError reports that an EXDEV move copied and verified src at
// copy but could not fully remove src, which may now be incomplete.
type partialMoveError struct {
	src, copy string
	err       error
}

func (e *partialMoveError) Error() string {
	return fmt.Sprintf("cross-device move %s -> %s: removing source failed, %s may be incomplete; intact copy is at %s: %v", e.src, e.copy, e.src, e.copy, e.err)
}

func (e *partialMoveError) Unwrap() error { return e.err }

// renameAside moves live to aside for a restore. If an EXDEV move leaves
// live partially removed, the verified copy is copied back over live and
// checked; if that fails too, the error names the intact copy.
func renameAside(live, aside string) error {
	err := renameDir(live, aside)
	var pe *partialMoveError
	if !errors.As(err, &pe) {
		return err
	}
	if rerr := copyTreeOver(pe.copy, live); rerr != nil {
		return fmt.Errorf("%w; copying back to %s failed, intact copy is at %s: %w", err, live, pe.copy, rerr)
	}
	if verr := verifyTree(pe.copy, live); verr != nil {
		return fmt.Errorf("%w; %s does not match after copy-back, intact copy is at %s: %w", err, live, pe.copy, verr)
	}
	return fmt.Errorf("%w; %s was restored from the copy", err, live)
}

// copyTreeOver copies src onto dst, replacing existing files and links.
func copyTreeOver(src, dst string) error {
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
		if info.IsDir() {
			if err := os.MkdirAll(target, info.Mode()&keepModeBits); err != nil {
				return err
			}
			return os.Chmod(target, info.Mode()&keepModeBits)
		}
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path) //nolint:gosec // root-owned CA dir; links are copied, never followed
			if err != nil {
				return err
			}
			return os.Symlink(link, target) //nolint:gosec // root-owned CA dir; stale entries are replaced, never followed
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported file type %s at %s", info.Mode().Type(), path)
		}
		return copyRegular(path, target, info.Mode()&keepModeBits)
	})
}

// moveContents moves the entries of src into dst (created if missing, or
// required to be an empty directory) and leaves the src directory itself
// in place when it is busy. On failure it moves entries back.
func moveContents(src, dst string, cause error) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return cause
	}
	created := false
	if dt, err := os.Lstat(dst); err == nil {
		if !dt.IsDir() {
			return fmt.Errorf("rename %s -> %s: destination is not a directory: %w", src, dst, cause)
		}
		if ents, err := os.ReadDir(dst); err != nil {
			return err
		} else if len(ents) > 0 {
			return fmt.Errorf("rename %s -> %s: destination not empty: %w", src, dst, cause)
		}
	} else {
		if err := os.Mkdir(dst, st.Mode()&keepModeBits); err != nil {
			return err
		}
		created = true
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	var moved []string
	for _, e := range ents {
		from, to := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		if err := renameDir(from, to); err != nil {
			var rerrs []error
			for i := len(moved) - 1; i >= 0; i-- {
				if rerr := renameDir(filepath.Join(dst, moved[i]), filepath.Join(src, moved[i])); rerr != nil {
					rerrs = append(rerrs, rerr)
				}
			}
			if len(rerrs) > 0 {
				return fmt.Errorf("moving contents %s -> %s: %w; rollback incomplete, entries split between %s and %s: %w", src, dst, err, src, dst, errors.Join(rerrs...))
			}
			if created {
				_ = os.Remove(dst)
			}
			return fmt.Errorf("moving contents %s -> %s: %w", src, dst, err)
		}
		moved = append(moved, e.Name())
	}
	if created {
		// src is the busy mount point: leave it, now empty, in place.
		return nil
	}
	// dst was the busy mount point; src is an ordinary directory.
	if err := os.Remove(src); err != nil && !errors.Is(err, syscall.EBUSY) && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// verifyTree checks that dst mirrors src: same types, modes, symlink
// targets, and file contents.
func verifyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		si, err := d.Info()
		if err != nil {
			return err
		}
		ti, err := os.Lstat(target)
		if err != nil {
			return err
		}
		if si.Mode() != ti.Mode() {
			return fmt.Errorf("%s: mode %v, want %v", target, ti.Mode(), si.Mode())
		}
		switch {
		case si.Mode()&os.ModeSymlink != 0:
			a, err := os.Readlink(path) //nolint:gosec // root-owned CA dir; links are compared, never followed
			if err != nil {
				return err
			}
			b, err := os.Readlink(target)
			if err != nil {
				return err
			}
			if a != b {
				return fmt.Errorf("%s: symlink %q, want %q", target, b, a)
			}
		case si.Mode().IsRegular():
			a, err := os.ReadFile(path) //nolint:gosec // root-owned CA dir
			if err != nil {
				return err
			}
			b, err := os.ReadFile(target) //nolint:gosec // our own copy
			if err != nil {
				return err
			}
			if !bytes.Equal(a, b) {
				return fmt.Errorf("%s: content differs from %s", target, path)
			}
		}
		return nil
	})
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
			if err := os.Mkdir(target, info.Mode()&keepModeBits); err != nil {
				return err
			}
			return os.Chmod(target, info.Mode()&keepModeBits)
		case info.Mode().IsRegular():
			return copyRegular(path, target, info.Mode()&keepModeBits)
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
