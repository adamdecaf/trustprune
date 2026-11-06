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

//go:build darwin || linux || freebsd
// +build darwin linux freebsd

package file

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// execCopy checks if we are in need of dropping to an elevated shell in order to
// perform a file copy. Otherwise, use the default CopyFile methodep
func execCopy(src, dst string) error {
	// Only escalate if the dst path exists and is owned by root, or if the
	// destination is missing (e.g. restoring /etc/ssl/cert.pem after deletion).
	sdst, err := os.Stat(dst)
	if os.IsNotExist(err) {
		// Prefer a normal create when the parent dir is writable (tests, user
		// paths). Escalate only for permission failures on root-owned parents
		// like /etc/ssl; other errors (missing parent dir, etc.) return as-is.
		if copyErr := CopyFile(src, dst); copyErr == nil {
			return nil
		} else if errors.Is(copyErr, os.ErrPermission) {
			return execSudoCopy(src, dst)
		} else {
			return copyErr
		}
	}
	if err != nil {
		return err
	}

	// From https://groups.google.com/d/msg/golang-nuts/ywS7xQYJkHY/cRUWjhPfZPQJ
	uid := sdst.Sys().(*syscall.Stat_t).Uid
	if uid == 0 { // root
		return execSudoCopy(src, dst)
	}
	return CopyFile(src, dst)
}

// execSudoCopy drops down to an elevated shell to copy when the destination
// is root-owned (or a create needs elevation). Prefers sudo, then su (#134).
func execSudoCopy(src, dst string) error {
	cmd, err := ElevatedCommand("cp", src, dst)
	if err != nil {
		return fmt.Errorf("error copying file from %q to %q, err=%w", src, dst, err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("error copying file from %q to %q, err=%w, stderr=%s", src, dst, err, stderr.String())
		}
		return fmt.Errorf("error copying file from %q to %q, err=%w", src, dst, err)
	}
	return nil
}
