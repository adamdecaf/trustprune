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

//go:build darwin || linux || freebsd
// +build darwin linux freebsd

package file

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSudoCopyFile_MissingDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("payload\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Missing parent: must return an error without prompting for sudo.
	missingParent := filepath.Join(dir, "no-such-dir", "dst")
	if err := SudoCopyFile(src, missingParent); err == nil {
		t.Fatal("expected error when parent directory is missing")
	}

	// Missing dest, writable parent: creates the file.
	dst := filepath.Join(dir, "missing-dest")
	if err := SudoCopyFile(src, dst); err != nil {
		t.Fatalf("SudoCopyFile missing dest: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("payload\n")) {
		t.Fatalf("got %q", got)
	}
}
