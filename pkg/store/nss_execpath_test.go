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

package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNSSExecPaths_Names(t *testing.T) {
	for _, p := range cutil.execPaths {
		if filepath.Base(p) != "certutil" {
			t.Errorf("exec path %q should end in certutil", p)
		}
	}
	found := false
	for _, p := range cutil.execPaths {
		if p == "/usr/bin/certutil" {
			found = true
		}
	}
	if !found {
		t.Error("expected /usr/bin/certutil in exec paths for Linux")
	}
}

func TestNSSGetExecPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("exec bit checks do not apply on Windows")
	}
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing", "certutil")
	bin := filepath.Join(dir, "certutil")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	c := crtutil{execPaths: []string{missing, bin}}
	got, err := c.getExecPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != bin {
		t.Errorf("got %q, want %q", got, bin)
	}

	// Not in execPaths, but on PATH: found through the PATH fallback.
	t.Setenv("PATH", dir)
	c = crtutil{execPaths: []string{missing}}
	got, err = c.getExecPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != bin {
		t.Errorf("PATH fallback: got %q, want %q", got, bin)
	}

	// Neither in execPaths nor on PATH.
	t.Setenv("PATH", t.TempDir())
	if _, err := c.getExecPath(); err == nil || !strings.Contains(err.Error(), "install NSS tools") {
		t.Errorf("expected actionable not-found error, got %v", err)
	}
}

func TestNSSGetExecPath_WindowsSkipsPATH(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PATH skip is Windows-only")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "certutil.exe")
	if err := os.WriteFile(bin, []byte("MZ"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	c := crtutil{execPaths: []string{filepath.Join(dir, "missing", "certutil")}}
	if _, err := c.getExecPath(); err == nil || !strings.Contains(err.Error(), "install NSS tools") {
		t.Errorf("Windows PATH must not yield system certutil, got %v", err)
	}
}
