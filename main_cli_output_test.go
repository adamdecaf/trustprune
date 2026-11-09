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

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/store"
)

func TestCLIOutputPolish(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()

	bundle := filepath.Join(t.TempDir(), "cacert.pem")
	src, err := os.ReadFile(filepath.Join("testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, src, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("help exits 0", func(t *testing.T) {
		for _, args := range [][]string{
			{"-h"},
			{"list", "-h"},
			{"list", "--help"},
			{"backup", "-help"},
			{"add"},
			{"bad-arg", "-h"},
		} {
			res := runCLI(t, bin, home, args...)
			if res.code != 0 {
				t.Fatalf("%v code=%d stdout=%s stderr=%s", args, res.code, res.stdout, res.stderr)
			}
		}
		res := runCLI(t, bin, home, "bad-arg")
		if res.code == 0 {
			t.Fatalf("unknown command exited 0: stdout=%s stderr=%s", res.stdout, res.stderr)
		}
	})

	t.Run("list platform os name", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "-app", runtime.GOOS, "-count")
		if res.code != 0 || strings.Contains(res.stdout+res.stderr, "unknown app") {
			t.Fatalf("list -app %s code=%d stdout=%s stderr=%s", runtime.GOOS, res.code, res.stdout, res.stderr)
		}
		if _, err := strconv.Atoi(strings.TrimSpace(res.stdout)); err != nil {
			t.Fatalf("count %q: %v", res.stdout, err)
		}

		res = runCLI(t, bin, home, "list", "-app", runtime.GOOS, "-store", filepath.Join(home, "nope"))
		if res.code == 0 || !strings.HasPrefix(strings.TrimSpace(res.stdout), "ERROR:") || !strings.Contains(res.stdout, "-store with -app") {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
	})

	t.Run("missing store has ERROR prefix", func(t *testing.T) {
		missing := filepath.Join(home, "missing.pem")
		res := runCLI(t, bin, home, "list", "-app", "certifi", "-store", missing, "-count")
		if res.code == 0 {
			t.Fatal("expected non-zero exit")
		}
		// main prints ERROR: on stdout (fmt.Printf), which list used to skip.
		if !strings.HasPrefix(strings.TrimSpace(res.stdout), "ERROR:") || !strings.Contains(res.stdout, "not found") {
			t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
		}
	})

	t.Run("backup and restore print paths", func(t *testing.T) {
		res := runCLI(t, bin, home, "backup", "-app", "certifi", "-store", bundle)
		if res.code != 0 {
			t.Fatalf("backup code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		latest := soleCertifiBackup(t, home)
		if strings.TrimSpace(res.stdout) != "Backup completed successfully: "+latest {
			t.Fatalf("backup stdout %q", res.stdout)
		}

		if err := os.WriteFile(bundle, []byte("MUTATED\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res = runCLI(t, bin, home, "restore", "-app", "certifi", "-store", bundle)
		if res.code != 0 {
			t.Fatalf("restore code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		info := store.CertifiStoreAt(bundle).GetInfo()
		if info == nil || info.Path == "" {
			t.Fatalf("info %#v", info)
		}
		if strings.TrimSpace(res.stdout) != "Restore completed successfully: "+info.Path {
			t.Fatalf("restore stdout %q", res.stdout)
		}

		res = runCLI(t, bin, home, "backup", "-app", "certifi", "-store", bundle, "-dry-run")
		if res.code != 0 || !strings.Contains(res.stdout, "dry-run: no changes made") || strings.Contains(res.stdout, "Backup completed successfully") {
			t.Fatalf("dry-run code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
	})
}

func soleCertifiBackup(t *testing.T, home string) string {
	t.Helper()
	root := filepath.Join(home, ".trustprune", "certifi")
	if runtime.GOOS == "darwin" {
		root = filepath.Join(home, "Library", "trustprune", "certifi")
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("backup dir %s: %v", root, err)
	}
	var dirs []string
	for _, ent := range ents {
		if ent.IsDir() {
			dirs = append(dirs, filepath.Join(root, ent.Name()))
		}
	}
	if len(dirs) != 1 {
		t.Fatalf("certifi backups under %s: %v", root, dirs)
	}
	return dirs[0]
}
