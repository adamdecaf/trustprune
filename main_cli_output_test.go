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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
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
			{"bad-arg", "-h"},
			{},
			{"help"},
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
		// --store with the platform OS name is a usage error before any
		// certificate read, so this checks the runtime.GOOS alias without
		// listing the host store.
		storePath := filepath.Join(home, "nope")
		res := runCLI(t, bin, home, "list", "-app", runtime.GOOS, "-store", storePath)
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		want := "--store with --app " + runtime.GOOS + " is only supported for java (keystore override) and certifi (cacert.pem override)"
		if strings.Contains(res.stdout, "ERROR:") || strings.Contains(res.stdout+res.stderr, "unknown app") || !strings.Contains(res.stderr, want) {
			t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		if _, err := os.Stat(storePath); !os.IsNotExist(err) {
			t.Fatalf("store path created: %v", err)
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

func TestCLIAllowlistDryRunDefaultAndVerbose(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()

	help := runCLI(t, bin, home, "allowlist", "--help")
	if help.code != 0 {
		t.Fatalf("help code=%d stdout=%s stderr=%s", help.code, help.stdout, help.stderr)
	}
	helpBody := help.stdout + help.stderr
	if !strings.Contains(helpBody, "show per-certificate remove/keep details in --dry-run output") {
		t.Fatalf("allowlist help missing -v usage:\n%s", helpBody)
	}
	if strings.Contains(helpBody, "show full fingerprints, serials, and paths in table output") {
		t.Fatalf("allowlist -v reused list verbose usage:\n%s", helpBody)
	}

	bundle := filepath.Join(t.TempDir(), "cacert.pem")
	src, err := os.ReadFile(filepath.Join("testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, src, 0o644); err != nil {
		t.Fatal(err)
	}
	backup := runCLI(t, bin, home, "backup", "-app", "certifi", "-store", bundle)
	if backup.code != 0 {
		t.Fatalf("backup code=%d stdout=%s stderr=%s", backup.code, backup.stdout, backup.stderr)
	}

	certs, err := certutil.FromFile(bundle)
	if err != nil || len(certs) < 2 {
		t.Fatalf("bundle certs: %d %v", len(certs), err)
	}
	keep := allowlist.FromCertificates(certs[:1])
	var keptN, removedN int
	var keptLine, removeDetail string
	for _, c := range certs {
		line := fmt.Sprintf("%s (SHA256 %s)", certutil.StringifyPKIXName(c.Subject), certutil.GetHexSHA256Fingerprint(*c))
		if keep.Matches(c) {
			keptN++
			if keptLine == "" {
				keptLine = line
			}
			continue
		}
		removedN++
		if removeDetail == "" {
			removeDetail = "remove " + line
		}
	}
	if keptN == 0 || removedN == 0 || keptLine == "" || removeDetail == "" {
		t.Fatalf("kept=%d removed=%d", keptN, removedN)
	}
	alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])
	if err := os.WriteFile(alPath, []byte("fingerprints:\n  - \""+fp+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	closing := fmt.Sprintf("dry-run: no changes made\ndry-run: %d kept, %d removed\n", keptN, removedN)

	before := readTestFile(t, bundle)
	def := runCLI(t, bin, home, "allowlist", "-app", "certifi", "-store", bundle, "-file", alPath, "-dry-run")
	if def.code != 0 {
		t.Fatalf("default dry-run code=%d stdout=%s stderr=%s", def.code, def.stdout, def.stderr)
	}
	if !strings.HasSuffix(def.stdout, closing) {
		t.Fatalf("default stdout does not end with %q\n%s", closing, def.stdout)
	}
	if !strings.Contains(def.stdout, "dry-run: would remove certificates from certifi at ") || !strings.Contains(def.stdout, "Kept:\n") || !strings.Contains(def.stdout, "  "+keptLine+"\n") {
		t.Fatalf("default plan missing kept certificate:\n%s", def.stdout)
	}
	if strings.Contains(def.stdout, "\n  remove ") {
		t.Fatalf("default plan included remove details:\n%s", def.stdout)
	}
	if strings.Contains(def.stdout, "Allowlist completed successfully") {
		t.Fatalf("dry-run printed a success line:\n%s", def.stdout)
	}
	assertSameBytes(t, bundle, before)

	verb := runCLI(t, bin, home, "allowlist", "-app", "certifi", "-store", bundle, "-file", alPath, "-dry-run", "-v")
	if verb.code != 0 {
		t.Fatalf("verbose dry-run code=%d stdout=%s stderr=%s", verb.code, verb.stdout, verb.stderr)
	}
	if !strings.HasSuffix(verb.stdout, closing) {
		t.Fatalf("verbose stdout does not end with %q\n%s", closing, verb.stdout)
	}
	if !strings.Contains(verb.stdout, "Kept:\n") || !strings.Contains(verb.stdout, "\n  "+removeDetail+"\n") {
		t.Fatalf("verbose plan missing remove detail %q:\n%s", removeDetail, verb.stdout)
	}

	long := runCLI(t, bin, home, "allowlist", "-app", "certifi", "-store", bundle, "-file", alPath, "--dry-run", "--v")
	if long.code != 0 {
		t.Fatalf("--v code=%d stdout=%s stderr=%s", long.code, long.stdout, long.stderr)
	}
	if long.stdout != verb.stdout {
		t.Fatalf("-v and --v stdout differ\n-v:\n%s\n--v:\n%s", verb.stdout, long.stdout)
	}
	assertSameBytes(t, bundle, before)
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
