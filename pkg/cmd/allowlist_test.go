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

package cmd

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/store"
)

// treeSnapshot records every path under root with its size and mod time.
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = info.Mode().String() + "|" + info.ModTime().String() + "|" + strconv.FormatInt(info.Size(), 10)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertSameTree(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("%s changed: before=%v after=%v", what, before, after)
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("%s: %s changed", what, k)
		}
	}
}

// allowlistNoBackupEnv points HOME at an empty temp dir and the openssl/curl
// bundle env vars at a temp bundle, so nothing touches the real system store.
func allowlistNoBackupEnv(t *testing.T) (home, storeDir, alPath string) {
	t.Helper()
	home = t.TempDir()
	storeDir = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	bundle := filepath.Join(storeDir, "cert.pem")
	if err := os.WriteFile(bundle, []byte("not a real bundle\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", bundle)
	t.Setenv("CURL_CA_BUNDLE", bundle)
	alDir := t.TempDir()
	alPath = filepath.Join(alDir, "allowlist.json")
	if err := os.WriteFile(alPath, []byte(`{"Fingerprints":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return home, storeDir, alPath
}

// noWriteStore delegates reads to a real store and records, without
// performing, any Remove call.
type noWriteStore struct {
	store.Store
	removed bool
}

func (s *noWriteStore) Remove(allowlist.Allowlist) error {
	s.removed = true
	return errors.New("Remove must not be called in this test")
}

func TestAllowlist_NoBackupRefusesBeforeWrite(t *testing.T) {
	apps := []string{"certifi", "chrome", "firefox", "java", "openssl", "ssl", ""}
	for _, app := range apps {
		for _, dry := range []bool{false, true} {
			name := app
			if name == "" {
				name = "platform"
			}
			if dry {
				name += "/dry-run"
			}
			t.Run(name, func(t *testing.T) {
				if _, err := store.ForApp(app); app != "" && err != nil {
					t.Skipf("app %s not available: %v", app, err)
				}
				home, storeDir, alPath := allowlistNoBackupEnv(t)
				var plan bytes.Buffer
				store.SetDryRunOutput(&plan)
				defer store.SetDryRunOutput(nil)
				if dry {
					store.SetDryRun(true)
					defer store.SetDryRun(false)
				}
				beforeHome := treeSnapshot(t, home)
				beforeStore := treeSnapshot(t, storeDir)
				beforeAl := treeSnapshot(t, filepath.Dir(alPath))

				// Wrap the real store so its backup lookup runs, but any write
				// (Remove) is caught instead of reaching a system, Java or
				// browser store if the guard ever regresses.
				var inner store.Store
				if app == "" {
					inner = store.Platform()
				} else {
					inner, _ = store.ForApp(app)
				}
				g := &noWriteStore{Store: inner}
				err := allowlistStore(g, app, alPath)
				if g.removed {
					t.Fatal("Remove was called with no backup")
				}
				if err == nil {
					t.Fatal("expected an error with no backup")
				}
				if app == "java" && (strings.Contains(err.Error(), "never found java") || strings.Contains(err.Error(), "has no cacerts")) {
					// No JDK keystore on this machine: still refused, nothing written.
					t.Logf("java refused without a keystore: %v", err)
				} else {
					want := store.NoBackupError(app).Error()
					if err.Error() != want {
						t.Fatalf("got %q, want %q", err.Error(), want)
					}
					hint := "run: trustprune backup"
					if app != "" {
						hint += " --app " + app
					}
					if !strings.HasSuffix(want, hint) {
						t.Fatalf("%q missing hint %q", want, hint)
					}
				}
				if plan.Len() != 0 {
					t.Fatalf("dry-run plan printed before refusing: %q", plan.String())
				}
				assertSameTree(t, "HOME", beforeHome, treeSnapshot(t, home))
				assertSameTree(t, "store dir", beforeStore, treeSnapshot(t, storeDir))
				assertSameTree(t, "allowlist dir", beforeAl, treeSnapshot(t, filepath.Dir(alPath)))
			})
		}
	}
}

// allowlistRecorder counts Remove and does not touch the live NSS DB.
type allowlistRecorder struct {
	store.Store
	removed bool
}

func (s *allowlistRecorder) Remove(allowlist.Allowlist) error {
	s.removed = true
	return nil
}

func TestAllowlist_NSSBackupSourceMustMatchStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store.SetForceRestore(false)
	store.SetDryRun(false)
	t.Cleanup(func() {
		store.SetForceRestore(false)
		store.SetDryRun(false)
		store.SetDryRunOutput(nil)
	})

	a := filepath.Join(t.TempDir(), "a")
	b := filepath.Join(t.TempDir(), "b")
	for _, dir := range []string{a, b} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cert9.db"), []byte(dir+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	alPath := filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(alPath, []byte(`{"Fingerprints":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	sA := store.NssStore("poppler", "0", a)
	if err := sA.Backup(); err != nil {
		t.Fatal(err)
	}

	t.Run("mismatch refuses before remove", func(t *testing.T) {
		for _, dry := range []bool{false, true} {
			name := "write"
			if dry {
				name = "dry-run"
			}
			t.Run(name, func(t *testing.T) {
				store.SetForceRestore(false)
				store.SetDryRun(dry)
				var plan bytes.Buffer
				store.SetDryRunOutput(&plan)
				g := &noWriteStore{Store: store.NssStore("poppler", "0", b)}
				err := allowlistStore(g, "poppler", alPath)
				if g.removed {
					t.Fatal("Remove was called for a backup recorded from another directory")
				}
				if err == nil {
					t.Fatal("expected an error")
				}
				msg := err.Error()
				if !strings.Contains(msg, "trustprune backup") || !strings.Contains(msg, b) || !strings.Contains(msg, "--store") || !strings.Contains(msg, a) {
					t.Fatalf("error should name store B, source A, and trustprune backup: %v", err)
				}
				if !strings.Contains(msg, "--force") {
					t.Fatalf("error should mention --force: %v", err)
				}
				if plan.Len() != 0 {
					t.Fatalf("plan printed before refusing: %q", plan.String())
				}
			})
		}
	})

	t.Run("force reaches remove", func(t *testing.T) {
		store.SetForceRestore(true)
		store.SetDryRun(true)
		g := &allowlistRecorder{Store: store.NssStore("poppler", "0", b)}
		if err := allowlistStore(g, "poppler", alPath); err != nil {
			t.Fatal(err)
		}
		if !g.removed {
			t.Fatal("--force did not reach Remove")
		}
	})

	t.Run("older backup of this store still authorizes", func(t *testing.T) {
		store.SetForceRestore(false)
		store.SetDryRun(false)
		sB := store.NssStore("poppler", "0", b)
		if err := sB.Backup(); err != nil {
			t.Fatal(err)
		}
		// A newer backup of A must not hide B's own backup.
		if err := store.NssStore("poppler", "0", a).Backup(); err != nil {
			t.Fatal(err)
		}
		store.SetDryRun(true)
		g := &allowlistRecorder{Store: store.NssStore("poppler", "0", b)}
		if err := allowlistStore(g, "poppler", alPath); err != nil {
			t.Fatal(err)
		}
		if !g.removed {
			t.Fatal("B's own backup did not authorize allowlist")
		}
	})
}

func TestNoBackupError_Platform(t *testing.T) {
	err := store.NoBackupError("")
	if !strings.Contains(err.Error(), "no backup for "+runtime.GOOS+" in ") ||
		!strings.HasSuffix(err.Error(), "; run: trustprune backup") {
		t.Fatalf("unexpected message %q", err)
	}
}
