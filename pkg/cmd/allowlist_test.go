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
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

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

				var err error
				if app == "" {
					err = AllowlistForPlatform(alPath)
				} else {
					err = AllowlistForApp(app, alPath)
				}
				if err == nil {
					t.Fatal("expected an error with no backup")
				}
				if app == "java" && strings.Contains(err.Error(), "never found java") {
					// No JDK keystore on this machine: still refused, nothing written.
					t.Logf("java refused without a keystore: %v", err)
				} else {
					want := store.NoBackupError(app).Error()
					if err.Error() != want {
						t.Fatalf("got %q, want %q", err.Error(), want)
					}
					hint := "run: trustprune backup"
					if app != "" {
						hint += " -app " + app
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

func TestNoBackupError_Platform(t *testing.T) {
	err := store.NoBackupError("")
	if !strings.Contains(err.Error(), "no backup for "+runtime.GOOS+" in ") ||
		!strings.HasSuffix(err.Error(), "; run: trustprune backup") {
		t.Fatalf("unexpected message %q", err)
	}
}
