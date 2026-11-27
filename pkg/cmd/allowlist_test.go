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
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
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

var (
	_ store.Store    = (*noWriteStore)(nil)
	_ store.Lister   = (*noWriteStore)(nil)
	_ store.Modifier = (*noWriteStore)(nil)
	_ store.Saver    = (*noWriteStore)(nil)
	_ store.Informer = (*noWriteStore)(nil)
)

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
				err := allowlistStore(g, app, alPath, allowlist.FetchOptions{}, nil)
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

var (
	_ store.Store    = (*allowlistRecorder)(nil)
	_ store.Lister   = (*allowlistRecorder)(nil)
	_ store.Modifier = (*allowlistRecorder)(nil)
	_ store.Saver    = (*allowlistRecorder)(nil)
	_ store.Informer = (*allowlistRecorder)(nil)
)

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
				err := allowlistStore(g, "poppler", alPath, allowlist.FetchOptions{}, nil)
				if g.removed {
					t.Fatal("Remove was called for a backup recorded from another directory")
				}
				if err == nil {
					t.Fatal("expected an error")
				}
				msg := err.Error()
				canon := func(p string) string {
					if r, err := filepath.EvalSymlinks(p); err == nil {
						return r
					}
					return p
				}
				if !strings.Contains(msg, "trustprune backup") || !strings.Contains(msg, canon(b)) || !strings.Contains(msg, "--store") || !strings.Contains(msg, canon(a)) {
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
		if err := allowlistStore(g, "poppler", alPath, allowlist.FetchOptions{}, nil); err != nil {
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
		if err := allowlistStore(g, "poppler", alPath, allowlist.FetchOptions{}, nil); err != nil {
			t.Fatal(err)
		}
		if !g.removed {
			t.Fatal("B's own backup did not authorize allowlist")
		}
	})

}

func TestAllowlist_NSSSourceLessBackupRequiresForce(t *testing.T) {
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
	latest, err := sA.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("latest backup: %q err=%v", latest, err)
	}
	if err := os.Remove(filepath.Join(latest, "source")); err != nil {
		t.Fatal(err)
	}

	store.SetDryRun(true)
	var plan bytes.Buffer
	store.SetDryRunOutput(&plan)
	g := &noWriteStore{Store: store.NssStore("poppler", "0", b)}
	err = allowlistStore(g, "poppler", alPath, allowlist.FetchOptions{}, nil)
	if g.removed {
		t.Fatal("Remove was called for a source-less backup")
	}
	if err == nil || !strings.Contains(err.Error(), "no recorded source") || !strings.Contains(err.Error(), "--force") || !strings.Contains(err.Error(), "trustprune backup") {
		t.Fatalf("expected source-less refusal mentioning --force, got %v", err)
	}
	if plan.Len() != 0 {
		t.Fatalf("plan printed before refusing: %q", plan.String())
	}

	store.SetForceRestore(true)
	g2 := &allowlistRecorder{Store: store.NssStore("poppler", "0", b)}
	if err := allowlistStore(g2, "poppler", alPath, allowlist.FetchOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	if !g2.removed {
		t.Fatal("--force did not reach Remove for a source-less backup")
	}
}

func countAllowlistSplit(certs []*x509.Certificate, al allowlist.Allowlist) (kept, removed int) {
	for _, c := range certs {
		if al.Matches(c) {
			kept++
			continue
		}
		removed++
	}
	return kept, removed
}

func certifiAllowlistEnv(t *testing.T) (bundle string, certs []*x509.Certificate) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	bundle = writeLotsBundle(t, filepath.Join(t.TempDir(), "cacert.pem"))
	var err error
	certs, err = certutil.FromFile(bundle)
	if err != nil || len(certs) < 2 {
		t.Fatalf("bundle certs: %d %v", len(certs), err)
	}
	store.SetDryRun(false)
	store.SetDryRunVerbose(false)
	store.SetAllowlistCountOnly(false)
	store.SetDryRunOutput(nil)
	if err := BackupForAppWithFile("certifi", bundle); err != nil {
		t.Fatal(err)
	}
	return bundle, certs
}

func TestAllowlist_SummaryUnmatchedAndCount(t *testing.T) {
	store.SetDryRun(false)
	store.SetDryRunVerbose(false)
	store.SetAllowlistCountOnly(false)
	store.SetForceRestore(false)
	store.SetDryRunOutput(nil)
	t.Cleanup(func() {
		store.SetDryRun(false)
		store.SetDryRunVerbose(false)
		store.SetAllowlistCountOnly(false)
		store.SetForceRestore(false)
		store.SetDryRunOutput(nil)
	})

	t.Run("partial keep lists stale fingerprints and counts", func(t *testing.T) {
		bundle, certs := certifiAllowlistEnv(t)
		var keep *x509.Certificate
		for _, c := range certs {
			if c == nil {
				continue
			}
			fp := certutil.GetHexSHA256Fingerprint(*c)
			if (allowlist.Allowlist{Fingerprints: []string{fp}}).Matches(c) {
				keep = c
				break
			}
		}
		if keep == nil {
			t.Fatal("no certificate matches its own fingerprint")
		}
		keepFP := certutil.GetHexSHA256Fingerprint(*keep)
		stale1 := strings.Repeat("ab", 32)
		stale2 := strings.Repeat("cd", 32)
		for _, fp := range []string{stale1, stale2} {
			for _, c := range certs {
				if c != nil && certutil.GetHexSHA256Fingerprint(*c) == fp {
					t.Fatalf("stale fingerprint %s collided with the bundle", fp)
				}
			}
		}
		al := allowlist.Allowlist{
			Fingerprints: []string{keepFP, stale1, stale1, stale2},
			Countries:    []string{"ZZ"},
		}
		keptN, removedN := countAllowlistSplit(certs, al)
		if keptN == 0 || removedN == 0 {
			t.Fatalf("kept=%d removed=%d", keptN, removedN)
		}
		alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
		if err := al.ToFile(alPath); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		unmatched := "Unmatched allowlist entries:\n  " + stale1 + "\n  " + stale2 + "\n"
		closing := fmt.Sprintf("dry-run: no changes made\ndry-run: %d kept, %d removed\n", keptN, removedN)

		store.SetDryRun(true)
		var plan bytes.Buffer
		store.SetDryRunOutput(&plan)
		stdout := captureStdout(t, func() error {
			return AllowlistForAppWithStore("certifi", bundle, alPath, allowlist.FetchOptions{}, nil)
		})
		if stdout != "" {
			t.Fatalf("dry-run wrote stdout %q", stdout)
		}
		planText := plan.String()
		if strings.Count(planText, unmatched) != 1 {
			t.Fatalf("unmatched section count=%d\n%s", strings.Count(planText, unmatched), planText)
		}
		closeAt := strings.Index(planText, "dry-run: no changes made\n")
		if closeAt < 0 || !strings.Contains(planText[:closeAt], unmatched) || !strings.HasSuffix(planText, closing) {
			t.Fatalf("dry-run plan:\n%s", planText)
		}
		if strings.Contains(planText, "Allowlist completed successfully") || strings.Contains(planText, "\n  ZZ\n") {
			t.Fatalf("dry-run plan:\n%s", planText)
		}
		after, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("dry-run allowlist modified the bundle")
		}

		store.SetAllowlistCountOnly(true)
		plan.Reset()
		stdout = captureStdout(t, func() error {
			return AllowlistForAppWithStore("certifi", bundle, alPath, allowlist.FetchOptions{}, nil)
		})
		if stdout != fmt.Sprintf("%d\n", removedN) {
			t.Fatalf("dry-run --count stdout %q", stdout)
		}
		if plan.Len() != 0 {
			t.Fatalf("dry-run --count printed a plan:\n%s", plan.String())
		}
		after, err = os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("dry-run --count modified the bundle")
		}

		store.SetAllowlistCountOnly(false)
		store.SetDryRun(false)
		store.SetDryRunOutput(nil)
		want := "Allowlist completed successfully\n" + unmatched + fmt.Sprintf("%d removed, %d kept\n", removedN, keptN)
		stdout = captureStdout(t, func() error {
			return AllowlistForAppWithStore("certifi", bundle, alPath, allowlist.FetchOptions{}, nil)
		})
		if stdout != want {
			t.Fatalf("stdout:\n%s\nwant:\n%s", stdout, want)
		}
		left, err := store.CertifiStoreAt(bundle).List(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) != keptN {
			t.Fatalf("store has %d certificates, want %d kept", len(left), keptN)
		}
	})

	t.Run("full match omits unmatched and count prints removed", func(t *testing.T) {
		bundle, certs := certifiAllowlistEnv(t)
		alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
		if err := os.WriteFile(alPath, []byte(allFingerprintAllowlist(t, bundle)), 0o644); err != nil {
			t.Fatal(err)
		}
		al, err := allowlist.FromFile(alPath)
		if err != nil {
			t.Fatal(err)
		}
		keptN, removedN := countAllowlistSplit(certs, al)

		store.SetDryRun(true)
		store.SetAllowlistCountOnly(true)
		var plan bytes.Buffer
		store.SetDryRunOutput(&plan)
		stdout := captureStdout(t, func() error {
			return AllowlistForAppWithStore("certifi", bundle, alPath, allowlist.FetchOptions{}, nil)
		})
		if stdout != fmt.Sprintf("%d\n", removedN) || plan.Len() != 0 {
			t.Fatalf("count stdout %q plan %q", stdout, plan.String())
		}

		store.SetAllowlistCountOnly(false)
		store.SetDryRun(false)
		store.SetDryRunOutput(nil)
		want := fmt.Sprintf("Allowlist completed successfully\n%d removed, %d kept\n", removedN, keptN)
		stdout = captureStdout(t, func() error {
			return AllowlistForAppWithStore("certifi", bundle, alPath, allowlist.FetchOptions{}, nil)
		})
		if stdout != want {
			t.Fatalf("stdout:\n%s\nwant:\n%s", stdout, want)
		}
		if strings.Contains(stdout, "Unmatched allowlist entries:") {
			t.Fatalf("matched allowlist listed unmatched entries:\n%s", stdout)
		}
	})

	t.Run("real count prints only the removed number", func(t *testing.T) {
		bundle, certs := certifiAllowlistEnv(t)
		var keepFP string
		for _, c := range certs {
			if c == nil {
				continue
			}
			fp := certutil.GetHexSHA256Fingerprint(*c)
			if (allowlist.Allowlist{Fingerprints: []string{fp}}).Matches(c) {
				keepFP = fp
				break
			}
		}
		if keepFP == "" {
			t.Fatal("no certificate matches its own fingerprint")
		}
		al := allowlist.Allowlist{Fingerprints: []string{keepFP, strings.Repeat("ef", 32)}}
		keptN, removedN := countAllowlistSplit(certs, al)
		if removedN == 0 {
			t.Fatal("expected at least one removal")
		}
		alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
		if err := al.ToFile(alPath); err != nil {
			t.Fatal(err)
		}
		store.SetDryRun(false)
		store.SetAllowlistCountOnly(true)
		stdout := captureStdout(t, func() error {
			return AllowlistForAppWithStore("certifi", bundle, alPath, allowlist.FetchOptions{}, nil)
		})
		if stdout != fmt.Sprintf("%d\n", removedN) {
			t.Fatalf("count stdout %q", stdout)
		}
		if strings.Contains(stdout, "Allowlist") || strings.Contains(stdout, "Unmatched") || strings.Contains(stdout, "kept") {
			t.Fatalf("count stdout included a summary: %q", stdout)
		}
		left, err := store.CertifiStoreAt(bundle).List(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) != keptN {
			t.Fatalf("store has %d certificates, want %d kept", len(left), keptN)
		}
	})
	t.Run("count writes to the provided writer", func(t *testing.T) {
		bundle, certs := certifiAllowlistEnv(t)
		var keepFP string
		for _, c := range certs {
			if c == nil {
				continue
			}
			fp := certutil.GetHexSHA256Fingerprint(*c)
			if (allowlist.Allowlist{Fingerprints: []string{fp}}).Matches(c) {
				keepFP = fp
				break
			}
		}
		if keepFP == "" {
			t.Fatal("no certificate matches its own fingerprint")
		}
		al := allowlist.Allowlist{Fingerprints: []string{keepFP}}
		_, removedN := countAllowlistSplit(certs, al)
		if removedN == 0 {
			t.Fatal("expected at least one removal")
		}
		alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
		if err := al.ToFile(alPath); err != nil {
			t.Fatal(err)
		}
		store.SetDryRun(false)
		store.SetAllowlistCountOnly(true)
		var buf bytes.Buffer
		stdout := captureStdout(t, func() error {
			return AllowlistForAppWithStore("certifi", bundle, alPath, allowlist.FetchOptions{}, &buf)
		})
		if stdout != "" {
			t.Fatalf("count wrote os.Stdout %q", stdout)
		}
		if buf.String() != fmt.Sprintf("%d\n", removedN) {
			t.Fatalf("count buffer %q, want %d", buf.String(), removedN)
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
