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

package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/adamdecaf/trustprune/pkg/ui"
)

func TestCheckBundleFlag(t *testing.T) {
	t.Parallel()
	if err := CheckBundleFlag("list", "openssl", ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckBundleFlag("allowlist", "OpenSSL", "/tmp/ca.pem"); err != nil {
		t.Fatal(err)
	}
	err := CheckBundleFlag("add", "openssl", "/tmp/ca.pem")
	if err == nil || !strings.Contains(err.Error(), "only supported for list") {
		t.Fatalf("add: %v", err)
	}
	err = CheckBundleFlag("list", "java", "/tmp/ca.pem")
	if err == nil || !strings.Contains(err.Error(), "requires --app openssl") {
		t.Fatalf("java: %v", err)
	}
	err = CheckBundleFlag("restore", "", "/tmp/ca.pem")
	if err == nil || !strings.Contains(err.Error(), "requires --app openssl") {
		t.Fatalf("no app: %v", err)
	}
}

func TestOpenSSLBundleCmd_ListBackupRestoreAllowlist(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store.SetDryRun(false)
	store.SetForceRestore(false)
	t.Cleanup(func() {
		store.SetDryRun(false)
		store.SetForceRestore(false)
		store.SetDryRunOutput(nil)
	})

	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certs) < 2 {
		t.Fatalf("lots.crt: len=%d err=%v", len(certs), err)
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca-bundle.pem")
	decoy := filepath.Join(dir, "decoy.pem")
	other := filepath.Join(dir, "other.pem")
	if err := certutil.ToFile(bundle, certs); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(decoy, []byte("not-a-pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(other, certs); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bundle, decoy, other} {
		if strings.HasPrefix(filepath.Clean(p), "/etc/") || strings.HasPrefix(filepath.Clean(p), "/usr/") {
			t.Fatalf("refusing system path in tests: %s", p)
		}
	}
	t.Setenv("SSL_CERT_FILE", decoy)
	t.Setenv("CURL_CA_BUNDLE", decoy)
	decoyBefore, err := os.ReadFile(decoy)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}

	if err := ListCertsForBundle(bundle, &ui.Config{Count: true}); err != nil {
		t.Fatal(err)
	}
	if err := BackupForBundle(bundle); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSSLBundleAt(bundle)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := st.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("latest backup: %q err=%v", latest, err)
	}
	backed, err := os.ReadFile(filepath.Join(latest, "ca-bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backed, orig) {
		t.Fatal("backup bytes differ from the -bundle PEM")
	}
	recorded, err := os.ReadFile(filepath.Join(latest, "source"))
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(bundle)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(recorded)) != resolved && strings.TrimSpace(string(recorded)) != filepath.Clean(abs) {
		t.Fatalf("source=%q want %q", strings.TrimSpace(string(recorded)), resolved)
	}

	if err := os.WriteFile(bundle, []byte("MUTATED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RestoreForBundle("openssl", "", bundle); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatal("restore -bundle did not restore the PEM")
	}

	otherBefore, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	err = RestoreForBundle("openssl", latest, other)
	if err == nil || !strings.Contains(err.Error(), "refusing restore") {
		t.Fatalf("cross-path: %v", err)
	}
	otherAfter, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(otherAfter, otherBefore) {
		t.Fatal("refused restore mutated the other PEM")
	}

	unbacked := filepath.Join(dir, "unbacked.pem")
	if err := certutil.ToFile(unbacked, certs); err != nil {
		t.Fatal(err)
	}
	unbackedBefore, err := os.ReadFile(unbacked)
	if err != nil {
		t.Fatal(err)
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])
	alPath := filepath.Join(dir, "allowlist.json")
	if err := os.WriteFile(alPath, []byte(fmt.Sprintf("{\"Fingerprints\":[%q]}\n", fp)), 0o644); err != nil {
		t.Fatal(err)
	}
	err = AllowlistForBundle("openssl", alPath, unbacked)
	if err == nil || !strings.Contains(err.Error(), "no backup for openssl") {
		t.Fatalf("allowlist without backup: %v", err)
	}
	unbackedAfter, err := os.ReadFile(unbacked)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unbackedAfter, unbackedBefore) {
		t.Fatal("allowlist with no backup mutated the PEM")
	}
	if _, statErr := os.Stat(unbacked + ".restore-old"); !os.IsNotExist(statErr) {
		t.Fatalf("allowlist with no backup left aside: %v", statErr)
	}

	if err := BackupForBundle(bundle); err != nil {
		t.Fatal(err)
	}
	var plan bytes.Buffer
	store.SetDryRunOutput(&plan)
	store.SetDryRun(true)
	if err := AllowlistForBundle("openssl", alPath, bundle); err != nil {
		t.Fatal(err)
	}
	store.SetDryRun(false)
	dryGot, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dryGot, orig) {
		t.Fatal("allowlist dry-run mutated the PEM")
	}
	if !strings.Contains(plan.String(), "dry-run") {
		t.Fatalf("missing dry-run plan: %q", plan.String())
	}

	if err := AllowlistForBundle("openssl", alPath, bundle); err != nil {
		t.Fatal(err)
	}
	kept, err := certutil.FromFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 {
		t.Fatalf("allowlist kept %d certs, want 1", len(kept))
	}
	if certutil.GetHexSHA256Fingerprint(*kept[0]) != fp {
		t.Fatal("allowlist kept a different certificate")
	}

	decoyAfter, err := os.ReadFile(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoyAfter, decoyBefore) {
		t.Fatal("operations mutated SSL_CERT_FILE decoy")
	}

	if err := BackupForBundle(dir); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory -bundle: %v", err)
	}
	if err := AllowlistForBundle("firefox", alPath, bundle); err == nil || !strings.Contains(err.Error(), "requires --app openssl") {
		t.Fatalf("firefox -bundle: %v", err)
	}
}

func TestListCertsForBundle_ReturnsError(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing.pem")
	err := ListCertsForBundle(missing, &ui.Config{Count: true})
	if err == nil {
		t.Fatal("missing bundle must return an error")
	}
	if strings.Contains(err.Error(), "exit status") {
		t.Fatalf("library list returned a process exit: %v", err)
	}
}
