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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func enableDryRunCapture(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	SetDryRun(true)
	SetDryRunOutput(buf)
	t.Cleanup(func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	})
	return buf
}

func hashDir(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	snap := snapshotDir(t, dir)
	// stable order
	names := make([]string, 0, len(snap))
	for name := range snap {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		h.Write([]byte(name))
		h.Write(snap[name])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestLinuxDryRun_RestoreLeavesStoreUnchanged(t *testing.T) {
	s := linuxTestStore(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.ca.dir, "example.crt"), []byte("mutated-for-dry-run\n"), 0644); err != nil {
		t.Fatal(err)
	}
	before := hashDir(t, s.ca.dir)

	buf := enableDryRunCapture(t)
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore dry-run: %v", err)
	}
	after := hashDir(t, s.ca.dir)
	if before != after {
		t.Fatalf("dry-run Restore mutated store: before=%s after=%s", before, after)
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would restore linux") {
		t.Fatalf("missing restore plan header: %q", out)
	}
	if !strings.Contains(out, "source ") || !strings.Contains(out, "copy ") {
		t.Fatalf("plan missing source/copy details: %q", out)
	}
	if !strings.Contains(out, "example.crt") {
		t.Fatalf("plan missing example.crt: %q", out)
	}
}

func TestLinuxDryRun_AddLeavesStoreUnchanged(t *testing.T) {
	s := linuxTestStore(t)
	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil || len(certs) == 0 {
		t.Fatalf("load example.crt: %v", err)
	}
	beforeDir := hashDir(t, s.ca.dir)
	beforeAdd := hashDir(t, s.ca.add)
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	buf := enableDryRunCapture(t)
	if err := s.Add(certs); err != nil {
		t.Fatalf("Add dry-run: %v", err)
	}
	if hashDir(t, s.ca.dir) != beforeDir {
		t.Fatal("dry-run Add mutated ca.dir")
	}
	if hashDir(t, s.ca.add) != beforeAdd {
		t.Fatal("dry-run Add mutated ca.add")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would add certificates to linux") {
		t.Fatalf("missing add plan: %q", out)
	}
	if !strings.Contains(out, fp) {
		t.Fatalf("plan missing fingerprint %s: %q", fp, out)
	}
}

func TestLinuxDryRun_RemoveLeavesStoreUnchanged(t *testing.T) {
	s := linuxTestStore(t)
	before := hashDir(t, s.ca.dir)
	certs, err := certutil.FromFile(filepath.Join(s.ca.dir, "example.crt"))
	if err != nil || len(certs) == 0 {
		t.Fatalf("read example.crt: %v", err)
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	// Empty allowlist matches nothing, so example.crt would be removed.
	buf := enableDryRunCapture(t)
	if err := s.Remove(allowlist.Allowlist{}); err != nil {
		t.Fatalf("Remove dry-run: %v", err)
	}
	if hashDir(t, s.ca.dir) != before {
		t.Fatal("dry-run Remove mutated store")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would remove certificates from linux") {
		t.Fatalf("missing remove plan: %q", out)
	}
	if !strings.Contains(out, fp) {
		t.Fatalf("plan missing fingerprint %s: %q", out, fp)
	}
}

func TestLinuxDryRun_BackupMakesNoWrites(t *testing.T) {
	s := linuxTestStore(t)
	before := hashDir(t, s.ca.dir)
	home := os.Getenv("HOME")

	buf := enableDryRunCapture(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup dry-run: %v", err)
	}
	if hashDir(t, s.ca.dir) != before {
		t.Fatal("dry-run Backup mutated store")
	}
	// Prefer no writes at all: no backup tree under HOME.
	for _, name := range []string{".cert-manage", ".trustprune"} {
		cm := filepath.Join(home, name)
		if _, err := os.Stat(cm); !os.IsNotExist(err) {
			t.Fatalf("dry-run Backup must not create %s (err=%v)", cm, err)
		}
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would backup linux") {
		t.Fatalf("missing backup plan: %q", out)
	}
}

// Prove the dry-run restore assertion is not vacuous: the same mutated store
// is actually rewritten by Restore when dry-run is off.
func TestLinuxDryRun_RestoreWithoutFlagDoesMutate(t *testing.T) {
	s := linuxTestStore(t)
	want := snapshotDir(t, s.ca.dir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.ca.dir, "example.crt"), []byte("mutated-control\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mutated := hashDir(t, s.ca.dir)

	SetDryRun(false)
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restored := hashDir(t, s.ca.dir)
	if mutated == restored {
		t.Fatal("Restore without dry-run did not change the mutated store")
	}
	assertDirSnapshotEqual(t, s.ca.dir, want)
}

func TestLinuxRemove_KeepsUnparsablePEM(t *testing.T) {
	s := linuxTestStore(t)
	if err := os.Remove(filepath.Join(s.ca.dir, "extra.crt")); err != nil {
		t.Fatal(err)
	}

	good, err := os.ReadFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil {
		t.Fatal(err)
	}
	neg, err := os.ReadFile(filepath.Join("..", "..", "testdata", "negative-serial.pem"))
	if err != nil {
		t.Fatal(err)
	}
	lots, err := os.ReadFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(neg)
	if block == nil {
		t.Fatal("negative-serial.pem: no PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		t.Skip("crypto/x509 accepted a negative serial; cannot test skip path")
	}
	rawSkip := certificatePEMBlock(t, neg)

	mixed := filepath.Join(s.ca.dir, "mixed.crt")
	var blob bytes.Buffer
	blob.Write(good)
	blob.Write(neg)
	blob.Write(lots)
	if err := os.WriteFile(mixed, blob.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	certs, err := certutil.FromFile(mixed)
	if err != nil || len(certs) < 2 {
		t.Fatalf("mixed.crt parseable: len=%d err=%v", len(certs), err)
	}
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	keepFP := certutil.GetHexSHA256Fingerprint(*certs[0])

	before := mustRead(t, mixed)
	buf := enableDryRunCapture(t)
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove dry-run: %v", err)
	}
	if !bytes.Equal(before, mustRead(t, mixed)) {
		t.Fatal("dry-run Remove mutated mixed.crt")
	}
	out := buf.String()
	if !strings.Contains(out, "keep unparsable PEM block") {
		t.Fatalf("dry-run should report the kept unparsable block, got %q", out)
	}
	if !strings.Contains(out, mixed) {
		t.Fatalf("dry-run should name %s, got %q", mixed, out)
	}

	SetDryRun(false)
	SetDryRunOutput(nil)
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	written := mustRead(t, mixed)
	if !bytes.Contains(written, rawSkip) {
		t.Fatal("linux Remove dropped the unparsable PEM block")
	}
	got, err := certutil.FromFile(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("after allowlist mixed.crt len=%d want 1", len(got))
	}
	if certutil.GetHexSHA256Fingerprint(*got[0]) != keepFP {
		t.Fatal("kept unexpected certificate in mixed.crt")
	}
}
