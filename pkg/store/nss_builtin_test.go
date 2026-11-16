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

package store

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

// fakeCertutil answers certutil -L / -A / -M from canned output.
type fakeCertutil struct {
	cmds         [][]string
	listInternal string
	listAll      string
	pemByNick    map[string]string
	addedPEM     []byte
	failAll      bool
}

func (f *fakeCertutil) run(_ string, args []string) ([]byte, []byte, error) {
	f.cmds = append(f.cmds, append([]string(nil), args...))
	switch {
	case f.failAll && certutilFlagIs(args, "-h", "all"):
		return nil, []byte("could not find token"), errors.New("exit status 1")
	case certutilHasFlag(args, "-A"):
		path, ok := certutilFlag(args, "-i")
		if !ok {
			return nil, []byte("missing -i"), errors.New("exit status 1")
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		f.addedPEM = body
		return nil, nil, nil
	case certutilHasFlag(args, "-M"):
		return nil, nil, nil
	case certutilHasFlag(args, "-a"):
		nick, ok := certutilFlag(args, "-n")
		if !ok {
			return nil, []byte("missing -n"), errors.New("exit status 1")
		}
		pem, ok := f.pemByNick[nick]
		if !ok {
			return nil, []byte("unknown nick"), fmt.Errorf("no certificate named %q", nick)
		}
		return []byte(pem), nil, nil
	case certutilFlagIs(args, "-h", "all"):
		return []byte(f.listAll), nil, nil
	case certutilHasFlag(args, "-L"):
		return []byte(f.listInternal), nil, nil
	default:
		return nil, nil, fmt.Errorf("unexpected certutil args: %q", args)
	}
}

func certutilHasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func certutilFlag(args []string, flag string) (string, bool) {
	for i := range args {
		if args[i] == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func certutilFlagIs(args []string, flag, want string) bool {
	got, ok := certutilFlag(args, flag)
	return ok && got == want
}

func findCertutilFlag(cmds [][]string, flag string) (int, []string) {
	for i, args := range cmds {
		if certutilHasFlag(args, flag) {
			return i, args
		}
	}
	return -1, nil
}

func sawInternalCertutilList(cmds [][]string) bool {
	for _, args := range cmds {
		if certutilHasFlag(args, "-L") && !certutilHasFlag(args, "-h") && !certutilHasFlag(args, "-a") && !certutilHasFlag(args, "-A") {
			return true
		}
	}
	return false
}

func sawBuiltinCertutilList(cmds [][]string) bool {
	for _, args := range cmds {
		if certutilHasFlag(args, "-L") && certutilFlagIs(args, "-h", "all") {
			return true
		}
	}
	return false
}

func nssListOutput(rows ...string) string {
	var b strings.Builder
	b.WriteString("\nCertificate Nickname                                         Trust Attributes\n")
	b.WriteString("                                                             SSL,S/MIME,JAR/XPI\n\n")
	for _, row := range rows {
		b.WriteString(row)
		b.WriteByte('\n')
	}
	return b.String()
}

func nssListRow(nick, trust string) string {
	return nick + "  " + trust
}

func nssStoreWithCertutil(t *testing.T, run certutilRun) nssStore {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert9.db"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	tool := crtutil{run: run}
	return nssStore{
		nssType:             "firefox",
		foundCertdbLocation: dir,
		notify:              &sync.Once{},
		tool:                &tool,
	}
}

func loadStoreCert(t *testing.T, file string, idx int) *x509.Certificate {
	t.Helper()
	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", file))
	if err != nil {
		t.Fatalf("load %s: %v", file, err)
	}
	if idx < 0 || idx >= len(certs) {
		t.Fatalf("%s has %d certs, index %d", file, len(certs), idx)
	}
	return certs[idx]
}

func distinctStoreCerts(t *testing.T, n int) []*x509.Certificate {
	t.Helper()
	out := []*x509.Certificate{loadStoreCert(t, "example.crt", 0)}
	seen := map[string]struct{}{
		certutil.GetHexSHA256Fingerprint(*out[0]): {},
	}
	lots, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range lots {
		fp := certutil.GetHexSHA256Fingerprint(*c)
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, c)
		if len(out) == n {
			return out
		}
	}
	t.Fatalf("need %d distinct certs, found %d", n, len(out))
	return nil
}

func certPEM(t *testing.T, c *x509.Certificate) string {
	t.Helper()
	b, err := certutil.EncodePEMEntries([]certutil.PEMEntry{{Cert: c}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func listTrustedNSS(t *testing.T, s nssStore) []*x509.Certificate {
	t.Helper()
	certs, err := s.List(&ListOptions{Trusted: true})
	if err != nil {
		t.Fatal(err)
	}
	return certs
}

func fingerprintCounts(certs []*x509.Certificate) map[string]int {
	counts := make(map[string]int, len(certs))
	for _, c := range certs {
		counts[certutil.GetHexSHA256Fingerprint(*c)]++
	}
	return counts
}

func TestNSSList_IncludesBuiltinOnlyRoot(t *testing.T) {
	root := loadStoreCert(t, "example.crt", 0)
	const nick = "Example Builtin Root"
	full := nssBuiltinTokenPrefix + nick
	fake := &fakeCertutil{
		listInternal: nssListOutput(),
		listAll:      nssListOutput(nssListRow(full, "C,C,C")),
		pemByNick:    map[string]string{full: certPEM(t, root)},
	}
	got := listTrustedNSS(t, nssStoreWithCertutil(t, fake.run))
	fp := certutil.GetHexSHA256Fingerprint(*root)
	counts := fingerprintCounts(got)
	if len(got) != 1 || counts[fp] != 1 {
		t.Fatalf("builtin-only root listed %d times (len %d), want 1", counts[fp], len(got))
	}
	if !sawInternalCertutilList(fake.cmds) {
		t.Fatalf("missing internal certutil -L (no -h): %#v", fake.cmds)
	}
	if !sawBuiltinCertutilList(fake.cmds) {
		t.Fatalf("missing certutil -L -h all: %#v", fake.cmds)
	}
}

func TestNSSList_DedupesBuiltinRootByNickAndFingerprint(t *testing.T) {
	certs := distinctStoreCerts(t, 2)
	shared, only := certs[0], certs[1]
	sharedPEM := certPEM(t, shared)
	fullShared := nssBuiltinTokenPrefix + "Shared Root"
	fullRenamed := nssBuiltinTokenPrefix + "Renamed Shared"
	fullOnly := nssBuiltinTokenPrefix + "Builtin Only"
	fake := &fakeCertutil{
		listInternal: nssListOutput(nssListRow("Shared Root", "CT,C,C")),
		listAll: nssListOutput(
			nssListRow("Shared Root", "CT,C,C"),
			nssListRow(fullShared, "C,C,C"),
			nssListRow(fullRenamed, "C,C,C"),
			nssListRow(fullOnly, "C,C,C"),
		),
		// fullShared is intentionally missing. Nickname dedupe must skip it
		// before reading; a read would fail the test.
		pemByNick: map[string]string{
			"Shared Root": sharedPEM,
			fullRenamed:   sharedPEM,
			fullOnly:      certPEM(t, only),
		},
	}
	got := listTrustedNSS(t, nssStoreWithCertutil(t, fake.run))
	counts := fingerprintCounts(got)
	sharedFP := certutil.GetHexSHA256Fingerprint(*shared)
	onlyFP := certutil.GetHexSHA256Fingerprint(*only)
	if counts[sharedFP] != 1 {
		t.Fatalf("shared root counted %d times, want 1", counts[sharedFP])
	}
	if counts[onlyFP] != 1 {
		t.Fatalf("builtin-only root counted %d times, want 1", counts[onlyFP])
	}
	if len(got) != 2 {
		t.Fatalf("listed %d certs, want the internal root and the builtin-only root", len(got))
	}
}

func TestNSSRemove_BuiltinOnlyRootAddsThenDistrusts(t *testing.T) {
	root := loadStoreCert(t, "example.crt", 0)
	const nick = "Example Builtin Root"
	full := nssBuiltinTokenPrefix + nick
	fake := &fakeCertutil{
		listInternal: nssListOutput(),
		listAll:      nssListOutput(nssListRow(full, "C,C,C")),
		pemByNick:    map[string]string{full: certPEM(t, root)},
	}
	s := nssStoreWithCertutil(t, fake.run)
	if err := s.Remove(allowlist.Allowlist{}); err != nil {
		t.Fatal(err)
	}

	addAt, addArgs := findCertutilFlag(fake.cmds, "-A")
	modAt, modArgs := findCertutilFlag(fake.cmds, "-M")
	if addAt < 0 || modAt < 0 || addAt > modAt {
		t.Fatalf("want certutil -A before certutil -M, cmds %#v", fake.cmds)
	}
	if !certutilHasFlag(addArgs, "-a") {
		t.Fatalf("add args missing -a: %q", addArgs)
	}
	for _, args := range [][]string{addArgs, modArgs} {
		trust, ok := certutilFlag(args, "-t")
		if !ok || trust != trustAttrsProhibited {
			t.Fatalf("args %q trust %q, want %s", args, trust, trustAttrsProhibited)
		}
		got, ok := certutilFlag(args, "-n")
		if !ok || got != nick {
			t.Fatalf("args %q nick %q, want %q", args, got, nick)
		}
		if _, ok := certutilFlag(args, "-h"); ok {
			t.Fatalf("override must target the internal token, args %q", args)
		}
		dir, ok := certutilFlag(args, "-d")
		if !ok || !strings.HasPrefix(dir, "sql:") {
			t.Fatalf("args %q -d %q, want sql:", args, dir)
		}
	}
	added, err := certutil.ParsePEM(fake.addedPEM)
	if err != nil || len(added) != 1 {
		t.Fatalf("added PEM: %v (%d certs)", err, len(added))
	}
	if certutil.GetHexSHA256Fingerprint(*added[0]) != certutil.GetHexSHA256Fingerprint(*root) {
		t.Fatal("certutil -A did not receive the built-in root")
	}
}

func TestNSSRemove_InternalRootIsModifyOnly(t *testing.T) {
	root := loadStoreCert(t, "example.crt", 0)
	const nick = "Internal Root"
	fake := &fakeCertutil{
		listInternal: nssListOutput(nssListRow(nick, "CT,C,C")),
		listAll:      nssListOutput(nssListRow(nick, "CT,C,C")),
		pemByNick:    map[string]string{nick: certPEM(t, root)},
	}
	s := nssStoreWithCertutil(t, fake.run)
	if err := s.Remove(allowlist.Allowlist{}); err != nil {
		t.Fatal(err)
	}
	if _, args := findCertutilFlag(fake.cmds, "-A"); args != nil {
		t.Fatalf("internal root must not be added with certutil -A, args %q", args)
	}
	_, modArgs := findCertutilFlag(fake.cmds, "-M")
	if modArgs == nil {
		t.Fatalf("missing certutil -M, cmds %#v", fake.cmds)
	}
	if got, _ := certutilFlag(modArgs, "-n"); got != nick {
		t.Fatalf("modify -n %q, want %q", got, nick)
	}
	if trust, _ := certutilFlag(modArgs, "-t"); trust != trustAttrsProhibited {
		t.Fatalf("modify -t %q, want %s", trust, trustAttrsProhibited)
	}
}

func TestNSSRemove_BuiltinOnlyDryRunDoesNotMutate(t *testing.T) {
	root := loadStoreCert(t, "example.crt", 0)
	const nick = "Example Builtin Root"
	full := nssBuiltinTokenPrefix + nick
	fake := &fakeCertutil{
		listInternal: nssListOutput(),
		listAll:      nssListOutput(nssListRow(full, "C,C,C")),
		pemByNick:    map[string]string{full: certPEM(t, root)},
	}
	buf := enableDryRunCaptureAny(t)
	s := nssStoreWithCertutil(t, fake.run)
	if err := s.Remove(allowlist.Allowlist{}); err != nil {
		t.Fatal(err)
	}
	if _, args := findCertutilFlag(fake.cmds, "-A"); args != nil {
		t.Fatalf("dry-run issued certutil -A: %q", args)
	}
	if _, args := findCertutilFlag(fake.cmds, "-M"); args != nil {
		t.Fatalf("dry-run issued certutil -M: %q", args)
	}
	out := buf.String()
	if !strings.Contains(out, nick) || !strings.Contains(out, trustAttrsProhibited) {
		t.Fatalf("dry-run plan missing built-in override: %s", out)
	}
	if !strings.Contains(out, "no changes made") {
		t.Fatalf("dry-run plan: %s", out)
	}
}

func TestNSSList_BuiltinListError(t *testing.T) {
	fake := &fakeCertutil{listInternal: nssListOutput(), failAll: true}
	s := nssStoreWithCertutil(t, fake.run)
	_, err := s.List(&ListOptions{Trusted: true})
	if err == nil || !strings.Contains(err.Error(), "built-in roots") {
		t.Fatalf("err = %v, want built-in roots failure", err)
	}
}
