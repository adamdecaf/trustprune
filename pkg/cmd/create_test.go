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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

func TestNormalizeCreateFormat(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"", "pem", "PEM", " Pem "} {
		got, err := NormalizeCreateFormat(format)
		if err != nil || got != "pem" {
			t.Fatalf("format %q: got %q err=%v", format, got, err)
		}
	}
	for _, format := range []string{"java", "jks", "pkcs12", "JAVA"} {
		_, err := NormalizeCreateFormat(format)
		if err == nil {
			t.Fatalf("format %q: expected error", format)
		}
		if !strings.Contains(err.Error(), "unknown format") || !strings.Contains(err.Error(), CreateFormats) {
			t.Fatalf("format %q: %v", format, err)
		}
		if !strings.Contains(err.Error(), format) {
			t.Fatalf("format %q: error should quote the value: %v", format, err)
		}
	}
}

func TestCreateFromStore_FiltersAndWritesPEM(t *testing.T) {
	keep := mustCreateCert(t, "Keep", "US", 1)
	drop := mustCreateCert(t, "Drop", "DE", 2)
	other := mustCreateCert(t, "Other", "JP", 3)
	dir := t.TempDir()
	storeFile := filepath.Join(dir, "store.pem")
	if err := os.WriteFile(storeFile, []byte("store-bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &fakeCreateStore{
		info:  &store.Info{Name: "fake", Path: storeFile},
		certs: []*x509.Certificate{keep, nil, drop, other},
	}
	alPath := writeCreateAllowlist(t, allowlist.Allowlist{
		Fingerprints: []string{certutil.GetHexSHA256Fingerprint(*keep)},
		Countries:    []string{"JP"},
	})
	out := filepath.Join(dir, "out.pem")
	if err := os.WriteFile(out, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := CreateFromStore(st, CreateOptions{
		AllowlistPath: alPath,
		Format:        "PEM",
		Out:           out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.mutated {
		t.Fatal("create called a store mutation")
	}
	if st.listCalls != 1 || st.listOpts == nil || !st.listOpts.Trusted || st.listOpts.Untrusted {
		t.Fatalf("list calls=%d opts=%+v", st.listCalls, st.listOpts)
	}
	gotStore, err := os.ReadFile(storeFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotStore) != "store-bytes\n" {
		t.Fatalf("store file changed: %q", gotStore)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports Perm() as 0666 and does not honor Unix mode bits.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Fatalf("mode=%o want 0644", info.Mode().Perm())
	}
	got, err := certutil.FromFile(out)
	if err != nil {
		t.Fatal(err)
	}
	wantFP := []string{
		certutil.GetHexSHA256Fingerprint(*keep),
		certutil.GetHexSHA256Fingerprint(*other),
	}
	if fingerprints(got) != strings.Join(wantFP, ",") {
		t.Fatalf("certs=%s want %s", fingerprints(got), strings.Join(wantFP, ","))
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) || !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatalf("pem shape: %q", raw)
	}
}

func TestCreateFromStore_StdoutAndOrder(t *testing.T) {
	first := mustCreateCert(t, "First", "US", 1)
	second := mustCreateCert(t, "Second", "US", 2)
	st := &fakeCreateStore{
		info:  &store.Info{Name: "fake"},
		certs: []*x509.Certificate{first, second},
	}
	alPath := writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{second, first}))
	var buf bytes.Buffer
	err := CreateFromStore(st, CreateOptions{
		AllowlistPath: alPath,
		Stdout:        &buf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.mutated || st.infoCalls != 0 {
		t.Fatalf("mutated=%v infoCalls=%d", st.mutated, st.infoCalls)
	}
	got, err := certutil.Decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	want := fingerprints([]*x509.Certificate{first, second})
	if fingerprints(got) != want {
		t.Fatalf("order=%s want %s", fingerprints(got), want)
	}
}

func TestCreateFromStore_NoMatchWritesNothing(t *testing.T) {
	cert := mustCreateCert(t, "Keep", "US", 1)
	dir := t.TempDir()
	out := filepath.Join(dir, "out.pem")
	if err := os.WriteFile(out, []byte("keep-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &fakeCreateStore{
		info:  &store.Info{Name: "fake", Path: filepath.Join(dir, "store.pem")},
		certs: []*x509.Certificate{cert},
	}
	alPath := writeCreateAllowlist(t, allowlist.Allowlist{
		Fingerprints: []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	})
	err := CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Out: out})
	if !errors.Is(err, ErrNoMatchingCerts) {
		t.Fatalf("err=%v", err)
	}
	if st.mutated {
		t.Fatal("create called a store mutation")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep-me\n" {
		t.Fatalf("output changed: %q", got)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports Perm() as 0666 and does not honor Unix mode bits.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o want 0600", info.Mode().Perm())
	}

	missing := filepath.Join(dir, "missing.pem")
	err = CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Out: missing})
	if !errors.Is(err, ErrNoMatchingCerts) {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(missing); !os.IsNotExist(statErr) {
		t.Fatalf("empty match created %s: %v", missing, statErr)
	}
}

func TestCreateFromStore_RefusesStorePath(t *testing.T) {
	cert := mustCreateCert(t, "Keep", "US", 1)
	dir := t.TempDir()
	storeFile := filepath.Join(dir, "cacert.pem")
	if err := os.WriteFile(storeFile, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	alPath := writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{cert}))
	st := &fakeCreateStore{
		info:  &store.Info{Name: "fake", Path: storeFile},
		certs: []*x509.Certificate{cert},
	}
	err := CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Out: storeFile})
	if err == nil || !strings.Contains(err.Error(), "refusing to write") {
		t.Fatalf("err=%v", err)
	}
	got, err := os.ReadFile(storeFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original\n" {
		t.Fatalf("store overwritten: %q", got)
	}
	if st.mutated {
		t.Fatal("create called a store mutation")
	}

	nss := filepath.Join(dir, "nssdb")
	if err := os.Mkdir(nss, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(nss, "out.pem")
	if err := os.WriteFile(inside, []byte("inside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st.info = &store.Info{Name: "fake", Path: nss}
	err = CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Out: inside})
	if err == nil || !strings.Contains(err.Error(), "refusing to write") {
		t.Fatalf("dir err=%v", err)
	}
	got, err = os.ReadFile(inside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "inside\n" {
		t.Fatalf("directory store file changed: %q", got)
	}
}

func TestCreateFromStore_ErrorsLeaveOutputAbsent(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.pem")
	alPath := writeCreateAllowlist(t, allowlist.Allowlist{Countries: []string{"US"}})

	err := CreateFromStore(nil, CreateOptions{AllowlistPath: alPath, Out: out})
	if err == nil || !strings.Contains(err.Error(), "no certificate store") {
		t.Fatalf("nil store: %v", err)
	}

	st := &fakeCreateStore{listErr: errors.New("list failed")}
	err = CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Out: out})
	if err == nil || !strings.Contains(err.Error(), "list failed") {
		t.Fatalf("list: %v", err)
	}
	if st.mutated {
		t.Fatal("create called a store mutation")
	}

	err = CreateFromStore(st, CreateOptions{AllowlistPath: filepath.Join(dir, "missing.yaml"), Out: out})
	if err == nil {
		t.Fatal("missing allowlist")
	}
	err = CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Format: "jks", Out: out})
	if err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Fatalf("format: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("output created: %v", statErr)
	}
}

func TestCreateForBundle_DoesNotModifyPEM(t *testing.T) {
	keep := mustCreateCert(t, "Keep", "US", 1)
	drop := mustCreateCert(t, "Drop", "DE", 2)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca-bundle.pem")
	if err := certutil.ToFile(bundle, []*x509.Certificate{keep, drop}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	alPath := writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{keep}))
	out := filepath.Join(dir, "kept.pem")

	if err := CreateForBundle("firefox", bundle, CreateOptions{AllowlistPath: alPath, Out: out}); err == nil || !strings.Contains(err.Error(), "requires --app openssl") {
		t.Fatalf("firefox: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("firefox create wrote %s: %v", out, statErr)
	}

	if err := CreateForBundle("openssl", bundle, CreateOptions{AllowlistPath: alPath, Out: out}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("openssl bundle was modified")
	}
	got, err := certutil.FromFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || certutil.GetHexSHA256Fingerprint(*got[0]) != certutil.GetHexSHA256Fingerprint(*keep) {
		t.Fatalf("kept %d certs", len(got))
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports Perm() as 0666 and does not honor Unix mode bits.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Fatalf("mode=%o want 0644", info.Mode().Perm())
	}
}

func TestCreateForAppWithStore_CertifiReadOnly(t *testing.T) {
	keep := mustCreateCert(t, "Keep", "US", 1)
	drop := mustCreateCert(t, "Drop", "DE", 2)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "cacert.pem")
	if err := certutil.ToFile(bundle, []*x509.Certificate{drop, keep}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	alPath := writeCreateAllowlist(t, allowlist.Allowlist{Countries: []string{"US"}})
	out := filepath.Join(dir, "kept.pem")
	if err := CreateForAppWithStore("certifi", bundle, CreateOptions{AllowlistPath: alPath, Out: out}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("certifi bundle was modified")
	}
	got, err := certutil.FromFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Subject.CommonName != "Keep" {
		t.Fatalf("kept %#v", got)
	}
}

func TestCreateForApp_Unknown(t *testing.T) {
	t.Parallel()
	err := CreateForApp("nope", CreateOptions{AllowlistPath: "unused"})
	if err == nil || !strings.Contains(err.Error(), "unknown app") {
		t.Fatalf("err=%v", err)
	}
}

type fakeCreateStore struct {
	info      *store.Info
	certs     []*x509.Certificate
	listErr   error
	listOpts  *store.ListOptions
	listCalls int
	infoCalls int
	mutated   bool
}

func (f *fakeCreateStore) GetInfo() *store.Info {
	f.infoCalls++
	return f.info
}

func (f *fakeCreateStore) List(opts *store.ListOptions) ([]*x509.Certificate, error) {
	f.listCalls++
	if opts != nil {
		copied := *opts
		f.listOpts = &copied
	}
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.certs, nil
}

func (f *fakeCreateStore) Add([]*x509.Certificate) error {
	f.mutated = true
	return errors.New("add called")
}

func (f *fakeCreateStore) Remove(allowlist.Allowlist) error {
	f.mutated = true
	return errors.New("remove called")
}

func (f *fakeCreateStore) Backup() error {
	f.mutated = true
	return errors.New("backup called")
}

func (f *fakeCreateStore) GetLatestBackup() (string, error) {
	f.mutated = true
	return "", errors.New("get latest backup called")
}

func (f *fakeCreateStore) Restore(string) error {
	f.mutated = true
	return errors.New("restore called")
}

func mustCreateCert(t *testing.T, cn, country string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Country: []string{country}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writeCreateAllowlist(t *testing.T, al allowlist.Allowlist) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := al.ToFile(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func fingerprints(certs []*x509.Certificate) string {
	out := make([]string, 0, len(certs))
	for i := range certs {
		if certs[i] == nil {
			continue
		}
		out = append(out, certutil.GetHexSHA256Fingerprint(*certs[i]))
	}
	return strings.Join(out, ",")
}
