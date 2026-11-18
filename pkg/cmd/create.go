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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

// CreateFormats is the create --format list, in help text and errors.
// pem is the only format in this slice. Java trust stores can be added later.
const CreateFormats = "pem"

const createFormatPEM = "pem"

// createFilePerm is the mode of a PEM bundle written by create.
// CA bundles are world-readable so other programs can load them.
const createFilePerm os.FileMode = 0o644

// ErrNoMatchingCerts is returned when no trusted certificate matches the
// allowlist. create writes no PEM in that case. allowlist refuses an empty
// result the same way, so an empty bundle is not a successful create.
var ErrNoMatchingCerts = errors.New("no certificates matched the allowlist; refusing to write an empty PEM bundle")

// CreateOptions is the input to the create command.
type CreateOptions struct {
	// AllowlistPath is the allowlist file (--file). Required.
	AllowlistPath string
	// Format is "pem" (the default). Empty means pem.
	// Matching is case-insensitive.
	Format string
	// Out is the PEM path (--out). Empty writes the bundle to Stdout.
	Out string
	// Stdout receives the PEM when Out is empty. Nil means os.Stdout.
	Stdout io.Writer
}

// NormalizeCreateFormat accepts pem (the default, including "").
// Matching is case-insensitive. Any other value is an error that lists the
// valid formats. The returned name is lowercase. The error quotes format
// unchanged so the caller can show what was passed.
func NormalizeCreateFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", createFormatPEM:
		return createFormatPEM, nil
	default:
		return "", fmt.Errorf("unknown format %q (formats: %s)", format, CreateFormats)
	}
}

// CreateForPlatform reads the platform store and writes a PEM bundle of the
// trusted certificates that match the allowlist. The store is not modified.
func CreateForPlatform(opts CreateOptions) error {
	return CreateFromStore(store.Platform(), opts)
}

// CreateForApp reads the named app store and writes a PEM bundle of the
// trusted certificates that match the allowlist. The store is not modified.
func CreateForApp(app string, opts CreateOptions) error {
	st, err := store.ForApp(app)
	if err != nil {
		return err
	}
	return CreateFromStore(st, opts)
}

// CreateForAppWithStore reads app with an explicit trust-store path (CLI
// --store: java keystore, certifi bundle, or poppler NSS directory) and
// writes a PEM bundle. The store is not modified.
func CreateForAppWithStore(app, storePath string, opts CreateOptions) error {
	st, err := store.ForAppWithStore(app, storePath)
	if err != nil {
		return err
	}
	return CreateFromStore(st, opts)
}

// CreateForBundle reads an explicit openssl PEM CA bundle (CLI --bundle)
// and writes a PEM bundle of the certificates that match the allowlist.
// app must be openssl. The source PEM is not modified.
func CreateForBundle(app, bundle string, opts CreateOptions) error {
	if strings.ToLower(strings.TrimSpace(app)) != "openssl" {
		return fmt.Errorf("--bundle requires --app openssl")
	}
	st, err := store.OpenSSLBundleAt(bundle)
	if err != nil {
		return err
	}
	return CreateFromStore(st, opts)
}

// createSource is the store surface create reads. It lists certificates
// and reports store info. create does not add, remove, back up, or restore.
type createSource interface {
	store.Lister
	store.Informer
}

// CreateFromStore lists trusted certificates from st, keeps those
// allowlist.Matches accepts, and writes a PEM bundle.
//
// The store is read-only. This calls List and, when a file output path is
// set, GetInfo. It does not call Add, Remove, Backup, Restore, or
// GetLatestBackup. An output path that is the store, or a file inside a
// directory store, is refused before any write. ErrNoMatchingCerts is
// returned before any write when nothing matches.
func CreateFromStore(st createSource, opts CreateOptions) error {
	if st == nil {
		return errors.New("no certificate store")
	}
	if _, err := NormalizeCreateFormat(opts.Format); err != nil {
		return err
	}
	al, err := allowlist.FromFile(opts.AllowlistPath)
	if err != nil {
		return err
	}
	certs, err := st.List(&store.ListOptions{Trusted: true})
	if err != nil {
		return err
	}
	kept := matchingCerts(certs, al)
	if len(kept) == 0 {
		return ErrNoMatchingCerts
	}
	body, err := encodeCreatePEM(kept)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return ErrNoMatchingCerts
	}
	out := strings.TrimSpace(opts.Out)
	if out == "" {
		w := opts.Stdout
		if w == nil {
			w = os.Stdout
		}
		_, err := w.Write(body)
		return err
	}
	if info := st.GetInfo(); info != nil {
		overlaps, err := createOutputOverlapsStore(info.Path, out)
		if err != nil {
			return err
		}
		if overlaps {
			return fmt.Errorf("refusing to write %s over the certificate store; choose a different --out", out)
		}
	}
	return writeCreateFile(out, body)
}

// matchingCerts returns certificates Matches accepts, in store order.
// A nil certificate does not match.
func matchingCerts(certs []*x509.Certificate, al allowlist.Allowlist) []*x509.Certificate {
	var kept []*x509.Certificate
	for i := range certs {
		if al.Matches(certs[i]) {
			kept = append(kept, certs[i])
		}
	}
	return kept
}

func encodeCreatePEM(certs []*x509.Certificate) ([]byte, error) {
	entries := make([]certutil.PEMEntry, 0, len(certs))
	for i := range certs {
		if certs[i] == nil {
			continue
		}
		entries = append(entries, certutil.PEMEntry{Cert: certs[i]})
	}
	return certutil.EncodePEMEntries(entries)
}

// writeCreateFile publishes body at path with mode 0644.
// The bytes land in a sibling temp file and replace path only after the
// write and chmod succeed, so a failure leaves an existing path untouched.
func writeCreateFile(path string, body []byte) error {
	dir := filepath.Dir(path)
	// #nosec G304 -- --out is the user-requested PEM path; stage beside it so rename stays on one filesystem
	tmp, err := os.CreateTemp(dir, ".trustprune-create-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	published := false
	defer func() {
		if !published {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	// CreateTemp uses 0600, and umask would narrow a direct WriteFile.
	// chmod after the bytes are written so the published file is 0644.
	if err := tmp.Chmod(createFilePerm); err != nil { //nolint:gosec // G302: PEM CA bundles are world-readable by design
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// #nosec G304 -- --out is the user-requested PEM path
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	published = true
	return nil
}

// createOutputOverlapsStore reports whether out is the store path, or a
// file inside a directory store. out may not exist yet. A store path that
// cannot be stated is treated as a file: only an equal path overlaps.
func createOutputOverlapsStore(storePath, out string) (bool, error) {
	storePath = strings.TrimSpace(storePath)
	out = strings.TrimSpace(out)
	if storePath == "" || out == "" {
		return false, nil
	}
	storeCanon, err := canonicalCreatePath(storePath)
	if err != nil {
		return false, err
	}
	outCanon, err := canonicalCreatePath(out)
	if err != nil {
		return false, err
	}
	if storeCanon == outCanon {
		return true, nil
	}
	st, err := os.Stat(storeCanon)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if !st.IsDir() {
		return false, nil
	}
	rel, err := filepath.Rel(storeCanon, outCanon)
	if err != nil {
		return false, err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false, nil
	}
	return true, nil
}

// canonicalCreatePath returns an absolute cleaned path. An existing path,
// including the final symlink, is resolved. A path whose last element does
// not exist yet resolves its parent so a symlink directory still compares
// equal to the store.
func canonicalCreatePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil && resolved != "" {
		return filepath.Clean(resolved), nil
	}
	parent, name := filepath.Split(abs)
	if parent == "" {
		return abs, nil
	}
	parentResolved, perr := filepath.EvalSymlinks(filepath.Clean(parent))
	if perr != nil || parentResolved == "" {
		return abs, nil
	}
	return filepath.Join(parentResolved, name), nil
}
