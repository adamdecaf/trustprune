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

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/file"
)

const (
	okularAppName        = "okular"
	okularConfigFileName = "okular-generator-popplerrc"
	okularSignaturesGrp  = "Signatures"
	okularBackendNSS     = "NSS"
	okularBackendGPG     = "GPG"
)

// OkularCompiledSignatureBackend is poppler's DEFAULT_SIGNATURE_BACKEND,
// used when SignatureBackend is unset and POPPLER_SIGNATURE_BACKEND is unset.
// Poppler compiles NSS first. Tests may set this to "GPG".
var OkularCompiledSignatureBackend = okularBackendNSS

// ErrOkularGPG is returned for every Okular operation when the effective
// signature backend is GPG. trustprune does not read or write gpgsm stores.
var ErrOkularGPG = errors.New("okular: signature backend is GPG; trustprune does not list, back up, or change GPG (gpgsm) stores")

// OkularStore returns the store Okular's poppler generator uses for PDF
// signatures. The effective backend is SignatureBackend in
// okular-generator-popplerrc [Signatures], else POPPLER_SIGNATURE_BACKEND,
// else OkularCompiledSignatureBackend. NSS uses DBCertificatePath when
// UseDefaultCertDB is false, otherwise the same directory poppler uses.
func OkularStore() Store {
	return newOkularStore(resolveOkular(file.HomeDir(), os.Getenv, popplerNSSDir))
}

func newOkularStore(backend, dir string) Store {
	return okularStore{
		nssStore: NssStore(okularAppName, "", dir).(nssStore),
		backend:  backend,
	}
}

// okularStore is Okular's signature trust store. When the backend is NSS it
// is the poppler NSS store at the configured directory. When the backend is
// GPG, every mutating and listing operation reports that and makes no change.
type okularStore struct {
	nssStore
	backend string
}

var _ Store = okularStore{}

func (s okularStore) gpg() bool {
	return s.backend == okularBackendGPG
}

func (s okularStore) refuseGPG() error {
	if s.gpg() {
		return ErrOkularGPG
	}
	return nil
}

func (s okularStore) GetInfo() *Info {
	if s.gpg() {
		return &Info{Name: titleASCII(okularAppName), Path: okularBackendGPG}
	}
	return s.nssStore.GetInfo()
}

func (s okularStore) List(opts *ListOptions) ([]*x509.Certificate, error) {
	if err := s.refuseGPG(); err != nil {
		return nil, err
	}
	if err := s.requireCert9(); err != nil {
		return nil, err
	}
	return s.nssStore.List(opts)
}

func (s okularStore) Add(certs []*x509.Certificate) error {
	if err := s.refuseGPG(); err != nil {
		return err
	}
	if err := s.requireCert9(); err != nil {
		return err
	}
	return s.nssStore.Add(certs)
}

func (s okularStore) Backup() error {
	if err := s.refuseGPG(); err != nil {
		return err
	}
	if err := s.requireCert9(); err != nil {
		return err
	}
	return s.nssStore.Backup()
}

func (s okularStore) Remove(al allowlist.Allowlist) error {
	if err := s.refuseGPG(); err != nil {
		return err
	}
	if err := s.requireCert9(); err != nil {
		return err
	}
	return s.nssStore.Remove(al)
}

func (s okularStore) GetLatestBackup() (string, error) {
	if err := s.refuseGPG(); err != nil {
		return "", err
	}
	return s.nssStore.GetLatestBackup()
}

func (s okularStore) Restore(where string) error {
	if err := s.refuseGPG(); err != nil {
		return err
	}
	return s.nssStore.Restore(where)
}

func (s okularStore) requireCert9() error {
	return requireNSSCert9(okularAppName, s.foundCertdbLocation)
}

// resolveOkular returns the effective signature backend and NSS directory.
// getenv supplies XDG_CONFIG_HOME and POPPLER_SIGNATURE_BACKEND. defaultNSS
// is poppler's directory when UseDefaultCertDB is true or unset.
func resolveOkular(home string, getenv func(string) string, defaultNSS func() string) (backend, dir string) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	settings := readOkularSignatures(okularConfigPath(home, getenv))
	backend = okularEffectiveBackend(settings, getenv)
	if backend == okularBackendGPG {
		return backend, ""
	}
	return backend, okularNSSDir(settings, defaultNSS)
}

func okularConfigPath(home string, getenv func(string) string) string {
	if getenv != nil {
		if xdg := strings.TrimSpace(getenv("XDG_CONFIG_HOME")); xdg != "" && filepath.IsAbs(xdg) {
			return filepath.Join(xdg, okularConfigFileName)
		}
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".config", okularConfigFileName)
}

func readOkularSignatures(path string) map[string]string {
	if path == "" {
		return nil
	}
	// #nosec G703 -- path is the user's KConfig file under XDG or ~/.config
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseKConfigSection(string(b), okularSignaturesGrp)
}

func okularEffectiveBackend(settings map[string]string, getenv func(string) string) string {
	if v := strings.TrimSpace(settings["SignatureBackend"]); v != "" {
		return canonicalOkularBackend(v)
	}
	if getenv != nil {
		if v := strings.TrimSpace(getenv("POPPLER_SIGNATURE_BACKEND")); v != "" {
			return canonicalOkularBackend(v)
		}
	}
	return canonicalOkularBackend(OkularCompiledSignatureBackend)
}

func canonicalOkularBackend(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case okularBackendGPG, "GPGME":
		return okularBackendGPG
	default:
		return okularBackendNSS
	}
}

func okularUseDefaultCertDB(settings map[string]string) bool {
	v, ok := settings["UseDefaultCertDB"]
	if !ok {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

func okularNSSDir(settings map[string]string, defaultNSS func() string) string {
	if okularUseDefaultCertDB(settings) {
		if defaultNSS == nil {
			return ""
		}
		return defaultNSS()
	}
	return strings.TrimSpace(settings["DBCertificatePath"])
}

// parseKConfigSection reads a KConfig INI file and returns keys from section.
// Group and key suffixes such as [$i] and [$e] are stripped. Comments and
// other sections are ignored.
func parseKConfigSection(content, section string) map[string]string {
	out := make(map[string]string)
	content = strings.TrimPrefix(content, "\ufeff")
	current := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			name := strings.TrimPrefix(line, "[")
			if i := strings.Index(name, "]"); i >= 0 {
				name = name[:i]
			}
			current = strings.TrimSpace(name)
			continue
		}
		if !strings.EqualFold(current, section) {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if i := strings.Index(key, "[$"); i >= 0 {
			key = strings.TrimSpace(key[:i])
		}
		if key == "" {
			continue
		}
		out[key] = kconfigValue(strings.TrimSpace(val))
	}
	return out
}

func kconfigValue(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

func requireNSSCert9(app, dir string) error {
	if dir == "" {
		return fmt.Errorf("%s: no NSS database found (looked in %s); run Firefox once or create one with certutil -N -d sql:%s", app, dir, dir)
	}
	fi, err := os.Stat(filepath.Join(dir, "cert9.db")) // #nosec G703 -- dir is the resolved NSS store directory
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s: no NSS database found (looked in %s); run Firefox once or create one with certutil -N -d sql:%s", app, dir, dir)
		}
		return fmt.Errorf("%s: checking NSS database in %s: %w", app, dir, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() == 0 {
		return fmt.Errorf("%s: no NSS database found (looked in %s); run Firefox once or create one with certutil -N -d sql:%s", app, dir, dir)
	}
	return nil
}
