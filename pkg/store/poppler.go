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
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/file"
)

// PopplerStore returns the NSS store pdfsig uses when no directory is given.
// The path is PopplerNSSDir with this process's home, APPDATA, and environment.
func PopplerStore() Store {
	return newPopplerStore(popplerNSSDir())
}

// PopplerStoreAt returns an NSS store at dir and skips PopplerNSSDir.
// dir is an explicit --store path (pdfsig -nssdir).
func PopplerStoreAt(dir string) Store {
	return newPopplerStore(dir)
}

func newPopplerStore(dir string) Store {
	return popplerStore{nssStore: NssStore("poppler", "", dir).(nssStore)}
}

// popplerStore is the pdfsig NSS store. list, backup, add, and allowlist
// refuse before certutil when the directory has no cert9.db. A missing
// database makes certutil exit 255 with no explanation.
type popplerStore struct {
	nssStore
}

func (s popplerStore) List(opts *ListOptions) ([]*x509.Certificate, error) {
	if err := s.requireCert9(); err != nil {
		return nil, err
	}
	return s.nssStore.List(opts)
}

func (s popplerStore) Add(certs []*x509.Certificate) error {
	if err := s.requireCert9(); err != nil {
		return err
	}
	return s.nssStore.Add(certs)
}

func (s popplerStore) Backup() error {
	if err := s.requireCert9(); err != nil {
		return err
	}
	return s.nssStore.Backup()
}

func (s popplerStore) Remove(al allowlist.Allowlist) error {
	if err := s.requireCert9(); err != nil {
		return err
	}
	return s.nssStore.Remove(al)
}

// requireCert9 is the single gate for poppler operations. systemHasCert9
// matches the database pdfsig will open: a regular, non-empty cert9.db.
func (s popplerStore) requireCert9() error {
	dir := s.foundCertdbLocation
	if systemHasCert9(dir) {
		return nil
	}
	return fmt.Errorf("poppler: no NSS database found (looked in %s); run Firefox once or create one with certutil -N -d sql:%s", dir, dir)
}

func popplerNSSDir() string {
	return PopplerNSSDir(file.HomeDir(), os.Getenv("APPDATA"), os.Getenv, "/etc/pki/nssdb", popplerNSSOpens)
}

// popplerNSSOpens reports whether certutil can list dir as a shared NSS DB.
// Output is discarded. A nil error with ok false means certutil ran and the
// database did not open. A non-nil error means the probe is unavailable
// (certutil cannot be found or started); that is not an open failure.
func popplerNSSOpens(dir string) (bool, error) {
	if dir == "" {
		return false, nil
	}
	expath, err := cutil.getExecPath()
	if err != nil {
		return false, err
	}
	cmd := exec.Command(expath, "-L", "-d", "sql:"+dir) // #nosec G702 G204 -- fixed certutil binary; dir is a single argv element
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	runErr := cmd.Run()
	if runErr == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return false, nil
	}
	return false, runErr
}

// PopplerNSSDir mirrors poppler's NSSSignatureConfiguration::setNSSDir when no
// explicit -nssdir is given. It uses the newest FirefoxProfileDirs entry that
// has a regular non-empty cert9.db (pdfsig does not use cert8-only profiles).
// opens reports (ok, err). err means the certutil probe is unavailable, which
// keeps that profile (or systemDir) instead of falling back. ok false with a
// nil error is an open failure: a profile then falls back to ~/.pki/nssdb and
// never to systemDir. With no cert9 profile, a systemDir that contains a
// regular non-empty cert9.db is used when it opens or when the probe is
// unavailable; otherwise ~/.pki/nssdb.
func PopplerNSSDir(home, appdata string, getenv func(string) string, systemDir string, opens func(dir string) (bool, error)) string {
	fallback := filepath.Join(home, ".pki", "nssdb")
	if dir, ok := popplerCert9Profile(home, appdata, getenv); ok {
		if popplerProbeKeeps(opens, dir) {
			return dir
		}
		return fallback
	}
	if systemHasCert9(systemDir) && popplerProbeKeeps(opens, systemDir) {
		return systemDir
	}
	return fallback
}

// popplerProbeKeeps reports whether dir should be selected. A probe error
// means certutil cannot be found or run, which is not an NSS open failure.
func popplerProbeKeeps(opens func(string) (bool, error), dir string) bool {
	ok, err := opens(dir)
	return err != nil || ok
}

func popplerCert9Profile(home, appdata string, getenv func(string) string) (string, bool) {
	for _, dir := range FirefoxProfileDirs(home, appdata, getenv) {
		if systemHasCert9(dir) {
			return dir, true
		}
	}
	return "", false
}

// systemHasCert9 reports whether dir contains a regular, non-empty cert9.db.
// Poppler ignores cert8-only profiles and empty or non-regular cert9.db files.
func systemHasCert9(dir string) bool {
	if dir == "" {
		return false
	}
	// #nosec G703 -- dir is an injected NSS directory (profile or system DB)
	fi, err := os.Stat(filepath.Join(dir, "cert9.db"))
	return err == nil && fi.Mode().IsRegular() && fi.Size() > 0
}
