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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

const (
	certifiBackupDir      = "certifi"
	certifiBackupFilename = "cacert.pem"
)

// certifiPythonWhere is the discovery probe used by findCertPath. Tests swap it.
var certifiPythonWhere = lookupCertifiWhere

// certifiFallbackPaths lists last-resort locations when Python import fails.
// Kept as a var so tests can isolate discovery.
var certifiFallbackPaths = defaultCertifiFallbackPaths()

func defaultCertifiFallbackPaths() []string {
	paths := []string{
		"/usr/lib/python3/dist-packages/certifi/cacert.pem",
		"/usr/local/lib/python3/dist-packages/certifi/cacert.pem",
		"/Library/Python/3.9/site-packages/certifi/cacert.pem",
		"/Library/Python/3.10/site-packages/certifi/cacert.pem",
		"/Library/Python/3.11/site-packages/certifi/cacert.pem",
		"/Library/Python/3.12/site-packages/certifi/cacert.pem",
		"/Library/Python/3.13/site-packages/certifi/cacert.pem",
		"/Library/Frameworks/Python.framework/Versions/Current/lib/python3.*/site-packages/certifi/cacert.pem",
	}
	if home := file.HomeDir(); home != "" {
		paths = append(paths,
			filepath.Join(home, ".local/lib/python3.*/site-packages/certifi/cacert.pem"),
			filepath.Join(home, "Library/Python/*/lib/python/site-packages/certifi/cacert.pem"),
			filepath.Join(home, "AppData/Roaming/Python/Python*/site-packages/certifi/cacert.pem"),
		)
	}
	return paths
}

// certifiStore manages Python certifi's cacert.pem (or the path certifi.where()
// returns on distro-patched installs). The path field is overridable for tests
// and for -app certifi -file <cacert.pem> so real system CAs are never touched
// by the unit suite.
type certifiStore struct {
	path string
}

// CertifiStore returns the Python certifi CA bundle store. Path discovery uses
// `python3 -c 'import certifi; print(certifi.where())'` (then python), then
// pip's vendored certifi, then common site-packages fallbacks.
func CertifiStore() Store {
	return certifiStore{}
}

// CertifiStoreAt returns a certifiStore pointed at path. Intended for tests and
// for -app certifi -file overrides (one cacert.pem per venv).
func CertifiStoreAt(path string) Store {
	return certifiStore{path: path}
}

func (s certifiStore) certPath() (string, error) {
	if s.path != "" {
		if !file.Exists(s.path) {
			return "", fmt.Errorf("certifi store path %s not found", s.path)
		}
		return resolveCertifiCertPath(s.path), nil
	}
	p, err := s.findCertPath()
	if err != nil {
		return "", err
	}
	return resolveCertifiCertPath(p), nil
}

// resolveCertifiCertPath follows symlinks so writes update the real file.
func resolveCertifiCertPath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == "" {
		return path
	}
	return resolved
}

func (s certifiStore) GetInfo() *Info {
	info := &Info{Name: "certifi"}
	path, err := s.certPath()
	if err != nil {
		return info
	}
	info.Path = path
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		info.Version = fmt.Sprintf("%d bytes", st.Size())
	}
	return info
}

func (s certifiStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	path, err := s.certPath()
	if err != nil {
		return nil, err
	}
	if !file.Exists(path) {
		return nil, fmt.Errorf("certifi bundle not found at %s", path)
	}
	certs, err := certutil.FromFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return certs, nil
}

func (s certifiStore) Add(certs []*x509.Certificate) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("certifi bundle not found at %s; create or restore it before adding certificates", path)
	}
	existing, err := certutil.FromFileResult(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if DryRun() {
		details := reportDryRunCerts("add", certs)
		details = append(details, reportKeptRawPEM(existing.Entries)...)
		reportDryRun("add certificates to", "certifi", path, details...)
		return nil
	}
	return s.replaceBundle(path, existing.AppendCerts(certs))
}

func (s certifiStore) Backup() error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("certifi bundle not found at %s; nothing to back up", path)
	}
	if DryRun() {
		reportDryRun("backup", "certifi", path,
			fmt.Sprintf("copy %s into %s/%s/<timestamp>/%s", path, backupParentDisplay(), certifiBackupDir, certifiBackupFilename))
		return nil
	}
	parent, err := getCertManageDir(certifiBackupDir)
	if err != nil {
		return err
	}
	dir, err := mkdirExclusiveTimestamp(parent)
	if err != nil {
		return err
	}
	dst := filepath.Join(dir, certifiBackupFilename)
	if err := file.CopyFile(path, dst); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("backup %s to %s: %w", path, dst, err)
	}
	return nil
}

func (s certifiStore) GetLatestBackup() (string, error) {
	dir, err := getLatestStoreBackup(certifiBackupDir)
	if err != nil {
		return "", fmt.Errorf("getLatestBackup: error getting certifi backup directory err=%w", err)
	}
	return dir, nil
}

func (s certifiStore) Remove(al allowlist.Allowlist) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("certifi bundle not found at %s; nothing to allowlist", path)
	}
	parsed, err := certutil.FromFileResult(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	kept, removed := parsed.KeepMatching(al.Matches)
	if len(kept.Certs) == 0 {
		return fmt.Errorf("allowlist would leave %s empty; refusing to write an empty bundle. Adjust the allowlist or restore from backup", path)
	}
	if DryRun() {
		details := reportDryRunCerts("remove", removed)
		details = append(details, reportKeptRawPEM(kept.Entries)...)
		reportDryRun("remove certificates from", "certifi", path, details...)
		return nil
	}
	return s.replaceBundle(path, kept)
}

func (s certifiStore) Restore(where string) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	src := where
	if src == "" {
		src, err = s.GetLatestBackup()
		if err != nil {
			return err
		}
		if src == "" {
			return errNoBackupCmd("certifi", certifiBackupDir, "trustprune backup -app certifi")
		}
	}
	srcFile, err := certifiBackupFile(src)
	if err != nil {
		return err
	}
	certs, err := certutil.FromFile(srcFile)
	if err != nil {
		return fmt.Errorf("restore source %s is not a valid PEM bundle: %w; pass -file to a cacert.pem backup", srcFile, err)
	}
	if len(certs) == 0 {
		return fmt.Errorf("restore source %s contains no certificates; refusing to overwrite %s", srcFile, path)
	}
	if DryRun() {
		reportDryRun("restore", "certifi", path,
			fmt.Sprintf("source %s", srcFile),
			fmt.Sprintf("stage into %s.restore-tmp then swap over %s", path, path))
		return nil
	}
	if err := sslInstallFile(srcFile, path); err != nil {
		return fmt.Errorf("restore %s from %s: %w; re-run with permission to write that path (often sudo)", path, srcFile, err)
	}
	return nil
}

// replaceBundle writes bundle entries to a staging PEM then installs via
// sslInstallFile (sibling temp dir + rename swap, refuse leftover .restore-old).
func (s certifiStore) replaceBundle(path string, bundle certutil.PEMResult) error {
	if len(bundle.Certs) == 0 {
		return fmt.Errorf("refusing to write an empty bundle to %s", path)
	}
	tmp, err := os.CreateTemp("", "trustprune-certifi-*.pem")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpName) }()

	if err := certutil.ToFileEntries(tmpName, bundle.Entries); err != nil {
		return fmt.Errorf("stage certifi bundle: %w", err)
	}
	if err := sslInstallFile(tmpName, path); err != nil {
		return fmt.Errorf("write %s: %w; re-run with permission to write that path (often sudo)", path, err)
	}
	return nil
}

func certifiBackupFile(src string) (string, error) {
	st, err := os.Stat(src)
	if err != nil {
		return "", fmt.Errorf("certifi backup %s: %w", src, err)
	}
	if st.IsDir() {
		candidate := filepath.Join(src, certifiBackupFilename)
		if !file.Exists(candidate) {
			return "", fmt.Errorf("certifi backup dir %s has no %s; pass -file to a PEM backup", src, certifiBackupFilename)
		}
		return candidate, nil
	}
	return src, nil
}

func (s certifiStore) findCertPath() (string, error) {
	if p := strings.TrimSpace(certifiPythonWhere()); p != "" && file.Exists(p) {
		return p, nil
	}
	for _, pattern := range certifiFallbackPaths {
		matches, _ := filepath.Glob(pattern)
		for _, p := range matches {
			if file.Exists(p) {
				return p, nil
			}
		}
		if !strings.ContainsAny(pattern, "*?[") && file.Exists(pattern) {
			return pattern, nil
		}
	}
	return "", errors.New("unable to find certifi cacert.pem; install the Python certifi package or pass -app certifi -file <path>")
}

// lookupCertifiWhere asks the active Python interpreters for certifi.where(),
// then pip's vendored copy. Empty string means not found.
func lookupCertifiWhere() string {
	// Drop the empty cwd entry from sys.path so a local certifi.py cannot shadow
	// the installed package (user site-packages stay enabled).
	const dropCwd = "import sys; sys.path = [p for p in sys.path if p]"
	for _, py := range certifiPythonBins() {
		if p := runCertifiWhere(py, dropCwd+"; import certifi; print(certifi.where())"); p != "" {
			return p
		}
		if p := runCertifiWhere(py, dropCwd+"; import pip._vendor.certifi as certifi; print(certifi.where())"); p != "" {
			return p
		}
	}
	return ""
}

func certifiPythonBins() []string {
	bins := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		bins = []string{"python", "python3", "py"}
	}
	out := make([]string, 0, len(bins))
	seen := map[string]bool{}
	for _, name := range bins {
		path, err := exec.LookPath(name)
		if err != nil || path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

func runCertifiWhere(python, snippet string) string {
	cmd := exec.Command(python, "-c", snippet)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
