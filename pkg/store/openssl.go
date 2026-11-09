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

package store

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

const (
	opensslBackupDir        = "openssl"
	opensslBackupFilename   = "ca-bundle.pem"
	opensslBackupSourceName = "source"
)

var (
	openSSLCertPaths = []string{
		"/etc/ssl/certs/ca-certificates.crt",  // Debian/Ubuntu/Alpine
		"/etc/pki/tls/certs/ca-bundle.crt",    // RHEL/CentOS/Fedora
		"/usr/local/etc/openssl/certs",        // Darwin Homebrew (Intel)
		"/usr/local/etc/openssl@3/certs",      // Darwin Homebrew openssl@3
		"/usr/local/etc/openssl@1.1/certs",    // Darwin Homebrew openssl@1.1
		"/opt/homebrew/etc/openssl/certs",     // Darwin Homebrew (Apple Silicon)
		"/opt/homebrew/etc/openssl@3/certs",   // Darwin Homebrew openssl@3 (Apple Silicon)
		"/opt/homebrew/etc/openssl@1.1/certs", // Darwin Homebrew openssl@1.1 (Apple Silicon)
	}

	openSSLRehashPaths = []string{
		"/usr/bin/c_rehash",                   // Ubuntu/Debian
		"/usr/local/opt/openssl/bin/c_rehash", // Darwin Homebrew (Intel)
		"/usr/local/opt/openssl@3/bin/c_rehash",
		"/usr/local/opt/openssl@1.1/bin/c_rehash",
		"/opt/homebrew/opt/openssl/bin/c_rehash", // Darwin Homebrew (Apple Silicon)
		"/opt/homebrew/opt/openssl@3/bin/c_rehash",
		"/opt/homebrew/opt/openssl@1.1/bin/c_rehash",
	}

	// gitHTTPSSLCAInfo is best-effort `git config --get http.sslCAInfo`.
	// Tests replace it so a developer gitconfig cannot leak into path lookup.
	gitHTTPSSLCAInfo = lookupGitHTTPSSLCAInfo
)

type opensslStore struct {
	// path, when set, is an explicit store location (file or directory).
	// Tests inject a temp path via opensslStoreAt so real system CAs are never touched.
	path string
}

// OpenSSLStore returns an implementation of Store for OpenSSL / curl / git CA
// bundles and OpenSSL cert directories.
func OpenSSLStore() Store {
	return opensslStore{}
}

// opensslStoreAt returns an opensslStore pointed at path. Intended for tests.
func opensslStoreAt(path string) opensslStore {
	return opensslStore{path: path}
}

// OpenSSLBundleAt returns an openssl store for an explicit PEM CA bundle file.
// The path is not discovered from SSL_CERT_FILE, CURL_CA_BUNDLE, git, or
// distro defaults. Directories are rejected; hashed cert directories stay on
// OpenSSLStore without an explicit file (CLI -bundle).
func OpenSSLBundleAt(path string) (Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("openssl -bundle path is empty")
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("openssl bundle %s not found: %w", path, err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("openssl -bundle %s is a directory; pass a PEM CA bundle file (hashed cert directories stay on -app openssl without -bundle)", path)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("openssl -bundle %s is not a regular PEM file", path)
	}
	return opensslStoreAt(path), nil
}

func (s opensslStore) certPath() (string, error) {
	if s.path != "" {
		return resolveOpenSSLCertPath(s.path), nil
	}
	p, err := s.findCertPath()
	if err != nil {
		return "", err
	}
	return resolveOpenSSLCertPath(p), nil
}

// resolveOpenSSLCertPath follows symlinks so writes update the real file.
// On RHEL/Fedora, ca-bundle.crt is often a symlink into the ca-trust tree;
// renaming over the link would replace it with a regular file and break
// later update-ca-trust refreshes. If resolution fails, return path unchanged.
func resolveOpenSSLCertPath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == "" {
		return path
	}
	return resolved
}

func (s opensslStore) Add(certs []*x509.Certificate) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("openssl store not found at %s", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return s.addToDir(path, certs)
	}
	return s.addToFile(path, certs)
}

func (s opensslStore) addToFile(path string, certs []*x509.Certificate) error {
	existing, err := certutil.FromFileResult(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if DryRun() {
		details := reportDryRunCerts("add", certs)
		details = append(details, reportKeptRawPEM(existing.Entries)...)
		reportDryRun("add certificates to", "openssl", path, details...)
		return nil
	}
	return s.replaceBundle(path, existing.AppendCerts(certs))
}

func (s opensslStore) addToDir(dir string, certs []*x509.Certificate) error {
	if DryRun() {
		details := reportDryRunCerts("add", certs)
		if len(certs) > 0 {
			if bin := findCRehash(); bin != "" {
				details = append(details, fmt.Sprintf("then run %s %s", bin, dir))
			}
		}
		reportDryRun("add certificates to", "openssl", dir, details...)
		return nil
	}
	if len(certs) > 0 && findCRehash() == "" {
		return errors.New("unable to find openssl c_rehash binary")
	}
	for i := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		path := filepath.Join(dir, fmt.Sprintf("%s.crt", fp))
		if err := certutil.ToFile(path, certs[i:i+1]); err != nil {
			return err
		}
	}
	if len(certs) > 0 {
		return s.rehash(dir, true)
	}
	return nil
}

func (s opensslStore) Backup() error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("openssl store not found at %s; nothing to back up", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if DryRun() {
		if st.IsDir() {
			names, err := listDirBasenames(path)
			if err != nil {
				return err
			}
			details := []string{fmt.Sprintf("mirror %s into %s/%s/<timestamp>", path, backupParentDisplay(), opensslBackupDir)}
			for _, name := range names {
				details = append(details, fmt.Sprintf("include %s", name))
			}
			reportDryRun("backup", "openssl", path, details...)
			return nil
		}
		reportDryRun("backup", "openssl", path,
			fmt.Sprintf("copy %s into %s/%s/<timestamp>/%s", path, backupParentDisplay(), opensslBackupDir, opensslBackupFilename),
			"record the bundle path in source")
		return nil
	}

	parent, err := getCertManageDir(opensslBackupDir)
	if err != nil {
		return err
	}
	dir, err := mkdirExclusiveTimestamp(parent)
	if err != nil {
		return err
	}
	if st.IsDir() {
		if err := file.MirrorDir(path, dir); err != nil {
			_ = os.RemoveAll(dir)
			return fmt.Errorf("backup %s to %s: %w", path, dir, err)
		}
		return nil
	}
	dst := filepath.Join(dir, opensslBackupFilename)
	if err := file.CopyFile(path, dst); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("backup %s to %s: %w", path, dst, err)
	}
	if err := writeOpenSSLBackupSource(dir, path); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	return nil
}

func (s opensslStore) GetLatestBackup() (string, error) {
	// Explicit PEM files match only backups recorded for that file. Discovery
	// of a PEM also accepts legacy backups with no source and ignores backups
	// recorded for another bundle. Cert directories have no source sidecar, so
	// they keep newest-timestamp selection. If discovery cannot resolve a
	// path, only unknown-source backups match.
	dest := s.path
	allowUnknown := dest == ""
	if dest == "" {
		if p, err := s.certPath(); err == nil {
			dest = p
		}
	}
	if dest != "" {
		isDir, err := opensslPathIsDir(dest)
		if err != nil {
			return "", err
		}
		if isDir {
			dir, err := getLatestStoreBackup(opensslBackupDir)
			if err != nil {
				return "", fmt.Errorf("getLatestBackup: error getting openssl backup directory err=%w", err)
			}
			return dir, nil
		}
	}
	dir, err := latestOpenSSLFileBackupFor(dest, allowUnknown)
	if err != nil {
		return "", fmt.Errorf("getLatestBackup: error getting openssl backup directory err=%w", err)
	}
	return dir, nil
}

func (s opensslStore) GetInfo() *Info {
	info := &Info{Name: "OpenSSL"}
	if path, err := s.certPath(); err == nil {
		info.Path = path
	}
	out, err := exec.Command("openssl", "version").CombinedOutput()
	if err != nil {
		return info
	}

	// 'LibreSSL 2.2.7' or 'OpenSSL 1.0.2g  1 Mar 2016'
	parts := strings.Split(string(out), " ")
	info.Name = strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		info.Version = strings.TrimSpace(parts[1])
	}
	return info
}

func (s opensslStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	path, err := s.certPath()
	if err != nil {
		return nil, err
	}
	if !file.Exists(path) {
		return nil, fmt.Errorf("openssl store not found at %s", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return listOpenSSLDir(path)
	}
	certs, err := certutil.FromFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return certs, nil
}

func (s opensslStore) Remove(al allowlist.Allowlist) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("openssl store not found at %s; nothing to allowlist", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return s.removeFromDir(path, al)
	}
	return s.removeFromFile(path, al)
}

func (s opensslStore) removeFromFile(path string, al allowlist.Allowlist) error {
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
		reportDryRun("remove certificates from", "openssl", path, details...)
		return nil
	}
	return s.replaceBundle(path, kept)
}

func (s opensslStore) removeFromDir(dir string, al allowlist.Allowlist) error {
	files, err := opensslCertFiles(dir)
	if err != nil {
		return err
	}
	type item struct {
		path    string
		kept    certutil.PEMResult
		removed []*x509.Certificate
	}
	var plan []item
	var totalKept int
	var allRemoved []*x509.Certificate
	var keptRaw []certutil.PEMEntry
	for _, p := range files {
		parsed, err := certutil.FromFileResult(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		kept, removed := parsed.KeepMatching(al.Matches)
		plan = append(plan, item{path: p, kept: kept, removed: removed})
		totalKept += len(kept.Certs)
		allRemoved = append(allRemoved, removed...)
		keptRaw = append(keptRaw, kept.Entries...)
	}
	if totalKept == 0 {
		return fmt.Errorf("allowlist would leave %s empty; refusing to remove the last certificates. Adjust the allowlist or restore from backup", dir)
	}
	if DryRun() {
		details := reportDryRunCerts("remove", allRemoved)
		details = append(details, reportKeptRawPEM(keptRaw)...)
		if bin := findCRehash(); bin != "" {
			details = append(details, fmt.Sprintf("then run %s %s", bin, dir))
		}
		reportDryRun("remove certificates from", "openssl", dir, details...)
		return nil
	}

	// Stage the pruned tree, then swap. A mid-loop failure must not leave the
	// live directory half-pruned (same safety as restoreDir).
	tmp := dir + ".restore-tmp"
	aside := dir + ".restore-old"
	if _, err := os.Lstat(aside); err == nil {
		return fmt.Errorf("previous restore left %s; inspect it and remove it, then rerun", aside)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", aside, err)
	}
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := file.MirrorDir(dir, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	for _, it := range plan {
		if len(it.removed) == 0 {
			continue
		}
		rel, err := filepath.Rel(dir, it.path)
		if err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
		staged := filepath.Join(tmp, rel)
		if len(it.kept.Certs) == 0 && it.kept.Skipped == 0 {
			if err := os.Remove(staged); err != nil {
				_ = os.RemoveAll(tmp)
				return err
			}
			continue
		}
		if err := certutil.ToFileEntries(staged, it.kept.Entries); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
	}
	if err := renameAside(dir, aside); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := renameDir(tmp, dir); err != nil {
		_ = os.RemoveAll(tmp)
		if rerr := renameDir(aside, dir); rerr != nil {
			fmt.Fprintf(os.Stderr, "store/openssl: previous cert directory moved aside to %s\n", aside)
			return fmt.Errorf("%w (previous openssl cert dir still at %s)", err, aside)
		}
		return err
	}
	if err := s.rehash(dir, false); err != nil {
		failed := dir + ".restore-failed"
		_ = os.RemoveAll(failed)
		if rerr := renameDir(dir, failed); rerr != nil {
			fmt.Fprintf(os.Stderr, "store/openssl: previous cert directory moved aside to %s\n", aside)
			return fmt.Errorf("%w (previous openssl cert dir still at %s)", err, aside)
		}
		if rerr := renameDir(aside, dir); rerr != nil {
			_ = renameDir(failed, dir)
			fmt.Fprintf(os.Stderr, "store/openssl: previous cert directory moved aside to %s\n", aside)
			return fmt.Errorf("failed to restore previous openssl cert dir from %s: %w", aside, errors.Join(err, rerr))
		}
		_ = os.RemoveAll(failed)
		return err
	}
	if err := os.RemoveAll(aside); err != nil {
		fmt.Fprintf(os.Stderr, "store/openssl: warning: could not fully remove %s after allowlist: %v (remaining contents may be incomplete)\n", aside, err)
	}
	return nil
}

func (s opensslStore) Restore(where string) error {
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
			return errNoBackupCmd("openssl", opensslBackupDir, "trustprune backup -app openssl")
		}
	}

	liveIsDir, err := opensslPathIsDir(path)
	if err != nil {
		return err
	}
	if liveIsDir {
		return s.restoreDir(src, path)
	}
	return s.restoreFile(src, path)
}

func (s opensslStore) restoreFile(src, path string) error {
	srcFile, err := opensslBackupFile(src)
	if err != nil {
		return err
	}
	// Discovery and explicit PEM restores both refuse a backup recorded for a
	// different file unless -force. Source-less backups stay allowed.
	if err := checkOpenSSLBackupSource(src, path, true, ForceRestore()); err != nil {
		return err
	}
	certs, err := certutil.FromFile(srcFile)
	if err != nil {
		return fmt.Errorf("restore source %s is not a valid PEM bundle: %w; pass -file to a PEM backup", srcFile, err)
	}
	if len(certs) == 0 {
		return fmt.Errorf("restore source %s contains no certificates; refusing to overwrite %s", srcFile, path)
	}
	if DryRun() {
		reportDryRun("restore", "openssl", path,
			fmt.Sprintf("source %s", srcFile),
			fmt.Sprintf("stage into %s.restore-tmp then swap over %s", path, path))
		return nil
	}
	if err := sslInstallFile(srcFile, path); err != nil {
		return fmt.Errorf("restore %s from %s: %w; re-run with permission to write that path (often sudo)", path, srcFile, err)
	}
	return nil
}

func (s opensslStore) restoreDir(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("openssl backup %s: %w", src, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("openssl restore source %s is not a directory; the live store is a cert directory", src)
	}
	certFiles, err := opensslCertFiles(src)
	if err != nil {
		return err
	}
	if len(certFiles) == 0 {
		return fmt.Errorf("restore source %s contains no certificates; refusing to overwrite %s", src, dst)
	}
	if DryRun() {
		names, err := listDirBasenames(src)
		if err != nil {
			return err
		}
		details := restoreFileDetails(src, dst, names)
		if bin := findCRehash(); bin != "" {
			details = append(details, fmt.Sprintf("then run %s %s", bin, dst))
		}
		reportDryRun("restore", "openssl", dst, details...)
		return nil
	}

	tmp := dst + ".restore-tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := file.MirrorDir(src, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}

	aside := dst + ".restore-old"
	liveExists := file.Exists(dst)
	if liveExists {
		if _, err := os.Lstat(aside); err == nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("previous restore left %s; inspect it and remove it, then rerun", aside)
		} else if !errors.Is(err, os.ErrNotExist) {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("stat %s: %w", aside, err)
		}
		if err := renameAside(dst, aside); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
	}

	if err := renameDir(tmp, dst); err != nil {
		_ = os.RemoveAll(tmp)
		if liveExists {
			if rerr := renameDir(aside, dst); rerr != nil {
				fmt.Fprintf(os.Stderr, "store/openssl: previous cert directory moved aside to %s\n", aside)
				return fmt.Errorf("%w (previous openssl cert dir still at %s)", err, aside)
			}
		}
		return err
	}

	if err := s.rehash(dst, false); err != nil {
		if liveExists {
			failed := dst + ".restore-failed"
			_ = os.RemoveAll(failed)
			if rerr := renameDir(dst, failed); rerr != nil {
				fmt.Fprintf(os.Stderr, "store/openssl: previous cert directory moved aside to %s\n", aside)
				return fmt.Errorf("%w (previous openssl cert dir still at %s)", err, aside)
			}
			if rerr := renameDir(aside, dst); rerr != nil {
				_ = renameDir(failed, dst)
				fmt.Fprintf(os.Stderr, "store/openssl: previous cert directory moved aside to %s\n", aside)
				return fmt.Errorf("failed to restore previous openssl cert dir from %s: %w", aside, errors.Join(err, rerr))
			}
			_ = os.RemoveAll(failed)
		}
		return err
	}

	if liveExists {
		if err := os.RemoveAll(aside); err != nil {
			fmt.Fprintf(os.Stderr, "store/openssl: warning: could not fully remove %s after restore: %v (remaining contents may be incomplete)\n", aside, err)
		}
	}
	return nil
}

// replaceBundle writes bundle entries to a staging PEM then installs via
// sslInstallFile (sibling temp dir + rename swap).
func (s opensslStore) replaceBundle(path string, bundle certutil.PEMResult) error {
	if len(bundle.Certs) == 0 {
		return fmt.Errorf("refusing to write an empty bundle to %s", path)
	}
	tmp, err := os.CreateTemp("", "trustprune-openssl-*.pem")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpName) }()

	if err := certutil.ToFileEntries(tmpName, bundle.Entries); err != nil {
		return fmt.Errorf("stage openssl bundle: %w", err)
	}
	if err := sslInstallFile(tmpName, path); err != nil {
		return fmt.Errorf("write %s: %w; re-run with permission to write that path (often sudo)", path, err)
	}
	return nil
}

// opensslCanonicalPath returns an absolute, cleaned path, following symlinks
// when they resolve so backup source matches the file that would be written.
func opensslCanonicalPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	p = filepath.Clean(p)
	return resolveOpenSSLCertPath(p)
}

func sameOpenSSLPath(recorded, dest string) bool {
	return opensslCanonicalPath(recorded) == opensslCanonicalPath(dest)
}

func opensslBackupSourceFile(src string) string {
	st, err := os.Stat(src)
	if err == nil && st.IsDir() {
		return filepath.Join(src, opensslBackupSourceName)
	}
	if filepath.Base(src) == opensslBackupFilename {
		return filepath.Join(filepath.Dir(src), opensslBackupSourceName)
	}
	return src + "." + opensslBackupSourceName
}

func writeOpenSSLBackupSource(dir, storePath string) error {
	path := filepath.Join(dir, opensslBackupSourceName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(opensslCanonicalPath(storePath) + "\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func readOpenSSLBackupSource(src string) (string, error) {
	b, err := os.ReadFile(opensslBackupSourceFile(src))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// checkOpenSSLBackupSource refuses a restore whose backup was taken from a
// different PEM than dest. Backups without a recorded source are allowed only
// when allowUnknown is set. force skips a path mismatch.
func checkOpenSSLBackupSource(backup, dst string, allowUnknown, force bool) error {
	recorded, err := readOpenSSLBackupSource(backup)
	if err != nil {
		return fmt.Errorf("reading source of openssl backup %s: %w", backup, err)
	}
	if recorded == "" {
		if allowUnknown || force {
			return nil
		}
		return fmt.Errorf("openssl backup %s has no recorded store path; pass it with restore -backup to use it", backup)
	}
	if sameOpenSSLPath(recorded, dst) {
		return nil
	}
	if force {
		return nil
	}
	return fmt.Errorf("refusing restore: openssl backup %s was taken from %s, not %s; pass -force to restore into a different path", backup, recorded, opensslCanonicalPath(dst))
}

// latestOpenSSLFileBackupFor returns the newest openssl backup directory
// recorded for storePath. Backups without a recorded source are considered
// only when allowUnknown is true. Empty storePath only matches unknown-source
// backups.
func latestOpenSSLFileBackupFor(storePath string, allowUnknown bool) (string, error) {
	uhome := file.HomeDir()
	if uhome == "" {
		return "", fmt.Errorf("home directory is unavailable")
	}
	dirs := []string{filepath.Join(primaryBackupParent(uhome), opensslBackupDir)}
	if lp := legacyBackupParent(uhome); lp != "" {
		dirs = append(dirs, filepath.Join(lp, opensslBackupDir))
	}

	best, bestTS := "", int64(-1)
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		for _, ent := range ents {
			if !ent.IsDir() {
				continue
			}
			ts, ok := backupBasenameUnix(ent.Name())
			if !ok {
				continue
			}
			if ts < bestTS {
				continue
			}
			path := filepath.Join(d, ent.Name())
			if !file.Exists(filepath.Join(path, opensslBackupFilename)) {
				continue
			}
			recorded, err := readOpenSSLBackupSource(path)
			if err != nil {
				return "", err
			}
			match := false
			switch {
			case recorded != "" && storePath != "" && sameOpenSSLPath(recorded, storePath):
				match = true
			case recorded == "" && allowUnknown:
				match = true
			}
			if !match {
				continue
			}
			if ts == bestTS && best != "" {
				continue
			}
			best, bestTS = path, ts
		}
	}
	return best, nil
}

func opensslBackupFile(src string) (string, error) {
	st, err := os.Stat(src)
	if err != nil {
		return "", fmt.Errorf("openssl backup %s: %w", src, err)
	}
	if st.IsDir() {
		candidate := filepath.Join(src, opensslBackupFilename)
		if !file.Exists(candidate) {
			return "", fmt.Errorf("openssl backup dir %s has no %s; pass -file to a PEM backup", src, opensslBackupFilename)
		}
		return candidate, nil
	}
	return src, nil
}

func opensslPathIsDir(path string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return st.IsDir(), nil
}

func listOpenSSLDir(dir string) ([]*x509.Certificate, error) {
	files, err := opensslCertFiles(dir)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, p := range files {
		got, err := certutil.FromFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		certs = append(certs, got...)
	}
	return certs, nil
}

func opensslCertFiles(dir string) ([]string, error) {
	var out []string
	seen := map[string]struct{}{}
	for _, pattern := range []string{"*.pem", "*.crt"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			st, err := os.Lstat(m)
			if err != nil {
				continue
			}
			if st.IsDir() {
				continue
			}
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}
	file.SortNames(out)
	return out, nil
}

// findCertPath returns the first existing OpenSSL CA location.
//
// Order: explicit store path, SSL_CERT_FILE, CURL_CA_BUNDLE, openSSLCertPaths,
// then git http.sslCAInfo. Darwin /etc/ssl/cert.pem is never chosen as a
// default (that file is -app ssl); an explicit SSL_CERT_FILE / CURL_CA_BUNDLE
// still wins if the user set it.
func (s opensslStore) findCertPath() (string, error) {
	if s.path != "" {
		if file.Exists(s.path) {
			return s.path, nil
		}
		return "", fmt.Errorf("openssl store path %s not found", s.path)
	}

	for _, raw := range []string{os.Getenv("SSL_CERT_FILE"), os.Getenv("CURL_CA_BUNDLE")} {
		p := strings.TrimSpace(raw)
		if p != "" && file.Exists(p) {
			return p, nil
		}
	}
	for i := range openSSLCertPaths {
		p := openSSLCertPaths[i]
		if skipOpenSSLDefault(p) {
			continue
		}
		if file.Exists(p) {
			return p, nil
		}
	}
	if p := gitHTTPSSLCAInfo(); p != "" && !skipOpenSSLDefault(p) && file.Exists(p) {
		return p, nil
	}
	return "", errors.New("unable to find openssl cert directory")
}

func skipOpenSSLDefault(path string) bool {
	if path == "" {
		return true
	}
	return filepath.Clean(path) == filepath.Clean(defaultDarwinSSLCertPEM)
}

func lookupGitHTTPSSLCAInfo() string {
	out, err := exec.Command("git", "config", "--get", "--path", "http.sslCAInfo").Output()
	if err != nil {
		out, err = exec.Command("git", "config", "--get", "http.sslCAInfo").Output()
		if err != nil {
			return ""
		}
	}
	return strings.TrimSpace(string(out))
}

func findCRehash() string {
	for i := range openSSLRehashPaths {
		if file.Exists(openSSLRehashPaths[i]) {
			return openSSLRehashPaths[i]
		}
	}
	if p, err := exec.LookPath("c_rehash"); err == nil {
		return p
	}
	return ""
}

func (s opensslStore) rehash(dir string, required bool) error {
	bin := findCRehash()
	if bin == "" {
		if required {
			return errors.New("unable to find openssl c_rehash binary")
		}
		return nil
	}

	cmd := exec.Command(bin, dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if debug {
			fmt.Printf("store/openssl: Command was: %s\n", strings.Join(cmd.Args, " "))
			fmt.Printf("store/openssl: Output: %q\n", string(out))
		}
		return err
	}
	return nil
}

// mkdirExclusiveTimestamp creates parent/<unix> with exclusive Mkdir, bumping
// the unix-second on collision so two backups in the same second never share a
// directory.
func mkdirExclusiveTimestamp(parent string) (string, error) {
	for ts := time.Now().Unix(); ; ts++ {
		candidate := filepath.Join(parent, fmt.Sprintf("%d", ts))
		err := os.Mkdir(candidate, os.ModeDir|backupDirPerms)
		if err == nil {
			return candidate, nil
		}
		if os.IsExist(err) {
			continue
		}
		return "", fmt.Errorf("create backup dir %s: %w", candidate, err)
	}
}
