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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

const (
	// defaultDarwinSSLCertPEM is the system OpenSSL/LibreSSL trust bundle that
	// curl, git, python3, and other CLI tools read on macOS. Apple's keychain
	// blocks do not apply to this file (see Apple support HT149555 / eMudhra).
	defaultDarwinSSLCertPEM = "/etc/ssl/cert.pem"

	sslBackupDir       = "ssl"
	sslStateDirName    = "ssl-state"
	sslBackupFilename  = "cert.pem"
	sslLastAppliedName = "last-applied.sha256"
)

// sslStore manages a PEM certificate bundle file (Darwin /etc/ssl/cert.pem by
// default). The path field is overridable for tests so real system CAs are
// never touched.
type sslStore struct {
	path string
}

// SSLStore returns the Darwin /etc/ssl/cert.pem store. On non-Darwin platforms
// the store reports itself unavailable; use sslStoreAt in tests to inject a
// temporary PEM path on any OS.
func SSLStore() Store {
	if runtime.GOOS != "darwin" {
		return sslStore{}
	}
	return sslStore{path: defaultDarwinSSLCertPEM}
}

// sslStoreAt returns an sslStore pointed at path. Intended for tests.
func sslStoreAt(path string) sslStore {
	return sslStore{path: path}
}

func (s sslStore) certPath() (string, error) {
	if s.path == "" {
		return "", errors.New("ssl store is only available on Darwin; use -app ssl on macOS where /etc/ssl/cert.pem exists")
	}
	return s.path, nil
}

func (s sslStore) GetInfo() *Info {
	info := &Info{Name: "ssl"}
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

func (s sslStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	path, err := s.certPath()
	if err != nil {
		return nil, err
	}
	if !file.Exists(path) {
		return nil, fmt.Errorf("ssl bundle not found at %s; expected Darwin /etc/ssl/cert.pem", path)
	}
	certs, err := certutil.FromFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	s.warnIfDrifted(os.Stderr)
	return certs, nil
}

func (s sslStore) Add(certs []*x509.Certificate) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("ssl bundle not found at %s; create or restore it before adding certificates", path)
	}
	existing, err := certutil.FromFileResult(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if DryRun() {
		details := reportDryRunCerts("add", certs)
		details = append(details, reportKeptRawPEM(existing.Entries)...)
		reportDryRun("add certificates to", "ssl", path, details...)
		return nil
	}
	return s.replaceBundle(existing.AppendCerts(certs))
}

func (s sslStore) Backup() error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("ssl bundle not found at %s; nothing to back up", path)
	}
	if DryRun() {
		reportDryRun("backup", "ssl", path,
			fmt.Sprintf("copy %s into %s/%s/<timestamp>/%s", path, backupParentDisplay(), sslBackupDir, sslBackupFilename))
		return nil
	}
	s.warnIfDrifted(os.Stderr)
	parent, err := getCertManageDir(sslBackupDir)
	if err != nil {
		return err
	}
	// Exclusive Mkdir so two backups in the same second never share a dir
	// (CopyFile would truncate the earlier cert.pem). Keep unix-second names
	// so latest-backup comparison stays compatible with other stores.
	var dir string
	for ts := time.Now().Unix(); ; ts++ {
		candidate := filepath.Join(parent, fmt.Sprintf("%d", ts))
		err := os.Mkdir(candidate, os.ModeDir|backupDirPerms)
		if err == nil {
			dir = candidate
			break
		}
		if os.IsExist(err) {
			continue
		}
		return fmt.Errorf("create ssl backup dir %s: %w", candidate, err)
	}
	dst := filepath.Join(dir, sslBackupFilename)
	if err := file.CopyFile(path, dst); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("backup %s to %s: %w", path, dst, err)
	}
	return nil
}

func (s sslStore) GetLatestBackup() (string, error) {
	dir, err := getLatestStoreBackup(sslBackupDir)
	if err != nil {
		return "", fmt.Errorf("getLatestBackup: error getting ssl backup directory err=%w", err)
	}
	return dir, nil
}

func (s sslStore) Remove(al allowlist.Allowlist) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("ssl bundle not found at %s; nothing to allowlist", path)
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
		reportDryRun("remove certificates from", "ssl", path, details...)
		return nil
	}
	return s.replaceBundle(kept)
}

func (s sslStore) Restore(where string) error {
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
			return fmt.Errorf("no ssl backup found under %s/%s; run: trustprune backup -app ssl", backupParentDisplay(), sslBackupDir)
		}
	}
	srcFile, err := sslBackupFile(src)
	if err != nil {
		return err
	}
	certs, err := certutil.FromFile(srcFile)
	if err != nil {
		return fmt.Errorf("restore source %s is not a valid PEM bundle: %w; pass -file to a cert.pem backup", srcFile, err)
	}
	if len(certs) == 0 {
		return fmt.Errorf("restore source %s contains no certificates; refusing to overwrite %s", srcFile, path)
	}
	if DryRun() {
		reportDryRun("restore", "ssl", path,
			fmt.Sprintf("source %s", srcFile),
			fmt.Sprintf("stage into %s.restore-tmp then swap over %s", path, path))
		return nil
	}
	if err := sslInstallFile(srcFile, path); err != nil {
		return fmt.Errorf("restore %s from %s: %w; re-run with permission to write that path (often sudo)", path, srcFile, err)
	}
	return s.recordLastAppliedFromFile(srcFile)
}

// replaceBundle writes bundle entries (parseable certs plus preserved
// unparsable PEM blocks) to a staging PEM then installs via a sibling temp
// directory + rename swap. The live file is left untouched until the swap
// succeeds.
func (s sslStore) replaceBundle(bundle certutil.PEMResult) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if len(bundle.Certs) == 0 {
		return fmt.Errorf("refusing to write an empty bundle to %s", path)
	}
	tmp, err := os.CreateTemp("", "trustprune-ssl-*.pem")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpName) }()

	if err := certutil.ToFileEntries(tmpName, bundle.Entries); err != nil {
		return fmt.Errorf("stage ssl bundle: %w", err)
	}
	if err := sslInstallFile(tmpName, path); err != nil {
		return fmt.Errorf("write %s: %w; re-run with permission to write that path (often sudo)", path, err)
	}
	return s.recordLastAppliedFromFile(tmpName)
}

func sslBackupFile(src string) (string, error) {
	st, err := os.Stat(src)
	if err != nil {
		return "", fmt.Errorf("ssl backup %s: %w", src, err)
	}
	if st.IsDir() {
		candidate := filepath.Join(src, sslBackupFilename)
		if !file.Exists(candidate) {
			return "", fmt.Errorf("ssl backup dir %s has no %s; pass -file to a PEM backup", src, sslBackupFilename)
		}
		return candidate, nil
	}
	return src, nil
}

func (s sslStore) lastAppliedPath() (string, error) {
	uhome := file.HomeDir()
	if uhome == "" {
		return "", errors.New("home directory is unavailable")
	}
	parent := primaryBackupParent(uhome)
	if parent == "" {
		return "", fmt.Errorf("unsupported platform for ssl state: %s", runtime.GOOS)
	}
	return filepath.Join(parent, sslStateDirName, sslLastAppliedName), nil
}

func (s sslStore) recordLastAppliedFromFile(path string) error {
	sum, err := fileSHA256Sum(path)
	if err != nil {
		return err
	}
	dest, err := s.lastAppliedPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), backupDirPerms); err != nil {
		return err
	}
	return os.WriteFile(dest, []byte(sum+"\n"), 0600)
}

func (s sslStore) readLastApplied() (string, error) {
	dest, err := s.lastAppliedPath()
	if err != nil {
		return "", err
	}
	bs, err := os.ReadFile(dest)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bs)), nil
}

// warnIfDrifted prints a one-line hint when the live bundle no longer matches
// the last content trustprune wrote (typical after a macOS update restores
// Apple's cert.pem).
func (s sslStore) warnIfDrifted(w io.Writer) {
	if w == nil {
		return
	}
	path, err := s.certPath()
	if err != nil || !file.Exists(path) {
		return
	}
	want, err := s.readLastApplied()
	if err != nil || want == "" {
		return
	}
	got, err := fileSHA256Sum(path)
	if err != nil || got == want {
		return
	}
	fmt.Fprintf(w, "ssl: %s differs from the last trustprune write (SHA256 %s -> %s); a macOS update may have restored Apple's copy. Re-apply: trustprune backup -app ssl && trustprune allowlist -app ssl -file <allowlist>, or trustprune restore -app ssl\n",
		path, shortSHA(want), shortSHA(got))
}

// sslRename is os.Rename; tests swap it to force a mid-swap failure.
var sslRename = os.Rename

// sslRemove is os.Remove; tests swap it to simulate aside cleanup failures.
var sslRemove = os.Remove

// sslInstallFile replaces dst with the contents of src by staging into a
// sibling temp directory (dst.restore-tmp), copying the live file to
// dst.restore-old, then renaming the staged file over dst so the live path is
// never missing. A failed stage leaves the live file untouched. If the parent
// directory is not writable, staging and swap run under elevated privileges.
func sslInstallFile(src, dst string) error {
	tmpDir := dst + ".restore-tmp"
	aside := dst + ".restore-old"
	staged := filepath.Join(tmpDir, filepath.Base(dst))

	if _, err := os.Lstat(aside); err == nil {
		return fmt.Errorf("previous restore left %s; inspect it and remove it, then rerun", aside)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", aside, err)
	}

	// Permission failures (e.g. a root-owned leftover staging dir) fall through
	// to the privileged installer, which clears and recreates the staging path.
	if err := os.RemoveAll(tmpDir); err != nil {
		return sslSudoInstallAtomic(src, dst)
	}
	if err := os.Mkdir(tmpDir, backupDirPerms); err != nil {
		return sslSudoInstallAtomic(src, dst)
	}
	if err := file.CopyFile(src, staged); err != nil {
		_ = os.RemoveAll(tmpDir)
		return err
	}
	if err := sslChmodInstalled(staged, dst); err != nil {
		_ = os.RemoveAll(tmpDir)
		return err
	}

	liveExists := file.Exists(dst)
	if liveExists {
		// Copy into the staging dir first, then rename to .restore-old so a
		// failed copy never leaves the guarded aside path behind.
		asideStaged := filepath.Join(tmpDir, filepath.Base(dst)+".aside")
		if err := file.CopyFile(dst, asideStaged); err != nil {
			_ = os.RemoveAll(tmpDir)
			return sslSudoInstallAtomic(src, dst)
		}
		if err := sslRename(asideStaged, aside); err != nil {
			_ = os.RemoveAll(tmpDir)
			return sslSudoInstallAtomic(src, dst)
		}
	}
	if err := sslRename(staged, dst); err != nil {
		if liveExists && !file.Exists(dst) {
			// Live path vanished somehow; put the copy back.
			if rerr := file.CopyFile(aside, dst); rerr != nil {
				_ = os.RemoveAll(tmpDir)
				return fmt.Errorf("install %s failed and could not restore previous file from %s: %w", dst, aside, errors.Join(err, rerr))
			}
		}
		_ = os.RemoveAll(tmpDir)
		if liveExists {
			_ = os.Remove(aside)
			// Parent was writable enough to stage and copy; do not escalate to
			// sudo after rolling back — that would risk rewriting the live file.
			return fmt.Errorf("install %s: %w", dst, err)
		}
		return sslSudoInstallAtomic(src, dst)
	}
	if err := os.RemoveAll(tmpDir); err != nil {
		fmt.Fprintf(os.Stderr, "store/ssl: warning: could not remove %s after restore: %v\n", tmpDir, err)
	}
	if liveExists {
		if err := sslRemove(aside); err != nil {
			fmt.Fprintf(os.Stderr, "store/ssl: warning: could not remove %s after restore: %v\n", aside, err)
		}
	}
	return nil
}

func sslChmodInstalled(tmpName, dst string) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(dst); err == nil {
		mode = st.Mode().Perm()
	}
	return os.Chmod(tmpName, mode)
}

func sslSudoInstallAtomic(src, dst string) error {
	// Stage into a sibling temp directory, copy live aside, then rename over dst.
	script := `set -e
src=$1
dst=$2
tmpDir="${dst}.restore-tmp"
aside="${dst}.restore-old"
if [ -e "$aside" ] || [ -L "$aside" ]; then
  echo "previous restore left $aside; inspect it and remove it, then rerun" >&2
  exit 1
fi
rm -rf "$tmpDir"
mkdir "$tmpDir"
staged="$tmpDir/$(basename "$dst")"
cp "$src" "$staged"
mode=644
if [ -e "$dst" ]; then
  mode=$(stat -f %OLp "$dst" 2>/dev/null || stat -c %a "$dst" 2>/dev/null || echo 644)
fi
chmod "$mode" "$staged"
if [ -e "$dst" ]; then
  asideStaged="$tmpDir/$(basename "$dst").aside"
  if ! cp "$dst" "$asideStaged"; then
    rm -rf "$tmpDir"
    exit 1
  fi
  if ! mv "$asideStaged" "$aside"; then
    rm -rf "$tmpDir"
    exit 1
  fi
fi
if ! mv "$staged" "$dst"; then
  if [ ! -e "$dst" ] && [ -e "$aside" ]; then
    if ! cp "$aside" "$dst"; then
      echo "could not restore $dst; previous file kept at $aside" >&2
      rm -rf "$tmpDir" || true
      exit 1
    fi
  fi
  if ! rm -rf "$tmpDir"; then
    echo "store/ssl: warning: could not remove $tmpDir after failed restore" >&2
  fi
  if ! rm -f "$aside"; then
    echo "store/ssl: warning: could not remove $aside after failed restore" >&2
  fi
  exit 1
fi
if ! rm -rf "$tmpDir"; then
  echo "store/ssl: warning: could not remove $tmpDir after restore" >&2
fi
if [ -e "$aside" ] || [ -L "$aside" ]; then
  if ! rm -f "$aside"; then
    echo "store/ssl: warning: could not remove $aside after restore" >&2
  fi
fi
`
	var cmd *exec.Cmd
	if os.Getuid() == 0 {
		cmd = exec.Command("sh", "-c", script, "ssl-install", src, dst)
	} else {
		cmd = exec.Command("sudo", "sh", "-c", script, "ssl-install", src, dst)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("atomic install %s -> %s: %w (%s)", src, dst, err, msg)
		}
		return fmt.Errorf("atomic install %s -> %s: %w", src, dst, err)
	}
	if msg := strings.TrimSpace(string(out)); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}
	return nil
}

func fileSHA256Sum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func shortSHA(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12]
}

// drifted reports whether the live bundle differs from last-applied. Exported
// for tests via the sslStore method on the concrete type.
func (s sslStore) drifted() (bool, error) {
	path, err := s.certPath()
	if err != nil {
		return false, err
	}
	want, err := s.readLastApplied()
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if want == "" {
		return false, nil
	}
	got, err := fileSHA256Sum(path)
	if err != nil {
		return false, err
	}
	return got != want, nil
}
