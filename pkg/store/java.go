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
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

const (
	keystoreTamperedMessage = "Keystore was tampered with, or password was incorrect"
)

const javaStorePassEnv = "TRUSTPRUNE_JAVA_STOREPASS"

var (
	defaultKeystorePassword = "changeit"
	javaCertManageDir       = "java"

	// keytoolTimeout bounds every keytool process so a password prompt or a
	// hung child cannot block forever. Tests override this to a short duration.
	keytoolTimeout = 30 * time.Second

	// keytoolWaitDelay bounds how long Run waits for I/O after the process is
	// canceled. Needed when a child (keytool under sudo) keeps stdout open.
	keytoolWaitDelay = 2 * time.Second

	// keytoolSudoPath is the sudo binary used when runKeytool is asked to
	// escalate. Tests replace it with a wrapper; never a reason to call real
	// sudo from unit tests.
	keytoolSudoPath = "sudo"

	// findTimeoutBin locates coreutils `timeout` so a sudo-wrapped keytool can
	// be killed as root. Tests override this.
	findTimeoutBin = defaultFindTimeoutBin
)

// keystorePassword is the effective keystore password for keytool calls.
// When TRUSTPRUNE_JAVA_STOREPASS is set (non-empty after trim), that value is
// used; otherwise the Java default "changeit". No other passwords are guessed.
// Custom passwords are never placed on keytool/sudo argv; see prepareStorepass.
func keystorePassword() string {
	if v := strings.TrimSpace(os.Getenv(javaStorePassEnv)); v != "" {
		return v
	}
	return defaultKeystorePassword
}

// prepareStorepass returns keytool argv fragments and optional child env
// overrides for the store password. The default "changeit" stays as
// "-storepass changeit". A custom password uses "-storepass:env
// TRUSTPRUNE_JAVA_STOREPASS" with the trimmed value supplied in the child
// environment (and sudo --preserve-env) so the secret never appears in
// process or sudo argv. Prefer :env over :file because keytool's :file
// reader only takes the first line. Requires keytool -storepass:env (JDK 6+).
func prepareStorepass() (flags []string, env []string, err error) {
	pass := keystorePassword()
	if pass == defaultKeystorePassword {
		return []string{"-storepass", defaultKeystorePassword}, nil, nil
	}
	return []string{"-storepass:env", javaStorePassEnv},
		[]string{javaStorePassEnv + "=" + pass}, nil
}

// redactKeytoolArgs replaces -storepass values so debug logs never print secrets.
// -storepass:env's next arg is only the env var name (not secret).
func redactKeytoolArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == "-storepass" {
			out[i+1] = "***"
		}
	}
	return out
}

// environWithOverrides returns base (or os.Environ) with override keys replaced.
func environWithOverrides(base []string, overrides []string) []string {
	if len(overrides) == 0 {
		return base
	}
	if base == nil {
		base = os.Environ()
	}
	drop := make(map[string]struct{}, len(overrides))
	for _, o := range overrides {
		if i := strings.IndexByte(o, '='); i > 0 {
			drop[o[:i]] = struct{}{}
		}
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, e := range base {
		if i := strings.IndexByte(e, '='); i > 0 {
			if _, ok := drop[e[:i]]; ok {
				continue
			}
		}
		out = append(out, e)
	}
	return append(out, overrides...)
}

type javaStore struct {
	// keystoreOverride, when set, is the cacerts (or other) keystore file to
	// use instead of searching JAVA_HOME / platform install paths. CLI -file
	// with -app java sets this for list/backup/connect/restore.
	keystoreOverride string
}

// JavaStore returns an implementation of Store for Java certificate stores
//
// Docs:
// - https://docs.oracle.com/cd/E19830-01/819-4712/ablqw/index.html
// - https://www.sslshopper.com/article-most-common-java-keytool-keystore-commands.html
func JavaStore() Store {
	return javaStore{}
}

// JavaStoreAt returns a Java store that always uses the given keystore file
// path instead of searching JAVA_HOME. path must be an existing non-empty file.
func JavaStoreAt(path string) Store {
	return javaStore{keystoreOverride: path}
}

func (s javaStore) tool() keytool {
	k := ktool
	k.explicitKeystore = s.keystoreOverride
	return k
}

func (s javaStore) keystorePath() (string, error) {
	return s.tool().getKeystorePath()
}

func validateJavaKeystoreFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("store/java: keystore %s: %w", path, err)
	}
	if st.IsDir() {
		return "", fmt.Errorf("store/java: keystore path %s is a directory, need the cacerts file", path)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("store/java: keystore path %s is not a regular file", path)
	}
	if st.Size() == 0 {
		return "", fmt.Errorf("store/java: keystore %s is empty", path)
	}
	return path, nil
}

func (s javaStore) Add(certs []*x509.Certificate) error {
	if DryRun() {
		kpath, err := s.keystorePath()
		if err != nil {
			return err
		}
		details := reportDryRunCerts("add", certs)
		reportDryRun("add certificates to", "java", kpath, details...)
		return nil
	}

	dir, err := os.MkdirTemp("", "cert-manage-java-add")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	for i := range certs {
		// Write each cert to its own file and then add it
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		path := filepath.Join(dir, fmt.Sprintf("%s.pem", fp))
		err := certutil.ToFile(path, certs[i:i+1])
		if err != nil {
			return err
		}

		// this replace is too simplistic
		alias := strings.ReplaceAll(certutil.StringifyPKIXName(certs[i].Subject), " ", "_")
		err = s.tool().addCertificate(path, alias)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s javaStore) Backup() error {
	kpath, err := s.keystorePath()
	if err != nil {
		return err
	}
	if DryRun() {
		_, filename := filepath.Split(kpath)
		reportDryRun("backup", "java", kpath,
			fmt.Sprintf("copy %s to %s/%s/%s-<timestamp>.bck", kpath, backupParentDisplay(), javaCertManageDir, filename))
		return nil
	}
	dir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		return err
	}

	_, filename := filepath.Split(kpath)
	// The backup is published together with a record of which keystore it
	// came from, so restore never copies it over a different keystore
	// (-file backups share the java/ directory).
	_, err = createJavaBackupFile(dir, filename, time.Now().Unix(), kpath)
	return err
}

// javaBackupBeforePublish is a test hook run after the temp copy and .source
// record are durable but before the final .bck name is published.
var javaBackupBeforePublish = func() error { return nil }

// createJavaBackupFile copies src into a new, never-overwritten backup in dir
// and records src as its source keystore.
//
// The copy is written and fsynced under a temp name that listing ignores
// ("."+filename+"-*.partial"), then the .source record is written (O_EXCL) and
// fsynced, and only then is the copy published with os.Link to the final
// ".bck" name (fails if it exists). An interrupted run therefore never leaves
// a .bck without its record, or a partial .bck.
//
// The name is "<filename>-<unix>.bck"; on collision a counter goes before the
// timestamp ("<filename>.<n>-<unix>.bck") so the timestamp still parses.
func createJavaBackupFile(dir, filename string, unix int64, src string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	st, err := in.Stat()
	if err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp(dir, "."+filename+"-*.partial")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // the published .bck is a hard link
	_, err = io.Copy(tmp, in)
	if err == nil {
		err = tmp.Chmod(st.Mode().Perm())
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if tst, err := os.Stat(tmpName); err != nil {
		return "", err
	} else if tst.Size() != st.Size() {
		return "", fmt.Errorf("store/java: short backup copy of %s (%d of %d bytes)", src, tst.Size(), st.Size())
	}

	for n := 0; n < 1000; n++ {
		name := fmt.Sprintf("%s-%d.bck", filename, unix)
		if n > 0 {
			name = fmt.Sprintf("%s.%d-%d.bck", filename, n, unix)
		}
		dst := filepath.Join(dir, name)
		if _, err := os.Lstat(dst); err == nil {
			continue
		}
		if err := writeJavaBackupSource(dst, src); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", err
		}
		// Make .source durable before the .bck name can appear.
		if err := syncDir(dir); err != nil {
			_ = os.Remove(dst + javaBackupSourceSuffix)
			return "", err
		}
		if err := javaBackupBeforePublish(); err != nil {
			_ = os.Remove(dst + javaBackupSourceSuffix)
			return "", err
		}
		if err := os.Link(tmpName, dst); err != nil {
			_ = os.Remove(dst + javaBackupSourceSuffix)
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", err
		}
		if err := syncDir(dir); err != nil {
			return "", err
		}
		return dst, nil
	}
	return "", fmt.Errorf("store/java: could not pick a unique backup name for %s in %s", filename, dir)
}

// syncDir fsyncs a directory so new entries are durable. Windows can't
// fsync directories, so it's a no-op there.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

// javaBackupCounter returns the collision counter in a backup name
// ("<file>.<n>-<unix>.bck"), or 0 when there is none.
func javaBackupCounter(name, unixPart string) int {
	base := strings.TrimSuffix(strings.TrimSuffix(name, ".bck"), "-"+unixPart)
	i := strings.LastIndexByte(base, '.')
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(base[i+1:])
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// javaBackupSourceSuffix names the sidecar holding a backup's source keystore.
// It does not end in .bck, so latest-backup selection skips it.
const javaBackupSourceSuffix = ".source"

// javaCanonicalPath returns the absolute, cleaned keystore path. Symlinks are
// not resolved here: some distros ship cacerts as a symlink that a later
// write replaces with a regular file, which would change the resolved path.
func javaCanonicalPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return filepath.Clean(p)
}

// sameJavaKeystore reports whether a recorded source path names keystore,
// either literally or after resolving symlinks on both sides.
func sameJavaKeystore(recorded, keystore string) bool {
	k := javaCanonicalPath(keystore)
	if recorded == k {
		return true
	}
	r1, err1 := filepath.EvalSymlinks(recorded)
	r2, err2 := filepath.EvalSymlinks(k)
	return err1 == nil && err2 == nil && r1 == r2
}

func writeJavaBackupSource(backup, keystore string) error {
	f, err := os.OpenFile(backup+javaBackupSourceSuffix, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(javaCanonicalPath(keystore) + "\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(backup + javaBackupSourceSuffix)
	}
	return err
}

// readJavaBackupSource returns the recorded source keystore, or "" when the
// backup predates source recording.
func readJavaBackupSource(backup string) (string, error) {
	b, err := os.ReadFile(backup + javaBackupSourceSuffix)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// checkJavaBackupSource refuses a restore whose backup was taken from a
// different keystore than dst. Backups without a recorded source are allowed
// only when allowUnknown is set. force skips a path mismatch.
func checkJavaBackupSource(backup, dst string, allowUnknown, force bool) error {
	recorded, err := readJavaBackupSource(backup)
	if err != nil {
		return fmt.Errorf("store/java: reading source of backup %s: %w", backup, err)
	}
	if recorded == "" {
		if allowUnknown {
			return nil
		}
		if force {
			return nil
		}
		return fmt.Errorf("store/java: backup %s has no recorded source keystore; pass it with restore -backup to use it", backup)
	}
	if sameJavaKeystore(recorded, dst) {
		return nil
	}
	if force {
		return nil
	}
	return fmt.Errorf("store/java: refusing restore: backup %s was taken from %s, not %s; pass -force to restore into a different path", backup, recorded, dst)
}

func (s javaStore) GetLatestBackup() (string, error) {
	dst, err := s.keystorePath()
	if err != nil {
		return "", err
	}
	return latestJavaBackupFor(dst, s.keystoreOverride == "")
}

// latestJavaBackupFor returns the newest java backup recorded for keystore.
// Backups without a recorded source (older releases only backed up the
// discovered keystore) are considered only when allowUnknown is true.
func latestJavaBackupFor(keystore string, allowUnknown bool) (string, error) {
	uhome := file.HomeDir()
	if uhome == "" {
		return "", fmt.Errorf("home directory is unavailable")
	}
	dirs := []string{filepath.Join(primaryBackupParent(uhome), javaCertManageDir)}
	if lp := legacyBackupParent(uhome); lp != "" {
		dirs = append(dirs, filepath.Join(lp, javaCertManageDir))
	}
	best, bestTS, bestN := "", int64(-1), -1
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", fmt.Errorf("getLatestBackup: error reading java backup directory, err=%w", err)
		}
		for _, ent := range ents {
			// Only regular .bck files are backups; skip .bck.source sidecars,
			// .partial temp copies, and anything else.
			if !ent.Type().IsRegular() || !strings.HasSuffix(ent.Name(), ".bck") {
				continue
			}
			ts, ok := backupBasenameUnix(ent.Name())
			if !ok {
				continue
			}
			n := javaBackupCounter(ent.Name(), strconv.FormatInt(ts, 10))
			if ts < bestTS || (ts == bestTS && n <= bestN) {
				continue
			}
			path := filepath.Join(d, ent.Name())
			recorded, err := readJavaBackupSource(path)
			if err != nil {
				return "", err
			}
			if (recorded != "" && sameJavaKeystore(recorded, keystore)) || (recorded == "" && allowUnknown) {
				best, bestTS, bestN = path, ts, n
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("store/java: %w for keystore %s", ErrNoBackupFound, keystore)
	}
	return best, nil
}

func (s javaStore) GetInfo() *Info {
	info := &Info{
		Name:    "Java",
		Version: s.version(),
	}
	if path, err := s.keystorePath(); err == nil {
		info.Path = path
	}
	return info
}

func (s javaStore) version() string {
	out, err := exec.Command("java", "-version").CombinedOutput()
	if err != nil {
		return ""
	}

	// e.g. java version "1.8.0_152"
	r := regexp.MustCompile(`"([\d\._]+)"`)
	m := r.FindString(string(out))
	return strings.ReplaceAll(m, `"`, "")
}

// List returns the x509 Certificates from a java TrustStore
//
// Note: keytool does not offer the ability to "untrust" a certificate
func (s javaStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	return s.tool().getCertificates()
}

func (s javaStore) Remove(al allowlist.Allowlist) error {
	tool := s.tool()
	kpath, err := tool.getKeystorePath()
	if err != nil {
		return err
	}

	certs, err := tool.getCertificates()
	if err != nil {
		return err
	}

	shortCerts, err := tool.getShortCerts()
	if err != nil {
		return err
	}

	if DryRun() {
		var details []string
		for i := range shortCerts {
			if !shortCerts[i].hasFingerprints() {
				return fmt.Errorf("no fingerprints found for certificate %s", shortCerts[i])
			}
			for j := range certs {
				if shortCerts[i].matches(certs[j]) {
					if !al.Matches(certs[j]) {
						details = append(details, fmt.Sprintf("remove %s (alias %s)", formatCertLine(certs[j]), shortCerts[i].alias))
					}
					break
				}
			}
		}
		reportDryRun("remove certificates from", "java", kpath, details...)
		return nil
	}

	// Map of short cert aliases we've already deleted
	// Used to cleanup debug logging
	deleted := make(map[string]bool)

	// compare against all listed certs
	for i := range shortCerts {
		if !shortCerts[i].hasFingerprints() {
			return fmt.Errorf("no fingerprints found for certificate %s", shortCerts[i])
		}

		// Find the cert
		for j := range certs {
			// Match the "short cert" to it's full x509.Certificate
			if shortCerts[i].matches(certs[j]) {
				// then remove if it's not allowlisted
				if !al.Matches(certs[j]) {
					err = tool.deleteCertificate(kpath, shortCerts[i].alias)
					if err != nil {
						return err
					}
					deleted[shortCerts[i].alias] = true
					if debug {
						fmt.Printf("store/java: deleted %s from %s\n", shortCerts[i], kpath)
					}
				}
				break // skip to next "short cert"
			}
		}

		_, alreadyDeleted := deleted[shortCerts[i].alias]
		if debug && !alreadyDeleted {
			// We didn't match the "short cert" to it's full x509.Certificate
			fmt.Printf("store/java: Unable to find cert %q in java store at %s\n", shortCerts[i].alias, kpath)
		}
	}

	return nil
}

func (s javaStore) Restore(where string) error {
	// Get destination path
	dst, err := s.keystorePath()
	if err != nil {
		return err
	}

	src := where
	if src == "" {
		src, err = latestJavaBackupFor(dst, s.keystoreOverride == "")
		if err != nil {
			return err
		}
	}
	// Never copy a backup over a different keystore than it came from unless
	// -force is set. An explicit backup without a recorded source is the
	// operator's choice.
	if err := checkJavaBackupSource(src, dst, true, ForceRestore()); err != nil {
		return err
	}

	if DryRun() {
		reportDryRun("restore", "java", dst,
			fmt.Sprintf("source %s", src),
			fmt.Sprintf("copy %s -> %s", src, dst))
		return nil
	}

	// This sometimes requires escalated permissions because the `cacerts` file
	// is often owned by root or have perms like: -rw-rw-r-- (which prevent global writes)
	return file.SudoCopyFile(src, dst)
}

type keytool struct {
	// JAVA_HOME env variable
	javahome string

	// Where is java installed, default is to look at JAVA_HOME
	javaInstallPaths []string

	// Under java install path where is the `cacerts` keystore located?
	// This changes on each platform...
	relativeKeystorePaths []string

	// explicitKeystore, when set, skips JAVA_HOME / install-path search and
	// uses this file directly (CLI -file with -app java on list/backup/connect/restore).
	explicitKeystore string
}

// addCertificate installs a certificate into the truststore
//
// It follows this command:
//
// keytool -importcert -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass .. -file .. -alias ..
func (k keytool) addCertificate(where string, alias string) error {
	kpath, err := k.getKeystorePath()
	if err != nil {
		return err
	}

	args := []string{
		"-importcert",
		"-keystore", kpath,
		"-file", where,
		"-alias", alias,
		"-noprompt",
	}
	_, err = k.runKeytool(kpath, args, false)
	return err
}

// expandSymlink takes in a symlink which refers to the `java` cli tool
// and attempts to return the home directory for that java install
//
// This shows up on linux flavors of /etc/alternatives/java which helps
// abstract over the java-$version-openjdk-$arch (or oracle) naming
func (k keytool) expandSymlink(p string) (string, error) {
	bin, err := os.Readlink(p)
	if err != nil {
		var pe *os.PathError
		if !errors.As(err, &pe) {
			// The error was something other than path related, so return it, could be bad
			return "", err
		}
		return "", nil // path doesn't exist
	}
	if bin != "" {
		// Relative link targets resolve against the link's own directory.
		if !filepath.IsAbs(bin) {
			bin = filepath.Join(filepath.Dir(p), bin)
		}
		if abs, err := filepath.Abs(bin); err == nil {
			bin = abs
		}
		dir := strings.TrimSuffix(bin, filepath.Join("bin", "java"))
		if debug {
			fmt.Printf("store/java: expanded %s to %s and stripped to %s\n", p, bin, dir)
		}
		return filepath.Clean(dir), nil
	}
	return "", nil // again, no error if we failed
}

func (k keytool) getKeystorePath() (string, error) {
	if k.explicitKeystore != "" {
		return validateJavaKeystoreFile(k.explicitKeystore)
	}

	kpath := ""
	if k.javahome == "" {
		for i := range k.javaInstallPaths {
			// Sometimes javaInstallPaths can be a symlink, if so expand it and use that
			installPath := k.javaInstallPaths[i]
			if debug {
				fmt.Printf("store/java: searching %s\n", installPath)
			}
			dir, err := k.expandSymlink(installPath)
			if err != nil {
				return "", err
			}
			if dir != "" {
				installPath = dir
			}

			// Check each possible relative location
			for j := range k.relativeKeystorePaths {
				where := filepath.Join(installPath, k.relativeKeystorePaths[j])
				if file.Exists(where) {
					kpath = where
					break
				}
			}
			if kpath != "" {
				if debug {
					fmt.Printf("store/java: found kpath %s\n", kpath)
				}
				break
			}
		}
	} else {
		// We've got JAVA_HOME, but need to add the relative path to `cacerts`
		for i := range k.relativeKeystorePaths {
			where := filepath.Join(k.javahome, k.relativeKeystorePaths[i])
			if file.Exists(where) {
				kpath = where
				if debug {
					fmt.Printf("store/java: found via JAVA_HOME %s\n", where)
				}
				break
			}
		}
		if kpath == "" {
			return "", fmt.Errorf("store/java: JAVA_HOME=%s has no cacerts under %v", k.javahome, k.relativeKeystorePaths)
		}
	}
	if kpath == "" {
		return "", errors.New("store/java: never found java and/or keystore path")
	}
	return validateJavaKeystoreFile(kpath)
}

func (k keytool) getShortCertsRaw(extraArgs ...string) ([]byte, error) {
	kpath, err := k.getKeystorePath()
	if err != nil {
		return nil, err
	}

	args := append([]string{
		"-list",
		"-keystore", kpath,
		"-noprompt",
	}, extraArgs...)
	return k.runKeytool(kpath, args, false)
}

func (k keytool) getCertificates() ([]*x509.Certificate, error) {
	out, err := k.getShortCertsRaw("-rfc")
	if err != nil {
		return nil, err
	}

	// TODO(adam): Filter out expired and revoked certs, based on ListOptions
	certs, err := certutil.ParsePEM(out)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

type cert struct {
	alias string

	// fingerprints
	sha1Fingerprint   string
	sha256Fingerprint string
}

func (c *cert) matches(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if c.sha1Fingerprint != "" {
		return certutil.GetHexSHA1Fingerprint(*cert) == c.sha1Fingerprint
	}
	if c.sha256Fingerprint != "" {
		return certutil.GetHexSHA256Fingerprint(*cert) == c.sha256Fingerprint
	}
	return false
}
func (c *cert) hasFingerprints() bool {
	return c.sha1Fingerprint != "" || c.sha256Fingerprint != ""
}
func (c *cert) String() string {
	if c.sha1Fingerprint != "" {
		return fmt.Sprintf("%s, SHA1=%s", c.alias, c.sha1Fingerprint)
	}
	if c.sha256Fingerprint != "" {
		return fmt.Sprintf("%s, SHA256=%s", c.alias, c.sha256Fingerprint)
	}
	return fmt.Sprintf("%s, but no fingerprints", c.alias)
}

// $ keytool -list -keystore <path> -storepass <pass>
// Keystore type: JKS
// Keystore provider: SUN
//
// # Your keystore contains 105 entries
//
// verisignclass2g2ca [jdk], Aug 25, 2016, trustedCertEntry,
// Certificate fingerprint (SHA1): B3:EA:C4:47:76:C9:C8:1C:EA:F2:9D:95:B6:CC:A0:08:1B:67:EC:9D
func (k keytool) getShortCerts() ([]*cert, error) {
	out, err := k.getShortCertsRaw()
	if err != nil {
		return nil, err
	}

	res := make([]*cert, 0)
	r := bufio.NewScanner(bytes.NewReader(out))
	var prev, curr string
	for r.Scan() {
		prev = curr     // $alias [info....]
		curr = r.Text() // Certificate fingerprint ...

		// Do we have a cert?
		if strings.HasPrefix(curr, "Certificate fingerprint") {
			item := &cert{
				// verisignclass2g2ca [jdk], Aug 25, 2016, trustedCertEntry,
				alias: strings.TrimSpace(strings.Split(prev, ",")[0]),
			}

			// Java 9 changes the fingerprint algorithm to SHA-256, which is identified inline
			// Certificate fingerprint (SHA1): B3:EA:C4:47:76:C9:C8:1C:EA:F2:9D:95:B6:CC:A0:08:1B:67:EC:9D
			// OR
			// Certificate fingerprint (SHA-256): 9A:CF:AB:7E:43:C8:D8:80:D0:6B:26:2A:94:DE:EE:E4:B4:65:99:89:C3:D0:CA:F1:9B:AF:64:05:E4:1A:B7:DF
			if strings.Contains(curr, "SHA1") {
				fp := curr[len(curr)-40-19:] // 40 chars from sha1 output, 19 :'s
				fp = strings.ToLower(strings.ReplaceAll(fp, ":", ""))
				item.sha1Fingerprint = fp
			}
			if strings.Contains(curr, "SHA-256") {
				fp := curr[len(curr)-64-31:] // 64 chars from sha1 output, 31 :'s
				fp = strings.ToLower(strings.ReplaceAll(fp, ":", ""))
				item.sha256Fingerprint = fp
			}

			if !item.hasFingerprints() {
				if debug {
					fmt.Printf("store/java: Failed to determine fingerprint algorithm of: %s\n%s\n", item.alias, curr)
				}
				return nil, fmt.Errorf("unable to determine fingerprint of cert: %s", item)
			}

			if debug {
				fmt.Printf("store/java: Parsed cert: %s\n", item)
			}

			res = append(res, item)
		}
	}

	return res, nil
}

// keytool -delete -alias <alias> -keystore <path> -storepass <pass>
// Pass kpath in so we don't have to rediscover it for every cert removal
func (k keytool) deleteCertificate(kpath, alias string) error {
	if strings.Contains(alias, "?") {
		// There seems to be an issue with aliases which contain certain characters. My guess
		// is that they're non-ascii and being encoded/decoded improperly.
		// I've filed a bug w/ openjdk (internal review ID 9051507), but until then
		// certs with these characters fail to be deleted.
		fmt.Printf("WARNING: alias %s cannot be currently removed from the keystore.\n", alias)
		return nil
	}

	args := []string{
		"-delete",
		"-alias", alias,
		"-keystore", kpath,
		"-noprompt",
	}
	useSudo := runtime.GOOS != "windows" && os.Getuid() != 0
	_, err := k.runKeytool(kpath, args, useSudo)
	return err
}

// keytoolBin prefers $JAVA_HOME/bin/keytool so a temp JAVA_HOME can supply a
// stub, then falls back to PATH.
func (k keytool) keytoolBin() string {
	home := strings.TrimSpace(k.javahome)
	if home == "" {
		return "keytool"
	}
	candidates := []string{filepath.Join(home, "bin", "keytool")}
	if runtime.GOOS == "windows" {
		candidates = []string{
			filepath.Join(home, "bin", "keytool.exe"),
			filepath.Join(home, "bin", "keytool.bat"),
			filepath.Join(home, "bin", "keytool.cmd"),
			filepath.Join(home, "bin", "keytool"),
		}
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "keytool"
}

func ensureKeytoolNonInteractive(args []string) (out []string, env []string, err error) {
	hasNoprompt, hasStorepass := false, false
	for _, a := range args {
		switch a {
		case "-noprompt":
			hasNoprompt = true
		case "-storepass", "-storepass:env", "-storepass:file":
			hasStorepass = true
		}
	}
	out = append([]string(nil), args...)
	if !hasStorepass {
		flags, e, err := prepareStorepass()
		if err != nil {
			return nil, nil, err
		}
		env = e
		out = append(out, flags...)
	}
	if !hasNoprompt {
		out = append(out, "-noprompt")
	}
	return out, env, nil
}

func defaultFindTimeoutBin() string {
	p, err := exec.LookPath("timeout")
	if err != nil {
		return ""
	}
	return p
}

// keytoolTimeoutSecs is keytoolTimeout rounded up to whole seconds, minimum 1,
// for `timeout -s KILL <secs>`.
func keytoolTimeoutSecs() int {
	d := keytoolTimeout
	if d < time.Second {
		return 1
	}
	secs := int(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	return secs
}

func sudoKeytoolArgs(bin string, args []string, preserveEnv []string) (sudoArgs []string, usedRootTimeout bool) {
	sudoArgs = []string{"-n"}
	for _, name := range preserveEnv {
		if name != "" {
			sudoArgs = append(sudoArgs, "--preserve-env="+name)
		}
	}
	if tbin := findTimeoutBin(); tbin != "" {
		sudoArgs = append(sudoArgs, tbin, "-s", "KILL", strconv.Itoa(keytoolTimeoutSecs()))
		usedRootTimeout = true
	}
	sudoArgs = append(sudoArgs, bin)
	sudoArgs = append(sudoArgs, args...)
	return sudoArgs, usedRootTimeout
}

// storepassEnvNames extracts env var names from "-storepass:env NAME" pairs.
func storepassEnvNames(args []string) []string {
	var names []string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-storepass:env" && args[i+1] != "" {
			names = append(names, args[i+1])
		}
	}
	return names
}

// runKeytool validates kpath, then runs keytool with a timeout and no stdin
// so it can never block on a password prompt.
func (k keytool) runKeytool(kpath string, args []string, useSudo bool) ([]byte, error) {
	if _, err := validateJavaKeystoreFile(kpath); err != nil {
		return nil, err
	}
	var err error
	var storeEnv []string
	args, storeEnv, err = ensureKeytoolNonInteractive(args)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), keytoolTimeout)
	defer cancel()

	bin := k.keytoolBin()
	usedRootTimeout := false
	var cmd *exec.Cmd
	if useSudo {
		var sudoArgs []string
		sudoArgs, usedRootTimeout = sudoKeytoolArgs(bin, args, storepassEnvNames(args))
		cmd = exec.CommandContext(ctx, keytoolSudoPath, sudoArgs...)
	} else {
		cmd = exec.CommandContext(ctx, bin, args...)
	}
	if len(storeEnv) > 0 {
		cmd.Env = environWithOverrides(nil, storeEnv)
	}
	// nil Stdin is the null device; keytool must never inherit a TTY.
	cmd.Stdin = nil
	cmd.WaitDelay = keytoolWaitDelay
	configureKeytoolCmd(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was: %s\n", strings.Join(redactKeytoolArgs(cmd.Args), " "))
			fmt.Printf("Stdout:\n%s\n", stdout.String())
			fmt.Printf("Stderr:\n%s\n", stderr.String())
		}
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
		if !timedOut && usedRootTimeout {
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 124 {
				timedOut = true
			}
		}
		rootMayStillRun := useSudo && !usedRootTimeout && timedOut
		return stdout.Bytes(), wrapKeytoolError(err, stdout.String(), stderr.String(), timedOut, rootMayStillRun)
	}
	return stdout.Bytes(), nil
}

func wrapKeytoolError(err error, stdout, stderr string, timedOut, rootMayStillRun bool) error {
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		detail = strings.TrimSpace(stdout)
	}
	if timedOut {
		msg := fmt.Sprintf("store/java: keytool timed out after %s", keytoolTimeout)
		if rootMayStillRun {
			msg += "; keytool may still be running as root"
		}
		if detail != "" {
			return fmt.Errorf("%s: %s", msg, detail)
		}
		return errors.New(msg)
	}
	combined := stdout + "\n" + stderr
	if strings.Contains(combined, keystoreTamperedMessage) {
		if detail == "" {
			detail = keystoreTamperedMessage
		}
		return fmt.Errorf("store/java: wrong keystore password: %s", detail)
	}
	if detail != "" {
		return fmt.Errorf("store/java: keytool: %w: %s", err, detail)
	}
	return fmt.Errorf("store/java: keytool: %w", err)
}
