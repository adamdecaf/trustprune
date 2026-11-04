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
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

var (
	defaultKeystorePassword = "changeit"
	javaCertManageDir       = "java"
)

type javaStore struct {
	// keystoreOverride, when set, is the cacerts (or other) keystore file to
	// use instead of searching JAVA_HOME / platform install paths. CLI -file
	// with -app java sets this for list/backup/connect.
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

	// Rename the file as is
	_, filename := filepath.Split(kpath)
	dst := filepath.Join(dir, fmt.Sprintf("%s-%d.bck", filename, time.Now().Unix()))

	if err := file.CopyFile(kpath, dst); err != nil {
		return err
	}
	// Record which keystore this backup came from so restore never copies it
	// over a different keystore (-file backups share the java/ directory).
	if err := writeJavaBackupSource(dst, kpath); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
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
	return os.WriteFile(backup+javaBackupSourceSuffix, []byte(javaCanonicalPath(keystore)+"\n"), 0600)
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
// only when allowUnknown is set.
func checkJavaBackupSource(backup, dst string, allowUnknown bool) error {
	recorded, err := readJavaBackupSource(backup)
	if err != nil {
		return fmt.Errorf("store/java: reading source of backup %s: %w", backup, err)
	}
	if recorded == "" {
		if allowUnknown {
			return nil
		}
		return fmt.Errorf("store/java: backup %s has no recorded source keystore; pass it with restore -file to use it", backup)
	}
	if !sameJavaKeystore(recorded, dst) {
		return fmt.Errorf("store/java: refusing restore: backup %s was taken from %s, not %s", backup, recorded, dst)
	}
	return nil
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
	best, bestTS := "", int64(-1)
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", fmt.Errorf("getLatestBackup: error reading java backup directory, err=%w", err)
		}
		for _, ent := range ents {
			ts, ok := backupBasenameUnix(ent.Name())
			if !ok || ent.IsDir() || ts <= bestTS {
				continue
			}
			path := filepath.Join(d, ent.Name())
			recorded, err := readJavaBackupSource(path)
			if err != nil {
				return "", err
			}
			if (recorded != "" && sameJavaKeystore(recorded, keystore)) || (recorded == "" && allowUnknown) {
				best, bestTS = path, ts
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("store/java: no backup found for keystore %s", keystore)
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
	// Never copy a backup over a different keystore than it came from. An
	// explicit backup without a recorded source is the operator's choice.
	if err := checkJavaBackupSource(src, dst, true); err != nil {
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
	// uses this file directly (CLI -file with -app java).
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
		"-storepass", defaultKeystorePassword,
		"-file", where,
		"-alias", alias,
		"-noprompt",
	}
	cmd := exec.Command("keytool", args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was: %s\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Stdout:\n%s\n", stdout.String())
			fmt.Printf("Stderr:\n%s\n", stderr.String())
		}
		return err
	}
	return nil
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
	// `keytool` gets installed onto PATH, so no need to search for it
	kpath, err := k.getKeystorePath()
	if err != nil {
		return nil, err
	}

	args := append([]string{
		"-list",
		"-storepass", defaultKeystorePassword,
		"-keystore", kpath,
		"-noprompt",
	}, extraArgs...)
	cmd := exec.Command("keytool", args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was: %s\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Stdout:\n%s\n", stdout.String())
			fmt.Printf("Stderr:\n%s\n", stderr.String())
		}
		return nil, err
	}
	return stdout.Bytes(), nil
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
		"keytool",
		"-delete",
		"-alias", alias,
		"-keystore", kpath,
		"-storepass", defaultKeystorePassword,
		"-noprompt",
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		// already root
		cmd = exec.Command(args[0], args[1:]...)
	} else {
		cmd = exec.Command("sudo", args...)
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was: %s\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Stdout:\n%s\n", stdout.String())
			fmt.Printf("Stderr:\n%s\n", stderr.String())
		}
		return fmt.Errorf("%v when running keytool -delete %s", err.Error(), strings.TrimSpace(stdout.String()))
	}
	return nil
}
