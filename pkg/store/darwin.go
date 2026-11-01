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

//go:build darwin
// +build darwin

package store

import (
	"crypto/x509"
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

var (
	// systemRootCertificates is the bundled set of CA's from Apple.
	//
	// After "System Integrity Protection" was added to macs not even root can modify files
	// like /System/Library/Keychains/SystemRootCertificates.keychain, because many (all?) files
	// under /System are write/modify protected. There is some super-hacky way to reboot and disable
	// that, but we'd never go down that route.
	//
	// SIP: https://support.apple.com/en-ca/HT204899
	// https://superuser.com/questions/1070664/security-seckeychainitemdelete-unixoperation-not-permitted-on-os-x-when-tryi
	systemRootCertificates = "/System/Library/Keychains/SystemRootCertificates.keychain"

	// systemKeychain is the device wide keychain. If a login keychain doesn't specify an override then the trust
	// is pulled from here. We're free to modify this with sudo
	systemKeychain = "/Library/Keychains/System.keychain"

	// loginKeychain represents the default location for the user's 'login.keychain', which
	// is typically where overrides (e.g. corporate CA's) are installed into.
	loginKeychain = filepath.Join(file.HomeDir(), "/Library/Keychains/login.keychain")

	// Sierra+ stores the login keychain as login.keychain-db. The security CLI
	// still accepts 'login.keychain' as an alias, but os.Stat does not.

	// Folder under ~/Library/trustprune/ to put backups
	darwinBackupDir = "darwin"
)

// Docs
// https://www.apple.com/certificateauthority/ca_program.html

// darwinStore represents the structure of a `store.Store`, but for the darwin (OSX and
// macOS) platform.
//
// Within the code a cli tool called `security` is often used to extract and modify the
// trust settings of installed certificates in the various Keychains.
//
// https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html
type darwinStore struct{}

func platform() Store {
	return darwinStore{}
}

func (s darwinStore) Add(certs []*x509.Certificate) error {
	if DryRun() {
		details := reportDryRunCerts("add", certs)
		reportDryRun("add certificates to", "darwin", loginKeychainFile(), details...)
		return nil
	}

	dir, err := os.MkdirTemp("", "cert-manage-add")
	if err != nil {
		return fmt.Errorf("add: error creating temp dir err=%w", err)
	}
	defer os.RemoveAll(dir)

	for i := range certs {
		// Write each cert to its own file and then add it
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		path := filepath.Join(dir, fmt.Sprintf("%s.pem", fp))
		err := certutil.ToFile(path, certs[i:i+1])
		if err != nil {
			return fmt.Errorf("add: error writing cert %s to tempfile %s, err=%w", certs[i].Subject, path, err)
		}

		// add cert to keychain
		resultType := "unspecified"
		if certs[i].IsCA {
			resultType = "trustAsRoot"
		}

		cmd := exec.Command("security", "add-trusted-cert", "-r", resultType, "-p", "ssl", "-k", loginKeychainFile(), path)
		out, err := cmd.CombinedOutput()
		if err != nil && debug {
			fmt.Printf("Command ran: %q\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Output was: %s\n", string(out))
		}
	}
	return nil
}

func (s darwinStore) Backup() error {
	if DryRun() {
		reportDryRun("backup", "darwin", loginKeychainFile(),
			"export trusted certificates from the login keychain into ~/Library/trustprune/darwin/<timestamp>/")
		return nil
	}

	// setup (and create) backup (parent) dir
	parent, err := getCertManageDir(fmt.Sprintf("%s/%d", darwinBackupDir, time.Now().Unix()))
	if err != nil {
		return fmt.Errorf("backup: error getting cert-manage dir, err=%w", err)
	}

	// Backup the certificates from the login keychain and export each into a separate file
	// The backup format looks like this: darwin/$time/$keychain-name/$fingerprint.crt
	// Files are PEM encoded x509 certificates.
	login := loginKeychainFile()
	if _, err := os.Stat(login); os.IsNotExist(err) {
		if debug {
			fmt.Printf("store/darwin: Backup: skipping login keychain as it's missing")
		}
		return nil
	}

	_, fname := filepath.Split(loginKeychain)
	certs, err := readInstalledCerts(login)
	if err != nil {
		return fmt.Errorf("backup: error reading installed certs from %s, err=%w", login, err)
	}
	dir, err := getCertManageDir(filepath.Join(parent, fname))
	if err != nil {
		return fmt.Errorf("backup: error getting cert-manage dir, err=%w", err)
	}

	// Write each certificate to the underlying fs
	for i := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		where := filepath.Join(dir, fmt.Sprintf("%s.crt", fp))

		err = certutil.ToFile(where, certs[i:i+1]) // avoid creating a new slice
		if err != nil {
			return fmt.Errorf("backup: error writing cert %s to temp file %s, err=%w", certs[i].Subject, where, err)
		}
	}

	return nil
}

func (s darwinStore) GetLatestBackup() (string, error) {
	dir, err := getLatestStoreBackup(darwinBackupDir)
	if err != nil {
		return "", fmt.Errorf("restore: error reading backup dir, err=%w", err)
	}
	return dir, nil
}

func (s darwinStore) GetInfo() *Info {
	return &Info{
		Name:    "Darwin (OSX)",
		Version: s.version(),
		Path:    systemKeychain,
	}
}

// Show OS version
// From: https://superuser.com/questions/75166/how-to-find-out-mac-os-x-version-from-terminal
func (s darwinStore) version() string {
	out, err := exec.Command("sw_vers", "-productVersion").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (s darwinStore) List(opts *ListOptions) ([]*x509.Certificate, error) {
	if opts == nil {
		opts = &ListOptions{Trusted: true}
	}

	installed, err := readInstalledCerts(darwinKeychainPaths()...)
	if err != nil {
		return nil, err
	}

	// verify-cert -p ssl treats each item as an SSL *server* cert. Root CAs
	// typically have no SSL EKU, so that check drops the whole store (0 certs
	// on a clean GitHub Actions runner). Trust settings are one `security`
	// invocation per domain instead of one process per certificate.
	trust := readDarwinTrustSettings()

	pool := certutil.Pool{}
	for i := range installed {
		denied := trust.certDenied(installed[i])
		if denied {
			if opts.Untrusted {
				pool.Add(installed[i])
			}
			continue
		}
		if opts.Trusted {
			pool.Add(installed[i])
		}
	}
	return pool.GetCertificates(), nil
}

// loginKeychainFile returns the on-disk login keychain path. Sierra+ uses
// login.keychain-db; older systems use login.keychain.
func loginKeychainFile() string {
	db := loginKeychain + "-db"
	if file.Exists(loginKeychain) {
		return loginKeychain
	}
	if file.Exists(db) {
		return db
	}
	return loginKeychain
}

func darwinKeychainPaths() []string {
	paths := []string{systemRootCertificates, systemKeychain, loginKeychain}
	if db := loginKeychain + "-db"; file.Exists(db) {
		paths = append(paths, db)
	}
	return paths
}

type darwinTrustSettings struct {
	trusted map[string]struct{}
	denied  map[string]struct{}
}

func (t darwinTrustSettings) isDenied(name string) bool {
	_, ok := t.denied[name]
	return ok
}

func (t darwinTrustSettings) isTrusted(name string) bool {
	if t.isDenied(name) {
		return false
	}
	_, ok := t.trusted[name]
	return ok
}

func (t darwinTrustSettings) certDenied(c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	for _, n := range darwinCertNames(c) {
		if t.isDenied(n) {
			return true
		}
	}
	return false
}

func darwinCertNames(c *x509.Certificate) []string {
	var names []string
	if c.Subject.CommonName != "" {
		names = append(names, c.Subject.CommonName)
	}
	if s := certutil.StringifyPKIXName(c.Subject); s != "" && s != c.Subject.CommonName {
		names = append(names, s)
	}
	return names
}

func readDarwinTrustSettings() darwinTrustSettings {
	t := darwinTrustSettings{
		trusted: make(map[string]struct{}),
		denied:  make(map[string]struct{}),
	}
	flags := [][]string{
		{"-s"},
		{"-d"},
		nil, // user domain
	}
	for _, extra := range flags {
		args := append([]string{"dump-trust-settings"}, extra...)
		out, _ := exec.Command("/usr/bin/security", args...).CombinedOutput()
		parseDarwinTrustSettings(string(out), &t)
	}
	return t
}

func parseDarwinTrustSettings(out string, t *darwinTrustSettings) {
	if t.trusted == nil {
		t.trusted = make(map[string]struct{})
	}
	if t.denied == nil {
		t.denied = make(map[string]struct{})
	}

	var current string
	var denied bool
	flush := func() {
		if current == "" {
			return
		}
		if denied {
			t.denied[current] = struct{}{}
		} else {
			t.trusted[current] = struct{}{}
		}
		current = ""
		denied = false
	}

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Cert ") {
			if idx := strings.Index(line, ":"); idx >= 0 {
				flush()
				current = strings.TrimSpace(line[idx+1:])
			}
			continue
		}
		if strings.Contains(line, "Result Type") && strings.Contains(line, "Deny") {
			denied = true
		}
	}
	flush()
}

// certTrustedWithSystem calls out to `verify-cert` of the `security` cli tool to check
// if a certificate is still trusted, this comes about when a custom policy has been
// applied typically by the user or System.
func certTrustedWithSystem(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	tmp, err := os.CreateTemp("", "verify-cert")
	if err != nil {
		if debug {
			fmt.Printf("store/darwin: error creating temp file for verify-cert: err=%v\n", err)
		}
		return false
	}
	defer os.Remove(tmp.Name())

	// write pem block somewhere and shell out
	err = certutil.ToFile(tmp.Name(), []*x509.Certificate{cert})
	if err != nil {
		if debug {
			fmt.Printf("store/darwin: error writing cert to tempfile, err=%v\n", err)
		}
		return false
	}

	// We don't specify -k systemKeychain to use the default search path, it's what apps would do.
	cmd := exec.Command("/usr/bin/security", "verify-cert", "-p", "ssl", "-c", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil && debug {
		fmt.Printf("Command ran: %q\n", strings.Join(cmd.Args, " "))
		fmt.Printf("Output was: %s\n", string(out))
	}
	return err == nil
}

// readInstalledCerts pulls certificates from the `security` cli tool that's
// installed. This will return certificates, but not their trust status.
func readInstalledCerts(paths ...string) ([]*x509.Certificate, error) {
	args := []string{"find-certificate", "-a", "-p"}
	args = append(args, paths...)
	cmd := exec.Command("/usr/bin/security", args...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		if debug {
			fmt.Printf("Command ran: %q\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Output was: %s\n", string(out))
		}
		return nil, err
	}

	certs, err := certutil.ParsePEM(out)
	if err != nil {
		return nil, err
	}

	var res []*x509.Certificate
	for _, c := range certs {
		if c == nil {
			continue
		}
		add := true
		sig := certutil.GetHexSHA256Fingerprint(*c)
		for i := range res {
			if res[i] == nil {
				continue
			}
			if sig == certutil.GetHexSHA256Fingerprint(*res[i]) {
				add = false
				break
			}
		}
		if add {
			res = append(res, c)
		}
	}

	return res, nil
}

// Remove works to mark certificates not allowlisted as 'Never Trust' in the System keychain.
// This effectively disables the certificate unless the user's login keychain has overrides.
func (s darwinStore) Remove(al allowlist.Allowlist) error {
	// We just want to read the system roots and remove trust in those not allowlisted
	roots, err := readInstalledCerts(systemRootCertificates)
	if err != nil {
		return fmt.Errorf("remove: error reading certs from %s, err=%w", systemRootCertificates, err)
	}

	if DryRun() {
		var details []string
		for i := range roots {
			if !al.Matches(roots[i]) {
				details = append(details, fmt.Sprintf("distrust %s", formatCertLine(roots[i])))
			}
		}
		reportDryRun("remove certificates from", "darwin", systemRootCertificates, details...)
		return nil
	}

	// prep a temp file we can re-use
	tmp, err := os.CreateTemp("", "cert-manage-darwin-remove")
	if err != nil {
		return fmt.Errorf("remove: error creating temp dir, err=%w", err)
	}
	defer os.Remove(tmp.Name())

	for i := range roots {
		if !al.Matches(roots[i]) {
			// Root CA isn't part of our allowlist, so we need to remove trust for
			// it in the system keychain
			err = certutil.ToFile(tmp.Name(), roots[i:i+1]) // avoid new slice
			if err != nil {
				return fmt.Errorf("error writing to temp file %s, err=%v", tmp.Name(), err)
			}

			// mark the certificate as 'Never Trust' in the system keychain
			cmd := exec.Command("sudo", "/usr/bin/security", "add-trusted-cert", "-d", "-r", "deny", "-p", "ssl", "-k", systemKeychain, tmp.Name())
			out, err := cmd.CombinedOutput()
			if err != nil {
				if debug {
					output := string(out)
					fmt.Printf("ERROR: during removing darwin certs, error=%v\n", err)
					fmt.Printf("  Command ran: %q\n", strings.Join(cmd.Args, " "))
					fmt.Printf("  Output was: %s\n", output)
				}
				return fmt.Errorf("error marking cert %s as 'Never Trust' in system keychain, err=%w", roots[i].Subject, err)
			}
		}
	}

	return nil
}

// defaultCertTrustPolicy removes any extra trust policies from a cert and
// deletes it from the System keychain, which we use as an override.
func defaultCertTrustPolicy(certPath string, cert *x509.Certificate) error {
	// -r unspecified removes 'Always Trust' or 'Never Trust' from entry
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "unspecified", "-k", systemKeychain, certPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("remove: error removing 'Never Trust' from cert %s, err=%w", cert.Subject, err)
	}

	fp := certutil.GetHexSHA1Fingerprint(*cert)
	cmd = exec.Command("sudo", "security", "delete-certificate", "-Z", fp, systemKeychain)
	if out, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "Unable to delete certificate matching") {
			return nil // cert didn't exist
		}
		return fmt.Errorf("remove: error deleting cert %s from keychain, err=%w", cert.Subject, err)
	}
	return nil
}

// No idea why, but there are some Apple certificates which don't get allowlisted.
// For now, let's force them to be fixed up
var appleRootFingerprints = []string{
	"b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024", // CN=Apple Root CA
	"c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050", // CN=Apple Root CA - G2
	"63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179", // CN=Apple Root CA - G3
	"0d83b611b648a1a75eb8558400795375cad92e264ed8e9d7a757c1f5ee2bb22d", // CN=Apple Root Certificate Authority
}

// apple root wraps a certificate and it's rendereed PEM contents in a file
type appleRoot struct {
	cert *x509.Certificate
	file string
}

func newAppleRoot(cert *x509.Certificate) *appleRoot {
	tmp, err := os.CreateTemp("", "apple-root")
	if err != nil {
		return nil
	}
	err = certutil.ToFile(tmp.Name(), []*x509.Certificate{cert})
	if err != nil {
		return nil
	}
	return &appleRoot{
		cert: cert,
		file: tmp.Name(),
	}
}

func (c *appleRoot) cleanup() error {
	return os.Remove(c.file)
}

// getAppleRootCertificates returns the known Apple roots so they can be explicitly restored along with
// anything from the system roots.
//
// TODO(adam): Figure out why these aren't normally being restored
func getAppleRootCertificates() []*appleRoot {
	installed, err := readInstalledCerts(systemRootCertificates)
	if err != nil {
		if debug {
			fmt.Printf("store/darwin: failed to read apple root certs, err=%v\n", err)
		}
		return nil
	}

	var roots []*appleRoot
	for i := range installed {
		fp := certutil.GetHexSHA256Fingerprint(*installed[i])
		for j := range appleRootFingerprints {
			if fp == appleRootFingerprints[j] {
				roots = append(roots, newAppleRoot(installed[i]))
			}
		}
	}
	if len(roots) != len(appleRootFingerprints) {
		fmt.Printf("WARNING: only found %d/%d apple root certs\n", len(roots), len(appleRootFingerprints))
	}
	return roots
}

// resolveDarwinLoginBackupDir maps a restore path to the directory that holds
// login-keychain PEM exports (*.crt).
//
// where may be a backup timestamp directory (…/darwin/<unix>/) containing a
// login.keychain child, the login.keychain directory itself, or a flat
// directory of .crt files. Empty where is rejected; Restore fills it from
// GetLatestBackup first.
func resolveDarwinLoginBackupDir(where string) (string, error) {
	if where == "" {
		return "", fmt.Errorf("restore: empty backup path")
	}
	st, err := os.Stat(where)
	if err != nil {
		return "", fmt.Errorf("restore: error stating backup path %s, err=%w", where, err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("restore: backup path %s is not a directory", where)
	}

	hasCrt := func(dir string) bool {
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			return false
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			return false
		}
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".crt") {
				return true
			}
		}
		return false
	}

	login := filepath.Join(where, "login.keychain")
	if hasCrt(login) {
		return login, nil
	}
	if hasCrt(where) {
		return where, nil
	}
	return "", fmt.Errorf("restore: no certificate backups found in %s", where)
}

// Restore operates mostly on the system keychain and removes certificates which we've
// explicitly marked "Never Trust". This re-enables them for use by apps.
//
// Afterwards, the login keychain is restored from where (CLI -file), or from the
// latest darwin backup when where is empty. where may be a backup timestamp
// directory (…/darwin/<unix>/) or the login.keychain directory that holds the
// exported PEM files.
func (s darwinStore) Restore(where string) error {
	if where == "" {
		var err error
		where, err = s.GetLatestBackup()
		if err != nil {
			return err
		}
	}
	loginBackup, err := resolveDarwinLoginBackupDir(where)
	if err != nil {
		return err
	}
	if DryRun() {
		details := []string{
			"reset trust settings toward Apple system roots",
			fmt.Sprintf("re-add missing login keychain certs from %s", loginBackup),
		}
		reportDryRun("restore", "darwin", systemKeychain, details...)
		return nil
	}

	// Grab apple provided system root, this is our baseline
	roots, err := readInstalledCerts(systemRootCertificates)
	if err != nil {
		return fmt.Errorf("restore: error reading certs from %s, err=%w", systemRootCertificates, err)
	}

	// temp file for certs
	tmp, err := os.CreateTemp("", "restore-verify-cert")
	if err != nil {
		return fmt.Errorf("restore: error creating temp dir, err=%w", err)
	}
	defer os.Remove(tmp.Name())

	for i := range roots {
		err = certutil.ToFile(tmp.Name(), roots[i:i+1])
		if err != nil {
			return fmt.Errorf("restore: error writing cert %s to temp dir %s, err=%v", roots[i].Subject, tmp.Name(), err)
		}

		cmd := exec.Command("security", "verify-cert", "-p", "ssl", "-k", systemKeychain, "-c", tmp.Name())
		out, err := cmd.CombinedOutput()
		outStr := string(out)
		if err != nil {
			if strings.Contains(outStr, "kSecTrustResultDeny") {
				// Cert is actually untrusted, so let's restore trust and remove it from the System keychain
				if err := defaultCertTrustPolicy(tmp.Name(), roots[i]); err != nil {
					return err
				}
			} else if strings.Contains(outStr, "CSSMERR_TP_CERT_EXPIRED") {
				if debug {
					fmt.Printf("store/darwin: cert %s is expired\n", roots[i].Subject)
				}
				continue
			} else if strings.Contains(outStr, "Invalid Extended Key Usage") {
				if debug {
					fmt.Printf("store/darwin: cert %s isn't created for SSL signing\n", roots[i].Subject)
				}
				continue
			} else {
				if debug {
					fmt.Printf("store/darwin: cert %s ran into other issue with verify-cert: %s\n", roots[i].Subject, strings.TrimSpace(outStr))
				}
				return fmt.Errorf("restore: ran into other error with verify-cert for %s, err=%w", roots[i].Subject, err)
			}
		}
	}

	// Make sure apple roots are restored
	appleRoots := getAppleRootCertificates()
	for i := range appleRoots {
		root := appleRoots[i]
		err = defaultCertTrustPolicy(root.file, root.cert)
		if err != nil {
			return fmt.Errorf("restore: error restoring apple root %s, err=%w", root.cert.Subject, err)
		}
		if err := root.cleanup(); err != nil {
			return fmt.Errorf("restore: problem cleaning up apple root %s: %w", root.cert.Subject, err)
		}
	}

	// Restore the login.keychain from the resolved backup directory
	// (login.keychain/$sha256.crt exports).
	dir := loginBackup
	if debug {
		fmt.Printf("store/darwin: Found backup dir at %s\n", dir)
	}

	alreadyInstalled, err := readInstalledCerts(loginKeychainFile())
	if err != nil {
		return fmt.Errorf("restore: error getting login keychain certs, err=%w", err)
	}
	var alreadyInstalledFingerprints []string
	for i := range alreadyInstalled {
		alreadyInstalledFingerprints = append(alreadyInstalledFingerprints, certutil.GetHexSHA256Fingerprint(*alreadyInstalled[i]))
	}

	// read each file from our backup
	certfiles, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("restore: error reading backup dir contents, err=%w", err)
	}
	for i := range certfiles {
		// For each cert file, grab the certs and find the one that matches the filename hash
		_, fp := filepath.Split(certfiles[i].Name())
		certs, err := certutil.FromFile(filepath.Join(dir, certfiles[i].Name()))
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("restore: error reading certs from %s, err=%v", certfiles[i].Name(), err)
		}
		if len(certs) == 0 {
			if debug {
				fmt.Printf("store/darwin: no certificates found in backup file: %s\n", certfiles[i].Name())
			}
			continue
		}
		// find cert whose fingerprint matches filename
		for j := range certs {
			if fp == certutil.GetHexSHA256Fingerprint(*certs[j]) { // found cert, now add if it's not already in keychain
				shouldAdd := true
				for k := range alreadyInstalledFingerprints {
					if fp == alreadyInstalledFingerprints[k] {
						shouldAdd = false
					}
				}
				if shouldAdd {
					err = s.Add(certs[j : j+1])
					if err != nil {
						return fmt.Errorf("restore: error adding cert %s to login keychain, err=%w", certs[j].Subject, err)
					}
				}
			}
		}
	}

	return nil
}
