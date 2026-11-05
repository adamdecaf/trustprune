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
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

var (
	cutil = crtutil{
		execPaths: []string{
			"/usr/local/opt/nss/bin/certutil", // Darwin
			"/usr/bin/certutil",               // Linux
		},
	}

	// certutil trust attrubutes
	// Run `certutil -A -H` for the full list
	trustAttrsProhibited = "p,p,p"
	trustAttrsTrusted    = "CT,C,C"

	// NSS shared DB (cert9) profile files that must be backed up/restored together.
	nssCert9ProfileFiles = []string{"cert9.db", "key4.db", "pkcs11.txt"}
	// Legacy NSS (cert8) profile files.
	nssCert8ProfileFiles = []string{"cert8.db", "key3.db", "secmod.db"}
)

type nssStore struct {
	// nssType refers to the application using this NSS instance
	// This is used for printing back to the user and for backup/restore.
	nssType string

	// appVersion refers to the version of whatever tool is using NSS
	appVersion string

	// foundCertdbLocation is the profile directory that contains cert9.db
	// (shared DB) and/or legacy cert8.db.
	foundCertdbLocation string

	// Holds a trigger if we've made modifications (useful for triggering a "Restart app" message
	// after we're done with modifications.
	notify *sync.Once
}

// NssStore returns an implementation of Store for NSS certificate stores
//
// Docs:
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/An_overview_of_NSS_Internals
// - https://wiki.mozilla.org/NSS_Shared_DB
// - https://wiki.mozilla.org/NSS_Shared_DB_And_LINUX
func NssStore(nssType string, appVersion string, certdbPath string) Store {
	// Callers sometimes pass the cert DB file itself; backup/restore operate on
	// the profile directory that contains it.
	switch filepath.Base(certdbPath) {
	case "cert9.db", "cert8.db":
		certdbPath = filepath.Dir(certdbPath)
	}
	return nssStore{
		nssType:             nssType,
		appVersion:          appVersion,
		foundCertdbLocation: certdbPath,
		notify:              &sync.Once{},
	}
}

// Checks if a cert8.db or cert9.db file exists at the given path
func containsCertdb(where string) bool {
	if fd, err := os.Stat(where); err != nil || !fd.IsDir() {
		return false // ignore non-directories
	}
	if fd, err := os.Stat(filepath.Join(where, "cert9.db")); !os.IsNotExist(err) {
		return fd.Size() > 0
	}
	if fd, err := os.Stat(filepath.Join(where, "cert8.db")); !os.IsNotExist(err) {
		return fd.Size() > 0
	}
	return false
}

// notifyRestart prints a one-shot restart hint for the app using this store.
func (s nssStore) notifyRestart() {
	s.notify.Do(func() {
		fmt.Printf("Restart %s to refresh certificate trust\n", titleASCII(s.nssType))
	})
}

// NSS apps on cert8.db require being restarted to get the updated set of trustAttrs for each certificate.
// Shared DB (cert9.db) picks up certutil trust-attribute changes without a restart; Restore still
// always hints via notifyRestart because it replaces the DB files under the app.
func (s nssStore) notifyToRestart() {
	if file.Exists(filepath.Join(s.foundCertdbLocation, "cert9.db")) {
		return
	}
	if !file.Exists(filepath.Join(s.foundCertdbLocation, "cert8.db")) {
		return
	}
	s.notifyRestart()
}

func (s nssStore) Add(certs []*x509.Certificate) error {
	if DryRun() {
		details := reportDryRunCerts("add", certs)
		reportDryRun("add certificates to", s.nssType, s.foundCertdbLocation, details...)
		return nil
	}

	dir, err := os.MkdirTemp("", "cert-manage-nss-add")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// write each cert out to a file and then add it
	for i := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		path := filepath.Join(dir, fmt.Sprintf("%s.pem", fp))

		err = certutil.ToFile(path, certs[i:i+1])
		if err != nil {
			return err
		}

		nick := strings.ReplaceAll(certutil.StringifyPKIXName(certs[i].Subject), " ", "_")
		err = cutil.addCertificate(s.foundCertdbLocation, path, nick)
		if err != nil {
			return err
		}
	}

	if len(certs) > 0 {
		s.notifyToRestart()
	}

	return nil
}

func (s nssStore) Backup() error {
	// Only backup the first nss cert.db path for now
	if s.foundCertdbLocation == "" {
		return errors.New("no NSS cert db paths found")
	}

	names, err := nssProfileFilesToBackup(s.foundCertdbLocation)
	if err != nil {
		return err
	}

	if DryRun() {
		details := []string{fmt.Sprintf("mirror profile set into %s/%s/<timestamp>", backupParentDisplay(), s.nssType)}
		for _, name := range names {
			src := filepath.Join(s.foundCertdbLocation, name)
			if file.Exists(src) {
				details = append(details, fmt.Sprintf("include %s", name))
			}
		}
		reportDryRun("backup", s.nssType, s.foundCertdbLocation, details...)
		return nil
	}

	dir, err := getCertManageDir(s.nssType)
	if err != nil {
		return err
	}

	// Backup into a timestamped directory so the profile set stays together.
	dstDir := filepath.Join(dir, fmt.Sprintf("%d", time.Now().Unix()))
	if err := os.MkdirAll(dstDir, backupDirPerms); err != nil {
		return err
	}

	copied := 0
	for _, name := range names {
		src := filepath.Join(s.foundCertdbLocation, name)
		if !file.Exists(src) {
			continue
		}
		if err := file.CopyFile(src, filepath.Join(dstDir, name)); err != nil {
			return err
		}
		copied++
	}
	if copied == 0 {
		return fmt.Errorf("no NSS profile files found under %s", s.foundCertdbLocation)
	}
	return nil
}

// nssProfileFilesToBackup picks the cert9 or cert8 file set based on which
// cert DB exists in the profile. Callers copy whichever members of the set exist.
func nssProfileFilesToBackup(profileDir string) ([]string, error) {
	if file.Exists(filepath.Join(profileDir, "cert9.db")) {
		return nssCert9ProfileFiles, nil
	}
	if file.Exists(filepath.Join(profileDir, "cert8.db")) {
		return nssCert8ProfileFiles, nil
	}
	return nil, fmt.Errorf("no cert9.db or cert8.db found under %s", profileDir)
}

func (s nssStore) GetLatestBackup() (string, error) {
	dir, err := getLatestStoreBackup(s.nssType)
	if err != nil {
		return "", fmt.Errorf("getLatestBackup: error getting %s backup directory err=%w", s.nssType, err)
	}
	return dir, nil
}

func (s nssStore) GetInfo() *Info {
	return &Info{
		Name:    titleASCII(s.nssType),
		Version: s.appVersion,
		Path:    s.foundCertdbLocation,
	}
}

// List returns the installed (and trusted) certificates contained in a NSS cert.db file
//
// To list certificates with the NSS `certutil` tool the following would be ran
// $ /usr/local/opt/nss/bin/certutil -L -d "$dir"
//
// Note: `dir` represents a directory path which contains a cert.db file
func (s nssStore) List(opts *ListOptions) ([]*x509.Certificate, error) {
	if s.foundCertdbLocation == "" {
		return nil, errors.New("unable to find NSS db directory")
	}

	items, err := cutil.listCertsFromDB(s.foundCertdbLocation)
	if err != nil {
		return nil, err
	}

	kept := make([]*x509.Certificate, 0)
	for i := range items {
		if opts.Trusted && items[i].trustedForSSL() {
			kept = append(kept, items[i].certs...)
		}
		if opts.Untrusted {
			kept = append(kept, items[i].certs...)
		}
	}
	return kept, nil
}

func (s nssStore) Remove(al allowlist.Allowlist) error {
	if s.foundCertdbLocation == "" {
		return errors.New("unable to find NSS db directory")
	}

	items, err := cutil.listCertsFromDB(s.foundCertdbLocation)
	if err != nil {
		return err
	}

	if DryRun() {
		var details []string
		for i := range items {
			if al.MatchesAll(items[i].certs) {
				continue
			}
			for j := range items[i].certs {
				details = append(details, fmt.Sprintf("distrust %s (nick %s)", formatCertLine(items[i].certs[j]), items[i].nick))
			}
		}
		reportDryRun("remove certificates from", s.nssType, s.foundCertdbLocation, details...)
		return nil
	}

	// Remove trust from each cert if needed.
	for i := range items {
		if al.MatchesAll(items[i].certs) {
			continue
		}

		// allowlist didn't match, blocklist cert
		defer s.notifyToRestart()
		err = cutil.modifyTrustAttributes(s.foundCertdbLocation, items[i].nick, trustAttrsProhibited)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s nssStore) Restore(where string) error {
	src := where
	var err error
	if src == "" {
		src, err = s.GetLatestBackup()
		if err != nil {
			return err
		}
		if src == "" {
			return errNoBackupCmd(s.nssType, s.nssType, "trustprune backup -app "+s.nssType)
		}
	}

	if DryRun() {
		details := []string{fmt.Sprintf("source %s", src), fmt.Sprintf("destination %s", s.foundCertdbLocation)}
		if st, err := os.Stat(src); err == nil && st.IsDir() {
			names := nssCert9ProfileFiles
			if file.Exists(filepath.Join(src, "cert8.db")) && !file.Exists(filepath.Join(src, "cert9.db")) {
				names = nssCert8ProfileFiles
			}
			for _, name := range names {
				from := filepath.Join(src, name)
				if file.Exists(from) {
					details = append(details, fmt.Sprintf("copy %s", from))
				}
			}
		} else {
			fname := "cert9.db"
			if strings.Contains(filepath.Base(src), "cert8") {
				fname = "cert8.db"
			}
			details = append(details, fmt.Sprintf("copy %s -> %s", src, filepath.Join(s.foundCertdbLocation, fname)))
		}
		reportDryRun("restore", s.nssType, s.foundCertdbLocation, details...)
		return nil
	}

	dst := s.foundCertdbLocation
	tmp := dst + ".restore-tmp"
	aside := dst + ".restore-old"

	// Stage the whole profile set into a sibling temp dir, then swap into
	// place with rollback. A failed stage must leave the live profile files
	// untouched (same idea as linuxStore.Restore since #240).
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := os.MkdirAll(tmp, backupDirPerms); err != nil {
		return err
	}

	names, err := nssStageRestoreFiles(src, tmp)
	if err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if len(names) == 0 {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("no NSS profile files to restore from %s", src)
	}
	if err := nssRejectIncompatibleRestore(dst, names); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}

	if err := nssSwapStagedFiles(dst, tmp, aside, names); err != nil {
		return err
	}
	// File-level restore can leave a running app on the previous inode even
	// for shared DB (cert9.db), so always hint a restart after a successful swap.
	s.notifyRestart()
	return nil
}

// nssRejectIncompatibleRestore refuses a legacy cert8-only backup when the live
// profile already has an active cert9.db. Restoring cert8 files would leave the
// shared DB untouched while reporting success.
func nssRejectIncompatibleRestore(dst string, stagedNames []string) error {
	if !file.Exists(filepath.Join(dst, "cert9.db")) {
		return nil
	}
	has9, has8 := false, false
	for _, name := range stagedNames {
		switch name {
		case "cert9.db":
			has9 = true
		case "cert8.db":
			has8 = true
		}
	}
	if has8 && !has9 {
		return fmt.Errorf("cannot restore legacy cert8.db backup into cert9.db profile at %s", dst)
	}
	return nil
}

// nssStageRestoreFiles copies the backup profile set (or a legacy single-file
// backup) into tmp and returns the basenames that were staged.
func nssStageRestoreFiles(src, tmp string) ([]string, error) {
	if st, err := os.Stat(src); err == nil && st.IsDir() {
		names := nssCert9ProfileFiles
		if file.Exists(filepath.Join(src, "cert8.db")) && !file.Exists(filepath.Join(src, "cert9.db")) {
			names = nssCert8ProfileFiles
		}
		var staged []string
		for _, name := range names {
			from := filepath.Join(src, name)
			if !file.Exists(from) {
				continue
			}
			if err := file.CopyFile(from, filepath.Join(tmp, name)); err != nil {
				return nil, err
			}
			staged = append(staged, name)
		}
		return staged, nil
	}

	fname := "cert9.db"
	if strings.Contains(filepath.Base(src), "cert8") {
		fname = "cert8.db"
	}
	if err := file.CopyFile(src, filepath.Join(tmp, fname)); err != nil {
		return nil, err
	}
	return []string{fname}, nil
}

// nssSwapStagedFiles renames staged files into dst. Existing live files are
// moved under aside first so a mid-swap failure can roll them back. On
// success tmp and aside are removed.
func nssSwapStagedFiles(dst, tmp, aside string, names []string) error {
	// A crash mid-swap can leave originals only under aside. Never wipe a
	// non-empty aside from a previous attempt.
	if st, err := os.Stat(aside); err == nil {
		if !st.IsDir() {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("previous restore aside exists as a file at %s; remove it before restoring again", aside)
		}
		entries, err := os.ReadDir(aside)
		if err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
		if len(entries) > 0 {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("previous restore aside still at %s; move those files back or remove the directory before restoring again", aside)
		}
	}
	if err := os.RemoveAll(aside); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.MkdirAll(aside, backupDirPerms); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}

	var swapped []string
	var rollbackErrs []error
	rollback := func() {
		for i := len(swapped) - 1; i >= 0; i-- {
			name := swapped[i]
			live := filepath.Join(dst, name)
			old := filepath.Join(aside, name)
			if err := os.Remove(live); err != nil && !errors.Is(err, os.ErrNotExist) {
				rollbackErrs = append(rollbackErrs, err)
			}
			if file.Exists(old) {
				if err := os.Rename(old, live); err != nil {
					rollbackErrs = append(rollbackErrs, err)
				}
			}
		}
	}
	fail := func(err error) error {
		rollback()
		_ = os.RemoveAll(tmp)
		if len(rollbackErrs) > 0 {
			// Keep aside: it may still hold the only copy of the originals.
			fmt.Printf("store/nss: previous profile files moved aside to %s\n", aside)
			return errors.Join(append([]error{err, fmt.Errorf("rollback incomplete, originals kept in %s", aside)}, rollbackErrs...)...)
		}
		_ = os.RemoveAll(aside)
		return err
	}

	for _, name := range names {
		live := filepath.Join(dst, name)
		staged := filepath.Join(tmp, name)
		old := filepath.Join(aside, name)

		if file.Exists(live) {
			if err := os.Rename(live, old); err != nil {
				return fail(err)
			}
		}
		// Register before install so a partial CopyFile is rolled back too.
		swapped = append(swapped, name)
		if err := os.Rename(staged, live); err != nil {
			// If rename across dirs fails, fall back to copy then remove staged.
			if cerr := file.CopyFile(staged, live); cerr != nil {
				return fail(errors.Join(err, cerr))
			}
			_ = os.Remove(staged)
		}
	}

	// Restore already applied; leftover temp/aside paths are warnings only
	// (same idea as linuxStore.Restore after a successful swap).
	if err := nssRemoveAll(tmp); err != nil {
		fmt.Printf("store/nss: warning: could not fully remove %s after restore: %v (remaining contents may be incomplete)\n", tmp, err)
	}
	if err := nssRemoveAll(aside); err != nil {
		fmt.Printf("store/nss: warning: could not fully remove %s after restore: %v (remaining contents may be incomplete)\n", aside, err)
	}
	return nil
}

// nssRemoveAll is os.RemoveAll; tests swap it to simulate cleanup failures.
var nssRemoveAll = os.RemoveAll

// certdbItem represents an x509 Certificate with the NSS trust attributes
type certdbItem struct {
	nick  string
	certs []*x509.Certificate

	// The 'Trust Attributes' header from `certutil -L`, this represents three usecases for
	// x509 Certificates: SSL,S/MIME,JAR/XPI
	trustAttrs string
}

func (c certdbItem) trustedForSSL() bool {
	// We only care about the first C,.,. attribute, which is for SSL
	parts := strings.SplitN(c.trustAttrs, ",", 2)
	if len(parts) != 2 {
		if debug {
			fmt.Printf("store/nss: after trustAttrs split (in %d parts): %s\n", len(parts), parts)
		}
		return false
	}

	// The only attribute for explicit distrust is 'p', which per the docs:
	//  p 	 prohibited (explicitly distrusted)
	//
	// The other flags refer to sending warnings (but still trusted), user certs,
	// or other attributes which may limit, but not explicitly remove trust
	// in regards to SSL/TLS communication.
	return !strings.Contains(parts[0], "p")
}

// crtutil represents the NSS cli tool by the same name
// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Tools/certutil
type crtutil struct {
	execPaths []string
}

func (c crtutil) getExecPath() (string, error) {
	for i := range c.execPaths {
		if file.IsExecutable(c.execPaths[i]) {
			return c.execPaths[i], nil
		}
	}
	return "", errors.New("nss: certutil not found; install NSS tools (libnss3-tools, nss-tools or brew install nss)")
}

// Different versions of NSS/cert.db files require different prefixes
// when passed to certutil. Shared DB (cert9.db) uses sql:; legacy
// cert8.db uses dbm:. Callers pass a profile directory (or, rarely, a
// path ending in cert8.db / cert9.db); when both DBs exist, prefer sql:
// because that is the active store after Firefox's migration.
func (c crtutil) appendScheme(where string) string {
	dir, scheme := nssCertutilDirAndScheme(where)
	return scheme + dir
}

func nssCertutilDirAndScheme(where string) (dir, scheme string) {
	switch filepath.Base(where) {
	case "cert9.db":
		return filepath.Dir(where), "sql:"
	case "cert8.db":
		return filepath.Dir(where), "dbm:"
	}
	if file.Exists(filepath.Join(where, "cert9.db")) {
		return where, "sql:"
	}
	return where, "dbm:"
}

// Emulates the following
// /usr/local/opt/nss/bin/certutil -A -a -n <nick> -t 'CT,C,C' -i cert.pem -d <dir>
func (c crtutil) addCertificate(dir string, where string, nick string) error {
	expath, err := c.getExecPath()
	if err != nil {
		return err
	}
	args := []string{
		"-A", "-a",
		"-n", nick,
		"-t", trustAttrsTrusted,
		"-i", where,
		"-d", c.appendScheme(dir),
	}
	cmd := exec.Command(expath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if debug {
			fmt.Printf("Command was:\n %s\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Output was: %q\n", string(out))
		}
		return err
	}
	return nil
}

// Emulates the following
// /usr/local/opt/nss/bin/certutil -L -d '~/Library/Application Support/Firefox/Profiles/rrdlhe7o.default'
//
// TODO(adam): Check for opts.Expired or opts.Revoked
func (c crtutil) listCertsFromDB(path string) ([]certdbItem, error) {
	expath, err := c.getExecPath()
	if err != nil {
		return nil, err
	}

	args := []string{
		"-L",
		"-d", c.appendScheme(path),
	}
	cmd := exec.Command(expath, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was:\n %s\n", strings.Join(cmd.Args, " "))
		}
		return nil, err
	}

	// parse out each 'Certificate Nickname' field
	// there are some header lines that are either whitespace or contain the following:
	//
	// Certificate Nickname                                         Trust Attributes
	// SSL,S/MIME,JAR/XPI
	//
	items := make([]certdbItem, 0)
	for {
		// read next line
		line, err := stdout.ReadString(byte('\n'))
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}

		// convert the line into a certdbItem
		nick, trust := c.parseCertdbItem(line)
		if nick == "" || trust == "" {
			if errors.Is(err, io.EOF) {
				break
			}
			continue // skip blank lines (headers are returned here as blank)
		}
		certs, err := c.readCertificatesForNick(path, nick)
		if err != nil {
			return nil, err
		}

		items = append(items, certdbItem{
			nick:       nick,
			certs:      certs,
			trustAttrs: trust,
		})

		// quit if we hit the end
		if errors.Is(err, io.EOF) {
			break
		}
	}

	return items, nil
}

func (c crtutil) parseCertdbItem(line string) (nick string, trust string) {
	line = strings.TrimSpace(line)

	if len(line) == 0 ||
		strings.Contains(line, "Certificate Nickname") ||
		strings.Contains(line, "SSL,S/MIME,JAR/XPI") {
		return
	}

	// Pull out the 'Certificate Nickname'
	// Examples:
	// DigiCert SHA2 Extended Validation Server CA                  ,,
	// Symantec Class 3 Extended Validation SHA256 SSL CA           CT,C,C
	split := strings.Split(line, " ")

	nick = strings.TrimSpace(strings.Join(split[:len(split)-1], " "))
	trust = strings.TrimSpace(split[len(split)-1:][0]) // last

	return
}

// Emulates
//
// /usr/local/opt/nss/bin/certutil -L -d "$dir" -n 'Microsoft IT SSL SHA2' -a
func (c crtutil) readCertificatesForNick(path string, nick string) ([]*x509.Certificate, error) {
	expath, err := c.getExecPath()
	if err != nil {
		return nil, err
	}

	args := []string{
		"-L",
		"-a",
		"-d", c.appendScheme(path),
		"-n", nick,
	}
	cmd := exec.Command(expath, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was:\n %s\n", strings.Join(cmd.Args, " "))
		}
		return nil, err
	}

	certs, err := certutil.ParsePEM(stdout.Bytes())
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// Emulates
//
// $ /usr/local/opt/nss/bin/certutil -M -n <nick> -t <trust-args> -d <dir>
func (c crtutil) modifyTrustAttributes(path string, nick, trustAttrs string) error {
	expath, err := c.getExecPath()
	if err != nil {
		return err
	}

	args := []string{
		"-M",
		"-n", nick,
		"-t", trustAttrs,
		"-d", c.appendScheme(path),
	}
	cmd := exec.Command(expath, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	if debug {
		fmt.Printf("Command was: \n%s\nOutput was: \n%s\n", strings.Join(cmd.Args, " "), stdout.String())
	}
	return err
}

func titleASCII(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] = r[0] - 'a' + 'A'
	}
	return string(r)
}
