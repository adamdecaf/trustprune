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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

var (
	cutil = crtutil{
		execPaths: []string{
			"/usr/local/opt/nss/bin/certutil", // Darwin
			"/usr/bin/certutil",               // Linux
			"/usr/local/bin/certutil",         // FreeBSD
		},
	}

	// certutil trust attrubutes
	// Run `certutil -A -H` for the full list
	trustAttrsProhibited = "p,p,p"
	trustAttrsTrusted    = "CT,C,C"

	// nssBuiltinTokenPrefix marks nicknames certutil prints for the
	// libnssckbi module ("Builtin Object Token") when listing every token.
	nssBuiltinTokenPrefix = "Builtin Object Token:"

	// NSS shared DB (cert9) profile files that must be backed up/restored together.
	nssCert9ProfileFiles = []string{"cert9.db", "key4.db", "pkcs11.txt"}
	// Legacy NSS (cert8) profile files.
	nssCert8ProfileFiles = []string{"cert8.db", "key3.db", "secmod.db"}
)

// nssBackupSourceName is the sidecar inside a backup directory recording the
// profile that backup was taken from. It is not a profile file.
// nssBackupSourceSuffix marks a sibling sidecar ("<name>.source", including
// java's "<file>.bck.source"). Latest-backup selection skips both.
const (
	nssBackupSourceName   = "source"
	nssBackupSourceSuffix = ".source"
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

	// tool, when set, replaces the package certutil client. Tests inject a
	// runner so list and remove do not spawn certutil. Nil uses cutil.
	tool *crtutil
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
		err = s.nssCertutil().addCertificate(s.foundCertdbLocation, path, nick)
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
		details := []string{
			fmt.Sprintf("mirror profile set into %s/%s/<timestamp>", backupParentDisplay(), s.nssType),
			"record the profile path in source",
		}
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

	// Exclusive timestamp dir so two backups in the same second never share a
	// directory (and never share one source sidecar).
	dstDir, err := mkdirExclusiveTimestamp(dir)
	if err != nil {
		return err
	}

	copied := 0
	for _, name := range names {
		src := filepath.Join(s.foundCertdbLocation, name)
		if !file.Exists(src) {
			continue
		}
		if err := file.CopyFile(src, filepath.Join(dstDir, name)); err != nil {
			_ = os.RemoveAll(dstDir)
			return err
		}
		copied++
	}
	if copied == 0 {
		_ = os.RemoveAll(dstDir)
		return fmt.Errorf("no NSS profile files found under %s", s.foundCertdbLocation)
	}
	// Record the profile only after the file set is in place. A failure here
	// removes the new directory so a source-less partial cannot become latest.
	if err := writeNSSBackupSource(dstDir, s.foundCertdbLocation); err != nil {
		_ = os.RemoveAll(dstDir)
		return err
	}
	if err := syncDir(dstDir); err != nil {
		_ = os.RemoveAll(dstDir)
		return err
	}
	if err := syncDir(dir); err != nil {
		_ = os.RemoveAll(dstDir)
		return err
	}
	return nil
}

// nssCleanPath returns the absolute, cleaned profile directory without
// following symlinks.
func nssCleanPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return filepath.Clean(p)
}

// nssResolvedPath follows symlinks after cleaning. It errors if resolution
// fails so a backup cannot record a path whose target may later change.
func nssResolvedPath(p string) (string, error) {
	p = nssCleanPath(p)
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

// nssCanonicalPath returns the absolute, cleaned profile directory, following
// symlinks when they resolve. If resolution fails, it returns the cleaned path.
func nssCanonicalPath(p string) string {
	resolved, err := nssResolvedPath(p)
	if err != nil {
		return nssCleanPath(p)
	}
	return resolved
}

// sameNSSProfile reports whether a recorded source path names profile, either
// literally or after resolving symlinks on both sides.
func sameNSSProfile(recorded, profile string) bool {
	k := nssCanonicalPath(profile)
	if recorded == k {
		return true
	}
	r1, err1 := filepath.EvalSymlinks(recorded)
	r2, err2 := filepath.EvalSymlinks(k)
	return err1 == nil && err2 == nil && r1 == r2
}

// writeNSSBackupSource creates the source sidecar exactly once (O_EXCL).
// The recorded path is the resolved profile directory. A second call fails
// and leaves the first record untouched.
func writeNSSBackupSource(dir, profile string) error {
	recorded, err := nssResolvedPath(profile)
	if err != nil {
		return fmt.Errorf("store/nss: resolving profile path %s: %w", nssCleanPath(profile), err)
	}
	path := filepath.Join(dir, nssBackupSourceName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(recorded + "\n")
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

// readNSSBackupSource returns the recorded profile, or "" when the backup
// predates source recording. A missing backup is an error; a missing sidecar
// is not.
func readNSSBackupSource(src string) (string, error) {
	st, err := os.Stat(src)
	if err != nil {
		return "", err
	}
	path := src + nssBackupSourceSuffix
	if st.IsDir() {
		path = filepath.Join(src, nssBackupSourceName)
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// checkNSSBackupSource refuses a restore whose backup was taken from a
// different profile than dst. Backups without a recorded source are allowed
// only when allowUnknown is set. force skips both a missing record and a
// path mismatch.
//
// NSS passes allowUnknown=false. Firefox profiles share one backup directory,
// so a source-less backup is not known to belong to the profile being restored.
func checkNSSBackupSource(backup, dst string, allowUnknown, force bool) error {
	recorded, err := readNSSBackupSource(backup)
	if err != nil {
		return fmt.Errorf("store/nss: reading source of backup %s: %w", backup, err)
	}
	if recorded == "" {
		if allowUnknown || force {
			return nil
		}
		return fmt.Errorf("store/nss: backup %s has no recorded source profile; pass --force to restore it", backup)
	}
	if sameNSSProfile(recorded, dst) {
		return nil
	}
	if force {
		return nil
	}
	return fmt.Errorf("store/nss: refusing restore: backup %s was taken from %s, not %s; pass --force to restore into a different profile", backup, recorded, nssCanonicalPath(dst))
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

// latestNSSBackupFor returns the newest backup for nssType. When dest is set,
// only backups whose recorded source matches dest are returned; source-less
// (legacy) backups are skipped so allowlist does not treat them as a backup
// of dest. An empty dest does not filter on source. Restore keeps using
// GetLatestBackup so a retargeted profile still surfaces the --force refusal.
func latestNSSBackupFor(nssType, dest string) (string, error) {
	uhome := file.HomeDir()
	if uhome == "" {
		return "", fmt.Errorf("home directory is unavailable")
	}
	primary := filepath.Join(primaryBackupParent(uhome), nssType)
	legacy := ""
	if lp := legacyBackupParent(uhome); lp != "" {
		legacy = filepath.Join(lp, nssType)
	}
	cands, err := listStoreBackupPaths(primary, legacy)
	if err != nil {
		return "", err
	}
	var matched []string
	paths := make(map[string]string, len(cands))
	var firstReadErr error
	for _, path := range cands {
		recorded, err := readNSSBackupSource(path)
		if err != nil {
			if firstReadErr == nil {
				firstReadErr = fmt.Errorf("store/nss: reading source of backup %s: %w", path, err)
			}
			continue
		}
		name := filepath.Base(path)
		// Prefer a later-listed path only if this basename is new;
		// listStoreBackupPaths already prefers primary for a basename.
		if _, ok := paths[name]; ok {
			continue
		}
		paths[name] = path
		if dest != "" {
			if recorded == "" || !sameNSSProfile(recorded, dest) {
				continue
			}
		}
		matched = append(matched, name)
	}
	if best := pickLatestBackupName(matched); best != "" {
		return paths[best], nil
	}
	if firstReadErr != nil {
		return "", firstReadErr
	}
	return "", nil
}

// NSSAllowlistBackupError reports that s is an NSS store with no backup of
// its own directory, while the newest backup for that app was recorded for
// a different directory. The error tells the caller to run trustprune backup
// for this store. ForceRestore suppresses it, matching restore. Non-NSS
// stores, and stores whose newest backup is not a different directory,
// return nil.
func NSSAllowlistBackupError(s Store, app string) error {
	if ForceRestore() {
		return nil
	}
	nssType, storePath, ok := nssAllowlistTarget(s, app)
	if !ok {
		return nil
	}
	// A sourced backup of this directory authorizes the change even when a
	// newer backup was taken from somewhere else. A source-less (legacy)
	// backup does not, matching restore, unless --force is set above.
	matched, err := latestNSSBackupFor(nssType, storePath)
	if err != nil {
		return err
	}
	if matched != "" {
		return nil
	}
	latest, err := latestNSSBackupFor(nssType, "")
	if err != nil {
		return err
	}
	if latest == "" {
		return nil
	}
	recorded, err := readNSSBackupSource(latest)
	if err != nil {
		return fmt.Errorf("store/nss: reading source of backup %s: %w", latest, err)
	}
	if recorded != "" && sameNSSProfile(recorded, storePath) {
		return nil
	}
	label := strings.TrimSpace(app)
	if label == "" {
		label = nssType
	}
	// Print the resolved store path so the message matches the recorded
	// source (Windows 8.3 short names expand under EvalSymlinks).
	display := nssCanonicalPath(storePath)
	cmd := "trustprune backup --app " + nssType
	if display != "" && SupportsStoreOverride(nssType) {
		cmd += " --store " + display
	}
	if recorded == "" {
		return fmt.Errorf("no backup for %s at %s; latest backup %s has no recorded source profile; run: %s; pass --force to allowlist this store anyway", label, display, latest, cmd)
	}
	return fmt.Errorf("no backup for %s at %s; latest backup %s was taken from %s; run: %s; pass --force to allowlist this store anyway", label, display, latest, recorded, cmd)
}

// nssAllowlistTarget is the NSS app and directory allowlist must have a
// backup of. A wrapped store (tests) still exposes the path through GetInfo
// for firefox and poppler.
func nssAllowlistTarget(s Store, app string) (nssType, storePath string, ok bool) {
	app = strings.ToLower(strings.TrimSpace(app))
	if ns, isNSS := s.(nssStore); isNSS {
		nssType = ns.nssType
		storePath = ns.foundCertdbLocation
		if app != "" {
			nssType = app
		}
		return nssType, storePath, nssType != "" && storePath != ""
	}
	if app != "firefox" && app != "poppler" {
		return "", "", false
	}
	info := s.GetInfo()
	if info == nil {
		return "", "", false
	}
	storePath = strings.TrimSpace(info.Path)
	return app, storePath, storePath != ""
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
// Built-in roots from libnssckbi are included via `certutil -L -h all`.
// Nicknames prefixed with "Builtin Object Token:" are read from that module
// and deduplicated against the internal token by nickname and fingerprint.
//
// Note: `dir` represents a directory path which contains a cert.db file
func (s nssStore) List(opts *ListOptions) ([]*x509.Certificate, error) {
	if s.foundCertdbLocation == "" {
		return nil, errors.New("unable to find NSS db directory")
	}

	items, err := s.nssCertutil().listCertsFromDB(s.foundCertdbLocation)
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

	items, err := s.nssCertutil().listCertsFromDB(s.foundCertdbLocation)
	if err != nil {
		return err
	}

	if DryRun() {
		var kept []*x509.Certificate
		var removed []*x509.Certificate
		var details []string
		var extras []string
		for i := range items {
			if al.MatchesAll(items[i].certs) {
				kept = append(kept, items[i].certs...)
				continue
			}
			if items[i].builtinOnly {
				extras = append(extras, fmt.Sprintf("add built-in root %q to the internal token with trust %s", items[i].nick, trustAttrsProhibited))
			}
			for j := range items[i].certs {
				removed = append(removed, items[i].certs[j])
				details = append(details, fmt.Sprintf("distrust %s (nick %s)", formatCertLine(items[i].certs[j]), items[i].nick))
			}
		}
		reportAllowlistDryRun(s.nssType, s.foundCertdbLocation, kept, removed, nil, extras, details)
		return nil
	}

	// Remove trust from each cert if needed.
	for i := range items {
		if al.MatchesAll(items[i].certs) {
			continue
		}

		// allowlist didn't match, blocklist cert
		defer s.notifyToRestart()
		if err := s.distrustNSSItem(items[i]); err != nil {
			return err
		}
	}
	return nil
}

// distrustNSSItem sets p,p,p on item. A root that exists only in libnssckbi
// is copied onto the internal token first; certutil -M cannot edit that module.
func (s nssStore) distrustNSSItem(item certdbItem) error {
	cu := s.nssCertutil()
	if item.builtinOnly {
		dir, err := os.MkdirTemp("", "cert-manage-nss-builtin")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()

		path := filepath.Join(dir, "cert.pem")
		if err := certutil.ToFile(path, item.certs); err != nil {
			return err
		}
		// Trust is p,p,p on add so a failed -M cannot leave the new copy trusted.
		if err := cu.addCertificateTrust(s.foundCertdbLocation, path, item.nick, trustAttrsProhibited); err != nil {
			return err
		}
	}
	return cu.modifyTrustAttributes(s.foundCertdbLocation, item.nick, trustAttrsProhibited)
}

// nssCertutil returns the certutil client for this store.
func (s nssStore) nssCertutil() crtutil {
	if s.tool != nil {
		return *s.tool
	}
	return cutil
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
			return errNoBackupCmd(s.nssType, s.nssType, "trustprune backup --app "+s.nssType)
		}
	}
	// Never copy a backup onto a different profile than it came from unless
	// --force is set. Older backups have no sidecar; those are refused too,
	// before dry-run output or any write.
	if err := checkNSSBackupSource(src, s.foundCertdbLocation, false, ForceRestore()); err != nil {
		return err
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

	// builtinOnly is true when the certificate was read from libnssckbi and
	// is not already present on the internal token. Remove adds it there
	// before applying a trust override.
	builtinOnly bool
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

// certutilRun executes certutil. bin is the resolved executable, or "certutil"
// when a test injected the runner. args is the certutil argument vector.
type certutilRun func(bin string, args []string) (stdout, stderr []byte, err error)

// crtutil represents the NSS cli tool by the same name
// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Tools/certutil
type crtutil struct {
	execPaths []string

	// run, when set, executes certutil instead of exec.Command.
	// Tests inject this so list and remove need no certutil binary and no network.
	run certutilRun
}

func (c crtutil) getExecPath() (string, error) {
	for i := range c.execPaths {
		if file.IsExecutable(c.execPaths[i]) {
			return c.execPaths[i], nil
		}
	}
	// Fall back to PATH so installs outside the usual prefixes are found.
	// Skip Windows: LookPath("certutil") can resolve System32\certutil.exe,
	// which is not the NSS tool.
	if runtime.GOOS != "windows" {
		if p, err := exec.LookPath("certutil"); err == nil {
			return p, nil
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
	return c.addCertificateTrust(dir, where, nick, trustAttrsTrusted)
}

// addCertificateTrust adds a PEM certificate to the internal token with trust.
func (c crtutil) addCertificateTrust(dir string, where string, nick string, trust string) error {
	args := []string{
		"-A", "-a",
		"-n", nick,
		"-t", trust,
		"-i", where,
		"-d", c.appendScheme(dir),
	}
	_, err := c.command(args...)
	return err
}

// Emulates the following
// /usr/local/opt/nss/bin/certutil -L -d '~/Library/Application Support/Firefox/Profiles/rrdlhe7o.default'
// and also `certutil -L -h all` so libnssckbi roots are visible.
//
// TODO(adam): Check for opts.Expired or opts.Revoked
func (c crtutil) listCertsFromDB(path string) ([]certdbItem, error) {
	// Without -h, certutil lists only the internal token.
	internalOut, err := c.command("-L", "-d", c.appendScheme(path))
	if err != nil {
		return nil, err
	}
	internal, err := c.attachCerts(path, c.parseCertutilList(internalOut))
	if err != nil {
		return nil, err
	}

	allOut, err := c.command("-L", "-h", "all", "-d", c.appendScheme(path))
	if err != nil {
		return nil, fmt.Errorf("store/nss: listing built-in roots in %s: %w", path, err)
	}
	return c.mergeBuiltinRoots(path, internal, c.parseCertutilList(allOut))
}

// command runs certutil. A nil run field uses the probed certutil binary.
func (c crtutil) command(args ...string) ([]byte, error) {
	run := c.run
	bin := "certutil"
	if run == nil {
		var err error
		bin, err = c.getExecPath()
		if err != nil {
			return nil, err
		}
		run = defaultCertutilRun
	}
	stdout, stderr, err := run(bin, args)
	if err != nil {
		if debug {
			fmt.Printf("Command was:\n %s %s\n", bin, strings.Join(args, " "))
			fmt.Printf("Output was: %q\n", string(stdout))
			fmt.Printf("Stderr was: %q\n", string(stderr))
		}
		if msg := strings.TrimSpace(string(stderr)); msg != "" {
			err = fmt.Errorf("store/nss: certutil: %w: %s", err, msg)
		}
	}
	return stdout, err
}

func defaultCertutilRun(bin string, args []string) ([]byte, []byte, error) {
	cmd := exec.Command(bin, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// parseCertutilList reads `certutil -L` output. Header and blank lines are skipped.
func (c crtutil) parseCertutilList(out []byte) []certdbItem {
	items := make([]certdbItem, 0)
	for _, line := range strings.Split(string(out), "\n") {
		nick, trust := c.parseCertdbItem(line)
		if nick == "" || trust == "" {
			continue
		}
		items = append(items, certdbItem{
			nick:       nick,
			trustAttrs: trust,
		})
	}
	return items
}

func (c crtutil) attachCerts(path string, items []certdbItem) ([]certdbItem, error) {
	for i := range items {
		certs, err := c.readCertificatesForNick(path, items[i].nick)
		if err != nil {
			return nil, err
		}
		items[i].certs = certs
	}
	return items, nil
}

// mergeBuiltinRoots appends libnssckbi certificates that are not already on
// the internal token. Matching uses the nickname with the token prefix
// removed, and the certificate fingerprint.
func (c crtutil) mergeBuiltinRoots(path string, internal, listed []certdbItem) ([]certdbItem, error) {
	nicks := make(map[string]struct{}, len(internal))
	fps := make(map[string]struct{})
	for i := range internal {
		if internal[i].nick != "" {
			nicks[internal[i].nick] = struct{}{}
		}
		indexNSSFingerprints(fps, internal[i].certs)
	}

	out := internal
	for i := range listed {
		full := listed[i].nick
		name, ok := nssBuiltinNick(full)
		if !ok {
			continue
		}
		if _, dup := nicks[name]; dup {
			continue
		}
		if _, dup := nicks[full]; dup {
			continue
		}
		certs, err := c.readCertificatesForNick(path, full)
		if err != nil {
			return nil, fmt.Errorf("store/nss: reading built-in root %q: %w", full, err)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("store/nss: no certificate for built-in root %q", full)
		}
		if nssFingerprintsOverlap(fps, certs) {
			continue
		}
		out = append(out, certdbItem{
			nick:        name,
			certs:       certs,
			trustAttrs:  listed[i].trustAttrs,
			builtinOnly: true,
		})
		nicks[name] = struct{}{}
		nicks[full] = struct{}{}
		indexNSSFingerprints(fps, certs)
	}
	return out, nil
}

// nssBuiltinNick returns the certificate nickname inside the built-in token.
func nssBuiltinNick(nick string) (string, bool) {
	if !strings.HasPrefix(nick, nssBuiltinTokenPrefix) {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimPrefix(nick, nssBuiltinTokenPrefix))
	if name == "" {
		return "", false
	}
	return name, true
}

func indexNSSFingerprints(dst map[string]struct{}, certs []*x509.Certificate) {
	for i := range certs {
		if certs[i] == nil {
			continue
		}
		dst[certutil.GetHexSHA256Fingerprint(*certs[i])] = struct{}{}
	}
}

func nssFingerprintsOverlap(known map[string]struct{}, certs []*x509.Certificate) bool {
	for i := range certs {
		if certs[i] == nil {
			continue
		}
		if _, ok := known[certutil.GetHexSHA256Fingerprint(*certs[i])]; ok {
			return true
		}
	}
	return false
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
	args := []string{
		"-L",
		"-a",
		"-d", c.appendScheme(path),
		"-n", nick,
	}
	stdout, err := c.command(args...)
	if err != nil {
		return nil, err
	}

	certs, err := certutil.ParsePEM(stdout)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// Emulates
//
// $ /usr/local/opt/nss/bin/certutil -M -n <nick> -t <trust-args> -d <dir>
func (c crtutil) modifyTrustAttributes(path string, nick, trustAttrs string) error {
	args := []string{
		"-M",
		"-n", nick,
		"-t", trustAttrs,
		"-d", c.appendScheme(path),
	}
	stdout, err := c.command(args...)
	if debug {
		fmt.Printf("Command was: \n%s\nOutput was: \n%s\n", strings.Join(args, " "), string(stdout))
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
