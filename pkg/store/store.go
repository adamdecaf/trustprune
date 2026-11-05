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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/file"
)

var (
	// internal options
	debug = len(os.Getenv("DEBUG")) > 0 ||
		strings.Contains(os.Getenv("GODEBUG"), "x509roots=1")

	// Define a mapping between -app and the Store instance
	appStores = map[string]Store{
		"chrome":  ChromeStore(),
		"firefox": FirefoxStore(),
		"java":    JavaStore(),
		"openssl": OpenSSLStore(),
		"ssl":     SSLStore(),
	}

	// ErrNoBackupMade is returned if no backup of a certificate store can be found
	ErrNoBackupMade = errors.New("unable to make backup of store")

	backupDirPerms os.FileMode = file.TempDirPermissions
)

type ListOptions struct {
	// Include "trusted" certificates
	// This represents what'a good acting application or would return
	Trusted bool

	// Include certificates specifically untrusted by a user/admin
	Untrusted bool

	// TODO(adam): Expired and Revoked
}

// Store represents a certificate store (set of x509 Certificates) and has
// operations on it which can mutate the underlying state (e.g. a file or
// directory).
type Store interface {
	// GetInfo returns basic information about the store
	GetInfo() *Info

	// List returns the currently trusted X509 certificates contained
	// within the cert store
	List(opts *ListOptions) ([]*x509.Certificate, error)

	// Add certificate(s) into the store
	Add([]*x509.Certificate) error

	// Remove will distrust the certificate in the store
	//
	// Note: This may not actually delete the certificate, but modify
	// the store such that the certificate is no longer trusted.
	// This is done when possible to limit the actual deletions to
	// preserve restore capabilities
	Remove(allowlist.Allowlist) error

	// Backup will attempt to save a backup of the certificate store
	// on the local system
	Backup() error

	// GetLatestBackup returns the latest directory (or file) backup
	// of a certificate store.
	//
	// If the path is non-empty the directory or file is guaranteed
	// to exist.
	GetLatestBackup() (string, error)

	// Restore will bring the system back to it's previous state
	// if a backup exists, otherwise it will attempt to bring the
	// cert trust status to the system's default state
	//
	// Optionally, this can take a specific filepath to use as the
	// restore point. This may not be supported on all stores.
	//
	// Note: It is strongly advised that any additional certs installed
	// be verified are still properly installed and working after
	// Restore() is called.
	Restore(where string) error
}

// Info represents high-level information about a certificate store
// There are no guarantees of machine parsing on this data, but it should
// be easily human readable.
type Info struct {
	Name    string
	Version string
	Path    string
}

// Platform returns a new instance of Store for the running os/platform
func Platform() Store {
	return platform()
}

// GetApps returns an array the supported app names
func GetApps() []string {
	var out []string
	for k := range appStores {
		out = append(out, k)
	}
	file.SortNames(out)
	return out
}

// ForApp returns a `Store` instance for the given app
func ForApp(app string) (Store, error) {
	s, ok := appStores[strings.ToLower(app)]
	if !ok {
		return nil, fmt.Errorf("application %q not found", app)
	}
	return s, nil
}

// ForAppWithFile returns a Store for app, optionally overriding the trust-store
// path with filePath. Today only java uses filePath (keystore override); other
// apps ignore it and behave like ForApp. Empty filePath is ForApp.
func ForAppWithFile(app, filePath string) (Store, error) {
	app = strings.ToLower(app)
	if strings.TrimSpace(filePath) == "" {
		return ForApp(app)
	}
	if app == "java" {
		return JavaStoreAt(filePath), nil
	}
	return nil, fmt.Errorf("-file with -app %s is only supported for java (keystore override)", app)
}

// getCertManageDir returns the fs location (always creating first) where a specific
// store can save files into. New backups are written under ~/.trustprune
// (or ~/Library/trustprune on Darwin). The legacy ~/.cert-manage tree is never
// created or modified here.
//
// If `name` is an absolute fs reference then just ensure that directory is created
// and has permissions setup properly.
func getCertManageDir(name string) (string, error) {
	parent, err := getCertManageParentDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(parent, name)
	// If `name` is actually an absolute fs reference then just ensure
	// it's created and owned properly, otherwise append whatever was
	// provided onto the parent dir.
	if filepath.IsAbs(name) {
		s, err := os.Stat(name)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if s != nil && !s.IsDir() {
			return "", fmt.Errorf("since %s exists and cannot be a file, should be a dir", name)
		}
		dir = name
	}

	// Create the dir and set ownership (skipped under dry-run so previews
	// make no filesystem writes at all).
	if !DryRun() {
		err = os.MkdirAll(dir, os.ModeDir|backupDirPerms)
		if err != nil {
			return "", err
		}
	}

	return dir, nil
}

func getCertManageParentDir() (string, error) {
	uhome := file.HomeDir()
	if uhome == "" {
		return "", fmt.Errorf("home directory is unavailable")
	}
	parent := primaryBackupParent(uhome)
	if parent == "" {
		return "", fmt.Errorf("unsupported platform for backups: %s", runtime.GOOS)
	}

	// Make parent dir and set ownership (skipped under dry-run).
	if !DryRun() {
		err := os.MkdirAll(parent, os.ModeDir|backupDirPerms)
		if err != nil {
			return "", err
		}
	}
	return parent, nil
}

// backupParentDisplay is a user-facing path for dry-run previews.
func backupParentDisplay() string {
	switch runtime.GOOS {
	case "darwin":
		return "~/Library/trustprune"
	default:
		return "$HOME/.trustprune"
	}
}

// errNoBackup is returned by Restore when no backup exists for a store. It is
// raised before any filesystem write (including under -dry-run).
func errNoBackup(store, name string) error {
	parent := "~/.trustprune"
	if runtime.GOOS == "darwin" {
		parent = "~/Library/trustprune"
	}
	return fmt.Errorf("no backup for %s in %s/%s; run: trustprune backup", store, parent, name)
}

// primaryBackupParent is where new backups are written.
func primaryBackupParent(uhome string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(uhome, "Library", "trustprune")
	case "linux", "windows":
		return filepath.Join(uhome, ".trustprune")
	default:
		return ""
	}
}

// legacyBackupParent is the pre-rename backup tree. It is read-only: callers
// must never create, move, rename, or delete anything under it.
func legacyBackupParent(uhome string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(uhome, "Library", "cert-manage")
	case "linux", "windows":
		return filepath.Join(uhome, ".cert-manage")
	default:
		return ""
	}
}

// getLatestStoreBackup returns the newest backup entry for a store-relative
// path (for example "linux" or "java"), considering both the primary
// ~/.trustprune tree and the legacy ~/.cert-manage tree. When the same
// basename exists in both, the primary path wins. Legacy is never created.
func getLatestStoreBackup(name string) (string, error) {
	uhome := file.HomeDir()
	if uhome == "" {
		return "", fmt.Errorf("home directory is unavailable")
	}

	primary := filepath.Join(primaryBackupParent(uhome), name)
	legacy := ""
	if lp := legacyBackupParent(uhome); lp != "" {
		legacy = filepath.Join(lp, name)
	}
	return getLatestBackupAmong(primary, legacy)
}

// backupBasenameUnix extracts a comparable unix timestamp from a backup
// basename. Supported forms:
//   - bare digits: "1761780000"
//   - legacy NSS: "cert8.db-1700000000", "cert.db-1700000000"
//   - Java: "cacerts-1761780000.bck" (any "<name>-<unix>.bck")
//
// Unparseable names return ok=false and are skipped by latest-backup selection.
func backupBasenameUnix(name string) (ts int64, ok bool) {
	if name == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(name, 10, 64); err == nil {
		return n, true
	}
	for _, prefix := range []string{"cert8.db-", "cert.db-"} {
		if strings.HasPrefix(name, prefix) {
			rest := name[len(prefix):]
			n, err := strconv.ParseInt(rest, 10, 64)
			if err != nil {
				return 0, false
			}
			return n, true
		}
	}
	if strings.HasSuffix(name, ".bck") {
		base := strings.TrimSuffix(name, ".bck")
		i := strings.LastIndexByte(base, '-')
		if i < 0 || i+1 >= len(base) {
			return 0, false
		}
		n, err := strconv.ParseInt(base[i+1:], 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// pickLatestBackupName chooses the backup basename with the greatest parsed
// unix timestamp. When no name parses, it falls back to lexicographic SortNames
// (last wins) for older non-timestamp layouts used in tests.
func pickLatestBackupName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	bestName := ""
	var bestTS int64
	found := false
	for _, name := range names {
		ts, ok := backupBasenameUnix(name)
		if !ok {
			continue
		}
		if !found || ts > bestTS {
			bestName = name
			bestTS = ts
			found = true
		}
	}
	if found {
		return bestName
	}
	sorted := append([]string(nil), names...)
	file.SortNames(sorted)
	return sorted[len(sorted)-1]
}

// getLatestBackup returns the newest file or dir at a given path.
//
// Newer backups use unix-timestamp basenames (bare digits, legacy NSS
// cert8.db-<ts>/cert.db-<ts>, or Java <name>-<ts>.bck). Selection compares
// those parsed timestamps. If nothing parses, names are sorted lexicographically
// and the last entry is returned.
func getLatestBackup(dir string) (string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	if len(ents) == 0 {
		return "", nil
	}

	names := make([]string, len(ents))
	for i := range ents {
		names[i] = ents[i].Name()
	}
	best := pickLatestBackupName(names)
	if best == "" {
		return "", nil
	}
	return filepath.Join(dir, best), nil
}

// getLatestBackupAmong merges directory listings and returns the path with the
// greatest parsed backup timestamp. primary is preferred for a given basename
// and on equal timestamps. A non-missing read error on primary is returned
// immediately; legacy is only consulted when primary is absent or readable.
// empty legacy is ignored. If no basename parses as a timestamp, falls back to
// lexicographic SortNames (last wins), still preferring primary for ties on the
// same basename.
func getLatestBackupAmong(primary string, legacy string) (string, error) {
	type cand struct {
		path        string
		fromPrimary bool
	}
	seen := make(map[string]cand)
	var names []string

	primaryEnts, primaryErr := os.ReadDir(primary)
	switch {
	case primaryErr == nil:
		for _, ent := range primaryEnts {
			name := ent.Name()
			seen[name] = cand{path: filepath.Join(primary, name), fromPrimary: true}
			names = append(names, name)
		}
	case os.IsNotExist(primaryErr):
		// Fall through to legacy.
	default:
		return "", primaryErr
	}

	if legacy != "" {
		legacyEnts, legacyErr := os.ReadDir(legacy)
		switch {
		case legacyErr == nil:
			for _, ent := range legacyEnts {
				name := ent.Name()
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = cand{path: filepath.Join(legacy, name), fromPrimary: false}
				names = append(names, name)
			}
		case os.IsNotExist(legacyErr):
			// No legacy backups.
		default:
			// No usable primary entries and legacy is unreadable: surface that.
			if len(names) == 0 {
				return "", legacyErr
			}
		}
	}

	if len(names) == 0 {
		return "", nil
	}

	bestName := ""
	var bestTS int64
	bestPrimary := false
	found := false
	for _, name := range names {
		ts, ok := backupBasenameUnix(name)
		if !ok {
			continue
		}
		c := seen[name]
		if !found || ts > bestTS || (ts == bestTS && c.fromPrimary && !bestPrimary) {
			bestName = name
			bestTS = ts
			bestPrimary = c.fromPrimary
			found = true
		}
	}
	if found {
		return seen[bestName].path, nil
	}

	// Nothing parsed: preserve prior lexicographic behavior.
	sorted := append([]string(nil), names...)
	file.SortNames(sorted)
	return seen[sorted[len(sorted)-1]].path, nil
}
