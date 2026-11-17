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
	"bytes"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/file"
)

// ErrAcrobatGuideOnly is returned for Acrobat operations that would edit
// trust or list address book entries. list --app acrobat prints
// AcrobatTrustReport instead. addressbook.acrodata is an opaque file:
// backup and restore copy it, and pruning is this guide. Listing address
// book entries read-only was not attempted.
var ErrAcrobatGuideOnly = errors.New(acrobatGuideMessage)

// acrobatGuideMessage is the pruning guide printed for add, allowlist, and
// connect. Menu names match Adobe's Trust Manager and Trusted Identities
// preferences. The address book format and the AATL download interval are
// unverified.
const acrobatGuideMessage = `acrobat pruning is guide only: trustprune does not edit Acrobat trust or list address book entries. list reports AATL, EUTL, and Windows store trust settings. backup and restore copy addressbook.acrodata as an opaque file and do not parse it. Listing address book entries read-only was not attempted. The address book format is unverified.
Trust comes from Trusted Identities in that address book. AATL and EUTL downloads load certificates into the same file. On Windows, Windows Integration can also trust the Windows certificate store.
Remove a root in Acrobat or Reader: Preferences > Trust Manager, or Preferences > Signatures > Identities & Trusted Certificates. Delete the certificate or clear its trust.
Turn off AATL and EUTL downloads in Preferences > Trust Manager so an update does not add the certificate back. The download interval is unverified.
Windows Integration is Windows only. Turning it off stops trusting Windows certificate store roots for signatures. A copy already in the address book stays.
Quit Acrobat, AcroRd32, and AdobeReader before backup or restore`

// ErrAcrobatRunning is returned when backup or restore is attempted while
// Acrobat, AcroRd32, or AdobeReader is running. The address book is left
// untouched.
var ErrAcrobatRunning = errors.New("acrobat is running; quit Acrobat, AcroRd32, or AdobeReader before backup or restore")

// errAcrobatAddressBookNotFound is the stable not-found text. A root, when
// there is one, is appended with "under".
var errAcrobatAddressBookNotFound = errors.New("addressbook.acrodata not found")

const (
	acrobatAppName             = "acrobat"
	acrobatBackupDir           = "acrobat"
	acrobatAddressBookFilename = "addressbook.acrodata"

	// acrobatClassOther is a version directory whose name is neither DC nor
	// a dotted integer. Numbered folders outrank it. DC outranks both.
	acrobatClassOther   = 0
	acrobatClassNumeric = 1
	acrobatClassDC      = 2
)

// acrobatProcessNames are the process image names that hold the address book
// open. Matching is case-insensitive and accepts an .exe suffix.
var acrobatProcessNames = []string{"Acrobat", "AcroRd32", "AdobeReader"}

// acrobatProcessRunning reports whether one of acrobatProcessNames is running.
// Tests replace it. A non-nil error means the check could not be made, and
// backup and restore refuse rather than copy a file Acrobat might have open.
var acrobatProcessRunning = detectAcrobatRunning

// acrobatRoots returns the directories searched for addressbook.acrodata.
// Tests replace it so a fixture is used instead of the real profile.
var acrobatRoots = currentAcrobatSearch

// acrobatSearch is the set of profile roots for one lookup. Tests pass temp
// directories. Empty roots are skipped. Linux and other GOOS values have no
// roots: a current Acrobat build for Linux is unverified and is not probed.
type acrobatSearch struct {
	goos    string
	appData string
	home    string
}

func currentAcrobatSearch() acrobatSearch {
	switch runtime.GOOS {
	case "windows":
		return acrobatSearch{goos: "windows", appData: os.Getenv("APPDATA")}
	case "darwin":
		return acrobatSearch{goos: "darwin", home: file.HomeDir()}
	default:
		return acrobatSearch{goos: runtime.GOOS}
	}
}

func detectAcrobat() Status {
	return locateAcrobat(acrobatRoots())
}

// locateAcrobat reports the newest addressbook.acrodata. Path is that file.
// A hit is a real store path (backup and restore copy it), so GuideOnly stays
// false. Pruning is still a guide.
func locateAcrobat(s acrobatSearch) Status {
	st := Status{Name: acrobatAppName}
	path, err := s.find()
	if err != nil || path == "" {
		return st
	}
	st.Found = true
	st.Path = path
	return st
}

// root is the Acrobat version parent (.../Adobe/Acrobat). ok is false when
// this GOOS is not probed or the root input is blank.
func (s acrobatSearch) root() (string, bool) {
	switch s.goos {
	case "windows":
		appData := strings.TrimSpace(s.appData)
		if appData == "" {
			return "", false
		}
		return filepath.Join(appData, "Adobe", "Acrobat"), true
	case "darwin":
		home := strings.TrimSpace(s.home)
		if home == "" {
			return "", false
		}
		return filepath.Join(home, "Library", "Application Support", "Adobe", "Acrobat"), true
	default:
		return "", false
	}
}

// find returns the newest <ver>/Security/addressbook.acrodata under root.
// An empty path and a nil error means the file is not there. A non-nil error
// means the version directory could not be read.
func (s acrobatSearch) find() (string, error) {
	root, ok := s.root()
	if !ok {
		return "", nil
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("acrobat: read %s: %w", root, err)
	}

	var best acrobatHit
	found := false
	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		full := filepath.Join(root, ent.Name(), "Security", acrobatAddressBookFilename)
		fi, err := os.Stat(full)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		class, nums := acrobatVersionClass(ent.Name())
		hit := acrobatHit{
			name:  ent.Name(),
			path:  full,
			class: class,
			nums:  nums,
			mod:   fi.ModTime(),
		}
		if !found || acrobatNewer(hit, best) {
			best = hit
			found = true
		}
	}
	if !found {
		return "", nil
	}
	return best.path, nil
}

type acrobatHit struct {
	name  string
	path  string
	class int
	nums  []int
	mod   time.Time
}

// acrobatVersionClass ranks a version directory name.
// DC (any case) is the Document Cloud folder Adobe documents as the current
// per-user path. Numbered names (2024, 11.0, 10.0, 9.0) compare as dotted
// integers, which matches the preference reference import order 11.0, then
// 10.0, then 9.0. Any other name is older than both.
func acrobatVersionClass(name string) (class int, nums []int) {
	if strings.EqualFold(name, "DC") {
		return acrobatClassDC, nil
	}
	parts := strings.Split(name, ".")
	nums = make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return acrobatClassOther, nil
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return acrobatClassOther, nil
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return acrobatClassOther, nil
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return acrobatClassOther, nil
	}
	return acrobatClassNumeric, nums
}

// acrobatNewer reports whether a is a newer version hit than b.
// DC beats every numbered folder, including a year folder such as 2024.
// A higher dotted number beats a lower one (2024, then 11.0, then 10.0).
// Equal rank uses the later address-book modification time, then the
// greater case-insensitive name, so the choice is stable.
func acrobatNewer(a, b acrobatHit) bool {
	if a.class != b.class {
		return a.class > b.class
	}
	if a.class == acrobatClassNumeric {
		if c := compareAcrobatNums(a.nums, b.nums); c != 0 {
			return c > 0
		}
	}
	if !a.mod.Equal(b.mod) {
		return a.mod.After(b.mod)
	}
	return strings.ToLower(a.name) > strings.ToLower(b.name)
}

func compareAcrobatNums(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av > bv {
				return 1
			}
			return -1
		}
	}
	return 0
}

func acrobatNotFoundError(root string) error {
	root = strings.TrimSpace(root)
	if root == "" {
		return errAcrobatAddressBookNotFound
	}
	return fmt.Errorf("%w under %s", errAcrobatAddressBookNotFound, root)
}

func acrobatAddressBook() (string, error) {
	search := acrobatRoots()
	path, err := search.find()
	if err != nil {
		return "", err
	}
	if path == "" {
		root, _ := search.root()
		return "", acrobatNotFoundError(root)
	}
	return path, nil
}

func acrobatRefuseIfRunning() error {
	running, err := acrobatProcessRunning()
	if err != nil {
		return fmt.Errorf("acrobat: check whether Acrobat is running: %w", err)
	}
	if running {
		return ErrAcrobatRunning
	}
	return nil
}

func detectAcrobatRunning() (bool, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
		if err != nil {
			return false, fmt.Errorf("acrobat: tasklist: %w", err)
		}
		return tasklistHasAcrobat(out)
	case "darwin":
		out, err := exec.Command("ps", "-ax", "-o", "comm=").Output()
		if err != nil {
			return false, fmt.Errorf("acrobat: ps: %w", err)
		}
		return psCommHasAcrobat(out), nil
	default:
		return false, nil
	}
}

func tasklistHasAcrobat(out []byte) (bool, error) {
	r := csv.NewReader(bytes.NewReader(out))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("acrobat: parse tasklist: %w", err)
		}
		if len(rec) == 0 {
			continue
		}
		if acrobatBaseMatch(rec[0]) {
			return true, nil
		}
	}
}

func psCommHasAcrobat(out []byte) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if acrobatBaseMatch(line) {
			return true
		}
	}
	return false
}

func acrobatBaseMatch(image string) bool {
	base := strings.TrimSpace(image)
	if base == "" {
		return false
	}
	base = filepath.Base(base)
	for _, name := range acrobatProcessNames {
		if strings.EqualFold(base, name) || strings.EqualFold(base, name+".exe") {
			return true
		}
	}
	return false
}

// AcrobatStore is the Adobe Acrobat / Reader address book. add and remove
// print the pruning guide. The list command reports AATL, EUTL, and Windows
// store trust settings and does not list address book entries. backup and
// restore copy addressbook.acrodata as an opaque file and refuse while
// Acrobat is running.
func AcrobatStore() Store {
	return acrobatStore{}
}

type acrobatStore struct{}

var _ Store = acrobatStore{}

func (acrobatStore) GetInfo() *Info {
	st := detectAcrobat()
	return &Info{Name: "Acrobat", Path: st.Path}
}

// List reports no certificates. add, remove, and connect use this guide.
// trustprune list --app acrobat prints AcrobatTrustReport instead and does
// not parse the address book.
func (acrobatStore) List(*ListOptions) ([]*x509.Certificate, error) {
	return nil, ErrAcrobatGuideOnly
}

func (acrobatStore) Add([]*x509.Certificate) error {
	return ErrAcrobatGuideOnly
}

func (acrobatStore) Remove(allowlist.Allowlist) error {
	return ErrAcrobatGuideOnly
}

func (acrobatStore) Backup() error {
	if err := acrobatRefuseIfRunning(); err != nil {
		return err
	}
	path, err := acrobatAddressBook()
	if err != nil {
		return err
	}
	if DryRun() {
		reportDryRun("backup", acrobatAppName, path,
			fmt.Sprintf("copy %s into %s/%s/<timestamp>/%s", path, backupParentDisplay(), acrobatBackupDir, acrobatAddressBookFilename))
		return nil
	}
	parent, err := getCertManageDir(acrobatBackupDir)
	if err != nil {
		return err
	}
	dir, err := mkdirExclusiveTimestamp(parent)
	if err != nil {
		return err
	}
	dst := filepath.Join(dir, acrobatAddressBookFilename)
	if err := file.CopyFile(path, dst); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("backup %s to %s: %w", path, dst, err)
	}
	if err := writeAcrobatBackupSource(dir, path); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	return nil
}

func (acrobatStore) GetLatestBackup() (string, error) {
	dir, err := getLatestStoreBackup(acrobatBackupDir)
	if err != nil {
		return "", fmt.Errorf("getLatestBackup: error getting acrobat backup directory err=%w", err)
	}
	return dir, nil
}

func (s acrobatStore) Restore(where string) error {
	if err := acrobatRefuseIfRunning(); err != nil {
		return err
	}
	path, err := acrobatAddressBook()
	if err != nil {
		return err
	}
	src := strings.TrimSpace(where)
	if src == "" {
		src, err = s.GetLatestBackup()
		if err != nil {
			return err
		}
		if src == "" {
			return errNoBackupCmd(acrobatAppName, acrobatBackupDir, "trustprune backup --app acrobat")
		}
	}
	srcFile, err := acrobatBackupFile(src)
	if err != nil {
		return err
	}
	if err := checkAcrobatBackupSource(src, path, true, ForceRestore()); err != nil {
		return err
	}
	if DryRun() {
		reportDryRun("restore", acrobatAppName, path,
			fmt.Sprintf("source %s", srcFile),
			fmt.Sprintf("stage into %s.restore-tmp then swap over %s", path, path))
		return nil
	}
	if err := sslInstallFile(srcFile, path); err != nil {
		return fmt.Errorf("restore %s from %s: %w", path, srcFile, err)
	}
	return nil
}

func acrobatBackupFile(src string) (string, error) {
	st, err := os.Stat(src)
	if err != nil {
		return "", fmt.Errorf("acrobat backup %s: %w", src, err)
	}
	if st.IsDir() {
		candidate := filepath.Join(src, acrobatAddressBookFilename)
		if !isRegularFile(candidate) {
			return "", fmt.Errorf("acrobat backup dir %s has no %s", src, acrobatAddressBookFilename)
		}
		return candidate, nil
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("acrobat backup %s is not a file", src)
	}
	return src, nil
}

func acrobatCanonicalPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	p = filepath.Clean(p)
	if resolved, err := filepath.EvalSymlinks(p); err == nil && resolved != "" {
		return resolved
	}
	return p
}

func sameAcrobatPath(recorded, dest string) bool {
	return acrobatCanonicalPath(recorded) == acrobatCanonicalPath(dest)
}

func acrobatBackupSourceFile(src string) string {
	st, err := os.Stat(src)
	if err == nil && st.IsDir() {
		return filepath.Join(src, nssBackupSourceName)
	}
	if filepath.Base(src) == acrobatAddressBookFilename {
		return filepath.Join(filepath.Dir(src), nssBackupSourceName)
	}
	return src + nssBackupSourceSuffix
}

func writeAcrobatBackupSource(dir, storePath string) error {
	path := filepath.Join(dir, nssBackupSourceName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(acrobatCanonicalPath(storePath) + "\n")
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

func readAcrobatBackupSource(src string) (string, error) {
	b, err := os.ReadFile(acrobatBackupSourceFile(src))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// checkAcrobatBackupSource refuses a restore whose backup was taken from a
// different address book than dest. A backup with no recorded source is
// allowed when allowUnknown is set. force skips a path mismatch.
func checkAcrobatBackupSource(backup, dst string, allowUnknown, force bool) error {
	recorded, err := readAcrobatBackupSource(backup)
	if err != nil {
		return fmt.Errorf("reading source of acrobat backup %s: %w", backup, err)
	}
	if recorded == "" {
		if allowUnknown || force {
			return nil
		}
		return fmt.Errorf("acrobat backup %s has no recorded address book path; pass it with restore --backup to use it", backup)
	}
	if sameAcrobatPath(recorded, dst) {
		return nil
	}
	if force {
		return nil
	}
	return fmt.Errorf("refusing restore: acrobat backup %s was taken from %s, not %s; pass --force to restore into a different path", backup, recorded, acrobatCanonicalPath(dst))
}
