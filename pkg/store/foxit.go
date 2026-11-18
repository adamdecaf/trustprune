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
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/file"
)

// ErrFoxitGuideOnly is returned for every Foxit operation that would read or
// write trust. Foxit's published guides describe Trusted Certificates, FATL,
// and Windows Integration, and they do not document the on-disk list, so
// list and backup are not attempted.
var ErrFoxitGuideOnly = errors.New(foxitGuideMessage)

// foxitGuideMessage is the pruning guide printed for --app foxit.
// Menu names match Foxit's Windows user guide, Mac Protect PDF guide, and
// the automatic-trust blog. The deployment guide names the FATL policy and
// the policy registry keys, and it does not name the registry values.
const foxitGuideMessage = `foxit is guide only: trustprune does not list, back up, or change Foxit trust. The on-disk Trusted Certificates list is unverified, so those operations are not attempted.
Trust comes from the local Trusted Certificates list, from Foxit Approved Trust List (FATL) downloads into that list, from European Union Trusted Lists (EUTL) downloads on Mac, and on Windows from the Windows certificate store when Windows Integration is on.
Remove a root: Protect > Sign & Certify > Trusted Certificates, then delete the certificate or clear its trust.
Turn off FATL so an update does not add it back: File > Preferences > Trust Manager, clear "Load trusted certificates from Foxit server" (on by default, about every 28 days). On Mac, clear "Load trusted certificates from Foxit FATL / EUTL server" for both FATL and EUTL.
Windows Integration: File > Preferences > Signature. Clear trusting Windows certificate store roots for signatures and certified documents. Removing a root from the Windows store does not remove the FATL copy.
Admin policy "Load trusted certificates from Foxit server" (Disable, Enable & Ask before updating, or Enable & Install silently) is under HKCU\Software\Policies\Foxit\PDFEditor or HKLM\SOFTWARE\Policies\Foxit\PDFEditor. The value names are unverified`

const foxitAppName = "foxit"

// foxitCandidate is one install marker, relative to a search root.
// rel is a regular file. drop is how many trailing path elements to remove
// before reporting the install (2 drops Contents/Info.plist, leaving the
// .app bundle).
type foxitCandidate struct {
	rel  []string
	drop int
}

// Editor is before Reader, and current names are before the older
// PhantomPDF and Foxit Reader names. Roots are searched in order, and the
// first existing file wins, so a Reader under the first root is reported
// ahead of an Editor under a later root.
var foxitWindowsCandidates = []foxitCandidate{
	{rel: []string{"Foxit Software", "Foxit PDF Editor", "FoxitPDFEditor.exe"}},
	{rel: []string{"Foxit Software", "Foxit PDF Reader", "FoxitPDFReader.exe"}},
	{rel: []string{"Foxit Software", "Foxit PhantomPDF", "FoxitPhantomPDF.exe"}},
	{rel: []string{"Foxit Software", "Foxit Reader", "FoxitReader.exe"}},
}

var foxitDarwinCandidates = []foxitCandidate{
	{rel: []string{"Foxit PDF Editor.app", "Contents", "Info.plist"}, drop: 2},
	{rel: []string{"Foxit PDF Reader.app", "Contents", "Info.plist"}, drop: 2},
	{rel: []string{"Foxit PhantomPDF.app", "Contents", "Info.plist"}, drop: 2},
	{rel: []string{"Foxit Reader.app", "Contents", "Info.plist"}, drop: 2},
}

// foxitSearch is the set of install roots for one lookup. Tests pass temp
// directories. Empty roots are skipped. Linux and other GOOS values have no
// roots: Foxit on Linux is unverified and is not probed.
type foxitSearch struct {
	goos             string
	programFiles     string
	programFilesX86  string
	applications     string
	userApplications string
}

func currentFoxitSearch() foxitSearch {
	switch runtime.GOOS {
	case "windows":
		pf := strings.TrimSpace(os.Getenv("ProgramFiles"))
		if pf == "" {
			pf = `C:\Program Files`
		}
		pf86 := strings.TrimSpace(os.Getenv("ProgramFiles(x86)"))
		if pf86 == "" {
			pf86 = `C:\Program Files (x86)`
		}
		return foxitSearch{goos: "windows", programFiles: pf, programFilesX86: pf86}
	case "darwin":
		s := foxitSearch{goos: "darwin", applications: "/Applications"}
		if home := file.HomeDir(); home != "" {
			s.userApplications = filepath.Join(home, "Applications")
		}
		return s
	default:
		return foxitSearch{goos: runtime.GOOS}
	}
}

func detectFoxit() Status {
	return locateFoxit(currentFoxitSearch())
}

// locateFoxit reports a Foxit PDF Editor or Reader install. A hit is guide
// only: Path is the executable (Windows) or the .app bundle (macOS).
func locateFoxit(s foxitSearch) Status {
	st := Status{Name: foxitAppName}
	path, ok := s.find()
	if !ok {
		return st
	}
	st.Found = true
	st.GuideOnly = true
	st.Path = path
	return st
}

func (s foxitSearch) find() (string, bool) {
	switch s.goos {
	case "windows":
		return firstFoxitInstall(s.windowsRoots(), foxitWindowsCandidates)
	case "darwin":
		return firstFoxitInstall(s.darwinRoots(), foxitDarwinCandidates)
	default:
		return "", false
	}
}

func (s foxitSearch) windowsRoots() []string {
	return uniqueCleanRoots(s.programFiles, s.programFilesX86)
}

func (s foxitSearch) darwinRoots() []string {
	return uniqueCleanRoots(s.applications, s.userApplications)
}

func uniqueCleanRoots(roots ...string) []string {
	var out []string
	seen := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		root = filepath.Clean(root)
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	return out
}

func firstFoxitInstall(roots []string, cands []foxitCandidate) (string, bool) {
	for _, root := range roots {
		for _, c := range cands {
			parts := make([]string, 0, 1+len(c.rel))
			parts = append(parts, root)
			parts = append(parts, c.rel...)
			full := filepath.Join(parts...)
			if !isRegularFile(full) {
				continue
			}
			reported := full
			for i := 0; i < c.drop; i++ {
				reported = filepath.Dir(reported)
			}
			return reported, true
		}
	}
	return "", false
}

func isRegularFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.Mode().IsRegular()
}

// FoxitStore is the Foxit PDF Reader / Editor app. Every trust operation
// returns ErrFoxitGuideOnly, including under --dry-run. Nothing is read
// from or written to a Foxit trust list.
func FoxitStore() Store {
	return foxitStore{}
}

type foxitStore struct{}

var (
	_ Store    = foxitStore{}
	_ Lister   = foxitStore{}
	_ Modifier = foxitStore{}
	_ Saver    = foxitStore{}
	_ Informer = foxitStore{}
)

func (foxitStore) GetInfo() *Info {
	st := detectFoxit()
	return &Info{Name: "Foxit", Path: st.Path}
}

func (foxitStore) List(*ListOptions) ([]*x509.Certificate, error) {
	return nil, ErrFoxitGuideOnly
}

func (foxitStore) Add([]*x509.Certificate) error {
	return ErrFoxitGuideOnly
}

func (foxitStore) Remove(allowlist.Allowlist) error {
	return ErrFoxitGuideOnly
}

func (foxitStore) Backup() error {
	return ErrFoxitGuideOnly
}

func (foxitStore) GetLatestBackup() (string, error) {
	return "", ErrFoxitGuideOnly
}

func (foxitStore) Restore(string) error {
	return ErrFoxitGuideOnly
}
