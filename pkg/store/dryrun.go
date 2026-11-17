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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

var (
	dryRunMu           sync.Mutex
	dryRun             bool
	dryRunVerbose      bool
	dryRunOut          io.Writer = os.Stdout
	forceRestore       bool
	allowlistCountOnly bool
	allowlistStats     *AllowlistStats
)

// AllowlistStats is the classification recorded by the latest allowlist Remove
// that got far enough to decide what to keep. Unmatched lists allowlist
// fingerprints that equaled no certificate the store considered, in file
// order, without duplicates.
type AllowlistStats struct {
	Kept      int
	Removed   int
	Unmatched []string
}

// SetDryRun enables or disables dry-run mode for store mutations.
// When enabled, Add/Remove/Backup/Restore report what they would do and
// make no writes to certificate stores (and create no backup directories).
func SetDryRun(v bool) {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	dryRun = v
}

// DryRun reports whether store mutations are currently in dry-run mode.
func DryRun() bool {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	return dryRun
}

// SetDryRunVerbose controls per-certificate detail lines in allowlist Remove
// dry-run plans. Add, backup, and restore ignore it. The default is false.
func SetDryRunVerbose(v bool) {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	dryRunVerbose = v
}

// DryRunVerbose reports whether allowlist dry-run plans include
// per-certificate remove and keep detail lines.
func DryRunVerbose() bool {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	return dryRunVerbose
}

// SetForceRestore allows Restore to write a backup into a different store path
// than the one recorded when the backup was taken (java, certifi, an explicit
// openssl PEM via -bundle, and an NSS profile). It also allows an NSS backup
// that has no recorded profile, and allows allowlist to change an NSS
// directory whose only backup was recorded for a different directory.
func SetForceRestore(v bool) {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	forceRestore = v
}

// ForceRestore reports whether cross-path restores are allowed.
func ForceRestore() bool {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	return forceRestore
}

// SetAllowlistCountOnly makes allowlist print only the number of certificates
// removed or untrusted. The store still applies the change unless dry-run is
// also set. The plan, unmatched list, and success line are omitted.
func SetAllowlistCountOnly(v bool) {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	allowlistCountOnly = v
}

// AllowlistCountOnly reports whether allowlist output is only the removed count.
func AllowlistCountOnly() bool {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	return allowlistCountOnly
}

// ResetAllowlistStats drops the classification recorded by the previous Remove.
func ResetAllowlistStats() {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	allowlistStats = nil
}

// LastAllowlistStats returns the classification recorded by the latest Remove.
// ok is false when that Remove did not record one.
func LastAllowlistStats() (AllowlistStats, bool) {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	if allowlistStats == nil {
		return AllowlistStats{}, false
	}
	out := *allowlistStats
	if len(out.Unmatched) > 0 {
		out.Unmatched = append([]string(nil), out.Unmatched...)
	}
	return out, true
}

func recordAllowlistStats(kept, removed int, unmatched []string) {
	var copied []string
	if len(unmatched) > 0 {
		copied = append([]string(nil), unmatched...)
	}
	dryRunMu.Lock()
	allowlistStats = &AllowlistStats{Kept: kept, Removed: removed, Unmatched: copied}
	dryRunMu.Unlock()
}

// AllowlistSummaryLine is the final line of a real allowlist run.
func AllowlistSummaryLine(removed, kept int) string {
	return fmt.Sprintf("%d removed, %d kept", removed, kept)
}

// WriteUnmatchedAllowlist lists fingerprints that matched no certificate.
// It writes nothing when unmatched is empty, so a fully matching allowlist
// does not gain a section.
func WriteUnmatchedAllowlist(w io.Writer, unmatched []string) {
	if w == nil || len(unmatched) == 0 {
		return
	}
	fmt.Fprintln(w, "Unmatched allowlist entries:")
	for _, fp := range unmatched {
		fmt.Fprintf(w, "  %s\n", fp)
	}
}

// unmatchedAllowlistFingerprints returns fingerprints that equal no
// certificate in groups. Comparison is exact, the same way Allowlist.Matches
// compares fingerprints. Duplicates are listed once, in input order.
func unmatchedAllowlistFingerprints(fingerprints []string, groups ...[]*x509.Certificate) []string {
	if len(fingerprints) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	for _, group := range groups {
		for _, c := range group {
			if c == nil {
				continue
			}
			seen[certutil.GetHexSHA256Fingerprint(*c)] = struct{}{}
		}
	}
	var out []string
	listed := make(map[string]struct{})
	for _, fp := range fingerprints {
		if _, ok := seen[fp]; ok {
			continue
		}
		if _, dup := listed[fp]; dup {
			continue
		}
		listed[fp] = struct{}{}
		out = append(out, fp)
	}
	return out
}

// finishAllowlist records kept and removed counts and the unmatched
// fingerprints. On a dry-run that is not count-only, it prints the plan.
// It returns true when the caller must not write.
func finishAllowlist(al allowlist.Allowlist, storeName, path string, kept, removed []*x509.Certificate, rawKeep, extras, details []string) bool {
	unmatched := unmatchedAllowlistFingerprints(al.Fingerprints, kept, removed)
	recordAllowlistStats(len(kept), len(removed), unmatched)
	if !DryRun() {
		return false
	}
	if !AllowlistCountOnly() {
		reportAllowlistDryRun(storeName, path, kept, removed, rawKeep, extras, details, unmatched)
	}
	return true
}

// SetDryRunOutput sets the writer used for dry-run plans. Pass nil to reset
// to os.Stdout. Intended for tests.
func SetDryRunOutput(w io.Writer) {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	if w == nil {
		dryRunOut = os.Stdout
		return
	}
	dryRunOut = w
}

func dryRunWriter() io.Writer {
	dryRunMu.Lock()
	defer dryRunMu.Unlock()
	if dryRunOut == nil {
		return os.Stdout
	}
	return dryRunOut
}

// formatCertLine returns a single-line cert description for dry-run plans.
func formatCertLine(c *x509.Certificate) string {
	if c == nil {
		return "(nil certificate)"
	}
	return fmt.Sprintf("%s (SHA256 %s)",
		certutil.StringifyPKIXName(c.Subject),
		certutil.GetHexSHA256Fingerprint(*c))
}

// reportDryRun prints a dry-run plan for a mutating store operation.
func reportDryRun(op, storeName, path string, details ...string) {
	w := dryRunWriter()
	if path != "" {
		fmt.Fprintf(w, "dry-run: would %s %s at %s\n", op, storeName, path)
	} else {
		fmt.Fprintf(w, "dry-run: would %s %s\n", op, storeName)
	}
	for _, d := range details {
		fmt.Fprintf(w, "  %s\n", d)
	}
}

func reportDryRunCerts(prefix string, certs []*x509.Certificate) []string {
	out := make([]string, 0, len(certs))
	for i := range certs {
		out = append(out, fmt.Sprintf("%s %s", prefix, formatCertLine(certs[i])))
	}
	return out
}

// reportAllowlistDryRun prints an allowlist Remove dry-run plan, including
// the closing "no changes made" line and the kept/removed summary.
// kept and removed are certificates. rawKeep lines are already formatted
// ("unparsable PEM block (N bytes)", plus "in <path>" when a path is known)
// and are not counted. extras are operational lines and are always printed.
// details are per-certificate lines and are printed only when verbose is on.
// unmatched fingerprints are listed after those details and before the
// closing lines, and are omitted when empty so the summary stays last.
// Kept is omitted when there is nothing to list.
func reportAllowlistDryRun(storeName, path string, kept, removed []*x509.Certificate, rawKeep, extras, details, unmatched []string) {
	w := dryRunWriter()
	if path != "" {
		fmt.Fprintf(w, "dry-run: would remove certificates from %s at %s\n", storeName, path)
	} else {
		fmt.Fprintf(w, "dry-run: would remove certificates from %s\n", storeName)
	}
	for _, line := range extras {
		fmt.Fprintf(w, "  %s\n", line)
	}
	if len(kept) > 0 || len(rawKeep) > 0 {
		fmt.Fprintln(w, "Kept:")
		for i := range kept {
			fmt.Fprintf(w, "  %s\n", formatCertLine(kept[i]))
		}
		for _, line := range rawKeep {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
	if DryRunVerbose() {
		for _, line := range details {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
	WriteUnmatchedAllowlist(w, unmatched)
	fmt.Fprintln(w, "dry-run: no changes made")
	fmt.Fprintf(w, "dry-run: %d kept, %d removed\n", len(kept), len(removed))
}

func reportKeptRawPEM(entries []certutil.PEMEntry) []string {
	return reportKeptRawPEMIn("", entries)
}

func reportKeptRawPEMIn(path string, entries []certutil.PEMEntry) []string {
	lines := unparsablePEMLines(path, entries)
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = "keep " + line
	}
	return out
}

// unparsablePEMLines formats kept CERTIFICATE blocks that did not parse.
// path, when set, is appended as "in <path>".
func unparsablePEMLines(path string, entries []certutil.PEMEntry) []string {
	var out []string
	for _, e := range entries {
		if e.Cert != nil || len(e.Raw) == 0 {
			continue
		}
		line := fmt.Sprintf("unparsable PEM block (%d bytes)", len(e.Raw))
		if path != "" {
			line = fmt.Sprintf("%s in %s", line, path)
		}
		out = append(out, line)
	}
	return out
}

// listDirBasenames returns basenames of regular files under dir (non-recursive).
// Missing directories yield an empty list and no error.
func listDirBasenames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}

func restoreFileDetails(src, dst string, names []string) []string {
	details := []string{
		fmt.Sprintf("source %s", src),
		fmt.Sprintf("destination %s", dst),
	}
	for _, name := range names {
		details = append(details, fmt.Sprintf("copy %s", filepath.Join(src, name)))
	}
	return details
}
