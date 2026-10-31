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

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

var (
	dryRunMu  sync.Mutex
	dryRun    bool
	dryRunOut io.Writer = os.Stdout
)

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

func reportKeptRawPEM(entries []certutil.PEMEntry) []string {
	return reportKeptRawPEMIn("", entries)
}

func reportKeptRawPEMIn(path string, entries []certutil.PEMEntry) []string {
	var out []string
	for _, e := range entries {
		if e.Cert != nil || len(e.Raw) == 0 {
			continue
		}
		line := fmt.Sprintf("keep unparsable PEM block (%d bytes)", len(e.Raw))
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
