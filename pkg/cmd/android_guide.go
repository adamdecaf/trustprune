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

package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/ui"
)

// androidGuideSteps is printed with the disable report. The command never
// writes to a device or to the pulled directory.
const androidGuideSteps = `trustprune cannot change an Android device's certificate store.

To disable a system CA, open Settings > Security > Encryption & credentials > Trusted credentials, tap the certificate, and choose Disable. To uninstall a user CA, use the User tab and Uninstall.

On a rooted device or emulator, adb can pull a copy of the store for this report (for example adb pull /system/etc/security/cacerts or adb pull /apex/com.android.conscrypt/cacerts), then re-run this command on the copied directory. trustprune does not write to the device.
`

// Disable ranking: built-in denylist, then Chromium, Mozilla, Apple, and
// CCADB-removed blocklists, then certificates not in the allowlist. Within
// a rank, user-CA files come before system files, then earlier NotAfter,
// then case-insensitive subject, then SHA-256 fingerprint.
const (
	androidRankDenylist = iota
	androidRankChromium
	androidRankMozilla
	androidRankApple
	androidRankCCADB
	androidRankAllowlist
)

type androidDisable struct {
	file   certutil.AndroidFile
	reason string
	rank   int
}

// ListAndroidGuide is the guide-only list --app android report. It reads a
// pulled Android cacerts directory with FromAndroidDirFiles, loads the
// allowlist at cfg.AllowlistPath, and prints the certificates
// allowlist.Matches would not keep, most important first. The default
// output is a compact table with SUBJECT, REASON, DAYS, a SHA-256
// preview, and LABELS, plus a footer of the form "N to disable of M".
// REASON includes a recorded Mozilla distrust-after instant when one
// exists. LABELS and JSON blocklists/distrust_after use the same
// embedded denylist and blocklist data as list. Settings and adb steps
// print only with -v, and only on the table. --format json and --count
// are supported; other formats are rejected. It does not write to dir
// or to a device. --out stages the same way as other list output.
func ListAndroidGuide(dir string, cfg *ui.Config) error {
	files, err := certutil.FromAndroidDirFiles(dir)
	if err != nil {
		return err
	}
	var path string
	opts := allowlist.FetchOptions{}
	if cfg != nil {
		path = strings.TrimSpace(cfg.AllowlistPath)
		opts.SHA256 = strings.TrimSpace(cfg.AllowlistSHA256)
		opts.Signature = strings.TrimSpace(cfg.AllowlistSignature)
		opts.PubKey = strings.TrimSpace(cfg.AllowlistPubKey)
	}
	al, err := allowlist.FromPathOrURL(path, opts)
	if err != nil {
		return err
	}
	now := time.Now()
	var rows []androidDisable
	for i := range files {
		if !al.Matches(files[i].Cert) {
			rows = append(rows, rankAndroidDisable(files[i], now))
		}
	}
	sortAndroidDisable(rows)
	if cfg != nil && cfg.Count {
		return ui.WriteCount(cfg, len(rows))
	}
	format := ui.DefaultFormat()
	if cfg != nil && strings.TrimSpace(cfg.Format) != "" {
		format = cfg.Format
	}
	switch {
	case strings.EqualFold(format, "json"):
		return writeAndroidGuideJSON(cfg, rows, len(files), now)
	case strings.EqualFold(format, ui.DefaultFormat()):
		verbose := cfg != nil && cfg.Verbose
		var buf bytes.Buffer
		if err := writeAndroidGuide(&buf, rows, len(files), now, verbose); err != nil {
			return err
		}
		return ui.WriteConfiguredText(cfg, strings.TrimRight(buf.String(), "\n"))
	default:
		return fmt.Errorf("list --app android --format supports table and json")
	}
}

func rankAndroidDisable(f certutil.AndroidFile, now time.Time) androidDisable {
	row := androidDisable{file: f, rank: androidRankAllowlist}
	var parts []string
	if denied, name := allowlist.Denied(f.Cert); denied {
		row.rank = androidRankDenylist
		if name != "" {
			parts = append(parts, "built-in denylist ("+name+")")
		} else {
			parts = append(parts, "built-in denylist")
		}
	}
	for _, name := range allowlist.BlocklistNames(f.Cert) {
		parts = append(parts, name)
		if r, ok := androidBlocklistRank(name); ok && r < row.rank {
			row.rank = r
		}
	}
	expired := androidCertExpired(f.Cert, now)
	if len(parts) == 0 {
		switch {
		case f.UserCA() && expired:
			parts = append(parts, "not in the allowlist (user CA, expired)")
		case f.UserCA():
			parts = append(parts, "not in the allowlist (user CA)")
		case expired:
			parts = append(parts, "not in the allowlist (expired)")
		default:
			parts = append(parts, "not in the allowlist")
		}
	} else if expired {
		parts[len(parts)-1] += ", expired"
	}
	if after := allowlist.MozillaDistrustAfter(f.Cert); !after.IsZero() {
		parts = append(parts, "distrust after "+after.UTC().Format(time.RFC3339))
	}
	row.reason = strings.Join(parts, "; ")
	return row
}

func androidBlocklistRank(name string) (int, bool) {
	switch name {
	case allowlist.BlocklistChromium:
		return androidRankChromium, true
	case allowlist.BlocklistMozilla:
		return androidRankMozilla, true
	case allowlist.BlocklistApple:
		return androidRankApple, true
	case allowlist.BlocklistCCADB:
		return androidRankCCADB, true
	default:
		return 0, false
	}
}

func androidCertExpired(cert *x509.Certificate, now time.Time) bool {
	if cert == nil || cert.NotAfter.IsZero() {
		return false
	}
	return !cert.NotAfter.After(now)
}

func sortAndroidDisable(rows []androidDisable) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].rank != rows[j].rank {
			return rows[i].rank < rows[j].rank
		}
		ui, uj := rows[i].file.UserCA(), rows[j].file.UserCA()
		if ui != uj {
			return ui
		}
		ai := androidNotAfter(rows[i].file.Cert)
		aj := androidNotAfter(rows[j].file.Cert)
		if ai.IsZero() != aj.IsZero() {
			return !ai.IsZero()
		}
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return certutil.Less(rows[i].file.Cert, rows[j].file.Cert)
	})
}

func androidNotAfter(cert *x509.Certificate) time.Time {
	if cert == nil {
		return time.Time{}
	}
	return cert.NotAfter.UTC()
}

func writeAndroidGuide(w io.Writer, disable []androidDisable, total int, now time.Time, verbose bool) error {
	if now.IsZero() {
		now = time.Now()
	}
	headers := []string{"SUBJECT", "REASON", "DAYS", "SHA256-FINGERPRINT", "LABELS"}
	if verbose {
		headers = []string{"SUBJECT", "REASON", "DAYS", "SHA256-FINGERPRINT", "PATH", "LABELS"}
	}
	rows := make([][]string, len(disable))
	for i := range disable {
		rows[i] = androidGuideRow(disable[i], now, verbose)
	}
	if _, err := io.WriteString(w, ui.AlignTable(headers, rows)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%d to disable of %d\n", len(disable), total); err != nil {
		return err
	}
	if !verbose {
		return nil
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}
	_, err := io.WriteString(w, androidGuideSteps)
	return err
}

func androidGuideRow(row androidDisable, now time.Time, verbose bool) []string {
	cert := row.file.Cert
	subject := "(no subject)"
	fp := ""
	days := "-"
	labels := "-"
	if cert != nil {
		subject = certutil.StringifyPKIXName(cert.Subject)
		if subject == "" {
			subject = "(no subject)"
		}
		subject = ui.TruncateTableColumn(subject)
		fp = certutil.GetHexSHA256Fingerprint(*cert)
		daysLeft := certutil.DaysUntilExpiry(cert, now)
		if verbose {
			days = fmt.Sprintf("%d", daysLeft)
		} else {
			days = ui.FormatTableDays(daysLeft)
			if len(fp) > ui.FingerprintPreviewLength {
				fp = fp[:ui.FingerprintPreviewLength]
			}
		}
		labels = formatAndroidLabels(cert, now)
	}
	reason := row.reason
	if reason == "" {
		reason = "-"
	}
	if verbose {
		path := strings.TrimSpace(row.file.Path)
		if path == "" {
			path = "-"
		} else {
			path = filepath.Base(path)
		}
		return []string{subject, reason, days, fp, path, labels}
	}
	return []string{subject, reason, days, fp, labels}
}

func formatAndroidLabels(cert *x509.Certificate, now time.Time) string {
	labels := allowlist.ListLabels(cert, now)
	if len(labels) == 0 {
		return "-"
	}
	return strings.Join(labels, ",")
}

type androidDisableJSON struct {
	Subject       string   `json:"subject"`
	Reason        string   `json:"reason"`
	Days          int      `json:"days"`
	Expired       bool     `json:"expired"`
	SHA256        string   `json:"sha256"`
	Path          string   `json:"path,omitempty"`
	UserCA        bool     `json:"user_ca,omitempty"`
	Labels        []string `json:"labels,omitempty"`
	Blocklists    []string `json:"blocklists,omitempty"`
	DistrustAfter string   `json:"distrust_after,omitempty"`
}

type androidGuideJSON struct {
	ToDisable    int                  `json:"to_disable"`
	Total        int                  `json:"total"`
	Certificates []androidDisableJSON `json:"certificates"`
}

func writeAndroidGuideJSON(cfg *ui.Config, disable []androidDisable, total int, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	out := androidGuideJSON{
		ToDisable:    len(disable),
		Total:        total,
		Certificates: make([]androidDisableJSON, 0, len(disable)),
	}
	for i := range disable {
		out.Certificates = append(out.Certificates, androidDisableJSONRow(disable[i], now))
	}
	return ui.WriteOutput(cfg, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	})
}

func androidDisableJSONRow(row androidDisable, now time.Time) androidDisableJSON {
	item := androidDisableJSON{Reason: row.reason, Path: row.file.Path}
	if row.file.UserCA() {
		item.UserCA = true
	}
	cert := row.file.Cert
	if cert == nil {
		return item
	}
	item.Subject = certutil.StringifyPKIXName(cert.Subject)
	item.SHA256 = certutil.GetHexSHA256Fingerprint(*cert)
	days := certutil.DaysUntilExpiry(cert, now)
	item.Days = days
	item.Expired = days < 0
	item.Labels = allowlist.ListLabels(cert, now)
	item.Blocklists = allowlist.BlocklistIDs(cert)
	if after := allowlist.MozillaDistrustAfter(cert); !after.IsZero() {
		item.DistrustAfter = after.UTC().Format(time.RFC3339)
	}
	return item
}
