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
	"fmt"
	"io"
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
// allowlist.Matches would not keep, most important first, with a short
// reason for each, plus short Settings and adb steps. It does not write to
// dir or to a device. The report is written with ui.WriteConfiguredText so
// --out stages the same way as other list output.
func ListAndroidGuide(dir string, cfg *ui.Config) error {
	files, err := certutil.FromAndroidDirFiles(dir)
	if err != nil {
		return err
	}
	var path, pin string
	if cfg != nil {
		path = strings.TrimSpace(cfg.AllowlistPath)
		pin = strings.TrimSpace(cfg.AllowlistSHA256)
	}
	al, err := allowlist.FromPathOrURL(path, allowlist.FetchOptions{SHA256: pin})
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
	var buf bytes.Buffer
	if err := writeAndroidGuide(&buf, rows); err != nil {
		return err
	}
	return ui.WriteConfiguredText(cfg, strings.TrimRight(buf.String(), "\n"))
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

func writeAndroidGuide(w io.Writer, disable []androidDisable) error {
	if len(disable) == 0 {
		if _, err := io.WriteString(w, "Certificates the allowlist/denylist would disable: none\n\n"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "Certificates the allowlist/denylist would disable (%d), most important first:\n", len(disable)); err != nil {
			return err
		}
		for i := range disable {
			cert := disable[i].file.Cert
			name := "(no subject)"
			fp := ""
			if cert != nil {
				name = certutil.StringifyPKIXName(cert.Subject)
				if name == "" {
					name = "(no subject)"
				}
				fp = certutil.GetHexSHA256Fingerprint(*cert)
			}
			if _, err := fmt.Fprintf(w, "\n  %s\n  SHA-256: %s\n  Reason: %s\n", name, fp, disable[i].reason); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, androidGuideSteps)
	return err
}
