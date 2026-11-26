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
	"strings"

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

// ListAndroidGuide is the guide-only list --app android report. It reads a
// pulled Android cacerts directory with FromAndroidDir, loads the allowlist
// at cfg.AllowlistPath, and prints the certificates allowlist.Matches would
// not keep, plus short Settings and adb steps. It does not write to dir or
// to a device. The report is written with ui.WriteConfiguredText so --out
// stages the same way as other list output.
func ListAndroidGuide(dir string, cfg *ui.Config) error {
	certs, err := certutil.FromAndroidDir(dir)
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
	var disable []*x509.Certificate
	for i := range certs {
		if !al.Matches(certs[i]) {
			disable = append(disable, certs[i])
		}
	}
	certutil.Sort(disable)
	var buf bytes.Buffer
	if err := writeAndroidGuide(&buf, disable); err != nil {
		return err
	}
	return ui.WriteConfiguredText(cfg, strings.TrimRight(buf.String(), "\n"))
}

func writeAndroidGuide(w io.Writer, disable []*x509.Certificate) error {
	if len(disable) == 0 {
		if _, err := io.WriteString(w, "Certificates the allowlist/denylist would disable: none\n\n"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "Certificates the allowlist/denylist would disable (%d):\n", len(disable)); err != nil {
			return err
		}
		for i := range disable {
			name := certutil.StringifyPKIXName(disable[i].Subject)
			if name == "" {
				name = "(no subject)"
			}
			fp := certutil.GetHexSHA256Fingerprint(*disable[i])
			if _, err := fmt.Fprintf(w, "\n  %s\n  SHA-256: %s\n", name, fp); err != nil {
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
