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

package certutil

import (
	"crypto/x509"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCertutil__sha1Fingerprint(t *testing.T) {
	certs, _ := FromFile("../../testdata/example.crt")
	if len(certs) != 1 {
		t.Errorf("didn't expect %d certs", len(certs))
	}
	fp := GetHexSHA1Fingerprint(*certs[0])
	if fp != "7e1874a98faa5d6d2f506a8920ff22fbd16652d9" {
		t.Fatalf("fp=%q didn't match", fp)
	}

	// verify it's what openssl gets too
	verify("../../testdata/example.crt", "sha1", "sha1 Fingerprint=7E:18:74:A9:8F:AA:5D:6D:2F:50:6A:89:20:FF:22:FB:D1:66:52:D9", t)
}

func TestCertutil__sha256Fingerprint(t *testing.T) {
	certs, _ := FromFile("../../testdata/example.crt")
	if len(certs) != 1 {
		t.Errorf("didn't expect %d certs", len(certs))
	}
	fp := GetHexSHA256Fingerprint(*certs[0])
	if fp != "05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030" {
		t.Fatalf("fp=%q didn't match", fp)
	}

	// verify with openssl
	verify("../../testdata/example.crt", "sha256", "sha256 Fingerprint=05:A6:DB:38:93:91:DF:92:E0:BE:93:FD:FA:4D:B1:E3:CF:53:90:39:18:B8:D9:D8:5A:9C:39:6C:B5:5D:F0:30", t)
}

func verify(path, algo, fp string, t *testing.T) {
	if err := exec.Command("openssl", "version").Run(); err != nil {
		t.Skipf("openssl ins't installed here.. err=%v", err)
	}

	// Shell out to openssl and verify the cert's fingerprints
	args := strings.Split(fmt.Sprintf("openssl x509 -noout -in %s -%s -fingerprint", path, algo), " ")
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Error(err)
	}
	resp := strings.TrimSpace(string(out))
	// OpenSSL 3 on some macOS images prints SHA1/SHA256; older builds use sha1/sha256.
	if !strings.EqualFold(resp, fp) {
		t.Errorf("bad fingerprint match with openssl:\n  openssl=%s\n  expected=%s", resp, fp)
	}
}

func TestDaysUntilExpiry(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		after time.Time
		want int
	}{
		{"exact day", now.Add(48 * time.Hour), 2},
		{"same day remaining", now.Add(6 * time.Hour), 0},
		{"expired one hour", now.Add(-1 * time.Hour), -1},
		{"expired almost one day", now.Add(-23 * time.Hour), -1},
		{"expired just over one day", now.Add(-25 * time.Hour), -2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &x509.Certificate{NotAfter: tc.after}
			if got := DaysUntilExpiry(c, now); got != tc.want {
				t.Fatalf("DaysUntilExpiry = %d, want %d", got, tc.want)
			}
		})
	}
	if DaysUntilExpiry(nil, now) != 0 {
		t.Fatal("nil cert should return 0")
	}
}
