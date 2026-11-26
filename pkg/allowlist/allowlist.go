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

package allowlist

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
	"gopkg.in/yaml.v3"
)

// Allowlist is the structure holding various `item` types that match against
// x509 certificates
type Allowlist struct {
	// SHA256 fingerprints. YAML and JSON files use the key "fingerprints".
	Fingerprints []string `json:"fingerprints,omitempty" yaml:"fingerprints,omitempty"`

	// ISO 3166-1 two-letter country codes used to match
	// RFC 2253 Distinguished Names in certificates
	Countries []string `json:"Countries,omitempty" yaml:"countries,omitempty"`
}

// Matches checks a given x509 certificate against the criteria and
// returns if it's matched by an item in the allowlist.
//
// A denylisted certificate never matches, even when this allowlist names
// its fingerprint or country. The denylist matches the certificate SHA-256
// and the SubjectPublicKeyInfo SHA-256. Chromium, Mozilla, Apple, and
// CCADB Removed CA Certificate Report blocklist fingerprints never match
// either.
func (a Allowlist) Matches(inc *x509.Certificate) bool {
	if inc == nil {
		return false
	}
	if denied, _ := Denied(inc); denied {
		return false
	}

	fp := certutil.GetHexSHA256Fingerprint(*inc)

	// is the certificate explicitly distrusted?
	if fingerprintBlocked(blocklistedFingerprints, fp) ||
		fingerprintBlocked(mozillaBlocklistedFingerprints, fp) ||
		fingerprintBlocked(appleBlocklistedFingerprints, fp) ||
		fingerprintBlocked(ccadbRemovedBlocklistedFingerprints, fp) {
		return false
	}

	// check if our allowlist's fingerprints include this certificate
	for i := range a.Fingerprints {
		if a.Fingerprints[i] == fp {
			return true
		}
	}

	// check Country in Subject (ASCII ISO codes only; EqualFold
	// would otherwise treat Uſ as matching US)
	for i := range inc.Subject.Country {
		for j := range a.Countries {
			if isASCIICountryCode(inc.Subject.Country[i]) &&
				isASCIICountryCode(a.Countries[j]) &&
				strings.EqualFold(inc.Subject.Country[i], a.Countries[j]) {
				return true
			}
		}
	}

	return false
}

func fingerprintBlocked(list []string, fp string) bool {
	for i := range list {
		if list[i] == fp {
			return true
		}
	}
	return false
}

// Blocklisted reports whether cert is on the embedded Chromium blocklist,
// the embedded Mozilla certdata.txt blocklist, or the embedded CCADB
// Mozilla Removed CA Certificate Report list. The match is the
// certificate SHA-256, the same comparison Matches uses. It does not use
// OCSP, CRLs, or the network.
func Blocklisted(cert *x509.Certificate) bool {
	if cert == nil || len(cert.Raw) == 0 {
		return false
	}
	fp := certutil.GetHexSHA256Fingerprint(*cert)
	return fingerprintBlocked(blocklistedFingerprints, fp) ||
		fingerprintBlocked(mozillaBlocklistedFingerprints, fp) ||
		fingerprintBlocked(appleBlocklistedFingerprints, fp) ||
		fingerprintBlocked(ccadbRemovedBlocklistedFingerprints, fp)
}

// MatchesAll checks if a given list of certificates all match against an allowlist
func (a Allowlist) MatchesAll(cs []*x509.Certificate) bool {
	for i := range cs {
		if !a.Matches(cs[i]) {
			return false
		}
	}
	return true
}

// FromCertificates returns an Allowlist with only the fingerprints of the passed
// certificates included.
func FromCertificates(certs []*x509.Certificate) Allowlist {
	al := Allowlist{}
	for i := range certs {
		if certs[i] == nil {
			continue
		}
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		al.Fingerprints = append(al.Fingerprints, fp)
	}
	return al
}

func isASCIICountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// UnmarshalJSON accepts "fingerprints" and the older "Fingerprints" key.
// "fingerprints" wins when both are present, including an empty array.
// "Countries" is unchanged.
func (a *Allowlist) UnmarshalJSON(data []byte) error {
	type allowlistJSON Allowlist
	var raw struct {
		allowlistJSON
		LegacyFingerprints []string `json:"Fingerprints"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	parsed := Allowlist(raw.allowlistJSON)

	// The alias fills Fingerprints only from "fingerprints". A missing
	// lowercase key leaves that field empty, so the older key is used
	// only when "fingerprints" itself is absent.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if _, ok := keys["fingerprints"]; !ok {
		if _, ok := keys["Fingerprints"]; ok {
			parsed.Fingerprints = raw.LegacyFingerprints
		}
	}
	*a = parsed
	return nil
}

// FromFile reads an allowlist file and parses it into items
func FromFile(path string) (Allowlist, error) {
	al := Allowlist{}
	b, err := os.ReadFile(path)
	if err != nil {
		return al, err
	}

	// try reading as json
	if err = json.Unmarshal(b, &al); err == nil {
		return al, nil
	}

	// try reading as yaml
	if err = yaml.Unmarshal(b, &al); err == nil {
		return al, nil
	}
	return al, fmt.Errorf("unable to read allowlist: %w", err)
}

// ToFile encodes an Allowlist and writes it to path. The format follows the
// file extension: .json writes JSON; .yaml and .yml write YAML. Other
// extensions default to YAML for compatibility with existing callers.
func (a Allowlist) ToFile(path string) error {
	var (
		out []byte
		err error
	)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		out, err = json.MarshalIndent(a, "", "  ")
		if err == nil {
			out = append(out, '\n')
		}
	default:
		out, err = yaml.Marshal(&a)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, file.TempFilePermissions)
}
