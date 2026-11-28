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
	"time"

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
// the embedded Mozilla certdata.txt blocklist, the embedded Apple
// blocklist, or the embedded CCADB Mozilla Removed CA Certificate Report
// list. The match is the certificate SHA-256, the same comparison Matches
// uses, except the Chromium list also matches the SHA-256 of the
// certificate's SubjectPublicKeyInfo against standalone public keys from
// Chromium's blocklist. It does not use OCSP, CRLs, or the network.
func Blocklisted(cert *x509.Certificate) bool {
	return len(BlocklistNames(cert)) > 0
}

// Names for BlocklistNames, in the order a hit is reported.
const (
	BlocklistChromium = "Chromium blocklist"
	BlocklistMozilla  = "Mozilla blocklist"
	BlocklistApple    = "Apple blocklist"
	BlocklistCCADB    = "CCADB removed"
)

// BlocklistNames reports which embedded blocklists contain cert, in a
// stable order: Chromium, Mozilla, Apple, then CCADB removed. It does
// not include the built-in denylist; use Denied for that. The match is
// the certificate SHA-256, the same comparison Matches uses, except the
// Chromium list also matches standalone public-key SPKI hashes.
func BlocklistNames(cert *x509.Certificate) []string {
	if cert == nil || len(cert.Raw) == 0 {
		return nil
	}
	fp := certutil.GetHexSHA256Fingerprint(*cert)
	var names []string
	if fingerprintBlocked(blocklistedFingerprints, fp) || fingerprintBlocked(blocklistedSPKIs, spkiSHA256(cert)) {
		names = append(names, BlocklistChromium)
	}
	if fingerprintBlocked(mozillaBlocklistedFingerprints, fp) {
		names = append(names, BlocklistMozilla)
	}
	if fingerprintBlocked(appleBlocklistedFingerprints, fp) {
		names = append(names, BlocklistApple)
	}
	if fingerprintBlocked(ccadbRemovedBlocklistedFingerprints, fp) {
		names = append(names, BlocklistCCADB)
	}
	return names
}

// MozillaDistrustAfter returns the embedded Mozilla
// CKA_NSS_SERVER_DISTRUST_AFTER instant for cert, or zero when the
// certificate has no recorded date. Dates come from the generated
// mozilla blocklist, not from a live certdata download.
func MozillaDistrustAfter(cert *x509.Certificate) time.Time {
	if cert == nil || len(cert.Raw) == 0 {
		return time.Time{}
	}
	s, ok := mozillaServerDistrustAfter[certutil.GetHexSHA256Fingerprint(*cert)]
	if !ok {
		return time.Time{}
	}
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return tm.UTC()
}

// List label values for table LABELS. JSON blocklists uses the same
// names without the "blocklist:" prefix.
const (
	ListLabelDeny       = "deny"
	ListLabelDistrusted = "distrusted"
	ListBlocklistPrefix = "blocklist:"
)

var listBlocklistIDs = []struct {
	name string
	id   string
}{
	{BlocklistChromium, "chromium"},
	{BlocklistMozilla, "mozilla"},
	{BlocklistApple, "apple"},
	{BlocklistCCADB, "ccadb"},
}

// BlocklistIDs returns the short names of embedded blocklists that contain
// cert, in the same order as BlocklistNames: chromium, mozilla, apple,
// then ccadb. It does not include the built-in denylist.
func BlocklistIDs(cert *x509.Certificate) []string {
	names := BlocklistNames(cert)
	if len(names) == 0 {
		return nil
	}
	var ids []string
	for _, n := range names {
		for _, item := range listBlocklistIDs {
			if n == item.name {
				ids = append(ids, item.id)
				break
			}
		}
	}
	return ids
}

// ListLabels returns the labels for list table output, in a stable order:
// deny (built-in denylist), distrusted (a recorded Mozilla
// CKA_NSS_SERVER_DISTRUST_AFTER instant that is not after now), then
// blocklist:<id> for each BlocklistIDs entry. now is time.Now when zero.
func ListLabels(cert *x509.Certificate, now time.Time) []string {
	if cert == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	var labels []string
	if denied, _ := Denied(cert); denied {
		labels = append(labels, ListLabelDeny)
	}
	if after := MozillaDistrustAfter(cert); !after.IsZero() && !after.After(now) {
		labels = append(labels, ListLabelDistrusted)
	}
	for _, id := range BlocklistIDs(cert) {
		labels = append(labels, ListBlocklistPrefix+id)
	}
	return labels
}

// AddBlocklistedForTest appends fingerprint to the named embedded blocklist
// until the returned function runs. list is "chromium", "mozilla", "apple",
// or "ccadb". It is for tests. Do not call it from parallel tests.
func AddBlocklistedForTest(list, fingerprint string) func() {
	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	switch strings.ToLower(strings.TrimSpace(list)) {
	case "chromium":
		prev := blocklistedFingerprints
		blocklistedFingerprints = append(append([]string{}, prev...), fp)
		return func() { blocklistedFingerprints = prev }
	case "mozilla":
		prev := mozillaBlocklistedFingerprints
		mozillaBlocklistedFingerprints = append(append([]string{}, prev...), fp)
		return func() { mozillaBlocklistedFingerprints = prev }
	case "apple":
		prev := appleBlocklistedFingerprints
		appleBlocklistedFingerprints = append(append([]string{}, prev...), fp)
		return func() { appleBlocklistedFingerprints = prev }
	case "ccadb":
		prev := ccadbRemovedBlocklistedFingerprints
		ccadbRemovedBlocklistedFingerprints = append(append([]string{}, prev...), fp)
		return func() { ccadbRemovedBlocklistedFingerprints = prev }
	default:
		panic("allowlist.AddBlocklistedForTest: unknown blocklist " + list)
	}
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

// FromFile reads a local allowlist file and parses it into items.
// JSON is tried first, then YAML.
func FromFile(path string) (Allowlist, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Allowlist{}, err
	}
	return FromBytes(b)
}

// FromBytes parses allowlist bytes with the same JSON-then-YAML rules as FromFile.
func FromBytes(b []byte) (Allowlist, error) {
	al := Allowlist{}

	// try reading as json
	if err := json.Unmarshal(b, &al); err == nil {
		return al, nil
	}

	// try reading as yaml. A failed JSON unmarshal may have filled al;
	// yaml replaces the fields it reads, matching FromFile.
	if err := yaml.Unmarshal(b, &al); err != nil {
		return al, fmt.Errorf("unable to read allowlist: %w", err)
	}
	return al, nil
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
