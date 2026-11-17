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
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// AcrobatNotInstalledReport is the list --app acrobat text when no registry
// key, no plist, and no address book is found. The process exits 0.
const AcrobatNotInstalledReport = "acrobat: not installed"

const acrobatTrustReportHeader = "acrobat trust settings (read only):"

const (
	acrobatProductAcrobat = "Adobe Acrobat"
	acrobatProductReader  = "Acrobat Reader"

	acrobatAATLLabel = "AATL download"
	acrobatEUTLLabel = "EUTL download"
	acrobatMSLabel   = "Windows store trust"

	// Absent-key labels name the PrefRef settings list looks for.
	// AATL is cAdobeDownload\bLoadSettingsFromURL, or a value named
	// bLoadSettingsFromURL or cAdobeDownload directly under cDigSig.
	// EUTL is cEUTLDownload (bLoadSettingsFromURL inside that key).
	// iMSStoreTrusted is read from cDigSig\cCustomDownload, then cDigSig,
	// then the PrefRef path cASPKI\cMSCAPI_DirectoryProvider.
	acrobatAATLAbsentKey = "cAdobeDownload or bLoadSettingsFromURL"
	acrobatEUTLAbsentKey = "cEUTLDownload"
	acrobatMSAbsentKey   = "iMSStoreTrusted"
)

// acrobatTrustValue is one integer preference. Found is false when the
// value is absent. Key is the relative name that held it, such as
// cAdobeDownload\bLoadSettingsFromURL.
type acrobatTrustValue struct {
	Found bool
	Raw   uint64
	Key   string
}

// acrobatTrustProduct is one Acrobat or Reader version hive.
// Source is the registry key or plist path the values were read from.
type acrobatTrustProduct struct {
	Product string
	Version string
	Source  string
	AATL    acrobatTrustValue
	EUTL    acrobatTrustValue
	MSStore acrobatTrustValue
}

// acrobatTrustRead reads AATL, EUTL, and Windows store trust settings.
// Tests replace it with fake values. The real reader never writes the
// registry or a plist. A nil slice means no registry key and no plist.
// Linux and other systems skip the read and return nil, nil.
var acrobatTrustRead = platformAcrobatTrustRead

// AcrobatTrustReport is the read-only settings report for list --app acrobat.
// The text has no trailing newline. When Acrobat is not installed the text
// is AcrobatNotInstalledReport.
func AcrobatTrustReport() (string, error) {
	products, err := acrobatTrustRead()
	if err != nil {
		return "", err
	}
	book, err := acrobatRoots().find()
	if err != nil {
		return "", err
	}
	return renderAcrobatTrustReport(products, book), nil
}

func renderAcrobatTrustReport(products []acrobatTrustProduct, book string) string {
	book = strings.TrimSpace(book)
	if len(products) == 0 && book == "" {
		return AcrobatNotInstalledReport
	}
	ordered := append([]acrobatTrustProduct(nil), products...)
	sortAcrobatTrustProducts(ordered)

	lines := []string{acrobatTrustReportHeader}
	if len(ordered) == 0 {
		lines = append(lines,
			acrobatValueLine(acrobatAATLLabel, acrobatAATLAbsentKey, acrobatTrustValue{}, formatAcrobatDownload),
			acrobatValueLine(acrobatEUTLLabel, acrobatEUTLAbsentKey, acrobatTrustValue{}, formatAcrobatDownload),
			acrobatValueLine(acrobatMSLabel, acrobatMSAbsentKey, acrobatTrustValue{}, formatAcrobatMSStore),
		)
	} else {
		for _, p := range ordered {
			lines = append(lines, p.heading())
			lines = append(lines,
				acrobatValueLine(acrobatAATLLabel, acrobatAATLAbsentKey, p.AATL, formatAcrobatDownload),
				acrobatValueLine(acrobatEUTLLabel, acrobatEUTLAbsentKey, p.EUTL, formatAcrobatDownload),
				acrobatValueLine(acrobatMSLabel, acrobatMSAbsentKey, p.MSStore, formatAcrobatMSStore),
			)
		}
	}
	lines = append(lines, acrobatAddressBookLine(book))
	return strings.Join(lines, "\n")
}

func (p acrobatTrustProduct) heading() string {
	name := strings.TrimSpace(p.Product)
	ver := strings.TrimSpace(p.Version)
	switch {
	case name != "" && ver != "":
		name = name + " " + ver
	case name == "" && ver != "":
		name = ver
	case name == "":
		name = "Acrobat"
	}
	if src := strings.TrimSpace(p.Source); src != "" {
		return name + " (" + src + "):"
	}
	return name + ":"
}

func acrobatAddressBookLine(path string) string {
	if path == "" {
		return "address book: not found"
	}
	return "address book: " + path
}

func acrobatValueLine(label, absentKey string, v acrobatTrustValue, format func(uint64) string) string {
	key := absentKey
	if v.Found && v.Key != "" {
		key = v.Key
	}
	if !v.Found {
		if key == "" {
			return "  " + label + ": not set"
		}
		return "  " + label + " (" + key + "): not set"
	}
	if key == "" {
		return "  " + label + ": " + format(v.Raw)
	}
	return "  " + label + " (" + key + "): " + format(v.Raw)
}

func formatAcrobatDownload(v uint64) string {
	switch v {
	case 0:
		return "0 (off)"
	case 1:
		return "1 (on)"
	default:
		return strconv.FormatUint(v, 10)
	}
}

// formatAcrobatMSStore prints iMSStoreTrusted. PrefRef: 0x00 none,
// 0x60 validating signatures, 0x62 signatures and certified documents.
func formatAcrobatMSStore(v uint64) string {
	hex := fmt.Sprintf("0x%02x", v)
	if v > 0xff {
		hex = fmt.Sprintf("0x%x", v)
	}
	switch v {
	case 0x00:
		return hex + " (none)"
	case 0x60:
		return hex + " (signatures)"
	case 0x62:
		return hex + " (signatures and certified documents)"
	default:
		return hex
	}
}

func acrobatProductRank(name string) int {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case strings.ToLower(acrobatProductAcrobat):
		return 0
	case strings.ToLower(acrobatProductReader):
		return 1
	default:
		return 2
	}
}

func acrobatVersionNewerName(a, b string) bool {
	ac, an := acrobatVersionClass(a)
	bc, bn := acrobatVersionClass(b)
	return acrobatNewer(
		acrobatHit{name: a, class: ac, nums: an},
		acrobatHit{name: b, class: bc, nums: bn},
	)
}

func sortAcrobatTrustProducts(ps []acrobatTrustProduct) {
	sort.SliceStable(ps, func(i, j int) bool {
		ri, rj := acrobatProductRank(ps[i].Product), acrobatProductRank(ps[j].Product)
		if ri != rj {
			return ri < rj
		}
		li := strings.ToLower(strings.TrimSpace(ps[i].Product))
		lj := strings.ToLower(strings.TrimSpace(ps[j].Product))
		if li != lj {
			return li < lj
		}
		if ps[i].Version != ps[j].Version && acrobatVersionNewerName(ps[i].Version, ps[j].Version) {
			return true
		}
		if ps[i].Version != ps[j].Version && acrobatVersionNewerName(ps[j].Version, ps[i].Version) {
			return false
		}
		return ps[i].Source < ps[j].Source
	})
}

// acrobatProductFromSecurity reads the three settings from one Security
// dictionary. security may be nil. Integers, numeric strings, and bools
// are accepted. The first matching location wins.
func acrobatProductFromSecurity(product, version, source string, security map[string]any) acrobatTrustProduct {
	security = normalizeAcrobatPrefsMap(security)
	var dig map[string]any
	if security != nil {
		dig, _ = asAcrobatMap(security["cDigSig"])
	}
	return acrobatTrustProduct{
		Product: product,
		Version: version,
		Source:  source,
		AATL:    acrobatLookupAATL(dig),
		EUTL:    acrobatLookupEUTL(dig),
		MSStore: acrobatLookupMSStore(security, dig),
	}
}

// acrobatProductsFromDefaults turns one defaults-read dictionary into
// product rows. Top-level keys whose value contains Security are version
// hives (DC, 11.0). A Security dictionary at the top level is used only
// when no version hive was found.
func acrobatProductsFromDefaults(product, source string, root map[string]any) []acrobatTrustProduct {
	if len(root) == 0 {
		return nil
	}
	keys := make([]string, 0, len(root))
	for k := range root {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []acrobatTrustProduct
	for _, ver := range keys {
		hive, ok := asAcrobatMap(root[ver])
		if !ok {
			continue
		}
		security, ok := asAcrobatMap(hive["Security"])
		if !ok {
			continue
		}
		out = append(out, acrobatProductFromSecurity(product, ver, source, security))
	}
	if len(out) == 0 {
		if security, ok := asAcrobatMap(root["Security"]); ok {
			out = append(out, acrobatProductFromSecurity(product, "", source, security))
		}
	}
	return out
}

func acrobatLookupAATL(dig map[string]any) acrobatTrustValue {
	if sub, ok := asAcrobatMap(dig["cAdobeDownload"]); ok {
		if v, ok := asAcrobatUint(sub["bLoadSettingsFromURL"]); ok {
			return acrobatTrustValue{Found: true, Raw: v, Key: `cAdobeDownload\bLoadSettingsFromURL`}
		}
	}
	if v, ok := asAcrobatUint(dig["bLoadSettingsFromURL"]); ok {
		return acrobatTrustValue{Found: true, Raw: v, Key: "bLoadSettingsFromURL"}
	}
	if v, ok := asAcrobatUint(dig["cAdobeDownload"]); ok {
		return acrobatTrustValue{Found: true, Raw: v, Key: "cAdobeDownload"}
	}
	return acrobatTrustValue{}
}

func acrobatLookupEUTL(dig map[string]any) acrobatTrustValue {
	if sub, ok := asAcrobatMap(dig["cEUTLDownload"]); ok {
		if v, ok := asAcrobatUint(sub["bLoadSettingsFromURL"]); ok {
			return acrobatTrustValue{Found: true, Raw: v, Key: `cEUTLDownload\bLoadSettingsFromURL`}
		}
	}
	if v, ok := asAcrobatUint(dig["cEUTLDownload"]); ok {
		return acrobatTrustValue{Found: true, Raw: v, Key: "cEUTLDownload"}
	}
	return acrobatTrustValue{}
}

func acrobatLookupMSStore(security, dig map[string]any) acrobatTrustValue {
	if sub, ok := asAcrobatMap(dig["cCustomDownload"]); ok {
		if v, ok := asAcrobatUint(sub["iMSStoreTrusted"]); ok {
			return acrobatTrustValue{Found: true, Raw: v, Key: `cCustomDownload\iMSStoreTrusted`}
		}
	}
	if v, ok := asAcrobatUint(dig["iMSStoreTrusted"]); ok {
		return acrobatTrustValue{Found: true, Raw: v, Key: "iMSStoreTrusted"}
	}
	// PrefRef stores Windows Integration at
	// Security\cASPKI\cMSCAPI_DirectoryProvider\iMSStoreTrusted.
	// cDigSig locations above are checked first.
	var aspki map[string]any
	if security != nil {
		aspki, _ = asAcrobatMap(security["cASPKI"])
	}
	if msc, ok := asAcrobatMap(aspki["cMSCAPI_DirectoryProvider"]); ok {
		if v, ok := asAcrobatUint(msc["iMSStoreTrusted"]); ok {
			return acrobatTrustValue{Found: true, Raw: v, Key: `cASPKI\cMSCAPI_DirectoryProvider\iMSStoreTrusted`}
		}
	}
	return acrobatTrustValue{}
}

func asAcrobatMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return nil, false
	}
	return m, true
}

// acrobatKeyCanon maps case-insensitive Windows names and unprefixed
// Macintosh PrefRef names onto the Windows-prefixed keys the shared
// lookup uses.
var acrobatKeyCanon = map[string]string{
	"cdigsig":                   "cDigSig",
	"digsig":                    "cDigSig",
	"cadobedownload":            "cAdobeDownload",
	"adobedownload":             "cAdobeDownload",
	"bloadsettingsfromurl":      "bLoadSettingsFromURL",
	"loadsettingsfromurl":       "bLoadSettingsFromURL",
	"ceutldownload":             "cEUTLDownload",
	"eutldownload":              "cEUTLDownload",
	"ccustomdownload":           "cCustomDownload",
	"customdownload":            "cCustomDownload",
	"imsstoretrusted":           "iMSStoreTrusted",
	"msstoretrusted":            "iMSStoreTrusted",
	"caspki":                    "cASPKI",
	"aspki":                     "cASPKI",
	"cmscapi_directoryprovider": "cMSCAPI_DirectoryProvider",
	"mscapi_directoryprovider":  "cMSCAPI_DirectoryProvider",
}

func acrobatCanonicalKey(name string) (canon string, rank int) {
	name = strings.TrimSpace(name)
	canon, ok := acrobatKeyCanon[strings.ToLower(name)]
	if !ok {
		return name, 2
	}
	if name == canon {
		return canon, 0
	}
	return canon, 1
}

func normalizeAcrobatPrefsMap(security map[string]any) map[string]any {
	if security == nil {
		return nil
	}
	m, ok := normalizeAcrobatPrefs(security).(map[string]any)
	if !ok {
		return security
	}
	return m
}

func normalizeAcrobatPrefs(v any) any {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return v
	}
	type cand struct {
		rank int
		val  any
	}
	best := make(map[string]cand, len(m))
	for k, val := range m {
		ck, rank := acrobatCanonicalKey(k)
		val = normalizeAcrobatPrefs(val)
		if prev, ok := best[ck]; !ok || rank < prev.rank {
			best[ck] = cand{rank: rank, val: val}
		}
	}
	out := make(map[string]any, len(best))
	for k, c := range best {
		out[k] = c.val
	}
	return out
}

func asAcrobatUint(v any) (uint64, bool) {
	if arr, ok := v.([]any); ok {
		return acrobatTypedArrayUint(arr)
	}
	return acrobatScalarUint(v)
}

// acrobatTypedArrayUint decodes a Macintosh typed preference
// (`defaults read` prints `(0, 1)`). Type 0 is boolean and only 0 or 1
// is accepted. Type 1 is integer. Other type codes are not trust settings.
func acrobatTypedArrayUint(arr []any) (uint64, bool) {
	if len(arr) != 2 {
		return 0, false
	}
	typ, ok := acrobatScalarUint(arr[0])
	if !ok {
		return 0, false
	}
	switch typ {
	case 0:
		return acrobatBooleanUint(arr[1])
	case 1:
		return acrobatScalarUint(arr[1])
	default:
		return 0, false
	}
}

func acrobatBooleanUint(v any) (uint64, bool) {
	switch n := v.(type) {
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	case uint64:
		if n <= 1 {
			return n, true
		}
	case int:
		if n == 0 || n == 1 {
			return uint64(n), true
		}
	case int64:
		if n == 0 || n == 1 {
			return uint64(n), true
		}
	case string:
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "1", "true", "yes":
			return 1, true
		case "0", "false", "no":
			return 0, true
		}
	}
	return 0, false
}

func acrobatScalarUint(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, true
	case int:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	case string:
		u, err := strconv.ParseUint(strings.TrimSpace(n), 0, 64)
		if err != nil {
			return 0, false
		}
		return u, true
	default:
		return 0, false
	}
}
