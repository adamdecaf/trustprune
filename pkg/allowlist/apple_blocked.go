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

package allowlist

import (
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
)

// AppleBlockedCert is one row from Apple's published "Blocked Certificates"
// table (https://support.apple.com/en-us/103255). Fingerprint is the
// lowercase hex SHA-256 Apple published. Name is the official certificate
// name from that table. Constrained certificates on the same page are not
// included.
type AppleBlockedCert struct {
	Fingerprint string
	Name        string
}

const appleBlockedHeading = "Blocked Certificates"
const appleConstrainedHeading = "Constrained Certificates"

var (
	htmlTR      = regexp.MustCompile(`(?is)<tr\b[^>]*>(.*?)</tr>`)
	htmlTD      = regexp.MustCompile(`(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>`)
	htmlBR      = regexp.MustCompile(`(?is)<br\s*/?>`)
	htmlTag     = regexp.MustCompile(`(?is)<[^>]*>`)
	htmlHeading = regexp.MustCompile(`(?is)<h[1-6]\b[^>]*>(.*?)</h[1-6]>`)
	hex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ParseAppleBlockedCertificates reads an HTML document and returns the
// certificates in the first table after a "Blocked Certificates" heading.
// Parsing stops at a "Constrained Certificates" heading, so certificates
// Apple only constrains are left out. Fingerprints are lowercase hex
// SHA-256 with spaces and colons removed. An invalid fingerprint, a
// duplicate fingerprint, an empty name, or a missing table is an error.
func ParseAppleBlockedCertificates(r io.Reader) ([]AppleBlockedCert, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty Apple blocked-certificates document")
	}
	doc := string(raw)

	start := indexHeading(doc, appleBlockedHeading)
	if start < 0 {
		return nil, fmt.Errorf("document has no %q heading", appleBlockedHeading)
	}
	section := doc[start:]
	if end := indexHeading(section, appleConstrainedHeading); end >= 0 {
		section = section[:end]
	}

	tableStart := strings.Index(strings.ToLower(section), "<table")
	if tableStart < 0 {
		return nil, fmt.Errorf("no table found under %q", appleBlockedHeading)
	}
	tableRest := section[tableStart:]
	tableEnd := strings.Index(strings.ToLower(tableRest), "</table>")
	if tableEnd < 0 {
		return nil, fmt.Errorf("unterminated table under %q", appleBlockedHeading)
	}
	table := tableRest[:tableEnd+len("</table>")]

	rows := htmlTR.FindAllStringSubmatch(table, -1)
	if len(rows) == 0 {
		return nil, fmt.Errorf("no rows in the %q table", appleBlockedHeading)
	}

	out := make([]AppleBlockedCert, 0, len(rows))
	seen := make(map[string]string, len(rows))
	headerSeen := false
	for _, row := range rows {
		cells := htmlTD.FindAllStringSubmatch(row[1], -1)
		if len(cells) == 0 {
			continue
		}
		texts := make([]string, 0, len(cells))
		for _, c := range cells {
			t := innerText(c[1])
			if t != "" {
				texts = append(texts, t)
			}
		}
		if !headerSeen {
			joined := strings.ToLower(strings.Join(texts, " "))
			if strings.Contains(joined, "fingerprint") || strings.Contains(joined, "certificate name") {
				headerSeen = true
				continue
			}
		}
		fp, name, ok := rowFingerprintName(texts)
		if !ok {
			return nil, fmt.Errorf("blocked-certificates row %q is missing a SHA-256 fingerprint and name", strings.Join(texts, " | "))
		}
		if prev, dup := seen[fp]; dup {
			return nil, fmt.Errorf("duplicate blocked fingerprint %s (%q and %q)", fp, prev, name)
		}
		seen[fp] = name
		out = append(out, AppleBlockedCert{Fingerprint: fp, Name: name})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no blocked certificates found under %q", appleBlockedHeading)
	}
	return out, nil
}

// indexHeading returns the start of the first h1-h6 whose text equals
// heading, or -1. Comments and body text are ignored so a mention of the
// section name outside a heading cannot truncate the table.
func indexHeading(doc, heading string) int {
	for _, m := range htmlHeading.FindAllStringSubmatchIndex(doc, -1) {
		if innerText(doc[m[2]:m[3]]) == heading {
			return m[0]
		}
	}
	return -1
}

func rowFingerprintName(cells []string) (fp, name string, ok bool) {
	for _, cell := range cells {
		compact := strings.ToLower(strings.Map(func(r rune) rune {
			if r == ' ' || r == ':' {
				return -1
			}
			return r
		}, cell))
		if hex64.MatchString(compact) {
			fp = compact
			continue
		}
		if cell != "" && name == "" {
			name = cell
		}
	}
	if fp == "" || name == "" {
		return "", "", false
	}
	return fp, name, true
}

func innerText(s string) string {
	s = htmlBR.ReplaceAllString(s, " ")
	s = htmlTag.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}
