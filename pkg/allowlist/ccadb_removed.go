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
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
)

const (
	ccadbSHA256FingerprintColumn = "SHA-256 Fingerprint"
	ccadbCommentsColumn          = "Comments"
)

var ccadbRemovedCommentExcludes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)expir`),
	regexp.MustCompile(`(?i)voluntar`),
	regexp.MustCompile(`(?i)asking for the removal`),
	regexp.MustCompile(`(?i)requested (the )?removal`),
	regexp.MustCompile(`(?i)at the (ca|certificate authority).{0,40}request`),
}

// ParseCCADBRemovedRoots reads a CCADB Mozilla Removed CA Certificate Report
// CSV from r and returns the lowercase SHA-256 fingerprints of roots that
// should be blocklisted, in report order.
//
// Official report, listed from https://wiki.mozilla.org/CA/Removed_Certificates :
// https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportCSVFormat
//
// The report has no structured removal-reason column. Comments is free text,
// and many rows have empty comments. Every row is included except those whose
// Comments indicate the removal is only expiry or a voluntary / CA-requested
// withdrawal. A row is excluded when Comments matches (case-insensitive):
//
//	expir
//	voluntar
//	asking for the removal
//	requested (the )?removal
//	at the (ca|certificate authority).{0,40}request
//
// Empty comments are kept. "Trust bit turned off" and other non-matching
// comments are kept. Fingerprints come from the "SHA-256 Fingerprint"
// column (lowercase hex, 64 characters). The "Subject + SPKI SHA256"
// column is not an SPKI hash of the certificate and is not used.
func ParseCCADBRemovedRoots(r io.Reader) ([]string, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true

	header, err := cr.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("ccadb removed roots: empty CSV")
		}
		return nil, fmt.Errorf("ccadb removed roots: header: %w", err)
	}
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "\ufeff")
	}

	fpIdx := csvColumnIndex(header, ccadbSHA256FingerprintColumn)
	if fpIdx < 0 {
		return nil, fmt.Errorf("ccadb removed roots: missing %q column", ccadbSHA256FingerprintColumn)
	}
	commentsIdx := csvColumnIndex(header, ccadbCommentsColumn)
	if commentsIdx < 0 {
		return nil, fmt.Errorf("ccadb removed roots: missing %q column", ccadbCommentsColumn)
	}

	var kept []string
	seen := make(map[string]struct{})
	row := 1
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		row++
		if err != nil {
			return nil, fmt.Errorf("ccadb removed roots: row %d: %w", row, err)
		}
		if csvRecordEmpty(rec) {
			continue
		}
		if fpIdx >= len(rec) || commentsIdx >= len(rec) {
			return nil, fmt.Errorf("ccadb removed roots: row %d: missing required columns", row)
		}
		if ccadbRemovedCommentExcluded(rec[commentsIdx]) {
			continue
		}
		fp, err := normalizeCCADBFingerprint(rec[fpIdx])
		if err != nil {
			return nil, fmt.Errorf("ccadb removed roots: row %d: %w", row, err)
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		kept = append(kept, fp)
	}
	return kept, nil
}

func csvColumnIndex(header []string, name string) int {
	for i := range header {
		if strings.TrimSpace(header[i]) == name {
			return i
		}
	}
	return -1
}

func csvRecordEmpty(rec []string) bool {
	for i := range rec {
		if strings.TrimSpace(rec[i]) != "" {
			return false
		}
	}
	return true
}

func normalizeCCADBFingerprint(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsSpace(r) || r == ':' {
			continue
		}
		b.WriteRune(r)
	}
	raw, err := hex.DecodeString(b.String())
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("invalid SHA-256 fingerprint %q", strings.TrimSpace(s))
	}
	return hex.EncodeToString(raw), nil
}

func ccadbRemovedCommentExcluded(comments string) bool {
	for _, re := range ccadbRemovedCommentExcludes {
		if re.MatchString(comments) {
			return true
		}
	}
	return false
}
