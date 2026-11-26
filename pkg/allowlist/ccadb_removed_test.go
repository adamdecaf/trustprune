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
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

const (
	ccadbRemovedCSV        = "testdata/ccadb-removed-ca-certificates.csv"
	ccadbRemovedExcerptCSV = "testdata/ccadb-removed-ca-certificates.excerpt.csv"
)

var ccadbRemovedExcludedNames = []string{
	"certSIGN ROOT CA",
	"Entrust Root Certification Authority",
	"EE Certification Centre Root CA",
}

func TestParseCCADBRemovedRoots_excerpt(t *testing.T) {
	t.Parallel()

	rows := readCCADBReport(t, ccadbRemovedExcerptCSV)
	got, err := ParseCCADBRemovedRoots(openTestdata(t, ccadbRemovedExcerptCSV))
	if err != nil {
		t.Fatal(err)
	}

	excluded := make(map[string]string, len(ccadbRemovedExcludedNames))
	for _, name := range ccadbRemovedExcludedNames {
		fp := rows.fingerprint(t, name)
		excluded[name] = fp
		if containsString(got, fp) {
			t.Errorf("excluded root %q fingerprint %s was kept", name, fp)
		}
	}

	var wantKept []string
	for _, row := range rows {
		if _, skip := excluded[row.name]; skip {
			continue
		}
		wantKept = append(wantKept, row.fingerprint)
		if !containsString(got, row.fingerprint) {
			t.Errorf("kept root %q fingerprint %s was excluded", row.name, row.fingerprint)
		}
	}
	if !containsString(got, rows.fingerprint(t, "CNNIC ROOT")) {
		t.Fatal("CNNIC ROOT must be kept")
	}
	aol := rows.byName(t, "America Online Root Certification Authority 1")
	if strings.TrimSpace(aol.comments) != "" {
		t.Fatalf("America Online root comments should be empty, got %q", aol.comments)
	}
	if !containsString(got, aol.fingerprint) {
		t.Fatal("empty-comment America Online root must be kept")
	}
	if len(got) != len(wantKept) {
		t.Fatalf("kept %d fingerprints, want %d", len(got), len(wantKept))
	}
	assertFingerprintsFromColumn(t, got, rows)
}

func TestParseCCADBRemovedRoots_fullTestdata(t *testing.T) {
	t.Parallel()

	rows := readCCADBReport(t, ccadbRemovedCSV)
	got, err := ParseCCADBRemovedRoots(openTestdata(t, ccadbRemovedCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 105 {
		t.Fatalf("kept %d fingerprints, want 105", len(got))
	}

	for _, name := range ccadbRemovedExcludedNames {
		fp := rows.fingerprint(t, name)
		if containsString(got, fp) {
			t.Errorf("excluded root %q fingerprint %s was kept", name, fp)
		}
	}

	assertFingerprintsFromColumn(t, got, rows)

	cnnic := rows.fingerprint(t, "CNNIC ROOT")
	aol := rows.fingerprint(t, "America Online Root Certification Authority 1")
	if !containsString(got, cnnic) {
		t.Fatalf("kept list missing CNNIC ROOT fingerprint %s parsed from the CSV", cnnic)
	}
	if !containsString(got, aol) {
		t.Fatalf("kept list missing America Online fingerprint %s parsed from the CSV", aol)
	}
}

func TestParseCCADBRemovedRoots_commentFilter(t *testing.T) {
	t.Parallel()

	fp := strings.Repeat("ab", 32)
	cases := []struct {
		name     string
		comments string
		keep     bool
	}{
		{name: "empty comments", comments: "", keep: true},
		{name: "trust bit", comments: "Trust bit turned off", keep: true},
		{name: "expiry", comments: "Root certificate expires in November 2026", keep: false},
		{name: "expiring", comments: "intermediate CAs expiring in June 2025", keep: false},
		{name: "voluntary", comments: "Voluntary withdrawal from the program", keep: false},
		{name: "asking for the removal", comments: "certSIGN is asking for the removal of this bit", keep: false},
		{name: "requested removal", comments: "The CA requested removal from NSS", keep: false},
		{name: "requested the removal", comments: "The CA requested the removal of this root", keep: false},
		{name: "at the CA request", comments: "Removed at the CA request after incident review", keep: false},
		{name: "at the certificate authority request", comments: "Removed at the certificate authority's request", keep: false},
		{name: "case insensitive", comments: "ASKING FOR THE REMOVAL", keep: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseCCADBRemovedRoots(strings.NewReader(ccadbTestCSV(t, fp, tc.comments)))
			if err != nil {
				t.Fatal(err)
			}
			kept := containsString(got, fp)
			if kept != tc.keep {
				t.Fatalf("comments %q: kept=%v want %v", tc.comments, kept, tc.keep)
			}
		})
	}
}

func TestParseCCADBRemovedRoots_errors(t *testing.T) {
	t.Parallel()

	if _, err := ParseCCADBRemovedRoots(strings.NewReader("")); err == nil {
		t.Fatal("empty CSV should error")
	}
	if _, err := ParseCCADBRemovedRoots(strings.NewReader("Comments\nhello\n")); err == nil {
		t.Fatal("missing SHA-256 Fingerprint column should error")
	}
	if _, err := ParseCCADBRemovedRoots(strings.NewReader("SHA-256 Fingerprint\n" + strings.Repeat("ab", 32) + "\n")); err == nil {
		t.Fatal("missing Comments column should error")
	}
	if _, err := ParseCCADBRemovedRoots(strings.NewReader(ccadbTestCSV(t, "not-a-fingerprint", ""))); err == nil {
		t.Fatal("invalid fingerprint should error")
	}
}

func ccadbTestCSV(t *testing.T, fp, comments string) string {
	t.Helper()
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"Root Certificate Name", "SHA-256 Fingerprint", "Comments"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write([]string{"Test Root", fp, comments}); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func openTestdata(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

type ccadbReportRow struct {
	name        string
	fingerprint string
	spki        string
	comments    string
}

type ccadbReport []ccadbReportRow

func readCCADBReport(t *testing.T, path string) ccadbReport {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	cr := csv.NewReader(f)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		t.Fatal(err)
	}
	fpIdx := csvColumnIndex(header, ccadbSHA256FingerprintColumn)
	spkiIdx := csvColumnIndex(header, "Subject + SPKI SHA256")
	nameIdx := csvColumnIndex(header, "Root Certificate Name")
	commentsIdx := csvColumnIndex(header, ccadbCommentsColumn)
	if fpIdx < 0 || nameIdx < 0 || commentsIdx < 0 {
		t.Fatalf("testdata %s is missing required columns", path)
	}
	var rows ccadbReport
	for {
		rec, err := cr.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		fp, err := normalizeCCADBFingerprint(rec[fpIdx])
		if err != nil {
			t.Fatal(err)
		}
		spki := ""
		if spkiIdx >= 0 && spkiIdx < len(rec) && strings.TrimSpace(rec[spkiIdx]) != "" {
			spki, err = normalizeCCADBFingerprint(rec[spkiIdx])
			if err != nil {
				t.Fatal(err)
			}
		}
		rows = append(rows, ccadbReportRow{
			name:        strings.TrimSpace(rec[nameIdx]),
			fingerprint: fp,
			spki:        spki,
			comments:    rec[commentsIdx],
		})
	}
	if len(rows) == 0 {
		t.Fatalf("no rows in %s", path)
	}
	return rows
}

func (rows ccadbReport) byName(t *testing.T, name string) ccadbReportRow {
	t.Helper()
	for _, row := range rows {
		if row.name == name {
			return row
		}
	}
	t.Fatalf("no row named %q", name)
	return ccadbReportRow{}
}

func (rows ccadbReport) fingerprint(t *testing.T, name string) string {
	t.Helper()
	return rows.byName(t, name).fingerprint
}

func assertFingerprintsFromColumn(t *testing.T, got []string, rows ccadbReport) {
	t.Helper()
	fromFile := make(map[string]struct{}, len(rows))
	spki := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		fromFile[row.fingerprint] = struct{}{}
		if row.spki != "" {
			spki[row.spki] = struct{}{}
		}
	}
	for _, fp := range got {
		if _, ok := fromFile[fp]; !ok {
			t.Errorf("fingerprint %s was not parsed from the SHA-256 Fingerprint column", fp)
		}
		if _, ok := spki[fp]; ok {
			t.Errorf("fingerprint %s is a Subject + SPKI SHA256 value", fp)
		}
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
