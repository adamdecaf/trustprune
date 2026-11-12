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

package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/store"
)

func TestPrintAppsTerse(t *testing.T) {
	t.Parallel()

	statuses := []store.Status{
		{Name: "chrome", Found: true, Path: "/tmp/chrome-nss"},
		{Name: "firefox", Found: false, Path: ""},
		{Name: "linux", Found: true, Path: "/etc/ssl/certs/ca-certificates.crt"},
	}
	var buf bytes.Buffer
	if err := printApps(&buf, statuses, ""); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 lines (header+3), got %d: %q", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "APP") || !strings.Contains(lines[0], "STATUS") || !strings.Contains(lines[0], "PATH") {
		t.Errorf("header line = %q", lines[0])
	}
	if !strings.Contains(lines[1], "chrome") || !strings.Contains(lines[1], "found") || !strings.Contains(lines[1], "/tmp/chrome-nss") {
		t.Errorf("chrome line = %q", lines[1])
	}
	if !strings.Contains(lines[2], "firefox") || !strings.Contains(lines[2], "not-found") || !strings.HasSuffix(strings.TrimSpace(lines[2]), "-") {
		t.Errorf("firefox line = %q", lines[2])
	}
	if !strings.Contains(lines[3], "linux") || !strings.Contains(lines[3], "found") {
		t.Errorf("os line = %q", lines[3])
	}
	// Names should be padded to the longest ("firefox")
	if !strings.HasPrefix(lines[1], "chrome ") {
		t.Errorf("expected chrome padded to firefox width, got %q", lines[1])
	}
}

func TestPrintAppsJSON(t *testing.T) {
	t.Parallel()

	statuses := []store.Status{
		{Name: "java", Found: false, Path: ""},
		{Name: "openssl", Found: true, Path: "/etc/ssl/certs/ca-certificates.crt"},
	}
	var buf bytes.Buffer
	if err := printApps(&buf, statuses, "json"); err != nil {
		t.Fatal(err)
	}
	var got []store.Status
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\nraw: %s", err, buf.String())
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %#v", got)
	}
	if got[0].Name != "java" || got[0].Found {
		t.Errorf("java entry = %#v", got[0])
	}
	if got[1].Name != "openssl" || !got[1].Found || got[1].Path == "" {
		t.Errorf("openssl entry = %#v", got[1])
	}
}

func TestPrintAppsShortIsTerse(t *testing.T) {
	t.Parallel()

	statuses := []store.Status{{Name: "chrome", Found: true, Path: "/tmp/chrome-nss"}}
	for _, format := range []string{"", "short", "SHORT"} {
		var buf bytes.Buffer
		if err := printApps(&buf, statuses, format); err != nil {
			t.Fatalf("format %q: %v", format, err)
		}
		if !strings.Contains(buf.String(), "APP") || !strings.Contains(buf.String(), "chrome") {
			t.Fatalf("format %q output:\n%s", format, buf.String())
		}
	}
	if err := printApps(&bytes.Buffer{}, statuses, "table"); err == nil {
		t.Fatal("table is not an apps format")
	}
}

func TestPrintAppsUnknownFormat(t *testing.T) {
	t.Parallel()

	err := printApps(&bytes.Buffer{}, nil, "openssl")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "json") {
		t.Errorf("error should say what to do next, got %v", err)
	}
}
