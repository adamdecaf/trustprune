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

package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withTempAppsCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := appsCacheDir
	appsCacheDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { appsCacheDir = orig })
	return dir
}

func TestFormatAppsHelpLineMissingCache(t *testing.T) {
	withTempAppsCache(t)

	got := FormatAppsHelpLine()
	want := strings.Join(GetApps(), ", ")
	if got != want {
		t.Fatalf("missing cache: got %q want %q", got, want)
	}
}

func TestFormatAppsHelpLineFreshCache(t *testing.T) {
	withTempAppsCache(t)

	statuses := []Status{
		{Name: "certifi", Found: true, Path: "/tmp/certifi"},
		{Name: "chrome", Found: true, Path: "/tmp/chrome"},
		{Name: "firefox", Found: false},
		{Name: "java", Found: true, Path: "/tmp/java"},
		{Name: "openssl", Found: false},
		{Name: "ssl", Found: false},
		{Name: "platform", Found: true, Path: "/tmp/platform"},
	}
	if err := SaveAppStatusesCache(statuses); err != nil {
		t.Fatal(err)
	}

	got := FormatAppsHelpLine()
	// Platform is omitted from the help line; apps show found/not found.
	for _, part := range []string{
		"certifi (found)",
		"chrome (found)",
		"firefox (not found)",
		"java (found)",
		"openssl (not found)",
		"ssl (not found)",
	} {
		if !strings.Contains(got, part) {
			t.Errorf("help line missing %q; got %q", part, got)
		}
	}
	if strings.Contains(got, "platform") {
		t.Errorf("help line should omit platform, got %q", got)
	}
}

func TestFormatAppsHelpLineStaleCache(t *testing.T) {
	dir := withTempAppsCache(t)

	payload, err := json.Marshal(appsCacheFile{
		SavedAt: time.Now().UTC().Add(-appsCacheTTL - time.Hour),
		Statuses: []Status{
			{Name: "certifi", Found: true, Path: "/tmp/certifi"},
			{Name: "chrome", Found: true, Path: "/tmp/chrome"},
			{Name: "firefox", Found: true, Path: "/tmp/ff"},
			{Name: "java", Found: true, Path: "/tmp/java"},
			{Name: "openssl", Found: true, Path: "/tmp/openssl"},
			{Name: "ssl", Found: true, Path: "/tmp/ssl"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, appsCacheFilename), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	got := FormatAppsHelpLine()
	want := strings.Join(GetApps(), ", ")
	if got != want {
		t.Fatalf("stale cache should fall back to static list: got %q want %q", got, want)
	}
	if strings.Contains(got, "(found)") {
		t.Fatalf("stale cache must not report found status: %q", got)
	}
}

func TestReadFreshAppStatusesCorrupt(t *testing.T) {
	dir := withTempAppsCache(t)
	if err := os.WriteFile(filepath.Join(dir, appsCacheFilename), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadFreshAppStatuses(); ok {
		t.Fatal("corrupt cache should not be fresh")
	}
}

func TestSaveAndReadFreshAppStatusesRoundTrip(t *testing.T) {
	withTempAppsCache(t)

	want := []Status{
		{Name: "chrome", Found: true, Path: "/tmp/c"},
		{Name: "platform", Found: false},
	}
	if err := SaveAppStatusesCache(want); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadFreshAppStatuses()
	if !ok {
		t.Fatal("expected fresh cache")
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d]=%#v want %#v", i, got[i], want[i])
		}
	}
}

func TestFormatAppsHelpLineDoesNotCreateCache(t *testing.T) {
	dir := withTempAppsCache(t)
	_ = FormatAppsHelpLine()
	if _, err := os.Stat(filepath.Join(dir, appsCacheFilename)); !os.IsNotExist(err) {
		t.Fatalf("FormatAppsHelpLine must not write a cache file, err=%v", err)
	}
}
