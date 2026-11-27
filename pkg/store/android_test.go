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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

func TestDetectAndroid(t *testing.T) {
	t.Parallel()

	st := detectAndroid()
	if st.Name != "android" || !st.Found || !st.GuideOnly || st.Path != "" {
		t.Fatalf("detectAndroid: %#v", st)
	}
	if st.StatusLabel() != "guide only" {
		t.Fatalf("status label = %q", st.StatusLabel())
	}
}

func TestAndroidStoreRefusesWithoutWriting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	s, err := ForApp("Android")
	if err != nil {
		t.Fatal(err)
	}
	info := s.GetInfo()
	if info == nil || info.Name != "Android" || info.Path != "" {
		t.Fatalf("info %#v", info)
	}

	if _, err := ForAppWithStore("android", filepath.Join(home, "store")); err == nil || !strings.Contains(err.Error(), "--store with --app android") {
		t.Fatalf("store override: %v", err)
	}

	certs, err := s.List(nil)
	if !errors.Is(err, ErrAndroidGuideOnly) || certs != nil {
		t.Fatalf("list certs=%v err=%v", certs, err)
	}
	for _, phrase := range []string{
		"guide only",
		"cannot change an Android device",
		"Settings > Security > Encryption & credentials > Trusted credentials",
		"Disable",
		"Uninstall",
		"adb pull",
		"/system/etc/security/cacerts",
		"/apex/com.android.conscrypt/cacerts",
		"list --app android --file",
		"does not write to the device",
	} {
		if !strings.Contains(err.Error(), phrase) {
			t.Errorf("guide missing %q", phrase)
		}
	}

	if err := s.Add(nil); !errors.Is(err, ErrAndroidGuideOnly) {
		t.Fatalf("add: %v", err)
	}
	if err := s.Remove(allowlist.Allowlist{}); !errors.Is(err, ErrAndroidGuideOnly) {
		t.Fatalf("remove: %v", err)
	}
	if err := s.Backup(); !errors.Is(err, ErrAndroidGuideOnly) {
		t.Fatalf("backup: %v", err)
	}
	if path, err := s.GetLatestBackup(); path != "" || !errors.Is(err, ErrAndroidGuideOnly) || errors.Is(err, ErrNoBackupFound) {
		t.Fatalf("latest backup path=%q err=%v", path, err)
	}
	if err := s.Restore(""); !errors.Is(err, ErrAndroidGuideOnly) {
		t.Fatalf("restore: %v", err)
	}

	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("android operations wrote into HOME: %v", entries)
	}
}
