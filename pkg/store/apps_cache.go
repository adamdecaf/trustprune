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
	"time"
)

const (
	appsCacheTTL      = 24 * time.Hour
	appsCacheFilename = "apps-status.json"
)

// appsCacheFile is the on-disk shape of DetectStatuses results.
type appsCacheFile struct {
	SavedAt  time.Time `json:"savedAt"`
	Statuses []Status  `json:"statuses"`
}

// appsCacheDir returns the directory that holds the apps detection cache.
// Overridden in tests so we never touch the real user cache.
var appsCacheDir = defaultAppsCacheDir

func defaultAppsCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "trustprune"), nil
}

func appsCachePath() (string, error) {
	dir, err := appsCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, appsCacheFilename), nil
}

// DetectAndCacheStatuses runs DetectStatuses and writes the result to the
// user cache. Cache write failures are ignored so apps listing still works.
func DetectAndCacheStatuses() []Status {
	statuses := DetectStatuses()
	_ = SaveAppStatusesCache(statuses)
	return statuses
}

// SaveAppStatusesCache writes statuses under the user cache dir. Safe to skip
// on failure; callers should not treat a write error as fatal.
func SaveAppStatusesCache(statuses []Status) error {
	path, err := appsCachePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.Marshal(appsCacheFile{
		SavedAt:  time.Now().UTC(),
		Statuses: statuses,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

// ReadFreshAppStatuses returns cached statuses when the file exists and is
// younger than appsCacheTTL. A missing, corrupt, or stale cache returns ok=false.
// This only reads the filesystem; it never runs detection.
func ReadFreshAppStatuses() (statuses []Status, ok bool) {
	path, err := appsCachePath()
	if err != nil {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cached appsCacheFile
	if err := json.Unmarshal(raw, &cached); err != nil {
		return nil, false
	}
	if cached.SavedAt.IsZero() || time.Since(cached.SavedAt) > appsCacheTTL {
		return nil, false
	}
	if len(cached.Statuses) == 0 {
		return nil, false
	}
	return cached.Statuses, true
}

// FormatAppsHelpLine returns the APPS help line. With a fresh cache it shows
// each supported app and whether it was found, e.g.
// "acrobat (not found), chrome (found), firefox (not found), foxit (guide only), java (found)".
// When the cache is missing or stale it falls back to the static supported
// list. It never runs detection, so -help stays fast on a cold start.
func FormatAppsHelpLine() string {
	cached, ok := ReadFreshAppStatuses()
	if !ok {
		return strings.Join(GetApps(), ", ")
	}
	byName := make(map[string]Status, len(cached))
	for _, s := range cached {
		byName[s.Name] = s
	}
	apps := GetApps()
	parts := make([]string, 0, len(apps))
	for _, name := range apps {
		state := "not found"
		if s, exists := byName[name]; exists && s.Found {
			state = "found"
			if s.GuideOnly {
				state = "guide only"
			}
		}
		parts = append(parts, name+" ("+state+")")
	}
	return strings.Join(parts, ", ")
}
