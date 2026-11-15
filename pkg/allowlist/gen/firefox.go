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

package gen

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/adamdecaf/trustprune/pkg/file"
	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/go-sqlite/sqlite3"
)

func firefox() ([]*url.URL, error) {
	db, err := findFirefoxPlacesDB()
	if err != nil {
		return nil, err
	}
	return getFirefoxUrls(db)
}

func getFirefoxUrls(db *sqlite3.DbFile) ([]*url.URL, error) {
	getter := func(rec sqlite3.Record) *record {
		u, _ := rec.Values[1].(string)
		when, _ := rec.Values[8].(int64) // last_visit_time
		return &record{
			URL:        u,
			VisistedAt: time.Unix(when/1e6, 0).UTC(), // throw away nsec
		}
	}
	return getSqliteHistoryUrls(db, "Firefox", "moz_places", getter, oldestBrowserHistoryItemDate)
}

func findFirefoxPlacesDB() (*sqlite3.DbFile, error) {
	path := findFirefoxPlacesPath(store.FirefoxProfileDirs(file.HomeDir(), os.Getenv("APPDATA")))
	if path == "" {
		return nil, errors.New("unable to find firefox places.sqlite")
	}
	return sqlite3.Open(path)
}

// findFirefoxPlacesPath returns the places.sqlite in the first profile dir
// that has one. dirs is the FirefoxProfileDirs order (newest cert DB first).
func findFirefoxPlacesPath(dirs []string) string {
	for _, dir := range dirs {
		path := filepath.Join(dir, "places.sqlite")
		if file.Exists(path) {
			return path
		}
	}
	return ""
}
