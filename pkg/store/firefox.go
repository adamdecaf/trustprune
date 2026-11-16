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
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/file"
)

var (
	firefoxBinaryPaths = []string{
		"/usr/bin/firefox", // Ubuntu
		`/Applications/Firefox.app/Contents/MacOS/firefox`, // Darwin
	}
)

// FirefoxStore returns a Mozilla Firefox implementation of Store
func FirefoxStore() Store {
	dirs := FirefoxProfileDirs(file.HomeDir(), os.Getenv("APPDATA"), os.Getenv)
	if len(dirs) > 0 {
		return NssStore("firefox", firefoxVersion(), dirs[0])
	}
	return emptyStore{}
}

// FirefoxProfileDirs returns NSS profile directories under the given home
// and Windows APPDATA roots. A profile is included when its directory name
// contains "default" and it holds a non-empty cert9.db or cert8.db.
// Results are ordered by most recent cert DB mtime first; equal mtimes
// sort by path.
//
// getenv looks up XDG_CONFIG_HOME and MOZ_LEGACY_HOME; nil means os.Getenv.
// The XDG root is $XDG_CONFIG_HOME/mozilla/firefox, or ~/.config/mozilla/firefox
// when XDG_CONFIG_HOME is unset or not absolute. MOZ_LEGACY_HOME=1 puts
// ~/.mozilla/firefox ahead of the XDG root.
func FirefoxProfileDirs(home, appdata string, getenv func(string) string) []string {
	if getenv == nil {
		getenv = os.Getenv
	}
	roots := firefoxProfileRoots(home, appdata, getenv)

	type profile struct {
		path  string
		mtime time.Time
	}
	var found []profile
	seen := make(map[string]struct{})
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !strings.Contains(ent.Name(), "default") {
				continue
			}
			dir := filepath.Join(root, ent.Name())
			if _, dup := seen[dir]; dup {
				continue
			}
			mt, ok := certDBModTime(dir)
			if !ok {
				continue
			}
			seen[dir] = struct{}{}
			found = append(found, profile{path: dir, mtime: mt})
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].mtime.Equal(found[j].mtime) {
			return found[i].path < found[j].path
		}
		return found[i].mtime.After(found[j].mtime)
	})
	out := make([]string, len(found))
	for i, p := range found {
		out[i] = p.path
	}
	return out
}

func firefoxProfileRoots(home, appdata string, getenv func(string) string) []string {
	var roots []string
	xdg := xdgMozillaFirefox(home, getenv)
	legacy := ""
	macos := ""
	if home != "" {
		legacy = filepath.Join(home, ".mozilla", "firefox")
		macos = filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	}
	if getenv("MOZ_LEGACY_HOME") == "1" {
		if legacy != "" {
			roots = append(roots, legacy)
		}
		if xdg != "" {
			roots = append(roots, xdg)
		}
	} else {
		if xdg != "" {
			roots = append(roots, xdg)
		}
		if legacy != "" {
			roots = append(roots, legacy)
		}
	}
	if macos != "" {
		roots = append(roots, macos)
	}
	if appdata != "" {
		roots = append(roots, filepath.Join(appdata, "Mozilla", "Firefox", "Profiles"))
	}
	return roots
}

func xdgMozillaFirefox(home string, getenv func(string) string) string {
	xdg := getenv("XDG_CONFIG_HOME")
	if xdg == "" || !filepath.IsAbs(xdg) {
		if home == "" {
			return ""
		}
		xdg = filepath.Join(home, ".config")
	}
	return filepath.Join(xdg, "mozilla", "firefox")
}

func certDBModTime(dir string) (time.Time, bool) {
	// #nosec G703 -- dir is joined from injected home/appdata roots
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return time.Time{}, false
	}
	for _, name := range []string{"cert9.db", "cert8.db"} {
		// #nosec G703 -- cert db under a profile joined from injected roots
		cfi, err := os.Stat(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || cfi.Size() == 0 {
			return time.Time{}, false
		}
		return cfi.ModTime(), true
	}
	return time.Time{}, false
}

func firefoxVersion() string {
	for i := range firefoxBinaryPaths {
		path := firefoxBinaryPaths[i]
		if file.Exists(path) {
			// returns "Mozilla Firefox 57.0.3"
			out, err := exec.Command(path, "-v").CombinedOutput()
			if err == nil && len(out) > 0 {
				r := strings.NewReplacer("Mozilla Firefox", "")
				return strings.TrimSpace(r.Replace(string(out)))
			}
		}
	}
	return ""
}
