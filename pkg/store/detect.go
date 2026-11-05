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
	"path/filepath"
	"runtime"

	"github.com/adamdecaf/trustprune/pkg/file"
)

// Status describes whether a named certificate store was found on this
// machine and the path used to reach it. Detection is read-only.
type Status struct {
	Name  string `json:"name"`
	Found bool   `json:"found"`
	Path  string `json:"path"`
}

// DetectStatuses returns status for every supported app (sorted) plus the
// platform store. Paths come from each store's existing probe logic.
func DetectStatuses() []Status {
	apps := GetApps()
	out := make([]Status, 0, len(apps)+1)
	for _, name := range apps {
		out = append(out, detectApp(name))
	}
	out = append(out, detectPlatform())
	return out
}

func detectApp(name string) Status {
	switch name {
	case "certifi":
		return detectCertifi()
	case "chrome":
		return detectChrome()
	case "firefox":
		return detectFirefox()
	case "java":
		return detectJava()
	case "openssl":
		return detectOpenSSL()
	case "ssl":
		return detectSSL()
	default:
		return Status{Name: name}
	}
}

func detectCertifi() Status {
	s := Status{Name: "certifi"}
	path, err := certifiStore{}.findCertPath()
	if err == nil && path != "" {
		s.Found = true
		s.Path = path
	}
	return s
}

func detectSSL() Status {
	s := Status{Name: "ssl"}
	if runtime.GOOS != "darwin" {
		return s
	}
	if file.Exists(defaultDarwinSSLCertPEM) {
		s.Found = true
		s.Path = defaultDarwinSSLCertPEM
	}
	return s
}

func detectChrome() Status {
	s := Status{Name: "chrome"}
	switch runtime.GOOS {
	case "darwin", "windows":
		// ChromeStore wraps the platform store on these OSes.
		p := detectPlatform()
		s.Found = p.Found
		s.Path = p.Path
	case "linux":
		if where, ok := locateChromeNSS(file.HomeDir()); ok {
			s.Found = true
			s.Path = where
		}
	}
	return s
}

// locateChromeNSS mirrors ChromeStore's Linux probe: the NSS db under
// $HOME/.pki/nssdb when that path exists.
func locateChromeNSS(home string) (string, bool) {
	if home == "" {
		return "", false
	}
	where := filepath.Join(home, ".pki", "nssdb")
	if _, err := os.Stat(where); !os.IsNotExist(err) {
		return where, true
	}
	return "", false
}

func detectFirefox() Status {
	s := Status{Name: "firefox"}
	if where, ok := locateFirefoxProfile(firefoxProfileSuggestions); ok {
		s.Found = true
		s.Path = where
	}
	return s
}

// locateFirefoxProfile mirrors FirefoxStore: first profile glob match that
// contains a non-empty cert8.db or cert9.db.
func locateFirefoxProfile(suggestions []string) (string, bool) {
	for i := range suggestions {
		matches, _ := filepath.Glob(suggestions[i])
		for j := range matches {
			if containsCertdb(matches[j]) {
				return matches[j], true
			}
		}
	}
	return "", false
}

func detectJava() Status {
	s := Status{Name: "java"}
	path, err := ktool.getKeystorePath()
	if err == nil && path != "" {
		s.Found = true
		s.Path = path
	}
	return s
}

func detectOpenSSL() Status {
	s := Status{Name: "openssl"}
	path, err := opensslStore{}.findCertPath()
	if err == nil && path != "" {
		s.Found = true
		s.Path = path
	}
	return s
}
