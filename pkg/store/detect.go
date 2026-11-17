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
//
// GuideOnly is set when the app is installed and trustprune only prints a
// pruning guide. The apps table shows that row as "guide only". Path is the
// install that was found, not a trust-store file.
type Status struct {
	Name      string `json:"name"`
	Found     bool   `json:"found"`
	Path      string `json:"path"`
	GuideOnly bool   `json:"guideOnly,omitempty"`
}

// StatusLabel is the STATUS cell in `trustprune apps`.
func (s Status) StatusLabel() string {
	if s.Found && s.GuideOnly {
		return "guide only"
	}
	if s.Found {
		return "found"
	}
	return "not-found"
}

// DetectStatuses returns status for every supported app (sorted) plus the
// system/OS store (named runtime.GOOS). Paths come from each store's existing probe logic.
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
	case "acrobat":
		return detectAcrobat()
	case "certifi":
		return detectCertifi()
	case "chrome":
		return detectChrome()
	case "firefox":
		return detectFirefox()
	case "foxit":
		return detectFoxit()
	case "java":
		return detectJava()
	case "openssl":
		return detectOpenSSL()
	case "poppler":
		return detectPoppler()
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
	dirs := FirefoxProfileDirs(file.HomeDir(), os.Getenv("APPDATA"), os.Getenv)
	if len(dirs) > 0 {
		s.Found = true
		s.Path = dirs[0]
	}
	return s
}

func detectPoppler() Status {
	// popplerNSSDir always returns a path, including ~/.pki/nssdb when nothing
	// else is selected. That fallback is not proof a store exists. Found is a
	// separate check: the selected directory must contain cert9.db.
	return popplerDetectStatus(popplerNSSDir())
}

// popplerDetectStatus marks poppler found only when dir contains a regular
// non-empty cert9.db. A missing directory, an empty fallback, or a directory
// without that file is not found, so a clean machine reports not found.
func popplerDetectStatus(dir string) Status {
	s := Status{Name: "poppler"}
	if systemHasCert9(dir) {
		s.Found = true
		s.Path = dir
	}
	return s
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
