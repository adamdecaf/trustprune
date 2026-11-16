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
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/adamdecaf/trustprune/pkg/file"
)

// PopplerStore returns the NSS store pdfsig uses when no directory is given.
// The path is PopplerNSSDir with this process's home, APPDATA, and environment.
func PopplerStore() Store {
	return NssStore("poppler", "", popplerNSSDir())
}

// PopplerStoreAt returns an NSS store at dir and skips PopplerNSSDir.
// dir is an explicit --store path (pdfsig -nssdir).
func PopplerStoreAt(dir string) Store {
	return NssStore("poppler", "", dir)
}

func popplerNSSDir() string {
	return PopplerNSSDir(file.HomeDir(), os.Getenv("APPDATA"), os.Getenv, "/etc/pki/nssdb", popplerNSSOpens)
}

// popplerNSSOpens reports whether certutil can list dir as a shared NSS DB.
// Output is discarded; only a zero exit counts as success.
func popplerNSSOpens(dir string) bool {
	if dir == "" {
		return false
	}
	expath, err := cutil.getExecPath()
	if err != nil {
		return false
	}
	cmd := exec.Command(expath, "-L", "-d", "sql:"+dir)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

// PopplerNSSDir mirrors poppler's NSSSignatureConfiguration::setNSSDir when no
// explicit -nssdir is given. It returns the first FirefoxProfileDirs entry if
// opens reports that NSS can initialize it. A profile that fails to open falls
// back to ~/.pki/nssdb and never to systemDir. With no profile, a systemDir
// that contains cert9.db and opens successfully is used; otherwise ~/.pki/nssdb.
func PopplerNSSDir(home, appdata string, getenv func(string) string, systemDir string, opens func(dir string) bool) string {
	fallback := filepath.Join(home, ".pki", "nssdb")
	dirs := FirefoxProfileDirs(home, appdata, getenv)
	if len(dirs) > 0 {
		dir := dirs[0]
		if opens(dir) {
			return dir
		}
		return fallback
	}
	if systemHasCert9(systemDir) && opens(systemDir) {
		return systemDir
	}
	return fallback
}

func systemHasCert9(dir string) bool {
	if dir == "" {
		return false
	}
	// #nosec G703 -- dir is an injected system NSS path
	fi, err := os.Stat(filepath.Join(dir, "cert9.db"))
	return err == nil && fi.Mode().IsRegular()
}
