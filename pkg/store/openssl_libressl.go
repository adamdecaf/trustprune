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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

// darwinSystemOpenSSL is Apple's LibreSSL CLI. Its version string starts with
// "LibreSSL", but /etc/ssl/cert.pem is --app ssl and this binary must not
// replace c_rehash for the openssl store.
const darwinSystemOpenSSL = "/usr/bin/openssl"

var (
	// libreSSLBinPaths are keg-only Homebrew LibreSSL openssl binaries.
	// Intel is listed before Apple Silicon, matching openSSLCertPaths.
	// Existence is enough to treat the install as LibreSSL; the formula is
	// not linked onto PATH, so LookPath would miss it.
	libreSSLBinPaths = []string{
		"/usr/local/opt/libressl/bin/openssl",    // Homebrew Intel
		"/opt/homebrew/opt/libressl/bin/openssl", // Homebrew Apple Silicon
	}

	// libreSSLCertPaths are searched before openSSLCertPaths when LibreSSL
	// is present. The CA bundle comes before the extra certs directory.
	// /etc/ssl/cert.pem is the OpenBSD and Alpine-style system bundle;
	// on Darwin that same path is skipped (it is --app ssl).
	libreSSLCertPaths = []string{
		"/usr/local/etc/libressl/cert.pem",    // Homebrew Intel CA bundle
		"/opt/homebrew/etc/libressl/cert.pem", // Homebrew Apple Silicon CA bundle
		"/usr/local/etc/libressl/certs",       // Homebrew Intel extra certs
		"/opt/homebrew/etc/libressl/certs",    // Homebrew Apple Silicon extra certs
		"/etc/ssl/cert.pem",                   // OpenBSD / Alpine-style LibreSSL
	}

	// opensslGOOS is the OS used for LibreSSL path policy. Tests set it.
	opensslGOOS = runtime.GOOS

	// opensslLookPath resolves "openssl" on PATH. Tests replace it.
	opensslLookPath = exec.LookPath

	// opensslVersionOutput is `<bin> version` combined output. Tests replace it.
	opensslVersionOutput = func(bin string) (string, error) {
		out, err := exec.Command(bin, "version").CombinedOutput() // #nosec G204 -- bin is openssl or a discovered LibreSSL path
		return string(out), err
	}

	// libreSSLPathExists reports whether a LibreSSL candidate exists.
	// Tests replace it so /etc/ssl/cert.pem can be simulated without creating it.
	libreSSLPathExists = file.Exists
)

// findLibreSSLBin returns the LibreSSL openssl binary to prefer, or "" when
// the openssl store should keep its existing paths and c_rehash behavior.
//
// Homebrew keg-only paths win first. Otherwise an openssl on PATH whose
// version output starts with "LibreSSL" wins (OpenBSD and Alpine-style
// installs). Darwin /usr/bin/openssl is excluded: it is Apple LibreSSL and
// must not take over --app openssl.
func findLibreSSLBin() string {
	for _, p := range libreSSLBinPaths {
		if p == "" || !libreSSLPathExists(p) {
			continue
		}
		return p
	}
	p, err := opensslLookPath("openssl")
	if err != nil || p == "" || isDarwinSystemOpenSSL(p) {
		return ""
	}
	out, err := opensslVersionOutput(p)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(strings.TrimSpace(out), "LibreSSL") {
		return p
	}
	return ""
}

func isDarwinSystemOpenSSL(bin string) bool {
	if opensslGOOS != "darwin" {
		return false
	}
	return filepath.Clean(bin) == filepath.Clean(darwinSystemOpenSSL)
}

// skipLibreSSLCertPath reports candidates that must not become the openssl
// store. Darwin /etc/ssl/cert.pem stays --app ssl. The same path is eligible
// on other OSes, where it is the OpenBSD/Alpine LibreSSL bundle.
func skipLibreSSLCertPath(path string) bool {
	if path == "" {
		return true
	}
	if opensslGOOS == "darwin" && filepath.Clean(path) == filepath.Clean(defaultDarwinSSLCertPEM) {
		return true
	}
	return false
}

// rehashInvoke is the command that rebuilds hash symlinks in dir.
// LibreSSL uses `<openssl> certhash <dir>` and takes precedence over c_rehash.
// ok is false when no tool exists.
func rehashInvoke(dir string) (bin string, args []string, ok bool) {
	if libre := findLibreSSLBin(); libre != "" {
		return libre, []string{"certhash", dir}, true
	}
	bin = findCRehash()
	if bin == "" {
		return "", nil, false
	}
	return bin, []string{dir}, true
}

// rehashCommandDisplay is the dry-run text for rehashInvoke.
// OpenSSL stays "<c_rehash> <dir>". LibreSSL is "<openssl> certhash <dir>".
func rehashCommandDisplay(dir string) string {
	bin, args, ok := rehashInvoke(dir)
	if !ok {
		return ""
	}
	return strings.Join(append([]string{bin}, args...), " ")
}

// opensslDirCertExt is the filename suffix used when adding a certificate
// to a hashed cert directory. OpenSSL c_rehash accepts .crt and .pem.
// LibreSSL certhash scans only *.pem and deletes hash links that do not
// match a scanned file, so LibreSSL directories must use .pem.
func opensslDirCertExt() string {
	if findLibreSSLBin() != "" {
		return ".pem"
	}
	return ".crt"
}

// promoteCRTsForCerthash makes every *.crt visible to LibreSSL certhash,
// which only scans *.pem and deletes hash links that do not match a
// scanned file. Regular *.crt files are renamed to *.pem when that name
// is free. Symlinks, and *.crt files whose *.pem name already holds a
// different certificate, get a *.pem alias so existing hash access is
// preserved. opensslCertFiles skips those aliases so List does not
// double-count.
func promoteCRTsForCerthash(dir string) error {
	matches, err := filepath.Glob(filepath.Join(dir, "*.crt"))
	if err != nil {
		return err
	}
	for _, crt := range matches {
		st, err := os.Lstat(crt)
		if err != nil {
			continue
		}
		if st.IsDir() {
			continue
		}
		if err := exposeCRTForCerthash(crt); err != nil {
			return err
		}
	}
	return nil
}

func exposeCRTForCerthash(crt string) error {
	st, err := os.Lstat(crt)
	if err != nil {
		return err
	}
	pem := strings.TrimSuffix(crt, ".crt") + ".pem"
	if st.Mode().IsRegular() && !file.Exists(pem) {
		if err := os.Rename(crt, pem); err != nil {
			return fmt.Errorf("rename %s to %s for certhash: %w", crt, pem, err)
		}
		return nil
	}
	if file.Exists(pem) && opensslCertFilesSame(crt, pem) {
		return nil
	}
	if !file.Exists(pem) {
		return aliasCRTAsPEM(crt, pem)
	}
	alias := crt + ".pem"
	if file.Exists(alias) && opensslCertFilesSame(crt, alias) {
		return nil
	}
	if file.Exists(alias) && !opensslCertFilesSame(crt, alias) {
		return fmt.Errorf("cannot promote %s for certhash: %s already exists and is a different certificate", crt, alias)
	}
	return aliasCRTAsPEM(crt, alias)
}

func aliasCRTAsPEM(crt, pem string) error {
	if err := os.Symlink(filepath.Base(crt), pem); err == nil {
		return nil
	}
	if err := file.CopyFile(crt, pem); err != nil {
		return fmt.Errorf("link or copy %s to %s for certhash: %w", crt, pem, err)
	}
	return nil
}

func opensslCertFilesSame(a, b string) bool {
	if ra, err := filepath.EvalSymlinks(a); err == nil {
		if rb, err := filepath.EvalSymlinks(b); err == nil && ra == rb {
			return true
		}
	}
	ca, err := certutil.FromFile(a)
	if err != nil || len(ca) == 0 {
		return false
	}
	cb, err := certutil.FromFile(b)
	if err != nil || len(ca) != len(cb) {
		return false
	}
	for i := range ca {
		if certutil.GetHexSHA256Fingerprint(*ca[i]) != certutil.GetHexSHA256Fingerprint(*cb[i]) {
			return false
		}
	}
	return true
}

// isCerthashAliasPEM reports a *.pem file created only so certhash can
// see a sibling *.crt. List skips these so the certificate is not counted twice.
func isCerthashAliasPEM(path string) bool {
	if !strings.HasSuffix(path, ".pem") {
		return false
	}
	st, err := os.Lstat(path)
	if err != nil {
		return false
	}
	dir := filepath.Dir(path)
	if st.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return false
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		return strings.HasSuffix(target, ".crt")
	}
	base := filepath.Base(path)
	if strings.HasSuffix(base, ".crt.pem") {
		return file.Exists(filepath.Join(dir, strings.TrimSuffix(base, ".pem")))
	}
	return false
}
