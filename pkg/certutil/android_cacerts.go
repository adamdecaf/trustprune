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

package certutil

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// androidCacertName matches Android system CA filenames: eight hex digits,
// a dot, and a decimal suffix (0, 1, …), as in Conscrypt's cacerts README.
var androidCacertName = regexp.MustCompile(`(?i)^[0-9a-f]{8}\.[0-9]+$`)

// FromAndroidDir reads a pulled Android system cacerts directory. It loads
// regular files named <hash>.<n> (OpenSSL legacy subject hash and a collision
// suffix) and .crt, .cer, or .der exports of user-installed CAs. Each file is
// a PEM certificate, optionally followed by OpenSSL text, or a single DER
// certificate. The directory is not walked recursively. Files whose names do
// not match, and empty matching files, are ignored.
func FromAndroidDir(dir string) ([]*x509.Certificate, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, ent := range ents {
		if ent.IsDir() || !androidCacertFile(ent.Name()) {
			continue
		}
		names = append(names, ent.Name())
	}
	sort.Strings(names)

	var certs []*x509.Certificate
	for _, name := range names {
		path := filepath.Join(dir, name)
		bs, err := os.ReadFile(path) // #nosec G304 -- user-selected cacerts directory
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if len(bytes.TrimSpace(bs)) == 0 {
			continue
		}
		got, err := parseAndroidCacert(path, bs)
		if err != nil {
			return nil, err
		}
		certs = append(certs, got...)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no Android cacerts files in %s (expected <hash>.0 PEM or DER entries, or .crt/.cer/.der files)", dir)
	}
	return certs, nil
}

func androidCacertFile(name string) bool {
	if androidCacertName.MatchString(name) {
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".crt", ".cer", ".der":
		return true
	default:
		return false
	}
}

// parseAndroidCacert reads one file as PEM (with optional OpenSSL text after
// the certificate) and, if that yields no certificates, as a single DER
// certificate.
func parseAndroidCacert(path string, bs []byte) ([]*x509.Certificate, error) {
	got, err := ParsePEM(bs)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(got) > 0 {
		return got, nil
	}
	cert, err := ParseCertificate(bs)
	if err != nil {
		return nil, fmt.Errorf("%s is not a PEM or DER certificate", path)
	}
	return []*x509.Certificate{cert}, nil
}
