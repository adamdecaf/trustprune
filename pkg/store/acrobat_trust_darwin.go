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

//go:build darwin

package store

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/file"
)

// macOS reads the same keys as Windows from the user plists via
// /usr/bin/defaults read. defaults write is never invoked.

const acrobatDefaultsRead = "/usr/bin/defaults"

const (
	acrobatPlistPro    = "com.adobe.Acrobat.Pro.plist"
	acrobatPlistReader = "com.adobe.Reader.plist"
)

func platformAcrobatTrustRead() ([]acrobatTrustProduct, error) {
	home := file.HomeDir()
	specs := []struct {
		product string
		name    string
	}{
		{acrobatProductAcrobat, acrobatPlistPro},
		{acrobatProductReader, acrobatPlistReader},
	}
	var out []acrobatTrustProduct
	for _, spec := range specs {
		path, ok := acrobatPlistPath(home, spec.name)
		if !ok {
			continue
		}
		products, found, err := readAcrobatPlist(spec.product, path)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, products...)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func acrobatPlistPath(home, name string) (string, bool) {
	home = strings.TrimSpace(home)
	if home == "" {
		return "", false
	}
	return filepath.Join(home, "Library", "Preferences", name), true
}

// readAcrobatPlist reports found when the plist file exists. A missing file
// is not an error. A defaults or parse failure is an error: the file is
// there, so this is not "not installed".
func readAcrobatPlist(product, path string) ([]acrobatTrustProduct, bool, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("acrobat: stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, nil
	}
	// Read only. The argument is the fixed defaults binary plus "read".
	cmd := exec.Command(acrobatDefaultsRead, "read", path)
	out, err := cmd.Output()
	if err != nil {
		msg := ""
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			msg = strings.TrimSpace(string(ee.Stderr))
		}
		if msg != "" {
			return nil, true, fmt.Errorf("acrobat: defaults read %s: %s: %w", path, msg, err)
		}
		return nil, true, fmt.Errorf("acrobat: defaults read %s: %w", path, err)
	}
	root, err := parseDefaultsPlist(string(out))
	if err != nil {
		return nil, true, fmt.Errorf("acrobat: parse defaults read %s: %w", path, err)
	}
	products := acrobatProductsFromDefaults(product, path, root)
	if len(products) == 0 {
		products = []acrobatTrustProduct{{
			Product: product,
			Source:  path,
		}}
	}
	return products, true, nil
}
