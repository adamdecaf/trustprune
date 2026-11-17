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

//go:build windows

package store

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Windows reads HKCU\Software\Adobe\{Adobe Acrobat,Acrobat Reader}\<ver>\Security.
// Keys are opened with registry.READ. This file does not create keys or set values.

const acrobatRegAdobe = `Software\Adobe`

// acrobatRegTreeDepth reaches Security\cDigSig\cAdobeDownload\<value> and
// Security\cASPKI\cMSCAPI_DirectoryProvider\iMSStoreTrusted.
const acrobatRegTreeDepth = 3

func platformAcrobatTrustRead() ([]acrobatTrustProduct, error) {
	var out []acrobatTrustProduct
	for _, product := range []string{acrobatProductAcrobat, acrobatProductReader} {
		found, err := readAcrobatRegProduct(product)
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func readAcrobatRegProduct(product string) ([]acrobatTrustProduct, error) {
	productPath := acrobatRegAdobe + `\` + product
	k, ok, err := acrobatRegOpen(productPath)
	if err != nil || !ok {
		return nil, err
	}
	versions, err := k.ReadSubKeyNames(-1)
	if err != nil {
		err = fmt.Errorf("acrobat: list HKCU\\%s: %w", productPath, err)
	}
	if err = acrobatRegClose(k, productPath, err); err != nil {
		return nil, err
	}

	var out []acrobatTrustProduct
	for _, ver := range versions {
		if !acrobatSafeRegName(ver) {
			continue
		}
		secPath := productPath + `\` + ver + `\Security`
		tree, found, err := acrobatRegSecurityTree(secPath)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		source := `HKCU\` + secPath
		if _, has := asAcrobatMap(tree["cDigSig"]); has {
			source += `\cDigSig`
		}
		out = append(out, acrobatProductFromSecurity(product, ver, source, tree))
	}
	if len(out) == 0 {
		// The product key exists, so Acrobat is installed, even when
		// Security\cDigSig is absent.
		out = []acrobatTrustProduct{{
			Product: product,
			Source:  `HKCU\` + productPath,
		}}
	}
	return out, nil
}

func acrobatRegSecurityTree(path string) (map[string]any, bool, error) {
	k, ok, err := acrobatRegOpen(path)
	if err != nil || !ok {
		return nil, false, err
	}
	tree, err := acrobatRegReadTree(k, path, acrobatRegTreeDepth)
	if err != nil {
		_ = k.Close()
		return nil, true, err
	}
	if cerr := k.Close(); cerr != nil {
		return nil, true, fmt.Errorf("acrobat: close HKCU\\%s: %w", path, cerr)
	}
	return tree, true, nil
}

func acrobatRegOpen(path string) (registry.Key, bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.READ)
	if acrobatRegMissing(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("acrobat: open HKCU\\%s: %w", path, err)
	}
	return k, true, nil
}

func acrobatRegClose(k registry.Key, path string, err error) error {
	if cerr := k.Close(); err == nil && cerr != nil {
		return fmt.Errorf("acrobat: close HKCU\\%s: %w", path, cerr)
	}
	return err
}

func acrobatRegMissing(err error) bool {
	return err != nil && (errors.Is(err, registry.ErrNotExist) || errors.Is(err, os.ErrNotExist))
}

func acrobatSafeRegName(name string) bool {
	if strings.TrimSpace(name) == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, `\/`)
}

// acrobatRegReadTree copies integer values and nested keys into a map the
// shared lookup understands. Non-integer values (URLs, binary) are skipped.
// A subkey replaces a value of the same name. cAdobeDownload is that subkey.
func acrobatRegReadTree(k registry.Key, path string, depth int) (map[string]any, error) {
	out := map[string]any{}
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, fmt.Errorf("acrobat: list values HKCU\\%s: %w", path, err)
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		v, ok, err := acrobatRegInteger(k, name)
		if err != nil {
			return nil, fmt.Errorf("acrobat: read HKCU\\%s %s: %w", path, name, err)
		}
		if ok {
			out[name] = v
		}
	}
	if depth == 0 {
		return out, nil
	}
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("acrobat: list HKCU\\%s: %w", path, err)
	}
	for _, name := range subs {
		if !acrobatSafeRegName(name) {
			continue
		}
		sub, err := registry.OpenKey(k, name, registry.READ)
		if acrobatRegMissing(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("acrobat: open HKCU\\%s\\%s: %w", path, name, err)
		}
		childPath := path + `\` + name
		child, rerr := acrobatRegReadTree(sub, childPath, depth-1)
		cerr := sub.Close()
		if rerr != nil {
			return nil, rerr
		}
		if cerr != nil {
			return nil, fmt.Errorf("acrobat: close HKCU\\%s: %w", childPath, cerr)
		}
		out[name] = child
	}
	return out, nil
}

// acrobatRegInteger reads a DWORD or QWORD. A missing value is not an error.
// A string that parses as an integer is accepted. Other types are skipped.
func acrobatRegInteger(k registry.Key, name string) (uint64, bool, error) {
	v, _, err := k.GetIntegerValue(name)
	if err == nil {
		return v, true, nil
	}
	if acrobatRegMissing(err) {
		return 0, false, nil
	}
	if errors.Is(err, registry.ErrUnexpectedType) {
		s, _, serr := k.GetStringValue(name)
		if serr != nil {
			return 0, false, nil
		}
		n, ok := asAcrobatUint(s)
		return n, ok, nil
	}
	return 0, false, err
}
