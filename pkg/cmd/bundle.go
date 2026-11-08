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

package cmd

import (
	"fmt"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/adamdecaf/trustprune/pkg/ui"
)

// CheckBundleFlag reports whether -bundle is allowed for this command.
// An empty bundle means the flag was not set. Non-empty requires -app openssl
// and one of list, backup, restore, allowlist, or the whitelist alias.
func CheckBundleFlag(command, app, bundle string) error {
	if strings.TrimSpace(bundle) == "" {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "list", "backup", "restore", "allowlist", "whitelist":
	default:
		return fmt.Errorf("-bundle is only supported for list, backup, restore, and allowlist")
	}
	if strings.ToLower(strings.TrimSpace(app)) != "openssl" {
		return fmt.Errorf("-bundle requires -app openssl")
	}
	return nil
}

// ListCertsForBundle lists certificates in an explicit openssl PEM CA bundle.
func ListCertsForBundle(bundle string, cfg *ui.Config) error {
	st, err := store.OpenSSLBundleAt(bundle)
	if err != nil {
		return err
	}
	certificates, err := st.List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return err
	}
	return ui.ListCertificatesWithMeta(createMeta(st), certificates, cfg)
}

// BackupForBundle backs up an explicit openssl PEM CA bundle.
func BackupForBundle(bundle string) error {
	s, err := store.OpenSSLBundleAt(bundle)
	if err != nil {
		return err
	}
	err = s.Backup()
	if err == nil {
		if store.DryRun() {
			fmt.Println("dry-run: no changes made")
		} else {
			fmt.Println("Backup completed successfully")
		}
	}
	return err
}

// AllowlistForBundle applies an allowlist to an explicit openssl PEM CA bundle.
// allowlistPath is the allowlist file (-file). bundle is the PEM (-bundle).
func AllowlistForBundle(app, allowlistPath, bundle string) error {
	if strings.ToLower(strings.TrimSpace(app)) != "openssl" {
		return fmt.Errorf("-bundle requires -app openssl")
	}
	s, err := store.OpenSSLBundleAt(bundle)
	if err != nil {
		return err
	}
	return allowlistStore(s, app, allowlistPath)
}
