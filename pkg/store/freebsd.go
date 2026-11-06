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

//go:build freebsd
// +build freebsd

package store

import (
	"crypto/x509"
	"fmt"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

// freebsdStore is a stub until a FreeBSD trust-store backend exists.
// Dry-run and GetLatestBackup follow the emptyStore contract so CLI
// guards still work; live mutating ops fail explicitly.
type freebsdStore struct{}

func platform() Store {
	return freebsdStore{}
}

func (s freebsdStore) GetInfo() *Info {
	return &Info{Name: "freebsd"}
}

func (s freebsdStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	return nil, nil
}

func (s freebsdStore) Add(certs []*x509.Certificate) error {
	if DryRun() {
		reportDryRun("add certificates to", "freebsd", "", reportDryRunCerts("add", certs)...)
		return nil
	}
	return fmt.Errorf("freebsd platform store is not implemented")
}

func (s freebsdStore) Remove(allowlist.Allowlist) error {
	if DryRun() {
		reportDryRun("remove certificates from", "freebsd", "")
		return nil
	}
	return fmt.Errorf("freebsd platform store is not implemented")
}

func (s freebsdStore) Backup() error {
	if DryRun() {
		reportDryRun("backup", "freebsd", "")
		return nil
	}
	return fmt.Errorf("freebsd platform store is not implemented")
}

func (s freebsdStore) GetLatestBackup() (string, error) {
	// No backups exist yet; callers (allowlist/restore) treat "" as missing.
	return "", nil
}

func (s freebsdStore) Restore(where string) error {
	if DryRun() {
		details := []string{}
		if where != "" {
			details = append(details, fmt.Sprintf("source %s", where))
		}
		reportDryRun("restore", "freebsd", "", details...)
		return nil
	}
	return fmt.Errorf("freebsd platform store is not implemented")
}
