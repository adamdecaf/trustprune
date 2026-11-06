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
// Mutating ops fail explicitly so callers never treat a no-op as success.
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

func (s freebsdStore) Add([]*x509.Certificate) error {
	return fmt.Errorf("freebsd platform store is not implemented")
}

func (s freebsdStore) Remove(allowlist.Allowlist) error {
	return fmt.Errorf("freebsd platform store is not implemented")
}

func (s freebsdStore) Backup() error {
	return fmt.Errorf("freebsd platform store is not implemented")
}

func (s freebsdStore) GetLatestBackup() (string, error) {
	return "", fmt.Errorf("freebsd platform store is not implemented")
}

func (s freebsdStore) Restore(string) error {
	return fmt.Errorf("freebsd platform store is not implemented")
}
