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

package ui

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestObservatoryOmitsEmptyVersion(t *testing.T) {
	cert := mustTestCertWithExpiry(t, "Example", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	certs := []*x509.Certificate{cert}

	emptyPath := filepath.Join(t.TempDir(), "empty.yaml")
	err := ListCertificatesWithMeta(Meta{Name: "certifi"}, certs, &Config{
		Format:  "observatory",
		Outfile: emptyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- output path under t.TempDir
	empty, err := os.ReadFile(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(empty), "version:") {
		t.Fatalf("empty version emitted:\n%s", empty)
	}
	if strings.Contains(string(empty), "url:") {
		t.Fatalf("empty url emitted:\n%s", empty)
	}

	const ver = "4.9.60-linuxkit"
	setPath := filepath.Join(t.TempDir(), "set.yaml")
	err = ListCertificatesWithMeta(Meta{Name: "openssl", Version: ver}, certs, &Config{
		Format:  "observatory",
		Outfile: setPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- output path under t.TempDir
	set, err := os.ReadFile(setPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(set), "version:") || !strings.Contains(string(set), ver) {
		t.Fatalf("version missing:\n%s", set)
	}
	if strings.Contains(string(set), "url:") {
		t.Fatalf("empty url emitted:\n%s", set)
	}
}
