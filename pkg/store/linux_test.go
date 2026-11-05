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

//go:build linux
// +build linux

package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStoreLinux__cadir(t *testing.T) {
	// just grab the linuxStore and make sure it has a cadir member
	s, ok := platform().(linuxStore)
	if !ok {
		t.Error("error casting to linuxStore")
	}
	if s.ca.empty() {
		t.Errorf("no cadir found on platform: %s", runtime.GOOS)
	}
}

func TestCadirsBundlePaths(t *testing.T) {
	if len(cadirs) < 3 {
		t.Fatalf("expected at least 3 cadirs, got %d", len(cadirs))
	}
	if cadirs[0].all != "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" {
		t.Errorf("fedora/rhel/rocky cadir should be first, got %s", cadirs[0].all)
	}
	if cadirs[0].blocklist != "/etc/pki/ca-trust/source/blocklist" {
		t.Errorf("fedora cadir missing blocklist, got %s", cadirs[0].blocklist)
	}
	if cadirs[1].all != "/etc/ca-certificates/extracted/tls-ca-bundle.pem" {
		t.Errorf("arch cadir should be second, got %s", cadirs[1].all)
	}
	if cadirs[1].blocklist != "/etc/ca-certificates/trust-source/blocklist" {
		t.Errorf("arch cadir missing blocklist, got %s", cadirs[1].blocklist)
	}
	if cadirs[2].all != "/etc/ssl/certs/ca-certificates.crt" {
		t.Errorf("debian cadir should be last, got %s", cadirs[2].all)
	}
	if cadirs[2].blocklist != "" {
		t.Errorf("debian cadir should not set blocklist, got %s", cadirs[2].blocklist)
	}
}

func TestSelectCadir(t *testing.T) {
	root := t.TempDir()
	fedoraAll := filepath.Join(root, "fedora-bundle.pem")
	archAll := filepath.Join(root, "arch-bundle.pem")
	debianAll := filepath.Join(root, "debian-bundle.crt")

	fedora := cadir{all: fedoraAll, dir: "fedora"}
	arch := cadir{all: archAll, dir: "arch"}
	debian := cadir{all: debianAll, dir: "debian"}
	dirs := []cadir{fedora, arch, debian}

	if _, ok := selectCadir(dirs); ok {
		t.Fatal("expected no cadir when no bundles exist")
	}

	if err := os.WriteFile(debianAll, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	got, ok := selectCadir(dirs)
	if !ok || got.dir != "debian" {
		t.Fatalf("got %+v ok=%v, want debian", got, ok)
	}

	if err := os.WriteFile(archAll, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	got, ok = selectCadir(dirs)
	if !ok || got.dir != "arch" {
		t.Fatalf("got %+v ok=%v, want arch (arch+debian like Arch Linux)", got, ok)
	}

	if err := os.WriteFile(fedoraAll, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	got, ok = selectCadir(dirs)
	if !ok || got.dir != "fedora" {
		t.Fatalf("got %+v ok=%v, want fedora (fedora+debian like Fedora 45)", got, ok)
	}
}
