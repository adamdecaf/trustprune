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

package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreJava__expandSymlink(t *testing.T) {
	// Make a symlink to a cacerts file
	dir, err := os.MkdirTemp("", "cert-manage-java")
	if err != nil {
		t.Error(err)
	}
	kpath := filepath.Join(dir, "cacerts")
	err = os.WriteFile(kpath, []byte("A"), 0666)
	if err != nil {
		t.Error(err)
	}
	// create the symlink
	other := "java-certs"
	err = os.Symlink(kpath, other)
	if err != nil {
		t.Fatalf("error creating symlink: %v", err)
	}

	// Verify it's found
	kt1 := keytool{}
	out, err := kt1.expandSymlink(other)
	if err != nil || out == "" {
		t.Fatalf("%s should have been seen as a symlink to %s, err=%v", other, kpath, err)
	}
	err = os.Remove(other)
	if err != nil {
		t.Error(err)
	}

	// Verify bin/java can be removed
	err = os.MkdirAll(filepath.Join("other", "bin"), 0777|os.ModeDir)
	if err != nil {
		t.Error(err)
	}
	err = os.Symlink(filepath.Join(dir, "bin", "java"), filepath.Join("other", "bin", "java"))
	if err != nil {
		t.Error(err)
	}
	p, _ := kt1.expandSymlink(filepath.Join("other", "bin", "java"))
	if p != dir {
		t.Errorf("%s should have been %s", p, dir)
	}
	_ = os.RemoveAll("other" + string(os.PathSeparator))
}

func TestStoreJava__getKeystorePath(t *testing.T) {
	// Create a fake cacerts file
	dir, err := os.MkdirTemp("", "cert-manage-java")
	if err != nil {
		t.Error(err)
	}
	kpath := filepath.Join(dir, "cacerts")
	err = os.WriteFile(kpath, []byte("A"), 0666)
	if err != nil {
		t.Error(err)
	}

	// Now try and find it
	kt1 := keytool{
		javahome:              dir,
		javaInstallPaths:      nil,
		relativeKeystorePaths: []string{"cacerts"},
	}
	kp1, err := kt1.getKeystorePath()
	if err != nil {
		t.Error(err)
	}
	if kp1 != kpath {
		t.Errorf("kp1=%s != kpath=%s", kp1, kpath)
	}

	// Find without JAVA_HOMe
	kt2 := keytool{
		javahome:              "",
		javaInstallPaths:      []string{dir},
		relativeKeystorePaths: []string{"cacerts"},
	}
	kp2, err := kt2.getKeystorePath()
	if err != nil {
		t.Error(err)
	}
	if kp2 != kpath {
		t.Errorf("kp2=%s != kpath=%s", kp2, kpath)
	}

	// JAVA_HOME pointing at a directory without cacerts must not be returned
	emptyHome, err := os.MkdirTemp("", "cert-manage-java-empty")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(emptyHome)
	kt3 := keytool{
		javahome:              emptyHome,
		javaInstallPaths:      nil,
		relativeKeystorePaths: []string{"cacerts"},
	}
	if _, err := kt3.getKeystorePath(); err == nil {
		t.Fatal("expected error when JAVA_HOME has no cacerts file")
	}

	err = os.RemoveAll(dir)
	if err != nil {
		t.Error(err)
	}
}

func TestStoreJava__info(t *testing.T) {
	bin, err := ktool.expandSymlink(ktool.javahome)
	if err != nil || bin == "" {
		t.Skip("java isn't installed / can't be found")
	}

	info := JavaStore().GetInfo()
	if info == nil {
		t.Fatal("nil Info")
	}
	if info.Name == "" {
		t.Error("blank Name")
	}
	if info.Version == "" {
		t.Error("blank Version")
	}
}

func TestJavaStoreAt_OverridesSearch(t *testing.T) {
	dir := t.TempDir()
	kpath := filepath.Join(dir, "cacerts")
	if err := os.WriteFile(kpath, []byte("not-empty-keystore"), 0644); err != nil {
		t.Fatal(err)
	}
	refuseSystemKeystore(t, kpath)

	s := JavaStoreAt(kpath).(javaStore)
	got, err := s.keystorePath()
	if err != nil {
		t.Fatal(err)
	}
	if got != kpath {
		t.Fatalf("keystorePath=%q want %q", got, kpath)
	}

	info := s.GetInfo()
	if info == nil || info.Path != kpath {
		t.Fatalf("GetInfo.Path=%v want %s", info, kpath)
	}
}

func TestJavaStoreAt_RejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	s := JavaStoreAt(dir).(javaStore)
	_, err := s.keystorePath()
	if err == nil {
		t.Fatal("expected error for directory keystore path")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("expected directory error, got %v", err)
	}
}

func TestForAppWithFile_Java(t *testing.T) {
	dir := t.TempDir()
	kpath := filepath.Join(dir, "cacerts")
	if err := os.WriteFile(kpath, []byte("ks"), 0644); err != nil {
		t.Fatal(err)
	}
	st, err := ForAppWithFile("java", kpath)
	if err != nil {
		t.Fatal(err)
	}
	info := st.GetInfo()
	if info.Path != kpath {
		t.Fatalf("Path=%q want %q", info.Path, kpath)
	}
}

func TestGetKeystorePath_JavaHomeMissingCacerts(t *testing.T) {
	dir := t.TempDir()
	k := keytool{
		javahome:              dir,
		relativeKeystorePaths: []string{"lib/security/cacerts"},
	}
	_, err := k.getKeystorePath()
	if err == nil || !strings.Contains(err.Error(), "has no cacerts") {
		t.Fatalf("expected missing cacerts error, got %v", err)
	}
}

func TestForAppWithFile_RejectsOtherApps(t *testing.T) {
	_, err := ForAppWithFile("firefox", "/tmp/x")
	if err == nil || !strings.Contains(err.Error(), "--store with --app firefox") {
		t.Fatalf("expected --store error, got %v", err)
	}
	_, err = ForAppWithStore("firefox", "/tmp/x")
	if err == nil || !strings.Contains(err.Error(), "--store with --app firefox") {
		t.Fatalf("expected --store error, got %v", err)
	}
}

func TestStoreJava__expandSymlinkRelativeIsAbsolute(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "Cellar", "openjdk", "21")
	if err := os.MkdirAll(filepath.Join(target, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "opt", "openjdk")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "Cellar", "openjdk", "21"), link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	got, err := keytool{}.expandSymlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) || got != target {
		t.Fatalf("got %q, want absolute %q", got, target)
	}
}
