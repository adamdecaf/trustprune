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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const dockerJavaImage = "eclipse-temurin:21-jdk-jammy"

// javaHomeLayout describes where cacerts lives under a JAVA_HOME-style root.
// Layouts mirror distro OpenJDK installs so Backup/Restore are exercised
// against the same relative paths production discovery uses.
type javaHomeLayout struct {
	name string
	// relativeKeystorePath is relative to JAVA_HOME (no leading slash).
	relativeKeystorePath string
}

// linuxJavaLayouts covers the Linux distro matrix (alpine, debian, ubuntu,
// rocky, fedora, arch) used by the docker integration suites and
// production java_linux.go paths.
var linuxJavaLayouts = []javaHomeLayout{
	{name: "ubuntu-openjdk", relativeKeystorePath: "lib/security/cacerts"},
	{name: "debian-openjdk", relativeKeystorePath: "lib/security/cacerts"},
	{name: "alpine-openjdk", relativeKeystorePath: "lib/security/cacerts"},
	// Production java_linux.go also lists the older jre/ subtree (alpine).
	{name: "alpine-jre", relativeKeystorePath: "jre/lib/security/cacerts"},
}

// darwinJavaLayouts mirrors production java_darwin.go relative paths.
// windowsJavaLayouts stay empty until Windows Java CI exists.
var (
	darwinJavaLayouts = []javaHomeLayout{
		{name: "darwin-temurin", relativeKeystorePath: "lib/security/cacerts"},
		{name: "darwin-jre", relativeKeystorePath: "jre/lib/security/cacerts"},
	}
	windowsJavaLayouts []javaHomeLayout
)

func activeJavaLayouts() []javaHomeLayout {
	// Unit tests create temp trees for Linux and Darwin OpenJDK layouts on every OS.
	out := append([]javaHomeLayout(nil), linuxJavaLayouts...)
	out = append(out, darwinJavaLayouts...)
	out = append(out, windowsJavaLayouts...)
	return out
}

// sharedTempCacertsBytes returns bytes of a real keystore created once per
// test process (keytool or docker). Copied into each layout under a temp dir.
func sharedTempCacertsBytes(t *testing.T) []byte {
	t.Helper()

	example := filepath.Join("..", "..", "testdata", "example.crt")
	if _, err := os.Stat(example); err != nil {
		t.Fatalf("testdata example.crt: %v", err)
	}

	staging := t.TempDir()
	cacerts := filepath.Join(staging, "cacerts")
	refuseSystemKeystore(t, cacerts)

	var errs []string
	if bin, err := exec.LookPath("keytool"); err != nil {
		errs = append(errs, "keytool not on PATH")
	} else if err := importCertWithKeytool(bin, example, cacerts); err != nil {
		errs = append(errs, fmt.Sprintf("local keytool: %v", err))
	} else {
		assertWritableNonEmptyCacerts(t, cacerts)
		b, err := os.ReadFile(cacerts)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	if err := createCacertsWithDocker(t, staging, example, cacerts); err != nil {
		errs = append(errs, err.Error())
		t.Skipf("cannot create a temp Java cacerts keystore: %s", strings.Join(errs, "; "))
	}
	assertWritableNonEmptyCacerts(t, cacerts)
	b, err := os.ReadFile(cacerts)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func importCertWithKeytool(keytoolBin, exampleCrt, cacertsPath string) error {
	cmd := exec.Command(keytoolBin,
		"-importcert", "-noprompt", "-alias", "example",
		"-file", exampleCrt,
		"-keystore", cacertsPath,
		"-storepass", defaultKeystorePassword,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func createCacertsWithDocker(t *testing.T, workDir, exampleCrt, cacertsPath string) error {
	t.Helper()

	docker, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker not on PATH: %w", err)
	}

	absWork, err := filepath.Abs(workDir)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(exampleCrt)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(absWork, "example.crt"), b, 0644); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	args := []string{"run", "--rm"}
	if uid := os.Getuid(); uid >= 0 {
		args = append(args, "--user", fmt.Sprintf("%d:%d", uid, os.Getgid()))
	}
	args = append(args,
		"-v", absWork+":/work",
		dockerJavaImage,
		"keytool", "-importcert", "-noprompt", "-alias", "example",
		"-file", "/work/example.crt",
		"-keystore", "/work/cacerts",
		"-storepass", defaultKeystorePassword,
	)
	out, err := exec.CommandContext(ctx, docker, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	_ = os.Remove(cacertsPath)
	keytoolErr := fmt.Errorf("docker keytool: %w: %s", err, bytes.TrimSpace(out))

	// Copy the image cacerts through stdout so the file is owned by this user
	// (a bind-mounted copy would often be root-owned and trip SudoCopyFile).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel2()
	cat := exec.CommandContext(ctx2, docker, "run", "--rm", dockerJavaImage,
		"bash", "-c", `cat "$JAVA_HOME/lib/security/cacerts"`)
	var stdout, stderr bytes.Buffer
	cat.Stdout = &stdout
	cat.Stderr = &stderr
	if err := cat.Run(); err != nil {
		return fmt.Errorf("docker cat cacerts: %s: %w", bytes.TrimSpace(stderr.Bytes()), errors.Join(keytoolErr, err))
	}
	if stdout.Len() == 0 {
		return fmt.Errorf("%w; docker cat cacerts: empty output", keytoolErr)
	}
	if err := os.WriteFile(cacertsPath, stdout.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

func assertWritableNonEmptyCacerts(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cacerts stat: %v", err)
	}
	if st.Size() == 0 {
		t.Fatalf("cacerts at %s is empty", path)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("temp cacerts must be writable by the current user so Restore uses CopyFile, not sudo: %v", err)
	}
	_ = f.Close()
}

func refuseIfOutside(t *testing.T, root, path, what string) {
	t.Helper()
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("refusing to use %s path %s outside %s", what, path, root)
	}
}

func refuseSystemKeystore(t *testing.T, path string) {
	t.Helper()
	cleaned := filepath.Clean(path)
	prefixes := []string{
		"/usr/lib/jvm",
		"/usr/java",
		"/Library/Java",
		"/System/Library/Java",
		"/etc/ssl/certs/java",
		"/etc/pki",
	}
	for _, p := range prefixes {
		if cleaned == p || strings.HasPrefix(cleaned, p+string(os.PathSeparator)) {
			t.Fatalf("refusing to run against system keystore path %s", path)
		}
	}
}

// javaBackupTestEnvFor points package-level ktool at a temp JAVA_HOME built
// for layout, with a temp copy of cacerts at layout.relativeKeystorePath.
func javaBackupTestEnvFor(t *testing.T, layout javaHomeLayout, cacertsBytes []byte) (javaStore, string) {
	t.Helper()

	javaHome := t.TempDir()
	cacertsPath := filepath.Join(javaHome, filepath.FromSlash(layout.relativeKeystorePath))
	if err := os.MkdirAll(filepath.Dir(cacertsPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacertsPath, cacertsBytes, 0644); err != nil {
		t.Fatal(err)
	}
	refuseSystemKeystore(t, cacertsPath)
	assertWritableNonEmptyCacerts(t, cacertsPath)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("JAVA_HOME", javaHome)

	orig := ktool
	t.Cleanup(func() { ktool = orig })
	ktool = keytool{
		javahome:              javaHome,
		javaInstallPaths:      nil,
		relativeKeystorePaths: []string{layout.relativeKeystorePath},
	}

	kpath, err := ktool.getKeystorePath()
	if err != nil {
		t.Fatalf("getKeystorePath: %v", err)
	}
	refuseIfOutside(t, javaHome, kpath, "keystore")
	refuseSystemKeystore(t, kpath)
	if filepath.Clean(kpath) != filepath.Clean(cacertsPath) {
		t.Fatalf("getKeystorePath=%s want %s for layout %s", kpath, cacertsPath, layout.name)
	}

	backupDir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		t.Fatalf("getCertManageDir: %v", err)
	}
	refuseIfOutside(t, home, backupDir, "backup dir")

	return javaStore{}, kpath
}

func TestJavaBackupRestoreRoundTrip(t *testing.T) {
	layouts := activeJavaLayouts()
	if len(layouts) == 0 {
		t.Skip("no java home layouts configured")
	}
	cacertsBytes := sharedTempCacertsBytes(t)

	for _, layout := range layouts {
		layout := layout
		t.Run(layout.name, func(t *testing.T) {
			s, kpath := javaBackupTestEnvFor(t, layout, cacertsBytes)

			original, err := os.ReadFile(kpath)
			if err != nil {
				t.Fatal(err)
			}
			if len(original) == 0 {
				t.Fatal("snapshot of live cacerts is empty")
			}

			if err := s.Backup(); err != nil {
				t.Fatalf("Backup: %v", err)
			}
			latest, err := s.GetLatestBackup()
			if err != nil {
				t.Fatalf("GetLatestBackup: %v", err)
			}
			if latest == "" {
				t.Fatal("GetLatestBackup returned empty path")
			}
			st, err := os.Stat(latest)
			if err != nil {
				t.Fatalf("stat backup: %v", err)
			}
			if st.IsDir() {
				t.Fatalf("latest backup %s is a directory, want file", latest)
			}
			backed, err := os.ReadFile(latest)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(backed, original) {
				t.Fatalf("backup is not a complete copy: got %d bytes, want %d", len(backed), len(original))
			}

			marker := []byte("MUTATED-JAVA-CACERTS-" + t.Name() + "\n")
			if err := os.WriteFile(kpath, marker, 0644); err != nil {
				t.Fatal(err)
			}
			mutated, err := os.ReadFile(kpath)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(mutated, original) {
				t.Fatal("mutation did not change live cacerts bytes")
			}

			if err := s.Restore(""); err != nil {
				t.Fatalf("Restore: %v", err)
			}
			got, err := os.ReadFile(kpath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, original) {
				t.Fatalf("live cacerts after Restore does not match original snapshot: got %d bytes, want %d", len(got), len(original))
			}
		})
	}
}

func TestJavaRestore_HonorsWherePath(t *testing.T) {
	// Restore(where) must copy the provided file (CLI --backup), not only GetLatestBackup().
	layouts := activeJavaLayouts()
	if len(layouts) == 0 {
		t.Skip("no java home layouts configured")
	}
	cacertsBytes := sharedTempCacertsBytes(t)

	for _, layout := range layouts {
		layout := layout
		t.Run(layout.name, func(t *testing.T) {
			s, kpath := javaBackupTestEnvFor(t, layout, cacertsBytes)

			if err := s.Backup(); err != nil {
				t.Fatalf("Backup: %v", err)
			}
			latest, err := s.GetLatestBackup()
			if err != nil || latest == "" {
				t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
			}

			if err := os.WriteFile(kpath, []byte("MUTATED-BEFORE-RESTORE-WHERE\n"), 0644); err != nil {
				t.Fatal(err)
			}

			alternate := filepath.Join(t.TempDir(), "alternate-java.bck")
			altBytes := []byte("ALTERNATE-JAVA-BACKUP-MARKER\n")
			if err := os.WriteFile(alternate, altBytes, 0644); err != nil {
				t.Fatal(err)
			}
			if alternate == latest {
				t.Fatal("alternate path unexpectedly equals latest backup")
			}

			if err := s.Restore(alternate); err != nil {
				t.Fatalf("Restore(alternate): %v", err)
			}

			got, err := os.ReadFile(kpath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, altBytes) {
				t.Fatalf("Restore did not use `where`; got %q want alternate marker", got)
			}
		})
	}
}
