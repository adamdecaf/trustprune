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

package allowlist

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures in testdata/minisign were produced by official minisign 0.12.
// The keys are throwaway test keys and must not be reused.
const (
	minisignFixtureDir    = "testdata/minisign"
	minisignFixtureFile   = minisignFixtureDir + "/allowlist.yaml"
	minisignFixturePub    = minisignFixtureDir + "/test-key.pub"
	minisignFixtureOther  = minisignFixtureDir + "/other-key.pub"
	minisignFixtureHashed = minisignFixtureDir + "/allowlist.yaml.minisig"
	minisignFixtureLegacy = minisignFixtureDir + "/allowlist.yaml.legacy.minisig"
)

func TestMinisignOfficialHashedAndLegacy(t *testing.T) {
	t.Parallel()
	for _, sig := range []string{minisignFixtureHashed, minisignFixtureLegacy} {
		if _, err := FromPathOrURL(minisignFixtureFile, FetchOptions{
			Signature: sig,
			PubKey:    minisignFixturePub,
		}); err != nil {
			t.Fatalf("%s: %v", sig, err)
		}
	}
}

func TestMinisignOfficialRejectsTampering(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body, err := os.ReadFile(minisignFixtureFile)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] = 'X'
	tampered := filepath.Join(dir, "allowlist.yaml")
	if err := os.WriteFile(tampered, body, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, file, sig, pub string
		want                 error
	}{
		{"tampered file", tampered, minisignFixtureHashed, minisignFixturePub, errMinisignVerify},
		{"wrong key", minisignFixtureFile, minisignFixtureHashed, minisignFixtureOther, errMinisignKeyID},
		{"tampered trusted comment", minisignFixtureFile, writeTamperedComment(t, dir), minisignFixturePub, errMinisignVerify},
		{"truncated signature", minisignFixtureFile, writeTruncatedSig(t, dir), minisignFixturePub, errMinisignSignature},
		{"garbage signature", minisignFixtureFile, writeGarbageSig(t, dir), minisignFixturePub, errMinisignSignature},
		{"wrong key same id", minisignFixtureFile, minisignFixtureHashed, writeSameIDWrongKey(t, dir), errMinisignVerify},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := FromPathOrURL(tc.file, FetchOptions{Signature: tc.sig, PubKey: tc.pub})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func writeTamperedComment(t *testing.T, dir string) string {
	t.Helper()
	sig, err := os.ReadFile(minisignFixtureHashed)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Replace(string(sig), "timestamp:1 file:allowlist.yaml", "timestamp:1 file:allowlist.yaml EVIL", 1)
	if out == string(sig) {
		t.Fatal("trusted comment not found")
	}
	path := filepath.Join(dir, "tampered-comment.minisig")
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTruncatedSig(t *testing.T, dir string) string {
	t.Helper()
	sig, err := os.ReadFile(minisignFixtureHashed)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(sig), "\n"), "\n")
	if len(lines) < 4 {
		t.Fatal("signature fixture is too short")
	}
	path := filepath.Join(dir, "truncated.minisig")
	if err := os.WriteFile(path, []byte(strings.Join(lines[:3], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeGarbageSig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "garbage.minisig")
	if err := os.WriteFile(path, []byte("this is not a signature\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeSameIDWrongKey(t *testing.T, dir string) string {
	t.Helper()
	other, err := os.ReadFile(minisignFixtureOther)
	if err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(minisignFixturePub)
	if err != nil {
		t.Fatal(err)
	}
	otherRaw, err := base64.StdEncoding.DecodeString(minisignKeyLine(t, other))
	if err != nil {
		t.Fatal(err)
	}
	goodRaw, err := base64.StdEncoding.DecodeString(minisignKeyLine(t, good))
	if err != nil {
		t.Fatal(err)
	}
	if len(otherRaw) != minisignPubLen || len(goodRaw) != minisignPubLen {
		t.Fatal("unexpected public key length")
	}
	crafted := append([]byte{}, otherRaw...)
	copy(crafted[2:10], goodRaw[2:10])
	path := filepath.Join(dir, "same-id-wrong.pub")
	body := minisignCommentPrefix + "TEST KEY; crafted same id\n" +
		base64.StdEncoding.EncodeToString(crafted) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func minisignKeyLine(t *testing.T, data []byte) string {
	t.Helper()
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, minisignCommentPrefix) {
			return line
		}
	}
	t.Fatal("public key line not found")
	return ""
}
