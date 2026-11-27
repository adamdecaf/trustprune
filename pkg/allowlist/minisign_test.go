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
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
)

func TestMinisignRoundTrip(t *testing.T) {
	t.Parallel()
	kp, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("fingerprints:\n  - abcdef\n")
	sig := kp.signHashed(msg, "timestamp:1 file:allowlist.yaml")
	pk, err := parseMinisignPublicKey([]byte(kp.publicFile()))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseMinisignSignature([]byte(sig))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.hashed {
		t.Fatal("expected hashed signature")
	}
	if err := verifyMinisign(msg, parsed, pk); err != nil {
		t.Fatal(err)
	}
	if err := verifyMinisign(append(msg, 'x'), parsed, pk); err == nil {
		t.Fatal("modified message should fail")
	}
}

func TestMinisignKeyIDMismatch(t *testing.T) {
	t.Parallel()
	a, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello")
	sig, err := parseMinisignSignature([]byte(a.signHashed(msg, "timestamp:1")))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := parseMinisignPublicKey([]byte(b.publicFile()))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMinisign(msg, sig, pk); !errors.Is(err, errMinisignKeyID) {
		t.Fatalf("got %v", err)
	}
}

func TestMinisignWrongKeySameIDDoesNotVerify(t *testing.T) {
	t.Parallel()
	a, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	copy(b.id[:], a.id[:])
	msg := []byte("hello")
	sig, err := parseMinisignSignature([]byte(a.signHashed(msg, "timestamp:1")))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := parseMinisignPublicKey([]byte(b.publicFile()))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMinisign(msg, sig, pk); !errors.Is(err, errMinisignVerify) {
		t.Fatalf("got %v", err)
	}
}

func TestMinisignLegacyRawSignature(t *testing.T) {
	t.Parallel()
	kp, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("legacy body")
	sig := ed25519.Sign(kp.priv, msg)
	packet := make([]byte, minisignSigLen)
	copy(packet[:2], minisignAlg)
	copy(packet[2:10], kp.id[:])
	copy(packet[10:], sig)
	comment := "timestamp:1"
	global := ed25519.Sign(kp.priv, append(append([]byte{}, sig...), comment...))
	file := minisignCommentPrefix + "sig\n" +
		encode64(packet) + "\n" +
		minisignTrustedCommentPrefix + comment + "\n" +
		encode64(global) + "\n"
	parsed, err := parseMinisignSignature([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.hashed {
		t.Fatal("expected unhashed signature")
	}
	pk, err := parseMinisignPublicKey([]byte(kp.publicFile()))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMinisign(msg, parsed, pk); err != nil {
		t.Fatal(err)
	}
}

func encode64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
