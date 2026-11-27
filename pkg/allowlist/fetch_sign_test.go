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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFromPathOrURL_SignatureLocal(t *testing.T) {
	kp, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("countries:\n  - US\n")
	dir := t.TempDir()
	alPath := filepath.Join(dir, "allowlist.yaml")
	sigPath := filepath.Join(dir, "allowlist.yaml.minisig")
	pubPath := filepath.Join(dir, "allowlist.pub")
	if err := os.WriteFile(alPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, []byte(kp.signHashed(body, "timestamp:1 file:allowlist.yaml")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, []byte(kp.publicFile()), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := FromPathOrURL(alPath, FetchOptions{Signature: sigPath, PubKey: pubPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Countries) != 1 || got.Countries[0] != "US" {
		t.Fatalf("got %#v", got)
	}

	// Literal public key (file contents) also works.
	got, err = FromPathOrURL(alPath, FetchOptions{Signature: sigPath, PubKey: kp.publicFile()})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Countries) != 1 {
		t.Fatalf("literal pubkey: %#v", got)
	}

	// Wrong message fails before parse.
	if err := os.WriteFile(alPath, []byte("countries:\n  - JP\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = FromPathOrURL(alPath, FetchOptions{Signature: sigPath, PubKey: pubPath})
	if err == nil || !errors.Is(err, errMinisignVerify) {
		t.Fatalf("tampered allowlist: %v", err)
	}
}

func TestFromPathOrURL_SignatureHTTPS(t *testing.T) {
	kp, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("countries:\n  - US\n")
	sig := kp.signHashed(body, "timestamp:1")
	var hits int
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/al.yaml":
			_, _ = w.Write(body)
		case "/al.yaml.minisig":
			_, _ = w.Write([]byte(sig))
		default:
			http.NotFound(w, r)
		}
	})
	pub := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(pub, []byte(kp.publicFile()), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := FromPathOrURL(srv.URL+"/al.yaml", FetchOptions{
		Client:    srv.Client(),
		Signature: srv.URL + "/al.yaml.minisig",
		PubKey:    pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Countries) != 1 || got.Countries[0] != "US" {
		t.Fatalf("got %#v", got)
	}
	if hits != 2 {
		t.Fatalf("hits=%d", hits)
	}
}

func TestFromPathOrURL_SignatureAndPin(t *testing.T) {
	kp, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("countries:\n  - US\n")
	sum := sha256.Sum256(body)
	dir := t.TempDir()
	alPath := filepath.Join(dir, "al.yaml")
	sigPath := filepath.Join(dir, "al.minisig")
	pubPath := filepath.Join(dir, "al.pub")
	if err := os.WriteFile(alPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, []byte(kp.signHashed(body, "t")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, []byte(kp.publicFile()), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := FetchOptions{
		SHA256:    hex.EncodeToString(sum[:]),
		Signature: sigPath,
		PubKey:    pubPath,
	}
	if _, err := FromPathOrURL(alPath, opts); err != nil {
		t.Fatal(err)
	}
	opts.SHA256 = strings.Repeat("ab", 32)
	_, err = FromPathOrURL(alPath, opts)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("bad pin: %v", err)
	}
}

func TestFromPathOrURL_SignatureFailClosed(t *testing.T) {
	kp, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("countries:\n  - US\n")
	dir := t.TempDir()
	alPath := filepath.Join(dir, "al.yaml")
	sigPath := filepath.Join(dir, "al.minisig")
	pubPath := filepath.Join(dir, "al.pub")
	otherPub := filepath.Join(dir, "other.pub")
	if err := os.WriteFile(alPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, []byte(kp.signHashed(body, "t")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, []byte(kp.publicFile()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPub, []byte(other.publicFile()), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("pubkey without signature", func(t *testing.T) {
		_, err := FromPathOrURL(alPath, FetchOptions{PubKey: pubPath})
		if err == nil || !strings.Contains(err.Error(), "no signature was provided") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("signature without pubkey", func(t *testing.T) {
		_, err := FromPathOrURL(alPath, FetchOptions{Signature: sigPath})
		if err == nil || !strings.Contains(err.Error(), "no public key was provided") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		_, err := FromPathOrURL(alPath, FetchOptions{Signature: sigPath, PubKey: otherPub})
		if err == nil || !errors.Is(err, errMinisignKeyID) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("truncated signature", func(t *testing.T) {
		bad := filepath.Join(dir, "bad.minisig")
		if err := os.WriteFile(bad, []byte("untrusted comment: x\nYQ==\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := FromPathOrURL(alPath, FetchOptions{Signature: bad, PubKey: pubPath})
		if err == nil || !errors.Is(err, errMinisignSignature) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("pubkey url refused", func(t *testing.T) {
		_, err := FromPathOrURL(alPath, FetchOptions{
			Signature: sigPath,
			PubKey:    "https://example.com/key.pub",
		})
		if err == nil || !errors.Is(err, errMinisignPubKeyURL) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("signature http refused", func(t *testing.T) {
		_, err := FromPathOrURL(alPath, FetchOptions{
			Signature: "http://127.0.0.1:1/al.minisig",
			PubKey:    pubPath,
		})
		if err == nil || !strings.Contains(err.Error(), "signature URLs must be https") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("oversize signature", func(t *testing.T) {
		big := filepath.Join(dir, "big.minisig")
		if err := os.WriteFile(big, bytesOf(int(DefaultMaxBytes)+1), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := FromPathOrURL(alPath, FetchOptions{Signature: big, PubKey: pubPath, MaxSize: 64})
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("got %v", err)
		}
	})
}

func bytesOf(n int) []byte {
	return []byte(strings.Repeat("a", n))
}

func TestFromPathOrURL_SignatureRedactsUserinfo(t *testing.T) {
	const password = "s3cret-sig"
	kp, err := generateMinisignKey()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("countries:\n  - US\n")
	var hits int
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/al.yaml":
			_, _ = w.Write(body)
		case "/missing.minisig":
			http.Error(w, "nope", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	})
	withUser := func(path string) string {
		t.Helper()
		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword("alice", password)
		u.Path = path
		return u.String()
	}
	pub := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(pub, []byte(kp.publicFile()), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = FromPathOrURL(srv.URL+"/al.yaml", FetchOptions{
		Client:    srv.Client(),
		Signature: withUser("/missing.minisig"),
		PubKey:    pub,
	})
	if err == nil {
		t.Fatal("expected status error")
	}
	msg := err.Error()
	if strings.Contains(msg, password) {
		t.Fatalf("password leaked: %s", msg)
	}
	if !strings.Contains(msg, "xxxxx") {
		t.Fatalf("not redacted: %s", msg)
	}
	if strings.Contains(msg, "s3cret") {
		t.Fatalf("password leaked: %s", msg)
	}

	ref := "https://alice:" + password + "@example.com/%zz"
	_, err = FromPathOrURL(srv.URL+"/al.yaml", FetchOptions{
		Client:    srv.Client(),
		Signature: ref,
		PubKey:    pub,
	})
	if err == nil || !errors.Is(err, errInvalidSignatureURL) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), ref) {
		t.Fatalf("raw URL leaked: %v", err)
	}
}

func TestValidateSignatureAndPubKeyRefs(t *testing.T) {
	t.Parallel()
	if err := ValidateSignatureRef("http://example.com/a.minisig"); err == nil || !strings.Contains(err.Error(), "signature URLs must be https") {
		t.Fatalf("http: %v", err)
	}
	if err := ValidateSignatureRef("https://example.com/a.minisig"); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePubKeyRef("https://example.com/key.pub"); !errors.Is(err, errMinisignPubKeyURL) {
		t.Fatalf("https pubkey: %v", err)
	}
	if err := ValidatePubKeyRef("/tmp/key.pub"); err != nil {
		t.Fatal(err)
	}
}
