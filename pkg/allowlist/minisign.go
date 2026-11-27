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
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// minisign is implemented here with crypto/ed25519 and
// golang.org/x/crypto/blake2b, which are already in the module. The
// format matches minisign (and is close to OpenBSD signify): a
// detached signature file plus a public key file. Hashed signatures
// ("ED") sign a BLAKE2b-512 of the message; legacy ("Ed") signs the
// raw bytes. The trusted comment is also signed. There is no new
// dependency.

const (
	minisignCommentPrefix        = "untrusted comment: "
	minisignTrustedCommentPrefix = "trusted comment: "
	minisignAlg                  = "Ed"
	minisignAlgHashed            = "ED"
	minisignPubLen               = 2 + 8 + ed25519.PublicKeySize // 42
	minisignSigLen               = 2 + 8 + ed25519.SignatureSize // 74
)

var (
	errMinisignPublicKey   = errors.New("allowlist public key is not a minisign public key")
	errMinisignSignature   = errors.New("allowlist signature is not a minisign signature")
	errMinisignKeyID       = errors.New("allowlist signature key id does not match the public key")
	errMinisignVerify      = errors.New("allowlist signature verification failed")
	errMinisignPubKeyURL   = errors.New("allowlist public key must be a local minisign public key file or a minisign public key, not a URL")
	errInvalidSignatureURL = errors.New("invalid signature URL: the address could not be parsed")
)

type minisignPublicKey struct {
	id  [8]byte
	key ed25519.PublicKey
}

type minisignSignature struct {
	hashed  bool
	id      [8]byte
	sig     []byte
	comment string
	global  []byte
}

type minisignKeyPair struct {
	id   [8]byte
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func parseMinisignPublicKey(data []byte) (minisignPublicKey, error) {
	raw, err := minisignKeyBytes(data)
	if err != nil {
		return minisignPublicKey{}, err
	}
	if len(raw) != minisignPubLen || string(raw[:2]) != minisignAlg {
		return minisignPublicKey{}, errMinisignPublicKey
	}
	var pk minisignPublicKey
	copy(pk.id[:], raw[2:10])
	pk.key = ed25519.PublicKey(append([]byte{}, raw[10:]...))
	return pk, nil
}

func minisignKeyBytes(data []byte) ([]byte, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, errMinisignPublicKey
	}
	if looksLikeURL(text) {
		return nil, errMinisignPubKeyURL
	}
	line := text
	if strings.HasPrefix(text, minisignCommentPrefix) || strings.Contains(text, "\n") {
		lines := minisignNonEmptyLines(text)
		if len(lines) == 0 {
			return nil, errMinisignPublicKey
		}
		if strings.HasPrefix(lines[0], minisignCommentPrefix) {
			if len(lines) < 2 {
				return nil, errMinisignPublicKey
			}
			line = lines[1]
		} else {
			line = lines[0]
		}
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		return nil, errMinisignPublicKey
	}
	return raw, nil
}

func parseMinisignSignature(data []byte) (minisignSignature, error) {
	lines := minisignNonEmptyLines(string(data))
	if len(lines) < 3 {
		return minisignSignature{}, errMinisignSignature
	}
	i := 0
	if strings.HasPrefix(lines[0], minisignCommentPrefix) {
		i++
	}
	if i+2 >= len(lines) {
		return minisignSignature{}, errMinisignSignature
	}
	raw, err := base64.StdEncoding.DecodeString(lines[i])
	if err != nil || len(raw) != minisignSigLen {
		return minisignSignature{}, errMinisignSignature
	}
	alg := string(raw[:2])
	var sig minisignSignature
	switch alg {
	case minisignAlgHashed:
		sig.hashed = true
	case minisignAlg:
	default:
		return minisignSignature{}, errMinisignSignature
	}
	copy(sig.id[:], raw[2:10])
	sig.sig = append([]byte{}, raw[10:]...)
	if !strings.HasPrefix(lines[i+1], minisignTrustedCommentPrefix) {
		return minisignSignature{}, errMinisignSignature
	}
	sig.comment = strings.TrimPrefix(lines[i+1], minisignTrustedCommentPrefix)
	global, err := base64.StdEncoding.DecodeString(lines[i+2])
	if err != nil || len(global) != ed25519.SignatureSize {
		return minisignSignature{}, errMinisignSignature
	}
	sig.global = global
	return sig, nil
}

func verifyMinisign(message []byte, sig minisignSignature, pk minisignPublicKey) error {
	if subtle.ConstantTimeCompare(sig.id[:], pk.id[:]) != 1 {
		return errMinisignKeyID
	}
	signed := message
	if sig.hashed {
		sum := blake2b.Sum512(message)
		signed = sum[:]
	}
	if !ed25519.Verify(pk.key, signed, sig.sig) {
		return errMinisignVerify
	}
	commentMsg := append(append([]byte{}, sig.sig...), sig.comment...)
	if !ed25519.Verify(pk.key, commentMsg, sig.global) {
		return errMinisignVerify
	}
	return nil
}

func minisignNonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func generateMinisignKey() (minisignKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return minisignKeyPair{}, err
	}
	var kp minisignKeyPair
	if _, err := rand.Read(kp.id[:]); err != nil {
		return minisignKeyPair{}, err
	}
	kp.pub = pub
	kp.priv = priv
	return kp, nil
}

func (k minisignKeyPair) publicFile() string {
	raw := make([]byte, minisignPubLen)
	copy(raw[:2], minisignAlg)
	copy(raw[2:10], k.id[:])
	copy(raw[10:], k.pub)
	return minisignCommentPrefix + "minisign public key " + fmt.Sprintf("%X", k.id) + "\n" +
		base64.StdEncoding.EncodeToString(raw) + "\n"
}

// signMinisignHashed writes a hashed ("ED") minisign signature for message.
func (k minisignKeyPair) signHashed(message []byte, trustedComment string) string {
	sum := blake2b.Sum512(message)
	sig := ed25519.Sign(k.priv, sum[:])
	packet := make([]byte, minisignSigLen)
	copy(packet[:2], minisignAlgHashed)
	copy(packet[2:10], k.id[:])
	copy(packet[10:], sig)
	commentMsg := append(append([]byte{}, sig...), trustedComment...)
	global := ed25519.Sign(k.priv, commentMsg)
	return minisignCommentPrefix + "signature from minisign secret key " + fmt.Sprintf("%X", k.id) + "\n" +
		base64.StdEncoding.EncodeToString(packet) + "\n" +
		minisignTrustedCommentPrefix + trustedComment + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n"
}
