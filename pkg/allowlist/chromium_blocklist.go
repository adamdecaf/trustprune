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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

const maxChromiumBlocklistBytes = 32 << 20

// ChromiumItem is one SHA-256 value taken from a Chromium
// net/data/ssl/blocklist file. SHA256 is lowercase hex of the certificate
// DER or of the SubjectPublicKeyInfo DER, always computed from the file
// bytes, never from the filename.
type ChromiumItem struct {
	SHA256  string
	Comment string
}

// ChromiumBlocklist is the certificates and standalone public keys in a
// Chromium net/data/ssl/blocklist directory or tarball.
type ChromiumBlocklist struct {
	Certs []ChromiumItem
	SPKIs []ChromiumItem
}

// ParseChromiumBlocklistArchive reads a gzip-compressed or plain tar
// archive of Chromium's net/data/ssl/blocklist directory. name is used in
// errors. CERTIFICATE PEM files contribute certificate SHA-256
// fingerprints. PUBLIC KEY .key files contribute SPKI SHA-256 hashes.
// Other files, including the README, are ignored. Unreadable .pem or .key
// entries return an error instead of inventing a fingerprint.
func ParseChromiumBlocklistArchive(r io.Reader, name string) (ChromiumBlocklist, error) {
	if name == "" {
		name = "chromium blocklist archive"
	}
	body, err := io.ReadAll(io.LimitReader(r, maxChromiumBlocklistBytes+1))
	if err != nil {
		return ChromiumBlocklist{}, fmt.Errorf("reading %s: %w", name, err)
	}
	if int64(len(body)) > maxChromiumBlocklistBytes {
		return ChromiumBlocklist{}, fmt.Errorf("%s: size exceeds %d byte limit", name, maxChromiumBlocklistBytes)
	}
	if len(body) == 0 {
		return ChromiumBlocklist{}, fmt.Errorf("%s is empty", name)
	}
	src := io.Reader(bytes.NewReader(body))
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return ChromiumBlocklist{}, fmt.Errorf("gzip %s: %w", name, err)
		}
		plain, err := io.ReadAll(io.LimitReader(gr, maxChromiumBlocklistBytes+1))
		cerr := gr.Close()
		if err != nil {
			return ChromiumBlocklist{}, fmt.Errorf("gzip %s: %w", name, err)
		}
		if cerr != nil {
			return ChromiumBlocklist{}, fmt.Errorf("gzip %s: %w", name, cerr)
		}
		if int64(len(plain)) > maxChromiumBlocklistBytes {
			return ChromiumBlocklist{}, fmt.Errorf("gzip %s: decompressed size exceeds %d byte limit", name, maxChromiumBlocklistBytes)
		}
		src = bytes.NewReader(plain)
	}

	var out ChromiumBlocklist
	seenCert := make(map[string]struct{})
	seenSPKI := make(map[string]struct{})
	tr := tar.NewReader(src)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ChromiumBlocklist{}, fmt.Errorf("tar %s: %w", name, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := path.Base(hdr.Name)
		if base == "" || base == "." || strings.HasPrefix(base, ".") {
			continue
		}
		ext := strings.ToLower(path.Ext(base))
		if ext != ".pem" && ext != ".key" {
			continue
		}
		if hdr.Size > maxChromiumBlocklistBytes {
			return ChromiumBlocklist{}, fmt.Errorf("%s: %s is larger than %d bytes", name, base, maxChromiumBlocklistBytes)
		}
		bs, err := io.ReadAll(io.LimitReader(tr, maxChromiumBlocklistBytes+1))
		if err != nil {
			return ChromiumBlocklist{}, fmt.Errorf("%s: reading %s: %w", name, base, err)
		}
		if int64(len(bs)) > maxChromiumBlocklistBytes {
			return ChromiumBlocklist{}, fmt.Errorf("%s: %s exceeds %d byte limit", name, base, maxChromiumBlocklistBytes)
		}
		certs, spkis, err := parseChromiumBlocklistFile(base, bs)
		if err != nil {
			return ChromiumBlocklist{}, fmt.Errorf("%s: %w", name, err)
		}
		for _, it := range certs {
			if _, ok := seenCert[it.SHA256]; ok {
				continue
			}
			seenCert[it.SHA256] = struct{}{}
			out.Certs = append(out.Certs, it)
		}
		for _, it := range spkis {
			if _, ok := seenSPKI[it.SHA256]; ok {
				continue
			}
			seenSPKI[it.SHA256] = struct{}{}
			out.SPKIs = append(out.SPKIs, it)
		}
	}
	if len(out.Certs) == 0 && len(out.SPKIs) == 0 {
		return ChromiumBlocklist{}, fmt.Errorf("%s: no certificates or public keys found", name)
	}
	sort.Slice(out.Certs, func(i, j int) bool { return out.Certs[i].SHA256 < out.Certs[j].SHA256 })
	sort.Slice(out.SPKIs, func(i, j int) bool { return out.SPKIs[i].SHA256 < out.SPKIs[j].SHA256 })
	return out, nil
}

func parseChromiumBlocklistFile(base string, body []byte) (certs, spkis []ChromiumItem, err error) {
	ext := strings.ToLower(path.Ext(base))
	remaining := body
	found := 0
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		switch block.Type {
		case "CERTIFICATE":
			found++
			if len(block.Bytes) == 0 {
				return nil, nil, fmt.Errorf("%s: empty CERTIFICATE block", base)
			}
			fp := chromiumSHA256Hex(block.Bytes)
			comment := "certificate"
			if c, perr := certutil.ParseCertificate(block.Bytes); perr == nil && c != nil {
				comment = certutil.StringifyPKIXName(c.Subject)
				if comment == "" {
					comment = "certificate"
				}
			}
			certs = append(certs, ChromiumItem{SHA256: fp, Comment: oneLineComment(comment)})
		case "PUBLIC KEY":
			found++
			if len(block.Bytes) == 0 {
				return nil, nil, fmt.Errorf("%s: empty PUBLIC KEY block", base)
			}
			if _, perr := x509.ParsePKIXPublicKey(block.Bytes); perr != nil {
				return nil, nil, fmt.Errorf("%s: public key: %w", base, perr)
			}
			spkis = append(spkis, ChromiumItem{SHA256: chromiumSHA256Hex(block.Bytes), Comment: "SPKI"})
		default:
			// Ignore other PEM types in the same file.
		}
	}
	if found == 0 {
		if ext == ".key" || ext == ".pem" {
			return nil, nil, fmt.Errorf("%s: no CERTIFICATE or PUBLIC KEY PEM block", base)
		}
	}
	return certs, spkis, nil
}

func chromiumSHA256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func oneLineComment(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "certificate"
	}
	return s
}

// ChromiumFingerprintOverlap counts how many certificate SHA-256 values in
// fps also appear on the embedded Apple and CCADB blocklists.
func ChromiumFingerprintOverlap(fps []string) (apple, ccadb, both, either int) {
	inApple := make(map[string]struct{}, len(appleBlocklistedFingerprints))
	for _, fp := range appleBlocklistedFingerprints {
		inApple[fp] = struct{}{}
	}
	inCCADB := make(map[string]struct{}, len(ccadbRemovedBlocklistedFingerprints))
	for _, fp := range ccadbRemovedBlocklistedFingerprints {
		inCCADB[fp] = struct{}{}
	}
	for _, fp := range fps {
		_, a := inApple[fp]
		_, c := inCCADB[fp]
		if a {
			apple++
		}
		if c {
			ccadb++
		}
		if a && c {
			both++
		}
		if a || c {
			either++
		}
	}
	return apple, ccadb, both, either
}
