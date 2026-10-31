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

package certutil

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

// pemParseWarn is where ParsePEM writes skip warnings. Tests may replace it.
var pemParseWarn io.Writer = os.Stderr

// PEMEntry is one CERTIFICATE block from a PEM bundle: a parsed certificate,
// or the original PEM bytes of a block that failed to parse.
type PEMEntry struct {
	Cert *x509.Certificate // set when the block parsed
	Raw  []byte            // original PEM block (BEGIN..END) when parse failed
}

// PEMResult is the outcome of parsing a PEM certificate bundle.
type PEMResult struct {
	Certs   []*x509.Certificate
	Entries []PEMEntry // parseable certs and unparsable CERTIFICATE blocks, in file order
	Skipped int        // CERTIFICATE blocks that failed to parse
}

// ParsePEM extracts certificates from a PEM bundle. Each CERTIFICATE block is
// parsed independently. Unparsable blocks (for example those with a negative
// serial number) are skipped with a warning to stderr so one bad entry cannot
// abort the rest of the bundle. Non-CERTIFICATE PEM types are ignored.
func ParsePEM(blob []byte) ([]*x509.Certificate, error) {
	return ParsePEMResult(blob).Certs, nil
}

// ParsePEMResult is ParsePEM plus the ordered mix of parseable certificates
// and raw unparsable CERTIFICATE blocks. List/read callers use Certs; rewrite
// callers should write Entries so skipped blocks are not dropped.
func ParsePEMResult(blob []byte) PEMResult {
	var out PEMResult
	n := 0
	remaining := blob
	for {
		src := remaining
		block, rest := pem.Decode(src)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		n++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(pemParseWarn, "certutil: skipping PEM block %d: %v\n", n, err)
			out.Skipped++
			out.Entries = append(out.Entries, PEMEntry{Raw: rawPEMBlock(src, rest)})
			continue
		}
		out.Certs = append(out.Certs, cert)
		out.Entries = append(out.Entries, PEMEntry{Cert: cert})
	}
	return out
}

// KeepMatching returns parseable certificates that match keep, plus every
// unparsable CERTIFICATE block, in original order. removed is the parseable
// certificates that did not match.
func (r PEMResult) KeepMatching(keep func(*x509.Certificate) bool) (kept PEMResult, removed []*x509.Certificate) {
	for _, e := range r.Entries {
		if e.Cert == nil {
			kept.Entries = append(kept.Entries, e)
			kept.Skipped++
			continue
		}
		if keep != nil && keep(e.Cert) {
			kept.Entries = append(kept.Entries, e)
			kept.Certs = append(kept.Certs, e.Cert)
			continue
		}
		removed = append(removed, e.Cert)
	}
	return kept, removed
}

// AppendCerts adds certs after the existing entries.
func (r PEMResult) AppendCerts(certs []*x509.Certificate) PEMResult {
	out := PEMResult{
		Certs:   make([]*x509.Certificate, 0, len(r.Certs)+len(certs)),
		Entries: make([]PEMEntry, 0, len(r.Entries)+len(certs)),
		Skipped: r.Skipped,
	}
	out.Certs = append(out.Certs, r.Certs...)
	out.Certs = append(out.Certs, certs...)
	out.Entries = append(out.Entries, r.Entries...)
	for i := range certs {
		out.Entries = append(out.Entries, PEMEntry{Cert: certs[i]})
	}
	return out
}

// rawPEMBlock returns the original PEM text of the block pem.Decode consumed
// from src, including BEGIN/END lines. rest is Decode's remainder.
func rawPEMBlock(src, rest []byte) []byte {
	consumed := src
	if len(rest) > 0 && len(rest) <= len(src) && bytes.HasSuffix(src, rest) {
		consumed = src[:len(src)-len(rest)]
	}
	const begin = "-----BEGIN "
	i := bytes.LastIndex(consumed, []byte(begin))
	for i > 0 && consumed[i-1] != '\n' {
		i = bytes.LastIndex(consumed[:i], []byte(begin))
	}
	if i < 0 {
		i = 0
	}
	out := make([]byte, len(consumed)-i)
	copy(out, consumed[i:])
	return out
}
