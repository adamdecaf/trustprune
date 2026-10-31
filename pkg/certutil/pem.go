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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

// pemParseWarn is where ParsePEM writes skip warnings. Tests may replace it.
var pemParseWarn io.Writer = os.Stderr

// PEMResult is the outcome of parsing a PEM certificate bundle.
type PEMResult struct {
	Certs   []*x509.Certificate
	Skipped int // CERTIFICATE blocks that failed to parse
}

// ParsePEM extracts certificates from a PEM bundle. Each CERTIFICATE block is
// parsed independently. Unparsable blocks (for example those with a negative
// serial number) are skipped with a warning to stderr so one bad entry cannot
// abort the rest of the bundle. Non-CERTIFICATE PEM types are ignored.
func ParsePEM(blob []byte) ([]*x509.Certificate, error) {
	return ParsePEMResult(blob).Certs, nil
}

// ParsePEMResult is ParsePEM plus a count of skipped CERTIFICATE blocks.
// List/read callers use Certs; rewrite callers should refuse when Skipped > 0
// so unparsable certificates are not silently dropped from a written bundle.
func ParsePEMResult(blob []byte) PEMResult {
	var out PEMResult
	var block *pem.Block
	n := 0
	for {
		block, blob = pem.Decode(blob)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		n++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(pemParseWarn, "certutil: skipping PEM block %d: %v\n", n, err)
			out.Skipped++
			continue
		}
		out.Certs = append(out.Certs, cert)
	}
	return out
}
