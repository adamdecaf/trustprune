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
	"fmt"
	"io"
	"os"

	"github.com/adamdecaf/trustprune/pkg/file"
)

// FromFile reads a series of PEM encoded blocks from the given file.
// Unparsable CERTIFICATE blocks are skipped (see ParsePEM).
func FromFile(path string) ([]*x509.Certificate, error) {
	parsed, err := FromFileResult(path)
	if err != nil {
		return nil, err
	}
	return parsed.Certs, nil
}

// FromFileResult is FromFile plus ordered entries (parseable certs and raw
// unparsable CERTIFICATE blocks) for rewrite callers.
func FromFileResult(path string) (PEMResult, error) {
	if !file.Exists(path) {
		return PEMResult{}, fmt.Errorf("%s does not exist", path)
	}

	r, err := os.Open(path)
	if err != nil {
		return PEMResult{}, fmt.Errorf("error opening file, err=%w", err)
	}
	defer func() {
		e := r.Close()
		if e != nil {
			fmt.Printf("error closing test pem file - %s\n", e)
		}
	}()

	body, err := io.ReadAll(r)
	if err != nil {
		return PEMResult{}, fmt.Errorf("error reading file, err=%w", err)
	}
	return ParsePEMResult(body), nil
}
