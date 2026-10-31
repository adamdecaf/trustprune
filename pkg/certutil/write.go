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
	"os"

	"github.com/adamdecaf/trustprune/pkg/file"
)

// ToFile overwrites file at `path` with the certificates encoded in
// PEM format.
func ToFile(path string, certs []*x509.Certificate) error {
	entries := make([]PEMEntry, 0, len(certs))
	for i := range certs {
		entries = append(entries, PEMEntry{Cert: certs[i]})
	}
	return ToFileEntries(path, entries)
}

// ToFileEntries overwrites path with parseable certificates re-encoded as PEM
// and unparsable CERTIFICATE blocks written as their original PEM bytes.
func ToFileEntries(path string, entries []PEMEntry) error {
	var perms os.FileMode = file.TempFilePermissions
	stat, err := os.Stat(path)
	if err == nil {
		perms = stat.Mode()
	}
	body, err := EncodePEMEntries(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, perms)
}

// EncodePEMEntries writes entries in order: parsed certificates via pem.Encode,
// unparsable blocks as the stored raw PEM (BEGIN..END).
func EncodePEMEntries(entries []PEMEntry) ([]byte, error) {
	var buf bytes.Buffer
	for i := range entries {
		if entries[i].Cert != nil {
			b := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: entries[i].Cert.Raw,
			}
			if err := pem.Encode(&buf, b); err != nil {
				return nil, err
			}
			continue
		}
		if len(entries[i].Raw) == 0 {
			continue
		}
		buf.Write(entries[i].Raw)
		next := i + 1
		for next < len(entries) && entries[next].Cert == nil && len(entries[next].Raw) == 0 {
			next++
		}
		// Separator only when another block follows; preserve final raw bytes as-is.
		if next < len(entries) && entries[i].Raw[len(entries[i].Raw)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes(), nil
}
