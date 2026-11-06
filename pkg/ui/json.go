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

package ui

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

const jsonFormat = "json"

type jsonCert struct {
	SHA256    string `json:"sha256"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Serial    string `json:"serial"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Days      int    `json:"days"`
	Expired   bool   `json:"expired"`
	KeyType   string `json:"key_type"`
	KeyBits   int    `json:"key_bits"`
	IsCA      bool   `json:"is_ca"`
	Store     string `json:"store"`
	Path      string `json:"path"`
}

type jsonPrinter struct {
	meta Meta
	cfg  *Config
	now  time.Time // zero means time.Now()
}

func (jsonPrinter) close() {}

func (p jsonPrinter) write(w io.Writer, certs []*x509.Certificate) error {
	out := make([]jsonCert, 0, len(certs))
	store := p.meta.Name
	path := ""
	if p.cfg != nil {
		path = p.cfg.SourcePath
	}
	if path == "" {
		path = p.meta.Path
	}
	now := p.now
	if now.IsZero() {
		now = time.Now()
	}
	for _, c := range certs {
		if c == nil {
			continue
		}
		algo, bits := certutil.PublicKeyInfo(c)
		days := certutil.DaysUntilExpiry(c, now)
		out = append(out, jsonCert{
			SHA256:    certutil.GetHexSHA256Fingerprint(*c),
			Subject:   certutil.StringifyPKIXName(c.Subject),
			Issuer:    certutil.StringifyPKIXName(c.Issuer),
			Serial:    c.SerialNumber.String(),
			NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
			Days:      days,
			Expired:   days < 0,
			KeyType:   algo,
			KeyBits:   bits,
			IsCA:      c.IsCA,
			Store:     store,
			Path:      path,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	return nil
}
