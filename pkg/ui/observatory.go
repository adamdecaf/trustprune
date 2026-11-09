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
	"io"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"gopkg.in/yaml.v3"
)

// observatory is a printer for the 'trust_stores_observatory'
// https://github.com/nabla-c0d3/trust_stores_observatory

var (
	observatoryFormat     = "observatory"
	observatoryTimeFormat = "2006-01-02"
)

func isObservatory(format string) bool {
	return format == observatoryFormat
}

type observatoryReport struct {
	Platform     string            `yaml:"platform"`
	Version      string            `yaml:"version"`
	URL          string            `yaml:"url"`
	DateFetched  string            `yaml:"date_fetched"`
	Count        int               `yaml:"trusted_certificates_count"`
	Certificates []observatoryCert `yaml:"trusted_certificates"`
}

type observatoryCert struct {
	SubjectName string `yaml:"subject_name"`
	Fingerprint string `yaml:"fingerprint"`
}

func writeObservatoryReport(meta Meta, certs []*x509.Certificate, cfg *Config) error {
	dateFetched := time.Now().Format(observatoryTimeFormat)
	count := len(certs)
	report := observatoryReport{
		Platform:    meta.Name,
		Version:     meta.Version,
		DateFetched: dateFetched,
		Count:       count,
	}
	obsCerts := make([]observatoryCert, count)
	for i := range obsCerts {
		cert := certs[i]
		obsCerts[i] = observatoryCert{
			SubjectName: certutil.StringifyPKIXName(cert.Subject),
			Fingerprint: certutil.GetHexSHA256Fingerprint(*cert),
		}
	}
	report.Certificates = obsCerts

	bs, err := yaml.Marshal(&report)
	if err != nil {
		return err
	}
	return writeToConfiguredOutput(cfg, func(w io.Writer) error {
		_, err := w.Write(bs)
		return err
	})
}
