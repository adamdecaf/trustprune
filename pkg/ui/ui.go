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
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

type uiface func(certs []*x509.Certificate, cfg *Config) error

var (
	cliFormat = "cli"

	uiOptions = map[string]uiface{
		cliFormat: showCertsOnCli,
		"web":     showCertsOnWeb,
	}
)

// DefaultUI returns the standard output medium
func DefaultUI() string {
	return cliFormat
}

// GetUIs returns all output mediums, sorted.
func GetUIs() []string {
	out := make([]string, 0, len(uiOptions))
	for k := range uiOptions {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type Config struct {
	// If we should only show the certificate count, rather than each one
	Count bool

	// What format to print certificates in, formats are defined in ../main.go and
	// checked in print.go
	Format string

	// Outfile, when non-empty, receives formatted list output (any format,
	// including -count) instead of stdout.
	Outfile string

	// Which user interface to show users, e.g. cli or web
	// Default (and possible) value(s) can be found in the ui package
	UI string

	// Verbose adds full fingerprint, serial, and store path columns to table output.
	Verbose bool

	// SourcePath is the -file path when listing from a file (included in JSON).
	SourcePath string
}

func ListCertificates(certs []*x509.Certificate, cfg *Config) error {
	return ListCertificatesWithMeta(Meta{}, certs, cfg)
}

// Meta is used to add additional details on the certficiate store
type Meta struct {
	Name    string
	Version string
	Path    string
}

func ListCertificatesWithMeta(meta Meta, certs []*x509.Certificate, cfg *Config) error {
	if cfg != nil && cfg.SourcePath == "" && meta.Path != "" {
		c := *cfg
		c.SourcePath = meta.Path
		cfg = &c
	}

	// -count ignores cfg.UI and the empty-store error. Text formats print "N\n".
	// --format json (case-insensitive) prints a pretty-printed {"count": N}
	// object. Either is written to cfg.Outfile when set so stdout stays empty,
	// the same as other list formats. An unknown format keeps the plain line.
	if cfg.Count {
		return writeToConfiguredOutput(cfg, func(w io.Writer) error {
			if strings.EqualFold(cfg.Format, jsonFormat) {
				return writeCountJSON(w, len(certs))
			}
			_, err := fmt.Fprintf(w, "%d\n", len(certs))
			return err
		})
	}

	// Show something meaningful if there's nothing otherwise
	if len(certs) == 0 {
		return errors.New("no certificates to display")
	}

	if isObservatory(cfg.Format) {
		return writeObservatoryReport(meta, certs, cfg)
	}
	if strings.EqualFold(cfg.Format, jsonFormat) {
		return showCertsOnCliWithPrinter(certs, cfg, jsonPrinter{meta: meta, cfg: cfg})
	}

	fn, ok := uiOptions[strings.ToLower(cfg.UI)]
	if !ok {
		return fmt.Errorf("unknown ui %q", cfg.UI)
	}
	return fn(certs, cfg)
}
