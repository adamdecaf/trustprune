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
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/adamdecaf/trustprune/pkg/file"
)

// showCertsOnCli outputs the slice of certificates in `cfg.Format`.
// A non-empty cfg.Outfile receives that output and stdout is left empty.
func showCertsOnCli(certs []*x509.Certificate, cfg *Config) error {
	p, ok := getPrinter(cfg.Format)
	if !ok {
		return fmt.Errorf("unknown format %s specified", cfg.Format)
	}
	return showCertsOnCliWithPrinter(certs, cfg, p)
}

func showCertsOnCliWithPrinter(certs []*x509.Certificate, cfg *Config, p printer) error {
	if tp, ok := p.(tablePrinter); ok {
		tp.verbose = cfg != nil && cfg.Verbose
		if cfg != nil {
			tp.path = cfg.SourcePath
		}
		p = tp
	}
	err := writeToConfiguredOutput(cfg, func(w io.Writer) error {
		return p.write(w, certs)
	})
	p.close()
	return err
}

// writeToConfiguredOutput runs write against stdout, or stages it beside
// cfg.Outfile and renames that file into place only after write succeeds.
// A failed write leaves any existing Outfile untouched. Stdout is unchanged
// when Outfile is empty. A set Outfile prints nothing on stdout.
func writeToConfiguredOutput(cfg *Config, write func(io.Writer) error) error {
	if cfg == nil || cfg.Outfile == "" {
		return write(os.Stdout)
	}
	return publishOutfile(cfg.Outfile, write)
}

// publishOutfile writes to a temporary file in the same directory as path
// (mode file.TempFilePermissions) and renames it onto path only after write
// returns nil. The rename stays on one filesystem and replaces an existing
// file, including when path is also the input file. On failure the destination
// is left as it was and the temporary file is removed.
func publishOutfile(path string, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	// #nosec G304 -- -out is the user-requested output path; stage beside it so rename stays on one filesystem
	tmp, err := os.CreateTemp(dir, ".trustprune-out-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	published := false
	defer func() {
		if !published {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(file.TempFilePermissions); err != nil {
		_ = tmp.Close()
		return err
	}
	writeErr := write(tmp)
	closeErr := tmp.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	// os.Rename replaces an existing file (Unix rename; Windows MoveFileEx
	// with MOVEFILE_REPLACE_EXISTING). The destination is untouched until here.
	// #nosec G304 -- -out is the user-requested output path
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	published = true
	return nil
}
