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

// writerForConfig returns where formatted list output goes.
// A non-empty Outfile creates or truncates that file (mode 0600) and the
// caller must close it. Otherwise the writer is stdout and closer is nil.
// A set Outfile prints nothing on stdout, matching observatory.
func writerForConfig(cfg *Config) (io.Writer, io.Closer, error) {
	if cfg == nil || cfg.Outfile == "" {
		return os.Stdout, nil, nil
	}
	// #nosec G304 -- -out is the user-requested output path
	f, err := os.OpenFile(cfg.Outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.TempFilePermissions)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}

// writeToConfiguredOutput runs write against stdout, or against cfg.Outfile
// when that path is set. The file is closed before return.
func writeToConfiguredOutput(cfg *Config, write func(io.Writer) error) (err error) {
	w, closer, openErr := writerForConfig(cfg)
	if openErr != nil {
		return openErr
	}
	if closer != nil {
		defer func() {
			cerr := closer.Close()
			if err == nil {
				err = cerr
			}
		}()
	}
	err = write(w)
	return err
}
