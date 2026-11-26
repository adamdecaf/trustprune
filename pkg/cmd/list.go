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

package cmd

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/httputil"
	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/adamdecaf/trustprune/pkg/ui"
)

var (
	maxDownloadSize int64 = 10 * 1024 * 1024 // bytes
)

// ListCertsFromFile finds certificates at the given filepath
// and lists them according to the ui/format options. A directory is
// treated as a pulled Android cacerts folder of <hash>.0 PEM files.
func ListCertsFromFile(where string, cfg *ui.Config) error {
	st, err := os.Stat(where)
	if err != nil {
		return err
	}
	var certs []*x509.Certificate
	if st.IsDir() {
		certs, err = certutil.FromAndroidDir(where)
	} else {
		var bs []byte
		bs, err = os.ReadFile(where)
		if err != nil {
			return err
		}
		certs, err = certutil.Decode(bs)
	}
	if err != nil {
		return err
	}
	if cfg != nil {
		c := *cfg
		c.SourcePath = where
		cfg = &c
	}
	return ui.ListCertificatesWithMeta(ui.Meta{Name: "file"}, certs, cfg)
}

// ListCertsFromURL downloads a PEM or DER certificate bundle and lists the
// certificates. Mozilla certdata.txt is also accepted. This does not dial
// the host for a TLS handshake. A response that parses to zero certificates
// is an error, including when --count is set.
func ListCertsFromURL(where string, cfg *ui.Config) (err error) {
	req, err := http.NewRequest("GET", where, nil)
	if err != nil {
		return fmt.Errorf("unable to create request for %s: %w", where, err)
	}
	req.Close = true

	resp, err := httputil.New().Do(req)
	if resp != nil && resp.Body != nil {
		defer func() {
			cerr := resp.Body.Close()
			if err == nil {
				err = cerr
			}
		}()
	}
	if err != nil {
		return err
	}

	// read out certs
	r := io.LimitReader(resp.Body, maxDownloadSize)
	bs, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return listURLNoCertsError(where)
	}
	return ui.ListCertificates(certs, cfg)
}

// listURLNoCertsError is used when --url downloaded a body with no
// certificates. The message names that URL and points at chain for a
// live site lookup, using the host when the URL can be parsed.
func listURLNoCertsError(where string) error {
	hint := "trustprune chain <host> --remote"
	if u, err := url.Parse(where); err == nil {
		if host := strings.TrimSpace(u.Hostname()); host != "" {
			hint = "trustprune chain " + host + " --remote"
		}
	}
	return fmt.Errorf("no PEM/DER certificates at %s; for a site chain use: %s", where, hint)
}

// ListCertsForPlatform finds certs for the given platform.
// The supported platforms can be found in the readme. They're compiled in
// with build flags in the `certs/find_*.go` files.
func ListCertsForPlatform(cfg *ui.Config) error {
	st := store.Platform()
	certificates, err := st.List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return err
	}
	meta := createMeta(st)
	return ui.ListCertificatesWithMeta(meta, certificates, cfg)
}

// ListCertsForApp finds certs for the given app.
// The supported applications are listed in the readme. This includes
// non-traditional applications like NSS.
// --app acrobat prints a read-only trust settings report instead of
// certificates. When Acrobat is not installed the text is
// store.AcrobatNotInstalledReport and the command exits 0.
func ListCertsForApp(app string, cfg *ui.Config) error {
	if strings.ToLower(app) == "acrobat" {
		return listAcrobatTrustReport(cfg)
	}
	st, err := store.ForApp(app)
	if err != nil {
		return err
	}

	certificates, err := st.List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return err
	}

	// Output the certificates
	meta := createMeta(st)
	return ui.ListCertificatesWithMeta(meta, certificates, cfg)
}

func listAcrobatTrustReport(cfg *ui.Config) error {
	text, err := store.AcrobatTrustReport()
	if err != nil {
		return err
	}
	return ui.WriteConfiguredText(cfg, text)
}

func createMeta(st store.Informer) ui.Meta {
	info := st.GetInfo()
	if info == nil {
		return ui.Meta{}
	}
	return ui.Meta{
		Name:    info.Name,
		Version: info.Version,
		Path:    info.Path,
	}
}

// ListCertsForAppWithFile lists certificates for app, optionally overriding the
// trust-store path with storePath (java keystore, certifi bundle, or poppler
// NSS directory). The parameter name is historical: callers pass the CLI
// --store path. List output includes that path.
func ListCertsForAppWithFile(app, storePath string, cfg *ui.Config) error {
	if strings.ToLower(app) == "acrobat" && strings.TrimSpace(storePath) == "" {
		return listAcrobatTrustReport(cfg)
	}
	st, err := store.ForAppWithStore(app, storePath)
	if err != nil {
		return err
	}

	certificates, err := st.List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return err
	}
	meta := createMeta(st)
	return ui.ListCertificatesWithMeta(meta, certificates, cfg)
}
