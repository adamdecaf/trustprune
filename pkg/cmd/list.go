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
	"bytes"
	"compress/gzip"
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

	// maxGunzipSize is the decompressed-size cap for list --file gzip
	// input. testdata/certdata.txt.gz is about 1.3 MiB uncompressed;
	// 32 MiB leaves room for that file to grow.
	maxGunzipSize int64 = 32 * 1024 * 1024
)

// ListCertsFromFile finds certificates at the given filepath
// and lists them according to the ui/format options. A directory is
// treated as a pulled Android cacerts folder of <hash>.0 PEM or DER
// files, including .crt, .cer, or .der exports of user-installed CAs.
// A regular file may be PEM, DER, Mozilla certdata.txt, or gzip
// compressed (a .gz suffix or a gzip magic header). A file that
// cannot be parsed is an error that names the path, including when
// --count is set.
func ListCertsFromFile(where string, cfg *ui.Config) error {
	st, err := os.Stat(where)
	if err != nil {
		return err
	}
	var certs []*x509.Certificate
	if st.IsDir() {
		certs, err = certutil.FromAndroidDir(where)
		if err != nil {
			return err
		}
	} else {
		var bs []byte
		bs, err = os.ReadFile(where)
		if err != nil {
			return err
		}
		bs, err = gunzipIfNeeded(where, bs)
		if err != nil {
			return err
		}
		certs, err = certutil.Decode(bs)
		if err != nil {
			return fmt.Errorf("read %s: %w", where, err)
		}
		if len(certs) == 0 {
			return listFileNoCertsError(where)
		}
	}
	if cfg != nil {
		c := *cfg
		c.SourcePath = where
		cfg = &c
	}
	return ui.ListCertificatesWithMeta(ui.Meta{Name: "file"}, certs, cfg)
}

// listFileNoCertsError is used when --file was a regular file with no
// parseable certificates. The message names that path. It is returned
// even when --count is set, so scripts do not treat a parse failure as
// a successful empty list.
func listFileNoCertsError(where string) error {
	return fmt.Errorf("no certificates in %s", where)
}

// gunzipIfNeeded decompresses body when path ends in .gz or the bytes
// start with a gzip magic header. Other files are returned unchanged.
// Decompression stops and returns an error naming path when the
// uncompressed size would exceed maxGunzipSize.
func gunzipIfNeeded(path string, body []byte) ([]byte, error) {
	return gunzipWithLimit(path, body, maxGunzipSize)
}

func gunzipWithLimit(path string, body []byte, limit int64) ([]byte, error) {
	gzipName := strings.HasSuffix(strings.ToLower(path), ".gz")
	gzipMagic := len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b
	if !gzipName && !gzipMagic {
		return body, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gzip %s: %w", path, err)
	}
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	cerr := r.Close()
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("gzip %s: decompressed size exceeds %d byte limit", path, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("gzip %s: %w", path, err)
	}
	if cerr != nil {
		return nil, fmt.Errorf("gzip %s: %w", path, cerr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("gzip %s is empty", path)
	}
	return out, nil
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
	path := listURLSource(where)
	if cfg != nil {
		c := *cfg
		c.SourcePath = path
		cfg = &c
	} else {
		cfg = &ui.Config{SourcePath: path}
	}
	return ui.ListCertificatesWithMeta(ui.Meta{Name: "url", Path: path}, certs, cfg)
}

// listURLSource is the URL shown as JSON path and verbose PATH.
// Userinfo passwords are masked with url.URL.Redacted, the same way
// allowlist fetch errors redact URLs. A value that cannot be parsed
// is replaced so the raw string is not printed.
func listURLSource(ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return "invalid URL"
	}
	if u.Scheme == "" {
		return ref
	}
	return u.Redacted()
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
