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
	"bufio"
	"bytes"
	"crypto/x509"
	"fmt"
	"html/template"
	"io"
	"net/http"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/ui/server"
)

const (
	head = `
<!doctype html>
<html>
  <head>
    <title>trustprune {{.Operation}}</title>
  <style>
  div.cert-wrapper {
    padding: 5px;
  }
  div.cert-wrapper:nth-child(even) {
    background: #CCC;
    border-radius: 5px;
  }
  </style>
  </head>
  <body>
`
	footer = `
<script>
function toggle(sel) {
  var elm = document.querySelector("#" + sel)
  if (elm.style.display == "none") {
    elm.style.display = "block";
  } else {
    elm.style.display = "none";
  }
}
</script>
</body></html>`

	list = `
<h3>Certificates</h3>
Options: <a href="/done" style="color: #000;">Close</a>
<hr />
{{range $idx, $cert := .Certificates}}
<div class="cert-wrapper">
Subject: {{ $cert.Subject }}<br />
Issuer: {{ $cert.Issuer }}<br />
SHA256: {{ $cert.Fingerprint }}<br />
Serial: {{ $cert.Serial }}<br />
NotBefore: {{ $cert.NotBefore }} | NotAfter: {{ $cert.NotAfter }}<br />
<a href="#" onclick="toggle('cert{{ $idx }}'); return false;" style="color: #000;">Details</a><br />
<span class="certificate" id="cert{{ $idx }}" style="display:none;"><pre>{{ $cert.Raw }}</pre></span>
</div>
{{else}}
<strong>No certificates</strong>
{{end}}
`
)

func launch() (err error) {
	server.Register()
	server.Start()
	defer func() {
		err2 := server.Stop()
		if err == nil {
			err = err2
		}
	}()
	err = Open()
	return err
}

func write(w io.Writer, tpl string, data interface{}) error {
	t := template.Must(template.New("contents").Parse(tpl))
	err := t.Execute(w, data)
	if err != nil {
		_, _ = io.WriteString(w, fmt.Sprintf("ERROR: %v", err))
		return err
	}
	return nil
}

// writePrinterFailure reports a printer error and still offers Close so /done is reachable.
func writePrinterFailure(w io.Writer, err error) {
	_, _ = io.WriteString(w, fmt.Sprintf(`<p>ERROR: %v</p>
Options: <a href="/done" style="color: #000;">Close</a>
`, err))
	_ = write(w, footer, nil)
}

// webCert is one certificate row in the web list UI.
type webCert struct {
	Subject     string
	Issuer      string
	Fingerprint string
	Serial      string
	NotBefore   string
	NotAfter    string
	Raw         string
}

func webCertFromX509(c *x509.Certificate, raw string) webCert {
	return webCert{
		Subject:     certutil.StringifyPKIXName(c.Subject),
		Issuer:      certutil.StringifyPKIXName(c.Issuer),
		Fingerprint: certutil.GetHexSHA256Fingerprint(*c),
		Serial:      c.SerialNumber.String(),
		NotBefore:   c.NotBefore.UTC().Format("2006-01-02"),
		NotAfter:    c.NotAfter.UTC().Format("2006-01-02"),
		Raw:         raw,
	}
}

func showCertsOnWeb(certs []*x509.Certificate, cfg *Config) error {
	server.Register()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p, ok := getPrinter(cfg.Format)
		if !ok {
			_, _ = io.WriteString(w, fmt.Sprintf("Unknown format %s", cfg.Format))
			return
		}
		defer p.close()

		err := write(w, head, struct {
			Operation string
		}{
			Operation: "list certificates",
		})
		if err != nil {
			return
		}

		// sort certs by Subject
		certutil.Sort(certs)

		contents := make([]webCert, len(certs))
		for i := range certs {
			var buf bytes.Buffer
			w1 := bufio.NewWriter(&buf)

			if err := p.write(w1, certs[i:i+1]); err != nil {
				writePrinterFailure(w, err)
				return
			}
			_ = w1.Flush()

			contents[i] = webCertFromX509(certs[i], buf.String())
		}
		_ = write(w, list, struct {
			Certificates []webCert
		}{
			Certificates: contents,
		})
		_ = write(w, footer, nil)
	})

	return launch()
}
