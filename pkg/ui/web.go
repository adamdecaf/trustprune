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
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
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
	// footer is the page script. It stays inline: the local server sets no
	// Content-Security-Policy, and this script does not fetch anything.
	// renderAllowlistJSON matches checklistAllowlistJSON (Fingerprints,
	// two-space indent, trailing newline, {} when nothing is checked).
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

function renderAllowlistJSON(fps) {
  var payload = {};
  if (fps.length > 0) {
    payload.Fingerprints = fps;
  }
  return JSON.stringify(payload, null, 2) + "\n";
}

function checkedFingerprints() {
  var boxes = document.querySelectorAll("input.cert-keep");
  var fps = [];
  var embedded = document.getElementById("checklist-fingerprints");
  var fromJSON = null;
  if (embedded && embedded.value) {
    try {
      fromJSON = JSON.parse(embedded.value);
    } catch (e) {
      fromJSON = null;
    }
  }
  for (var i = 0; i < boxes.length; i++) {
    if (!boxes[i].checked) {
      continue;
    }
    if (fromJSON && fromJSON.length == boxes.length) {
      fps.push(fromJSON[i]);
    } else {
      fps.push(boxes[i].value);
    }
  }
  return fps;
}

var checklistDirty = false;

function allowlistText() {
  var embedded = document.getElementById("checklist-allowlist");
  if (!checklistDirty && embedded && embedded.value) {
    return embedded.value;
  }
  return renderAllowlistJSON(checkedFingerprints());
}

function downloadAllowlist() {
  var text = allowlistText();
  var blob = new Blob([text], {type: "application/json"});
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url;
  a.download = "allowlist.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

var downloadBtn = document.getElementById("download-allowlist");
if (downloadBtn) {
  downloadBtn.addEventListener("click", downloadAllowlist);
}
var keepBoxes = document.querySelectorAll("input.cert-keep");
for (var i = 0; i < keepBoxes.length; i++) {
  keepBoxes[i].addEventListener("change", function () { checklistDirty = true; });
}
</script>
</body></html>`

	list = `
<h3>Certificates</h3>
<p>Checked certificates are kept. Download allowlist saves a JSON allowlist in this browser. The page leaves the trust store unchanged.</p>
<p><button type="button" id="download-allowlist">Download allowlist</button> <a href="/done" style="color: #000;">Close</a></p>
<textarea id="checklist-allowlist" hidden readonly>{{.AllowlistJSON}}</textarea>
<textarea id="checklist-fingerprints" hidden readonly>{{.FingerprintsJSON}}</textarea>
<hr />
{{range $idx, $cert := .Certificates}}
<div class="cert-wrapper">
<label class="keep"><input type="checkbox" class="cert-keep" value="{{ $cert.Fingerprint }}"{{ if $cert.Keep }} checked{{ end }}> Keep</label><br />
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
// Keep is the checkbox: checked means the certificate stays in the allowlist.
type webCert struct {
	Subject     string
	Issuer      string
	Fingerprint string
	Serial      string
	NotBefore   string
	NotAfter    string
	Raw         string
	Keep        bool
}

// webListData is the list page.
// AllowlistJSON is the allowlist file for certificates that start checked.
// FingerprintsJSON is every fingerprint in display order. The page script
// reads it when a checkbox changes and a new allowlist is built.
type webListData struct {
	Certificates     []webCert
	AllowlistJSON    string
	FingerprintsJSON string
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

// prepareWebAllowlist loads cfg.AllowlistPath. A nil allowlist means every
// certificate starts checked. The file is not applied to a trust store.
func prepareWebAllowlist(cfg *Config) (*allowlist.Allowlist, error) {
	if cfg == nil {
		return nil, nil
	}
	path := strings.TrimSpace(cfg.AllowlistPath)
	if path == "" {
		return nil, nil
	}
	al, err := allowlist.FromFile(path)
	if err != nil {
		return nil, fmt.Errorf("list --allowlist: %w", err)
	}
	return &al, nil
}

// certPrechecked reports whether the checklist box starts checked.
// A nil allowlist keeps every certificate. Otherwise the box follows
// Allowlist.Matches, the same decision allowlist --file would make.
func certPrechecked(al *allowlist.Allowlist, cert *x509.Certificate) bool {
	if al == nil {
		return true
	}
	return al.Matches(cert)
}

// checklistAllowlistJSON is the allowlist file the web checklist downloads.
// Bytes match allowlist.ToFile for a .json path: a Fingerprints array,
// two-space indent, and a trailing newline. An empty selection is {}.
func checklistAllowlistJSON(fingerprints []string) ([]byte, error) {
	al := allowlist.Allowlist{}
	if len(fingerprints) > 0 {
		al.Fingerprints = append([]string(nil), fingerprints...)
	}
	out, err := json.MarshalIndent(al, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// checklistFingerprintsJSON is the display-order fingerprint list embedded
// for the page script. It is a JSON array, [] when there are no certificates.
func checklistFingerprintsJSON(fingerprints []string) (string, error) {
	if fingerprints == nil {
		fingerprints = []string{}
	}
	out, err := json.Marshal(fingerprints)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// applyChecklist builds the list page from certs in their current order.
// raws[i] is the formatted dump for certs[i]. al nil checks every box.
func applyChecklist(certs []*x509.Certificate, raws []string, al *allowlist.Allowlist) (webListData, error) {
	contents := make([]webCert, len(certs))
	all := make([]string, 0, len(certs))
	kept := make([]string, 0, len(certs))
	for i := range certs {
		raw := ""
		if i < len(raws) {
			raw = raws[i]
		}
		contents[i] = webCertFromX509(certs[i], raw)
		contents[i].Keep = certPrechecked(al, certs[i])
		all = append(all, contents[i].Fingerprint)
		if contents[i].Keep {
			kept = append(kept, contents[i].Fingerprint)
		}
	}
	js, err := checklistAllowlistJSON(kept)
	if err != nil {
		return webListData{}, err
	}
	fps, err := checklistFingerprintsJSON(all)
	if err != nil {
		return webListData{}, err
	}
	return webListData{
		Certificates:     contents,
		AllowlistJSON:    string(js),
		FingerprintsJSON: fps,
	}, nil
}

func showCertsOnWeb(certs []*x509.Certificate, cfg *Config) error {
	al, err := prepareWebAllowlist(cfg)
	if err != nil {
		return err
	}

	server.Register()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p, ok := getPrinter(cfg.Format)
		if !ok {
			_, _ = io.WriteString(w, UnknownFormatError(cfg.Format).Error())
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

		raws := make([]string, len(certs))
		for i := range certs {
			var buf bytes.Buffer
			w1 := bufio.NewWriter(&buf)

			if err := p.write(w1, certs[i:i+1]); err != nil {
				writePrinterFailure(w, err)
				return
			}
			_ = w1.Flush()
			raws[i] = buf.String()
		}
		data, err := applyChecklist(certs, raws, al)
		if err != nil {
			writePrinterFailure(w, err)
			return
		}
		_ = write(w, list, data)
		_ = write(w, footer, nil)
	})

	return launch()
}
