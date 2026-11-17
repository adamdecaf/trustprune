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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/httputil"
)

func TestConnectWithLocalTLSServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	cert, err := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := connect(u, []*x509.Certificate{cert}, ConnectOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
}

func TestConnectPresentedChain(t *testing.T) {
	leaf, ca, serverCert := newPresentedChain(t)
	srv := newChainServer(t, serverCert)
	u := mustConnectURL(t, srv.URL)
	leafFP := certutil.GetHexSHA256Fingerprint(*leaf)
	caFP := certutil.GetHexSHA256Fingerprint(*ca)

	t.Run("verbose failure prints the presented chain", func(t *testing.T) {
		out, err := captureConnectOut(t, func() error {
			return connect(u, nil, ConnectOptions{Verbose: true})
		})
		if err == nil || err.Error() != u.String()+": unknown authority" {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(out, "\nok ") || strings.HasPrefix(out, "ok ") {
			t.Fatalf("failure reported success:\n%s", out)
		}
		table, ferr := formatConnectPresentedText([]*x509.Certificate{leaf, ca}, nil)
		if ferr != nil {
			t.Fatal(ferr)
		}
		if out != table {
			t.Fatalf("stdout =\n%s\nwant\n%s", out, table)
		}
		if !strings.Contains(out, "0") || !strings.Contains(out, leaf.Subject.CommonName) {
			t.Fatal("missing leaf")
		}
		if !strings.Contains(out, ca.Subject.CommonName+connectNotInStoreMark) {
			t.Fatalf("CA not marked:\n%s", out)
		}
		leafLine, caLine := presentedLines(t, out)
		if !strings.HasPrefix(leafLine, "0 ") || !strings.Contains(leafLine, leafFP[:16]) {
			t.Fatalf("leaf line = %q", leafLine)
		}
		if !strings.HasPrefix(caLine, "1 ") || !strings.Contains(caLine, caFP[:16]) {
			t.Fatalf("ca line = %q", caLine)
		}
		if !strings.Contains(out, connectTrustHint(caFP)) {
			t.Fatalf("missing hint:\n%s", out)
		}
		assertSkipVerifyOff(t)
	})

	t.Run("quiet failure stays a short error", func(t *testing.T) {
		out, err := captureConnectOut(t, func() error {
			return connect(u, nil, ConnectOptions{})
		})
		if err == nil || err.Error() != u.String()+": unknown authority" {
			t.Fatalf("err = %v", err)
		}
		if out != "" {
			t.Fatalf("stdout = %q", out)
		}
	})

	t.Run("json failure includes presented_chain", func(t *testing.T) {
		out, err := captureConnectOut(t, func() error {
			return connect(u, nil, ConnectOptions{Format: "json"})
		})
		if err == nil || err.Error() != u.String()+": unknown authority" {
			t.Fatalf("err = %v", err)
		}
		verbose, verr := captureConnectOut(t, func() error {
			return connect(u, nil, ConnectOptions{Format: "JSON", Verbose: true})
		})
		if verr == nil || verr.Error() != err.Error() {
			t.Fatalf("verbose json err = %v", verr)
		}
		if verbose != out {
			t.Fatalf("-v changed json\n got %s\nwant %s", verbose, out)
		}
		dec := json.NewDecoder(strings.NewReader(out))
		dec.DisallowUnknownFields()
		var doc connectFailJSON
		if derr := dec.Decode(&doc); derr != nil {
			t.Fatalf("decode %s: %v", out, derr)
		}
		if doc.Verified || doc.URL != u.String() || len(doc.PresentedChain) != 2 {
			t.Fatalf("doc = %+v", doc)
		}
		if doc.PresentedChain[0].Subject != leaf.Subject.CommonName || doc.PresentedChain[0].InStore || doc.PresentedChain[0].SHA256 != leafFP {
			t.Fatalf("leaf = %+v", doc.PresentedChain[0])
		}
		if doc.PresentedChain[1].Subject != ca.Subject.CommonName || doc.PresentedChain[1].InStore || doc.PresentedChain[1].SHA256 != caFP {
			t.Fatalf("ca = %+v", doc.PresentedChain[1])
		}
		if doc.PresentedChain[0].Issuer == "" || doc.PresentedChain[0].NotAfter == "" {
			t.Fatalf("missing fields: %+v", doc.PresentedChain[0])
		}
		if strings.Contains(out, "INDEX") || strings.Contains(out, "to trust a CA") {
			t.Fatalf("json included text table:\n%s", out)
		}
	})

	t.Run("self-signed failure", func(t *testing.T) {
		cert := newSelfSignedCert(t, "self.example", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2032, 5, 6, 0, 0, 0, 0, time.UTC), true)
		selfSrv := newChainServer(t, cert.tlsCert)
		selfURL := mustConnectURL(t, selfSrv.URL)
		out, err := captureConnectOut(t, func() error {
			return connect(selfURL, nil, ConnectOptions{Verbose: true})
		})
		if err == nil || !strings.Contains(err.Error(), "unknown authority") {
			t.Fatalf("err = %v", err)
		}
		fp := certutil.GetHexSHA256Fingerprint(*cert.cert)
		if !strings.Contains(out, "self.example"+connectNotInStoreMark) || !strings.Contains(out, "2032-05-06") || !strings.Contains(out, fp[:16]) {
			t.Fatalf("stdout =\n%s", out)
		}
		if !strings.Contains(out, connectTrustHint(fp)) {
			t.Fatalf("missing hint:\n%s", out)
		}
		js, jerr := captureConnectOut(t, func() error {
			return connect(selfURL, nil, ConnectOptions{Format: "json"})
		})
		if jerr == nil {
			t.Fatal("expected json failure")
		}
		if !strings.Contains(js, `"presented_chain"`) || !strings.Contains(js, fp) || !strings.Contains(js, `"in_store": false`) {
			t.Fatalf("json =\n%s", js)
		}
	})

	t.Run("success output unchanged", func(t *testing.T) {
		cert := newSelfSignedCert(t, "ok.example", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2033, 7, 8, 0, 0, 0, 0, time.UTC), true)
		okSrv := newChainServer(t, cert.tlsCert)
		okURL := mustConnectURL(t, okSrv.URL)
		out, err := captureConnectOut(t, func() error {
			return connect(okURL, []*x509.Certificate{cert.cert}, ConnectOptions{Verbose: true})
		})
		if err != nil {
			t.Fatal(err)
		}
		table, terr := formatConnectChainTable([]*x509.Certificate{cert.cert})
		if terr != nil {
			t.Fatal(terr)
		}
		if !strings.HasPrefix(out, "ok "+okURL.String()+" ") || !strings.HasSuffix(out, table) {
			t.Fatalf("stdout =\n%s", out)
		}
		if strings.Contains(out, "presented chain:") || strings.Contains(out, connectNotInStoreMark) || strings.Contains(out, "to trust a CA") || strings.Contains(out, "presented_chain") {
			t.Fatalf("success output changed:\n%s", out)
		}
		plain, perr := captureConnectOut(t, func() error {
			return connect(okURL, []*x509.Certificate{cert.cert}, ConnectOptions{})
		})
		if perr != nil {
			t.Fatal(perr)
		}
		if strings.Contains(plain, "\n") && strings.TrimSuffix(plain, "\n") != strings.Split(plain, "\n")[0] {
			t.Fatalf("summary is not one line: %q", plain)
		}
		if strings.Contains(plain, "INDEX") || !strings.HasPrefix(plain, "ok ") {
			t.Fatalf("summary = %q", plain)
		}
		js, jerr := captureConnectOut(t, func() error {
			return connect(okURL, []*x509.Certificate{cert.cert}, ConnectOptions{Format: "json", Verbose: true})
		})
		if jerr != nil {
			t.Fatal(jerr)
		}
		if strings.Contains(js, "presented_chain") || !strings.Contains(js, `"verified": true`) {
			t.Fatalf("json =\n%s", js)
		}
	})

	t.Run("expired and hostname still fail and show the chain", func(t *testing.T) {
		expired := newSelfSignedCert(t, "old.example", time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2015, 4, 12, 0, 0, 0, 0, time.UTC), true)
		expSrv := newChainServer(t, expired.tlsCert)
		expURL := mustConnectURL(t, expSrv.URL)
		out, err := captureConnectOut(t, func() error {
			return connect(expURL, []*x509.Certificate{expired.cert}, ConnectOptions{Verbose: true})
		})
		if err == nil || err.Error() != expURL.String()+": certificate expired 2015-04-12" {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(out, connectNotInStoreMark) || strings.Contains(out, "to trust a CA") || !strings.Contains(out, "old.example") {
			t.Fatalf("stdout =\n%s", out)
		}

		host := newSelfSignedCert(t, "wrong.example", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2034, 1, 2, 0, 0, 0, 0, time.UTC), false)
		hostSrv := newChainServer(t, host.tlsCert)
		hostURL := mustConnectURL(t, hostSrv.URL)
		hout, herr := captureConnectOut(t, func() error {
			return connect(hostURL, []*x509.Certificate{host.cert}, ConnectOptions{Verbose: true})
		})
		if herr == nil || herr.Error() != hostURL.String()+": hostname mismatch" {
			t.Fatalf("err = %v", herr)
		}
		if strings.Contains(hout, connectNotInStoreMark) || !strings.Contains(hout, "wrong.example") {
			t.Fatalf("stdout =\n%s", hout)
		}
	})

	t.Run("dial failure does not print a chain", func(t *testing.T) {
		closed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		cu := mustConnectURL(t, closed.URL)
		closed.Close()
		out, err := captureConnectOut(t, func() error {
			return connect(cu, nil, ConnectOptions{Verbose: true, Format: "json"})
		})
		if err == nil {
			t.Fatal("expected dial error")
		}
		if strings.Contains(err.Error(), "unknown authority") || strings.Contains(out, "presented_chain") || strings.Contains(out, "presented chain:") {
			t.Fatalf("err = %v\nstdout = %s", err, out)
		}
	})
}

func TestConnectWithAppStoreFileCertifi(t *testing.T) {
	// Exercise the ForAppWithFile error path with a missing file.
	u, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	err = ConnectWithAppStoreFile(u, "certifi", "/no/such/cacert.pem", ConnectOptions{})
	if err == nil {
		t.Fatal("expected error for missing certifi file")
	}
}

type mintedCert struct {
	tlsCert tls.Certificate
	cert    *x509.Certificate
}

func newSelfSignedCert(t *testing.T, cn string, notBefore, notAfter time.Time, ipSAN bool) mintedCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := serverTemplate(cn, notBefore, notAfter, ipSAN)
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return mintedCert{
		tlsCert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		cert:    cert,
	}
}

func newPresentedChain(t *testing.T) (leaf, ca *x509.Certificate, server tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := serverTemplate("ca.example", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC), false)
	caTmpl.IsCA = true
	caTmpl.KeyUsage = x509.KeyUsageCertSign
	caTmpl.ExtKeyUsage = nil
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := serverTemplate("leaf.example", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC), true)
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	server = tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
	return leaf, ca, server
}

func serverTemplate(cn string, notBefore, notAfter time.Time, ipSAN bool) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}
	if ipSAN {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	return tmpl
}

func newChainServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func mustConnectURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func presentedLines(t *testing.T, out string) (leaf, ca string) {
	t.Helper()
	var rows []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "0 ") || strings.HasPrefix(line, "1 ") {
			rows = append(rows, line)
		}
	}
	if len(rows) != 2 {
		t.Fatalf("chain rows = %q\n%s", rows, out)
	}
	return rows[0], rows[1]
}

func assertSkipVerifyOff(t *testing.T) {
	t.Helper()
	tr, ok := httputil.Client.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatal("shared client transport missing")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify left set on the shared client")
	}
}

func captureConnectOut(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	fnErr := fn()
	os.Stdout = old
	if cerr := w.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	var buf bytes.Buffer
	if _, cerr := io.Copy(&buf, r); cerr != nil {
		t.Fatal(cerr)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	return buf.String(), fnErr
}
