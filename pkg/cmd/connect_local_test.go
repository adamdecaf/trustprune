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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
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
	if err := connect(u, []*x509.Certificate{cert}); err != nil {
		t.Fatal(err)
	}
}

func TestConnectWithAppStoreFileCertifi(t *testing.T) {
	// Exercise the ForAppWithFile error path with a missing file.
	u, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	err = ConnectWithAppStoreFile(u, "certifi", "/no/such/cacert.pem")
	if err == nil {
		t.Fatal("expected error for missing certifi file")
	}
}
