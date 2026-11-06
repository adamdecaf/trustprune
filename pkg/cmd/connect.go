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
	"net/http"
	"net/url"

	"github.com/adamdecaf/trustprune/pkg/httputil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

func ConnectWithPlatformStore(uri *url.URL) error {
	st := store.Platform()
	certs, err := st.List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return fmt.Errorf("problem getting certs: %w", err)
	}
	return connect(uri, certs)
}

func ConnectWithAppStore(uri *url.URL, app string) error {
	return ConnectWithAppStoreFile(uri, app, "")
}

func ConnectWithAppStoreFile(uri *url.URL, app, filePath string) error {
	st, err := store.ForAppWithFile(app, filePath)
	if err != nil {
		return err
	}
	certs, err := st.List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		return fmt.Errorf("problem getting certs for %q: %w", app, err)
	}
	return connect(uri, certs)
}

func connect(uri *url.URL, roots []*x509.Certificate) error {
	req, err := http.NewRequest("HEAD", uri.String(), nil)
	if err != nil {
		return fmt.Errorf("unable to make request for %s: %w", uri.String(), err)
	}
	req.Close = true

	pool := x509.NewCertPool()
	for i := range roots {
		pool.AddCert(roots[i])
	}

	client := httputil.New()
	tr, ok := client.Transport.(*http.Transport)
	if ok {
		tr.TLSClientConfig.RootCAs = pool
	}
	client.Transport = tr

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("problem with HEAD to %s: %w", uri.String(), err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	fmt.Printf("Connection to %s passed!\n", uri.String())
	return nil
}
