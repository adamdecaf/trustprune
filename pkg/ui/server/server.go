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

package server

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	srv *http.Server
	wg  sync.WaitGroup

	doneTpl = `<!doctype html>
<html>
<head>
  <title>trustprune</title>
</head>
<body>
  <h3>All Done!</h3>
  <p>You can close this window.</p>
<script>
  window.close();
</script>
</body>
</html>
`
)

// Address returns the http://$server:$port/ representation for clients to load
func Address() string {
	if srv == nil {
		return ""
	}
	return fmt.Sprintf("http://%s/", srv.Addr)
}

func Register() {
	if srv != nil {
		return // already initialized
	}

	srv = &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", getPort()),
		ReadHeaderTimeout: 10 * time.Second,
	}

	http.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()

		t := template.Must(template.New("contents").Parse(doneTpl))
		err := t.Execute(w, nil)
		if err != nil {
			_, _ = io.WriteString(w, fmt.Sprintf("ERROR: %v", err))
		}
	})
}

func getPort() int {
	// Local UI only needs an ephemeral listen port, not cryptographic randomness.
	lowerBound := 1024 // ports below require elevated privileges
	n := rand.Intn(2<<15 - lowerBound)
	return n + lowerBound
}

// Start initializes the http server, binds and accepts connections
func Start() {
	if srv == nil {
		fmt.Fprint(os.Stderr, "ui/server: no http server has been registered")
		return
	}

	wg.Add(1) // force callers to wait

	// spawn off http server
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			fmt.Printf("ERROR: failed creating localhost server err=%s\n", err)
		}
	}()
}

// Stop calls for a shutdown of the http server, if it exists
func Stop() error {
	// hold on until the form has been filled out
	wg.Wait()

	if srv != nil {
		return srv.Shutdown(context.TODO())
	}
	return nil
}
