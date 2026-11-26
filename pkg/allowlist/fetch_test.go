// Copyright 2026 Adam Shannon
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

package allowlist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/httputil"
)

func TestFromPathOrURL_YAMLAndJSONMatchFile(t *testing.T) {
	for _, name := range []string{
		"../../testdata/complete-whitelist.yaml",
		"../../testdata/complete-whitelist.json",
	} {
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			want, err := FromFile(name)
			if err != nil {
				t.Fatal(err)
			}
			fromBytes, err := FromBytes(body)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fromBytes, want) {
				t.Fatalf("FromBytes = %#v, FromFile = %#v", fromBytes, want)
			}
			srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/allowlist" {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(body)
			})
			got, err := FromPathOrURL(srv.URL+"/allowlist", FetchOptions{Client: srv.Client()})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("URL = %#v, FromFile = %#v", got, want)
			}
			local, err := FromPathOrURL(name, FetchOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(local, want) {
				t.Fatalf("local URL loader = %#v, FromFile = %#v", local, want)
			}
		})
	}
}

func TestFromPathOrURL_UsesHTTPClientHook(t *testing.T) {
	body := []byte("countries:\n  - US\n")
	var hits int
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(body)
	})
	prev := HTTPClient
	HTTPClient = srv.Client()
	t.Cleanup(func() { HTTPClient = prev })

	got, err := FromPathOrURL(srv.URL+"/a.yaml", FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want, err := FromBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if hits != 1 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestFromPathOrURL_RejectsNonHTTPS(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("non-https allowlist URL made a request")
		return nil, nil
	})}
	cases := []string{
		"http://127.0.0.1/allowlist.yaml",
		"HTTP://127.0.0.1/allowlist.yaml",
		"ftp://127.0.0.1/allowlist.yaml",
		"file:///tmp/allowlist.yaml",
	}
	for _, ref := range cases {
		t.Run(ref, func(t *testing.T) {
			_, err := FromPathOrURL(ref, FetchOptions{Client: client})
			if err == nil || !strings.Contains(err.Error(), "allowlist URLs must be https") {
				t.Fatalf("err = %v", err)
			}
			if err := ValidateRef(ref); err == nil || !strings.Contains(err.Error(), "allowlist URLs must be https") {
				t.Fatalf("ValidateRef = %v", err)
			}
		})
	}
}

func TestFromPathOrURL_WindowsVolumePathIsLocal(t *testing.T) {
	for _, ref := range []string{`C:\no-such-allowlist.yaml`, `C:/no-such-allowlist.yaml`} {
		_, err := FromPathOrURL(ref, FetchOptions{})
		if err == nil {
			t.Fatalf("%s: expected a file error", ref)
		}
		if strings.Contains(err.Error(), "allowlist URLs must be https") {
			t.Fatalf("%s: treated as a URL: %v", ref, err)
		}
	}
}

func TestFromPathOrURL_UpperScheme(t *testing.T) {
	body := []byte("{}\n")
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	})
	ref := "HTTPS" + strings.TrimPrefix(srv.URL, "https") + "/a.yaml"
	got, err := FromPathOrURL(ref, FetchOptions{Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	want, err := FromBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestFromPathOrURL_SizeCap(t *testing.T) {
	const max int64 = 32
	valid := bytes.Repeat([]byte("y"), int(max)+8)

	t.Run("content length", func(t *testing.T) {
		payload := bytes.Repeat([]byte("a"), 1000)
		srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			_, _ = w.Write(payload)
		})
		_, err := FromPathOrURL(srv.URL+"/big.yaml", FetchOptions{Client: srv.Client(), MaxSize: max})
		if err == nil || !strings.Contains(err.Error(), "Content-Length") || !strings.Contains(err.Error(), "byte limit") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "unable to read allowlist") {
			t.Fatalf("size failure parsed the body: %v", err)
		}
	})

	t.Run("read", func(t *testing.T) {
		srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = w.Write(valid)
		})
		_, err := FromPathOrURL(srv.URL+"/big.yaml", FetchOptions{Client: srv.Client(), MaxSize: max})
		if err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "Content-Length") {
			t.Fatalf("chunked body took the Content-Length path: %v", err)
		}
		if strings.Contains(err.Error(), "unable to read allowlist") {
			t.Fatalf("size failure parsed the body: %v", err)
		}
	})
}

func TestFromPathOrURL_DefaultMaxBytes(t *testing.T) {
	if DefaultMaxBytes != 1<<20 {
		t.Fatalf("DefaultMaxBytes = %d, want 1 MiB", DefaultMaxBytes)
	}
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(DefaultMaxBytes+1, 10))
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	client := srv.Client()
	client.Timeout = 2 * time.Second
	_, err := FromPathOrURL(srv.URL+"/big.yaml", FetchOptions{Client: client})
	if err == nil || !strings.Contains(err.Error(), "Content-Length") || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "unable to read allowlist") {
		t.Fatalf("over-cap body was parsed: %v", err)
	}
}

func TestFromPathOrURL_Status(t *testing.T) {
	body := []byte("countries:\n  - US\n")
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, string(body), http.StatusNotFound)
	})
	_, err := FromPathOrURL(srv.URL+"/missing.yaml", FetchOptions{Client: srv.Client()})
	if err == nil || !strings.Contains(err.Error(), srv.URL) || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "unable to read allowlist") {
		t.Fatalf("non-200 was parsed: %v", err)
	}
}

func TestFromPathOrURL_Pin(t *testing.T) {
	body := []byte("countries:\n  - US\n")
	sum := sha256.Sum256(body)
	pin := hex.EncodeToString(sum[:])
	var hits int
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(body)
	})
	opts := FetchOptions{Client: srv.Client()}

	t.Run("match", func(t *testing.T) {
		opts.SHA256 = strings.ToUpper(pin)
		got, err := FromPathOrURL(srv.URL+"/a.yaml", opts)
		if err != nil {
			t.Fatal(err)
		}
		want, err := FromBytes(body)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})

	t.Run("local match", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "allowlist.yaml")
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := FromPathOrURL(path, FetchOptions{SHA256: "  " + pin + "  "})
		if err != nil {
			t.Fatal(err)
		}
		want, err := FromFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})

	t.Run("mismatch does not parse", func(t *testing.T) {
		bad := []byte("[\n")
		badSrv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(bad)
		})
		_, err := FromPathOrURL(badSrv.URL+"/bad.yaml", FetchOptions{
			Client: badSrv.Client(),
			SHA256: pin,
		})
		if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "unable to read allowlist") {
			t.Fatalf("mismatch still parsed: %v", err)
		}
	})

	t.Run("invalid pin makes no request", func(t *testing.T) {
		before := hits
		for _, pin := range []string{"abcd", strings.Repeat("ab", 31), strings.Repeat("zz", 32), "0x" + pin} {
			_, err := FromPathOrURL(srv.URL+"/a.yaml", FetchOptions{Client: srv.Client(), SHA256: pin})
			if err == nil || !strings.Contains(err.Error(), "64 hex") {
				t.Fatalf("pin %q err = %v", pin, err)
			}
		}
		if hits != before {
			t.Fatalf("invalid pin issued a request: hits %d to %d", before, hits)
		}
		if err := ValidateSHA256Pin("abcd"); err == nil {
			t.Fatal("short pin was accepted")
		}
	})
}

func TestFromPathOrURL_InvalidBodyMatchesFile(t *testing.T) {
	body := []byte("[\n")
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	_, fileErr := FromFile(path)
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	})
	src := srv.URL + "/bad.yaml"
	_, urlErr := FromPathOrURL(src, FetchOptions{Client: srv.Client()})
	if fileErr == nil || urlErr == nil {
		t.Fatalf("file=%v url=%v", fileErr, urlErr)
	}
	if !strings.Contains(fileErr.Error(), "unable to read allowlist") {
		t.Fatalf("err = %v", fileErr)
	}
	if !strings.Contains(urlErr.Error(), fileErr.Error()) {
		t.Fatalf("file %q\nurl  %q", fileErr.Error(), urlErr.Error())
	}
	if !strings.Contains(urlErr.Error(), src) {
		t.Fatalf("url error missing source %q: %v", src, urlErr)
	}
}

func TestFromPathOrURL_RedactsUserinfo(t *testing.T) {
	const password = "s3cret"
	var hits int
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/missing.yaml" {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("[\n"))
	})
	withUser := func(path string) string {
		t.Helper()
		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword("alice", password)
		u.Path = path
		return u.String()
	}
	opts := FetchOptions{Client: srv.Client()}

	t.Run("status", func(t *testing.T) {
		before := hits
		_, err := FromPathOrURL(withUser("/missing.yaml"), opts)
		if err == nil {
			t.Fatal("expected status error")
		}
		msg := err.Error()
		if strings.Contains(msg, password) {
			t.Fatalf("password leaked: %s", msg)
		}
		if !strings.Contains(msg, "xxxxx") {
			t.Fatalf("not redacted: %s", msg)
		}
		if !strings.Contains(msg, "404") && !strings.Contains(strings.ToLower(msg), "not found") {
			t.Fatalf("err = %v", err)
		}
		if hits == before {
			t.Fatal("no request was made")
		}
	})

	t.Run("parse", func(t *testing.T) {
		_, err := FromPathOrURL(withUser("/bad.yaml"), opts)
		if err == nil {
			t.Fatal("expected parse error")
		}
		msg := err.Error()
		if strings.Contains(msg, password) {
			t.Fatalf("password leaked: %s", msg)
		}
		if !strings.Contains(msg, "xxxxx") {
			t.Fatalf("not redacted: %s", msg)
		}
		if !strings.Contains(msg, "unable to read allowlist") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestFromPathOrURL_Redirect(t *testing.T) {
	body := []byte("countries:\n  - JP\n")
	var httpHits int
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/ok.yaml", http.StatusFound)
		case "/ok.yaml":
			_, _ = w.Write(body)
		case "/to-http":
			http.Redirect(w, r, "http://127.0.0.1:1/allowlist.yaml", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			httpHits++
			http.NotFound(w, r)
		}
	})
	opts := FetchOptions{Client: srv.Client()}

	t.Run("https to https", func(t *testing.T) {
		got, err := FromPathOrURL(srv.URL+"/start", opts)
		if err != nil {
			t.Fatal(err)
		}
		want, err := FromBytes(body)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})

	t.Run("http refused", func(t *testing.T) {
		_, err := FromPathOrURL(srv.URL+"/to-http", opts)
		if err == nil || !strings.Contains(err.Error(), "allowlist URLs must be https") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("redirect was followed: %v", err)
		}
		if httpHits != 0 {
			t.Fatalf("http target was requested: %d", httpHits)
		}
	})

	t.Run("hop limit", func(t *testing.T) {
		_, err := FromPathOrURL(srv.URL+"/loop", opts)
		if err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestFromPathOrURL_DoesNotMutateClient(t *testing.T) {
	srv := tlsAllowlistServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{}\n"))
	})
	client := srv.Client()
	if client.CheckRedirect != nil || client.Timeout != 0 {
		t.Fatalf("server client timeout=%s redirect set=%v", client.Timeout, client.CheckRedirect != nil)
	}
	if _, err := FromPathOrURL(srv.URL+"/a.yaml", FetchOptions{Client: client}); err != nil {
		t.Fatal(err)
	}
	if client.CheckRedirect != nil || client.Timeout != 0 {
		t.Fatal("fetch mutated the caller's client")
	}
	redirect := httputil.Client.CheckRedirect
	if redirect == nil {
		t.Fatal("httputil client lost CheckRedirect")
	}
	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := redirect(req, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("httputil redirect policy = %v", err)
	}
}

func tlsAllowlistServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
