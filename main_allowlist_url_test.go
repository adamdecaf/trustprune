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

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

func TestAllowlistURLUsageErrors(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	goodPin := strings.Repeat("ab", 32)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "allowlist http",
			args: []string{"allowlist", "--file", "http://127.0.0.1:1/allowlist.yaml", "--dry-run"},
			want: "allowlist URLs must be https",
		},
		{
			name: "allowlist ftp",
			args: []string{"allowlist", "--file", "ftp://127.0.0.1/allowlist.yaml"},
			want: "allowlist URLs must be https",
		},
		{
			name: "create http",
			args: []string{"create", "--file", "http://127.0.0.1:1/allowlist.yaml"},
			want: "allowlist URLs must be https",
		},
		{
			name: "list http allowlist",
			args: []string{"list", "--ui", "web", "--allowlist", "http://127.0.0.1:1/allowlist.yaml"},
			want: "allowlist URLs must be https",
		},
		{
			name: "allowlist short sha256",
			args: []string{"allowlist", "--file", "allowlist.yaml", "--sha256", "abcd"},
			want: "invalid --sha256: want 64 hex digits",
		},
		{
			name: "create bad sha256",
			args: []string{"create", "--file", "allowlist.yaml", "--sha256", strings.Repeat("zz", 32)},
			want: "invalid --sha256: want 64 hex digits",
		},
		{
			name: "list sha256 without allowlist",
			args: []string{"list", "--ui", "web", "--sha256", goodPin},
			want: "--sha256 requires --allowlist",
		},
		{
			name: "allowlist sha256 without file",
			args: []string{"allowlist", "--sha256", goodPin},
			want: "--file",
		},
		{
			name: "create empty file with sha256",
			args: []string{"create", "--file", "   ", "--sha256", goodPin},
			want: "--sha256 requires --file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCLI(t, bin, home, tc.args...)
			assertUsageError(t, res, tc.want)
		})
	}

	const password = "s3cret"
	ref := "https://alice:" + password + "@example.com/%zz"
	res := runCLI(t, bin, home, "allowlist", "--file", ref, "--dry-run")
	assertUsageError(t, res, "invalid allowlist URL")
	out := res.stdout + res.stderr
	if strings.Contains(out, password) {
		t.Fatalf("password leaked: stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if strings.Contains(out, ref) || strings.Contains(out, "invalid URL escape") {
		t.Fatalf("raw URL or parse error leaked: stdout=%q stderr=%q", res.stdout, res.stderr)
	}
}

func TestAllowlistURLHelp(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	for _, cmd := range []string{"allowlist", "create", "list"} {
		res := runCLI(t, bin, home, cmd, "-h")
		if res.code != 0 {
			t.Fatalf("%s help code=%d stderr=%s", cmd, res.code, res.stderr)
		}
		if !strings.Contains(res.stdout, "https URL") || !strings.Contains(res.stdout, "--sha256") {
			t.Fatalf("%s help missing https URL or --sha256:\n%s", cmd, res.stdout)
		}
	}
}

func TestCreateAllowlistURLClientHook(t *testing.T) {
	body := []byte("{}\n")
	sum := sha256.Sum256(body)
	pin := hex.EncodeToString(sum[:])
	var hits int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/bad.yaml" {
			_, _ = w.Write([]byte("[\n"))
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	prev := allowlist.HTTPClient
	allowlist.HTTPClient = srv.Client()
	t.Cleanup(func() { allowlist.HTTPClient = prev })

	t.Run("parsed", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		var stdout, stderr bytes.Buffer
		code := run([]string{"trustprune", "allowlist", "--dry-run", "--file", srv.URL + "/al.json", "--sha256", strings.ToUpper(pin)}, &stdout, &stderr)
		if code == 0 || !strings.Contains(stdout.String(), "no backup") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), "SHA-256 mismatch") || strings.Contains(stdout.String(), "unable to read allowlist") {
			t.Fatalf("fetch or pin failed: %s", stdout.String())
		}
	})

	t.Run("mismatch does not apply", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"trustprune", "create", "--file", srv.URL + "/al.json", "--sha256", strings.Repeat("ab", 32)}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), "SHA-256 mismatch") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), "no certificates matched") || strings.Contains(stdout.String(), "unable to read allowlist") {
			t.Fatalf("mismatch applied or parsed: %s", stdout.String())
		}
	})

	t.Run("invalid body", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"trustprune", "create", "--file", srv.URL + "/bad.yaml"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), "unable to read allowlist") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	})

	if hits < 3 {
		t.Fatalf("hook was not used for every fetch: hits=%d", hits)
	}
}
