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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func testListCerts(t *testing.T) []*x509.Certificate {
	t.Helper()
	bs, err := os.ReadFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("no certs")
	}
	return certs
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fnErr := fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(out), fnErr
}

func TestListOutfileMatchesStdout(t *testing.T) {
	certs := testListCerts(t)
	meta := Meta{Name: "file"}
	for _, format := range []string{"json", "long", "table", "observatory"} {
		t.Run(format, func(t *testing.T) {
			cfg := &Config{Format: format, UI: DefaultUI(), SourcePath: "testdata/lots.crt"}
			stdout, err := captureStdout(t, func() error {
				return ListCertificatesWithMeta(meta, certs, cfg)
			})
			if err != nil {
				t.Fatal(err)
			}
			if stdout == "" {
				t.Fatal("expected stdout")
			}

			path := filepath.Join(t.TempDir(), "out.txt")
			gotOut, err := captureStdout(t, func() error {
				c := *cfg
				c.Outfile = path
				return ListCertificatesWithMeta(meta, certs, &c)
			})
			if err != nil {
				t.Fatal(err)
			}
			if gotOut != "" {
				t.Fatalf("stdout = %q, want empty", gotOut)
			}
			// #nosec G304 -- output path under t.TempDir
			fileBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(fileBytes) != stdout {
				t.Fatalf("file differs from stdout\nfile:\n%s\nstdout:\n%s", fileBytes, stdout)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			// Windows does not honor Unix permission bits.
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
				t.Fatalf("perm = %o, want 600", info.Mode().Perm())
			}
		})
	}
}

func TestListOutfileOverwrites(t *testing.T) {
	certs := testListCerts(t)
	path := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Format: "json", SourcePath: "testdata/lots.crt", Outfile: path}
	stdout, err := captureStdout(t, func() error {
		c := *cfg
		c.Outfile = ""
		return ListCertificatesWithMeta(Meta{Name: "file"}, certs, &c)
	})
	if err != nil {
		t.Fatal(err)
	}
	gotOut, err := captureStdout(t, func() error {
		return ListCertificatesWithMeta(Meta{Name: "file"}, certs, cfg)
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotOut != "" {
		t.Fatalf("stdout = %q, want empty", gotOut)
	}
	// #nosec G304 -- output path under t.TempDir
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(fileBytes) != stdout {
		t.Fatal("outfile was not replaced with json output")
	}
	if strings.Contains(string(fileBytes), "stale") {
		t.Fatal("outfile still contains previous contents")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("perm = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestListOutfilePreservedWhenOpenSSLFails(t *testing.T) {
	certs := testListCerts(t)[:1]
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	const seed = "keep-me\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// An empty PATH still searches "." on Unix. Point PATH at an empty
	// directory, and skip Windows' current-directory search, so openssl
	// cannot be resolved.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("NoDefaultCurrentDirectoryInExePath", "1")

	gotOut, err := captureStdout(t, func() error {
		return ListCertificatesWithMeta(Meta{Name: "file"}, certs, &Config{
			Format:  "openssl",
			UI:      DefaultUI(),
			Outfile: path,
		})
	})
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("err = %v, want openssl not found", err)
	}
	if gotOut != "" {
		t.Fatalf("stdout = %q, want empty", gotOut)
	}
	// #nosec G304 -- output path under t.TempDir
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(fileBytes) != seed {
		t.Fatalf("outfile = %q, want %q", fileBytes, seed)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("perm = %o, want %o", after.Mode().Perm(), before.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "out.txt" {
		names := make([]string, len(entries))
		for i := range entries {
			names[i] = entries[i].Name()
		}
		t.Fatalf("dir entries = %v, want only out.txt", names)
	}
}

func TestListOutfileCount(t *testing.T) {
	certs := testListCerts(t)
	cases := []struct {
		name  string
		certs []*x509.Certificate
		want  string
	}{
		{name: "certs", certs: certs, want: fmt.Sprintf("%d\n", len(certs))},
		{name: "zero", certs: nil, want: "0\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, err := captureStdout(t, func() error {
				return ListCertificatesWithMeta(Meta{}, tc.certs, &Config{Count: true})
			})
			if err != nil {
				t.Fatal(err)
			}
			if stdout != tc.want {
				t.Fatalf("stdout = %q, want %q", stdout, tc.want)
			}

			path := filepath.Join(t.TempDir(), "count.txt")
			gotOut, err := captureStdout(t, func() error {
				return ListCertificatesWithMeta(Meta{}, tc.certs, &Config{Count: true, Outfile: path})
			})
			if err != nil {
				t.Fatal(err)
			}
			if gotOut != "" {
				t.Fatalf("stdout = %q, want empty", gotOut)
			}
			// #nosec G304 -- output path under t.TempDir
			fileBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(fileBytes) != tc.want {
				t.Fatalf("file = %q, want %q", fileBytes, tc.want)
			}
		})
	}
}

func TestListOutfileEmptyStillErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	gotOut, err := captureStdout(t, func() error {
		return ListCertificatesWithMeta(Meta{Name: "file"}, nil, &Config{Format: "json", Outfile: path})
	})
	if err == nil || err.Error() != "no certificates to display" {
		t.Fatalf("err=%v", err)
	}
	if gotOut != "" {
		t.Fatalf("stdout = %q, want empty", gotOut)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("outfile created on empty list: %v", statErr)
	}
}

func TestListOutfileOpenError(t *testing.T) {
	certs := testListCerts(t)[:1]
	dir := t.TempDir()
	gotOut, err := captureStdout(t, func() error {
		return ListCertificatesWithMeta(Meta{Name: "file"}, certs, &Config{Format: "json", Outfile: dir})
	})
	if err == nil {
		t.Fatal("expected error opening a directory")
	}
	if gotOut != "" {
		t.Fatalf("stdout = %q, want empty", gotOut)
	}
}
