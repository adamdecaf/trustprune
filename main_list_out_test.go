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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestListOutCLI(t *testing.T) {
	bin := cliBinary(t)
	lots := filepath.Join("testdata", "example.crt")
	home := t.TempDir()

	for _, format := range []string{"json", "short", "table", "openssl"} {
		t.Run(format, func(t *testing.T) {
			if format == "openssl" {
				if _, err := exec.LookPath("openssl"); err != nil {
					t.Skip("openssl not on PATH")
				}
			}
			stdoutRun := runCLI(t, bin, home, "list", "-file", lots, "-format", format)
			if stdoutRun.code != 0 {
				t.Fatalf("code=%d\nstdout=%s\nstderr=%s", stdoutRun.code, stdoutRun.stdout, stdoutRun.stderr)
			}
			if stdoutRun.stdout == "" {
				t.Fatal("expected stdout")
			}

			outPath := filepath.Join(t.TempDir(), "out.txt")
			fileRun := runCLI(t, bin, home, "list", "-file", lots, "-format", format, "-out", outPath)
			if fileRun.code != 0 {
				t.Fatalf("code=%d\nstdout=%s\nstderr=%s", fileRun.code, fileRun.stdout, fileRun.stderr)
			}
			if fileRun.stdout != "" {
				t.Fatalf("stdout = %q, want empty", fileRun.stdout)
			}
			// #nosec G304 -- output path under t.TempDir
			got, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != stdoutRun.stdout {
				t.Fatalf("file differs from stdout\nfile:\n%s\nstdout:\n%s", got, stdoutRun.stdout)
			}
		})
	}

	t.Run("observatory", func(t *testing.T) {
		stdoutRun := runCLI(t, bin, home, "list", "-file", lots, "-format", "observatory")
		if stdoutRun.code != 0 {
			t.Fatalf("code=%d\nstdout=%s\nstderr=%s", stdoutRun.code, stdoutRun.stdout, stdoutRun.stderr)
		}
		outPath := filepath.Join(t.TempDir(), "report.yaml")
		fileRun := runCLI(t, bin, home, "list", "-file", lots, "-format", "observatory", "-out", outPath)
		if fileRun.code != 0 {
			t.Fatalf("code=%d\nstdout=%s\nstderr=%s", fileRun.code, fileRun.stdout, fileRun.stderr)
		}
		if fileRun.stdout != "" {
			t.Fatalf("stdout = %q, want empty", fileRun.stdout)
		}
		// #nosec G304 -- output path under t.TempDir
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != stdoutRun.stdout {
			t.Fatalf("file differs from stdout\nfile:\n%s\nstdout:\n%s", got, stdoutRun.stdout)
		}
		if !strings.Contains(string(got), "trusted_certificates:") {
			t.Fatalf("observatory file missing report body:\n%s", got)
		}
	})

	t.Run("count", func(t *testing.T) {
		stdoutRun := runCLI(t, bin, home, "list", "-file", lots, "-count")
		if stdoutRun.code != 0 {
			t.Fatalf("code=%d\nstdout=%s\nstderr=%s", stdoutRun.code, stdoutRun.stdout, stdoutRun.stderr)
		}
		outPath := filepath.Join(t.TempDir(), "count.txt")
		fileRun := runCLI(t, bin, home, "list", "-file", lots, "-count", "-out", outPath)
		if fileRun.code != 0 {
			t.Fatalf("code=%d\nstdout=%s\nstderr=%s", fileRun.code, fileRun.stdout, fileRun.stderr)
		}
		if fileRun.stdout != "" {
			t.Fatalf("stdout = %q, want empty", fileRun.stdout)
		}
		// #nosec G304 -- output path under t.TempDir
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != stdoutRun.stdout {
			t.Fatalf("file = %q, stdout = %q", got, stdoutRun.stdout)
		}
	})

	t.Run("empty", func(t *testing.T) {
		empty := filepath.Join(t.TempDir(), "empty.pem")
		if err := os.WriteFile(empty, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		outPath := filepath.Join(t.TempDir(), "should-not-exist.json")
		res := runCLI(t, bin, home, "list", "-file", empty, "-format", "json", "-out", outPath)
		if res.code == 0 {
			t.Fatalf("expected failure, stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "no certificates to display") {
			t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		if _, err := os.Stat(outPath); !os.IsNotExist(err) {
			t.Fatalf("outfile created: %v", err)
		}
	})
}

func TestOutHelpText(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()

	top := runCLI(t, bin, home, "-h")
	if top.code != 0 {
		t.Fatalf("code=%d\nstdout=%s\nstderr=%s", top.code, top.stdout, top.stderr)
	}
	if !strings.Contains(top.stdout, "COMMANDS") {
		t.Fatal("root help missing COMMANDS")
	}
	if !strings.Contains(top.stdout, "APPS") {
		t.Fatal("root help missing APPS")
	}
	if !strings.Contains(top.stdout, "DEBUGGING") {
		t.Fatal("root help missing DEBUGGING")
	}
	if !strings.Contains(top.stdout, "TRUSTPRUNE_JAVA_STOREPASS") {
		t.Fatal("root help missing TRUSTPRUNE_JAVA_STOREPASS")
	}
	if !strings.Contains(top.stdout, "Run 'trustprune <command> --help' for that command's flags.") {
		t.Fatalf("root help missing per-command flags line:\n%s", top.stdout)
	}
	if strings.Contains(top.stdout, "\nFLAGS") || strings.Contains(top.stdout, "\nOUTPUT") {
		t.Fatalf("root help still has FLAGS/OUTPUT:\n%s", top.stdout)
	}

	list := runCLI(t, bin, home, "list", "-h")
	if list.code != 0 {
		t.Fatalf("expected list -h to exit 0, code=%d stdout=%q stderr=%q", list.code, list.stdout, list.stderr)
	}
	if strings.Contains(list.stdout, "used by -format observatory") {
		t.Fatal("list help still limits -out to observatory")
	}
	if !strings.Contains(list.stdout, "every --format") {
		t.Fatalf("list help missing every-format -out text:\n%s", list.stdout)
	}
	if !strings.Contains(list.stdout, "--format json --out") {
		t.Fatalf("list help missing json -out example:\n%s", list.stdout)
	}
}
