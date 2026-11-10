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
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIExitCodes(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()

	t.Run("help is 0", func(t *testing.T) {
		for _, args := range [][]string{
			{},
			{"-h"},
			{"--help"},
			{"help"},
			{"list", "-h"},
			{"list", "--help"},
			{"add", "-h"},
		} {
			res := runCLI(t, bin, home, args...)
			if res.code != 0 {
				t.Fatalf("%v code=%d stdout=%s stderr=%s", args, res.code, res.stdout, res.stderr)
			}
		}
	})

	t.Run("unknown flag is 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "apps", "--nope")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "unknown flag") || !strings.Contains(res.stderr, "--help") {
			t.Fatalf("stderr=%q", res.stderr)
		}
	})

	t.Run("unknown flag keeps double dash", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "--bogus")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "unknown flag --bogus") {
			t.Fatalf("expected unknown flag --bogus, stderr=%q", res.stderr)
		}
		if strings.Contains(res.stderr, "unknown flag -bogus") {
			t.Fatalf("dropped a dash: stderr=%q", res.stderr)
		}
	})

	t.Run("whitelist is unknown command", func(t *testing.T) {
		res := runCLI(t, bin, home, "whitelist")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, `unknown command "whitelist"`) {
			t.Fatalf("stderr=%q", res.stderr)
		}
	})

	t.Run("list --app --file is usage 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "--app", "java", "--file", "x")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if strings.Contains(res.stdout, "ERROR:") {
			t.Fatalf("usage error used ERROR: prefix, stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "--file lists a PEM") {
			t.Fatalf("stderr=%q", res.stderr)
		}
	})

	t.Run("bundle with store is usage 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "--app", "openssl", "--bundle", "x", "--store", "y")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if strings.Contains(res.stdout, "ERROR:") {
			t.Fatalf("usage error used ERROR: prefix, stdout=%q stderr=%q", res.stdout, res.stderr)
		}
	})

	t.Run("connect url and positional is usage 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "--url", "https://example.com", "https://other.example")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "not both") {
			t.Fatalf("stderr=%q", res.stderr)
		}
	})

	t.Run("unknown command is 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "nope")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, `unknown command "nope"`) || !strings.Contains(res.stderr, "--help") {
			t.Fatalf("stderr=%q", res.stderr)
		}
	})

	t.Run("stray args is 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "version", "extra")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
	})

	t.Run("missing --file is 2", func(t *testing.T) {
		for _, name := range []string{"add", "allowlist"} {
			res := runCLI(t, bin, home, name)
			if res.code != 2 {
				t.Fatalf("%s code=%d stdout=%s stderr=%s", name, res.code, res.stdout, res.stderr)
			}
			if !strings.Contains(res.stderr, "required flag --file not set") {
				t.Fatalf("%s stderr=%q", name, res.stderr)
			}
		}
	})
}

func TestCLIDashAndDoubleDashFlags(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	lots := filepath.Join("testdata", "example.crt")

	single := runCLI(t, bin, home, "list", "-file", lots, "-count")
	if single.code != 0 {
		t.Fatalf("-file code=%d stdout=%s stderr=%s", single.code, single.stdout, single.stderr)
	}
	double := runCLI(t, bin, home, "list", "--file", lots, "--count")
	if double.code != 0 {
		t.Fatalf("--file code=%d stdout=%s stderr=%s", double.code, double.stdout, double.stderr)
	}
	if strings.TrimSpace(single.stdout) != strings.TrimSpace(double.stdout) {
		t.Fatalf("-file stdout %q != --file stdout %q", single.stdout, double.stdout)
	}
}

func TestCLIRemovedFileAliasRejected(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	dummy := filepath.Join(home, "x")

	cases := [][]string{
		{"backup", "--file", dummy},
		{"restore", "--file", dummy},
		{"connect", "--file", dummy, "--url", "https://example.com"},
		{"backup", "-file", dummy},
		{"restore", "-file", dummy},
		{"connect", "-file", dummy, "-url", "https://example.com"},
	}
	for _, args := range cases {
		res := runCLI(t, bin, home, args...)
		if res.code != 2 {
			t.Fatalf("%v code=%d stdout=%s stderr=%s", args, res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "unknown flag") || !strings.Contains(res.stderr, "file") {
			t.Fatalf("%v stderr=%q", args, res.stderr)
		}
	}
}

func TestCLIPerCommandFlagScoping(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()

	res := runCLI(t, bin, home, "apps", "--store", filepath.Join(home, "x"))
	if res.code != 2 {
		t.Fatalf("apps --store code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "unknown flag") {
		t.Fatalf("stderr=%q", res.stderr)
	}

	res = runCLI(t, bin, home, "version", "--dry-run")
	if res.code != 2 || !strings.Contains(res.stderr, "unknown flag") {
		t.Fatalf("version --dry-run code=%d stderr=%q", res.code, res.stderr)
	}

	res = runCLI(t, bin, home, "list", "--backup", dummyPath(home))
	if res.code != 2 || !strings.Contains(res.stderr, "unknown flag") {
		t.Fatalf("list --backup code=%d stderr=%q", res.code, res.stderr)
	}
}

func dummyPath(home string) string {
	return filepath.Join(home, "nope")
}

func TestCLITraceOnUsageAndHelp(t *testing.T) {
	bin := cliBinary(t)
	const sentinel = "preserve-me\n"

	t.Run("unknown flag does not truncate TRACE", func(t *testing.T) {
		tracePath := writeTestFile(t, "trace.out", []byte(sentinel))
		res := runCLIWithEnv(t, bin, envWithTRACE(t.TempDir(), tracePath), "apps", "--store", "x")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		assertSameBytes(t, tracePath, []byte(sentinel))
	})

	t.Run("unknown command does not truncate TRACE", func(t *testing.T) {
		tracePath := writeTestFile(t, "trace.out", []byte(sentinel))
		res := runCLIWithEnv(t, bin, envWithTRACE(t.TempDir(), tracePath), "nope")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		assertSameBytes(t, tracePath, []byte(sentinel))
	})

	t.Run("missing required flag does not truncate TRACE", func(t *testing.T) {
		tracePath := writeTestFile(t, "trace.out", []byte(sentinel))
		res := runCLIWithEnv(t, bin, envWithTRACE(t.TempDir(), tracePath), "add")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		assertSameBytes(t, tracePath, []byte(sentinel))
	})

	t.Run("list --app --file does not truncate TRACE", func(t *testing.T) {
		tracePath := writeTestFile(t, "trace.out", []byte(sentinel))
		res := runCLIWithEnv(t, bin, envWithTRACE(t.TempDir(), tracePath), "list", "--app", "java", "--file", "x")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		assertSameBytes(t, tracePath, []byte(sentinel))
	})
}
