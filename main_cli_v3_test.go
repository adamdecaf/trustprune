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
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
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
		assertUsageError(t, res, "unknown flag")
	})

	t.Run("unknown flag keeps double dash", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "--bogus")
		assertUsageError(t, res, "unknown flag --bogus")
		if strings.Contains(res.stderr, "unknown flag -bogus") {
			t.Fatalf("dropped a dash: stderr=%q", res.stderr)
		}
	})

	t.Run("whitelist is unknown command", func(t *testing.T) {
		res := runCLI(t, bin, home, "whitelist")
		assertUsageError(t, res, `unknown command "whitelist"`)
	})

	t.Run("list --app --file is usage 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "--app", "java", "--file", "x")
		assertUsageError(t, res, "--file lists a PEM")
	})

	t.Run("bundle with store is usage 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "--app", "openssl", "--bundle", "x", "--store", "y")
		assertUsageError(t, res, "not both")
	})

	t.Run("connect url and positional is usage 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "--url", "https://example.com", "https://other.example")
		assertUsageError(t, res, "not both")
	})

	t.Run("unknown command is 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "nope")
		assertUsageError(t, res, `unknown command "nope"`)
	})

	t.Run("stray args is 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "version", "extra")
		assertUsageError(t, res, "unexpected argument")
	})

	t.Run("missing --file is 2", func(t *testing.T) {
		for _, name := range []string{"add", "allowlist"} {
			res := runCLI(t, bin, home, name)
			assertUsageError(t, res, "required flag --file not set")
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

func TestCLIUsageErrorPrefix(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()

	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "unknown flag",
			args: []string{"list", "--foo"},
			want: "ERROR: unknown flag --foo\nrun 'trustprune list --help' for usage\n",
		},
		{
			name: "unknown command",
			args: []string{"no-such"},
			want: "ERROR: unknown command \"no-such\"\nrun 'trustprune --help' for usage\n",
		},
		{
			name: "missing required flag",
			args: []string{"gen-allowlist"},
			want: "ERROR: required flag --out not set\nrun 'trustprune gen-allowlist --help' for usage\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCLI(t, bin, home, tc.args...)
			if res.code != 2 {
				t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
			}
			if res.stdout != "" {
				t.Fatalf("stdout=%q", res.stdout)
			}
			if res.stderr != tc.want {
				t.Fatalf("stderr=%q want %q", res.stderr, tc.want)
			}
		})
	}
}

func TestCLIVersionFlag(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	want := getVersion() + "\n"

	command := runCLI(t, bin, home, "version")
	long := runCLI(t, bin, home, "--version")
	single := runCLI(t, bin, home, "-version")
	for _, tc := range []struct {
		name string
		res  cliResult
	}{
		{"version", command},
		{"--version", long},
		{"-version", single},
	} {
		if tc.res.code != 0 {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", tc.name, tc.res.code, tc.res.stdout, tc.res.stderr)
		}
		if tc.res.stderr != "" {
			t.Fatalf("%s stderr=%q", tc.name, tc.res.stderr)
		}
		if tc.res.stdout != want {
			t.Fatalf("%s stdout=%q want %q", tc.name, tc.res.stdout, want)
		}
	}
	if long.stdout != command.stdout || single.stdout != command.stdout {
		t.Fatalf("version outputs differ: command=%q --version=%q -version=%q", command.stdout, long.stdout, single.stdout)
	}

	// -v is verbose on list, not a version alias. At the root it stays an unknown flag.
	dashV := runCLI(t, bin, home, "-v")
	assertUsageError(t, dashV, "unknown flag")
	if strings.Contains(dashV.stdout, want) || strings.Contains(dashV.stdout, "(Go:") {
		t.Fatalf("root -v printed the version: stdout=%q stderr=%q", dashV.stdout, dashV.stderr)
	}

	listVersion := runCLI(t, bin, home, "list", "--version")
	assertUsageError(t, listVersion, "unknown flag")
	if strings.Contains(listVersion.stdout, "(Go:") {
		t.Fatalf("list --version printed the version: stdout=%q", listVersion.stdout)
	}

	listVerbose := runCLI(t, bin, home, "list", "-file", filepath.Join("testdata", "example.crt"), "-count", "-v")
	if listVerbose.code != 0 {
		t.Fatalf("list -v code=%d stdout=%q stderr=%q", listVerbose.code, listVerbose.stdout, listVerbose.stderr)
	}

	help := runCLI(t, bin, home, "--help")
	if help.code != 0 {
		t.Fatalf("help code=%d stdout=%q stderr=%q", help.code, help.stdout, help.stderr)
	}
	var versionLine string
	for _, line := range strings.Split(help.stdout, "\n") {
		if strings.Contains(line, "--version") {
			versionLine = line
			break
		}
	}
	if versionLine == "" {
		t.Fatalf("root help missing --version:\n%s", help.stdout)
	}
	// "--version" itself contains the letters "-v"; an alias would remain after that name is removed.
	if strings.Contains(strings.ReplaceAll(versionLine, "--version", ""), "-v") {
		t.Fatalf("root --version aliased -v: %q", versionLine)
	}
}

func TestWriteUsageError(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "prefixes first line only",
			msg:  "unknown flag --foo\nrun 'trustprune list --help' for usage",
			want: "ERROR: unknown flag --foo\nrun 'trustprune list --help' for usage\n",
		},
		{
			name: "already prefixed",
			msg:  "ERROR: unknown flag --foo\nrun 'trustprune list --help' for usage",
			want: "ERROR: unknown flag --foo\nrun 'trustprune list --help' for usage\n",
		},
		{
			name: "single line",
			msg:  "unknown command \"nope\"",
			want: "ERROR: unknown command \"nope\"\n",
		},
		{
			name: "empty",
			msg:  "  \n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeUsageError(&buf, tc.msg)
			if buf.String() != tc.want {
				t.Fatalf("got %q want %q", buf.String(), tc.want)
			}
		})
	}
}

func TestFinishRunUsagePaths(t *testing.T) {
	t.Run("usageErr", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := finishRun(&stdout, &stderr, errUsage("no url specified"))
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		const want = "ERROR: no url specified\nrun 'trustprune --help' for usage\n"
		if stderr.String() != want {
			t.Fatalf("stderr=%q want %q", stderr.String(), want)
		}
	})

	t.Run("exit coder", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := finishRun(&stdout, &stderr, usageExit(nil, "unknown flag --foo"))
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		const want = "ERROR: unknown flag --foo\nrun 'trustprune --help' for usage\n"
		if stderr.String() != want {
			t.Fatalf("stderr=%q want %q", stderr.String(), want)
		}
	})

	t.Run("already prefixed exit coder", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := cli.Exit("ERROR: already\nrun 'trustprune --help' for usage", usageExitCode)
		code := finishRun(&stdout, &stderr, err)
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		const want = "ERROR: already\nrun 'trustprune --help' for usage\n"
		if stderr.String() != want {
			t.Fatalf("stderr=%q want %q", stderr.String(), want)
		}
	})

	t.Run("runtime error stays on stdout", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := finishRun(&stdout, &stderr, errors.New("boom"))
		if code != 1 || stderr.Len() != 0 || stdout.String() != "ERROR: boom\n" {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	})

	t.Run("non-usage exit coder stays on stdout", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := finishRun(&stdout, &stderr, cli.Exit("plain failure", 1))
		if code != 1 || stderr.Len() != 0 || stdout.String() != "plain failure\n" {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	})
}
