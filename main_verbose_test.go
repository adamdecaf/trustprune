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
	"unicode"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestCLIVerboseFlag(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	example := filepath.Join("testdata", "example.crt")
	lots := filepath.Join("testdata", "lots.crt")
	bundle := writeChainCLICert(t)

	t.Run("list -v and --verbose", func(t *testing.T) {
		plain := runCLI(t, bin, home, "list", "--file", lots)
		if plain.code != 0 {
			t.Fatalf("list code=%d stdout=%s stderr=%s", plain.code, plain.stdout, plain.stderr)
		}
		dashV := runCLI(t, bin, home, "list", "--file", lots, "-v")
		if dashV.code != 0 {
			t.Fatalf("list -v code=%d stdout=%s stderr=%s", dashV.code, dashV.stdout, dashV.stderr)
		}
		long := runCLI(t, bin, home, "list", "--file", lots, "--verbose")
		if long.code != 0 {
			t.Fatalf("list --verbose code=%d stdout=%s stderr=%s", long.code, long.stdout, long.stderr)
		}
		if dashV.stdout != long.stdout {
			t.Fatalf("-v and --verbose differ\n-v:\n%s\n--verbose:\n%s", dashV.stdout, long.stdout)
		}
		if dashV.stdout == plain.stdout {
			t.Fatal("list -v matched non-verbose output")
		}
		if !strings.Contains(dashV.stdout, "SERIAL") || !strings.Contains(dashV.stdout, "NOT-BEFORE") {
			t.Fatalf("list -v missing verbose headers:\n%s", dashV.stdout)
		}
		if strings.Contains(plain.stdout, "SERIAL") {
			t.Fatalf("list without -v showed SERIAL:\n%s", plain.stdout)
		}
	})

	t.Run("global -v list", func(t *testing.T) {
		local := runCLI(t, bin, home, "list", "--file", lots, "-v")
		global := runCLI(t, bin, home, "-v", "list", "--file", lots)
		longGlobal := runCLI(t, bin, home, "--verbose", "list", "--file", lots)
		if global.code != 0 {
			t.Fatalf("trustprune -v list code=%d stdout=%s stderr=%s", global.code, global.stdout, global.stderr)
		}
		if longGlobal.code != 0 {
			t.Fatalf("trustprune --verbose list code=%d stdout=%s stderr=%s", longGlobal.code, longGlobal.stdout, longGlobal.stderr)
		}
		if global.stdout != local.stdout {
			t.Fatalf("global -v list != list -v\nglobal:\n%s\nlocal:\n%s", global.stdout, local.stdout)
		}
		if longGlobal.stdout != local.stdout {
			t.Fatalf("global --verbose list != list -v\nglobal:\n%s\nlocal:\n%s", longGlobal.stdout, local.stdout)
		}
	})

	t.Run("connect accepts -v and --verbose", func(t *testing.T) {
		// http is rejected before any dial. An unknown flag is exit 2.
		for _, args := range [][]string{
			{"connect", "-v", "http://example.com"},
			{"connect", "--verbose", "http://example.com"},
			{"-v", "connect", "http://example.com"},
			{"--verbose", "connect", "http://example.com"},
		} {
			res := runCLI(t, bin, home, args...)
			if res.code == 2 || strings.Contains(res.stderr, "unknown flag") {
				t.Fatalf("%v treated -v as unknown: code=%d stdout=%q stderr=%q", args, res.code, res.stdout, res.stderr)
			}
			if res.code != 1 || !strings.Contains(res.stdout+res.stderr, "non-secure") {
				t.Fatalf("%v code=%d stdout=%q stderr=%q", args, res.code, res.stdout, res.stderr)
			}
		}
	})

	t.Run("diff accepts -v and --verbose", func(t *testing.T) {
		plain := runCLI(t, bin, home, "diff", example, example)
		if plain.code != 0 || plain.stdout != "identical\n" {
			t.Fatalf("diff code=%d stdout=%q stderr=%q", plain.code, plain.stdout, plain.stderr)
		}
		for _, args := range [][]string{
			{"diff", "-v", example, example},
			{"diff", "--verbose", example, example},
			{"-v", "diff", example, example},
			{"--verbose", "diff", example, example},
		} {
			res := runCLI(t, bin, home, args...)
			if res.code != 0 || res.stderr != "" {
				t.Fatalf("%v code=%d stdout=%q stderr=%q", args, res.code, res.stdout, res.stderr)
			}
			if res.stdout != plain.stdout {
				t.Fatalf("%v stdout=%q want %q", args, res.stdout, plain.stdout)
			}
		}
	})

	t.Run("chain -v prints full sha256", func(t *testing.T) {
		certs, err := certutil.FromFile(bundle)
		if err != nil || len(certs) != 1 {
			t.Fatalf("bundle certs: %d %v", len(certs), err)
		}
		full := certutil.GetHexSHA256Fingerprint(*certs[0])
		if len(full) != 64 {
			t.Fatalf("sha256 length = %d", len(full))
		}
		prefix := full[:16]

		plain := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle)
		if plain.code != 0 {
			t.Fatalf("chain code=%d stdout=%s stderr=%s", plain.code, plain.stdout, plain.stderr)
		}
		plainSHA := chainTableSHA256(t, plain.stdout)
		if plainSHA != prefix {
			t.Fatalf("default SHA256=%q want prefix %q\n%s", plainSHA, prefix, plain.stdout)
		}
		if strings.Contains(plain.stdout, full) {
			t.Fatalf("default table printed full sha256:\n%s", plain.stdout)
		}

		dashV := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle, "-v")
		if dashV.code != 0 {
			t.Fatalf("chain -v code=%d stdout=%s stderr=%s", dashV.code, dashV.stdout, dashV.stderr)
		}
		long := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle, "--verbose")
		if long.code != 0 {
			t.Fatalf("chain --verbose code=%d stdout=%s stderr=%s", long.code, long.stdout, long.stderr)
		}
		global := runCLI(t, bin, home, "-v", "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle)
		if global.code != 0 {
			t.Fatalf("trustprune -v chain code=%d stdout=%s stderr=%s", global.code, global.stdout, global.stderr)
		}
		if dashV.stdout != long.stdout || dashV.stdout != global.stdout {
			t.Fatalf("chain verbose outputs differ\n-v:\n%s\n--verbose:\n%s\nglobal:\n%s", dashV.stdout, long.stdout, global.stdout)
		}
		verboseSHA := chainTableSHA256(t, dashV.stdout)
		if verboseSHA != full {
			t.Fatalf("verbose SHA256=%q want %q\n%s", verboseSHA, full, dashV.stdout)
		}
		if dashV.stdout == plain.stdout {
			t.Fatal("chain -v matched non-verbose output")
		}

		jsonPlain := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle, "--format", "json")
		jsonVerbose := runCLI(t, bin, home, "chain", "--app", "openssl", "--bundle", bundle, "--file", bundle, "--format", "json", "-v")
		if jsonPlain.code != 0 || jsonVerbose.code != 0 {
			t.Fatalf("json code plain=%d verbose=%d", jsonPlain.code, jsonVerbose.code)
		}
		if jsonPlain.stdout != jsonVerbose.stdout {
			t.Fatalf("json changed with -v\nplain:\n%s\nverbose:\n%s", jsonPlain.stdout, jsonVerbose.stdout)
		}
		if !strings.Contains(jsonPlain.stdout, full) {
			t.Fatalf("json missing full sha256:\n%s", jsonPlain.stdout)
		}
	})

	t.Run("root help lists -v/--verbose", func(t *testing.T) {
		res := runCLI(t, bin, home, "--help")
		if res.code != 0 {
			t.Fatalf("help code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "--verbose") || !strings.Contains(res.stdout, "-v") {
			t.Fatalf("root help missing -v/--verbose:\n%s", res.stdout)
		}
		if !strings.Contains(res.stdout, "verbose output") {
			t.Fatalf("root help missing verbose usage:\n%s", res.stdout)
		}
	})

	t.Run("subcommand help lists --verbose", func(t *testing.T) {
		for _, cmd := range []string{"list", "connect", "chain", "diff"} {
			res := runCLI(t, bin, home, cmd, "--help")
			if res.code != 0 {
				t.Fatalf("%s help code=%d stdout=%s stderr=%s", cmd, res.code, res.stdout, res.stderr)
			}
			body := res.stdout + res.stderr
			if !strings.Contains(body, "--verbose") {
				t.Fatalf("%s help missing --verbose:\n%s", cmd, body)
			}
		}
	})
}

func chainTableSHA256(t *testing.T, out string) string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("chain table:\n%s", out)
	}
	header := splitAlignedCells(lines[0])
	shaCol := -1
	for i, cell := range header {
		if cell == "SHA256" {
			shaCol = i
			break
		}
	}
	if shaCol < 0 {
		t.Fatalf("chain table:\n%s", out)
	}
	fields := splitAlignedCells(lines[1])
	if shaCol >= len(fields) {
		t.Fatalf("chain row:\n%s", out)
	}
	sha := fields[shaCol]
	for _, r := range sha {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			t.Fatalf("SHA256 %q is not hex\n%s", sha, out)
		}
	}
	return sha
}
