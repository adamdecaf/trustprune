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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestDifferExitPrintsNothing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := finishRun(&stdout, &stderr, differExit{})
	if code != 1 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestDiffCLI(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	example := filepath.Join("testdata", "example.crt")
	local := filepath.Join("testdata", "localcert.pem")
	negative := filepath.Join("testdata", "negative-serial.pem")

	t.Run("help", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", "--help")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		for _, needle := range []string{
			"trustprune diff old.pem new.pem",
			"trustprune diff --format json old.pem new.der",
			"subject: \"CN=Old\" != \"CN=New\"",
			"signature_algorithm",
			"PEM or DER",
			"identical",
			"default: text",
			"options: json, text",
		} {
			if !strings.Contains(res.stdout, needle) {
				t.Fatalf("diff help missing %q:\n%s", needle, res.stdout)
			}
		}
	})

	t.Run("no paths", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff")
		assertUsageError(t, res, "expected two certificate files")
	})

	t.Run("one path", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", example)
		assertUsageError(t, res, "expected two certificate files")
	})

	t.Run("three paths", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", example, local, "extra.pem")
		assertUsageError(t, res, "unexpected argument(s): extra.pem")
	})

	t.Run("unknown format wins", func(t *testing.T) {
		missing := filepath.Join(home, "missing.pem")
		res := runCLI(t, bin, home, "diff", "--format", "nope", missing, missing)
		assertUsageError(t, res, `unknown format "nope" (formats: json, text)`)
		if strings.Contains(res.stdout+res.stderr, "does not exist") {
			t.Fatalf("format check read the files: stdout=%q stderr=%q", res.stdout, res.stderr)
		}
	})

	t.Run("format before path count", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", "--format", "Short")
		assertUsageError(t, res, `unknown format "Short" (formats: json, text)`)
	})

	t.Run("file flag rejected", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", "--file", example, "--file", local)
		assertUsageError(t, res, "unknown flag")
	})

	t.Run("identical text", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", example, example)
		if res.code != 0 || res.stdout != "identical\n" || res.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
	})

	t.Run("identical json", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", "--format", "JSON", example, example)
		if res.code != 0 || res.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		doc := decodeCLIDiff(t, res.stdout)
		if !doc.Identical || len(doc.Differences) != 0 || doc.Left != example || doc.Right != example {
			t.Fatalf("json = %#v", doc)
		}
	})

	t.Run("negative serial", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", negative, negative)
		if res.code != 0 || res.stdout != "identical\n" || res.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
	})

	t.Run("pem and der", func(t *testing.T) {
		certs, err := certutil.FromFile(example)
		if err != nil {
			t.Fatal(err)
		}
		if len(certs) != 1 {
			t.Fatalf("certs = %d", len(certs))
		}
		der := filepath.Join(home, "example.der")
		if err := os.WriteFile(der, certs[0].Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		res := runCLI(t, bin, home, "diff", "--format", "text", example, der)
		if res.code != 0 || res.stdout != "identical\n" || res.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
	})

	t.Run("differ text", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", example, local)
		if res.code != 1 || res.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if strings.Contains(res.stdout, "ERROR:") || strings.Contains(res.stdout, "identical") {
			t.Fatalf("stdout = %q", res.stdout)
		}
		for _, field := range []string{"subject:", "issuer:", "serial:", "validity:", "key:", "sans:", "sha256:", "signature_algorithm:"} {
			if !strings.Contains(res.stdout, field) {
				t.Fatalf("stdout missing %s\n%s", field, res.stdout)
			}
		}
	})

	t.Run("differ json", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", example, "--format", "json", local)
		if res.code != 1 || res.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if strings.Contains(res.stdout, "ERROR:") {
			t.Fatalf("stdout = %q", res.stdout)
		}
		doc := decodeCLIDiff(t, res.stdout)
		if doc.Identical || doc.Left != example || doc.Right != local || len(doc.Differences) == 0 {
			t.Fatalf("json = %#v", doc)
		}
		seen := map[string]bool{}
		for _, ch := range doc.Differences {
			if ch.Field == "" || ch.Left == ch.Right {
				t.Fatalf("change = %#v", ch)
			}
			seen[ch.Field] = true
		}
		if !seen["sha256"] || !seen["subject"] || !seen["signature_algorithm"] {
			t.Fatalf("fields = %#v", seen)
		}
	})

	t.Run("many certificates", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", filepath.Join("testdata", "lots.crt"), example)
		if res.code != 1 || res.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if !strings.HasPrefix(res.stdout, "ERROR: ") || !strings.Contains(res.stdout, "expected one certificate") {
			t.Fatalf("stdout = %q", res.stdout)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		res := runCLI(t, bin, home, "diff", example, filepath.Join(home, "nope.pem"))
		if res.code != 1 || res.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if !strings.HasPrefix(res.stdout, "ERROR: ") || !strings.Contains(res.stdout, "does not exist") {
			t.Fatalf("stdout = %q", res.stdout)
		}
	})
}

type cliDiffJSON struct {
	Identical   bool   `json:"identical"`
	Left        string `json:"left"`
	Right       string `json:"right"`
	Differences []struct {
		Field string `json:"field"`
		Left  string `json:"left"`
		Right string `json:"right"`
	} `json:"differences"`
}

func decodeCLIDiff(t *testing.T, raw string) cliDiffJSON {
	t.Helper()
	var doc cliDiffJSON
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	return doc
}
