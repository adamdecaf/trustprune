package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCertManage_help(t *testing.T) {
	t.Parallel()

	usage := "Usage of trustprune version"
	subCmdUsage := func(name string) string {
		return fmt.Sprintf("Usage: trustprune %s ", name)
	}

	// no args, fs.Usage()
	out, err := run(t)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(out, usage) {
		t.Error("expected Usage() text")
	}
	if !strings.Contains(out, "  allowlist") {
		t.Error("expected allowlist in top-level SUB-COMMANDS")
	}
	if !strings.Contains(out, "  gen-allowlist") {
		t.Error("expected gen-allowlist in top-level SUB-COMMANDS")
	}
	if strings.Contains(out, "whitelist") {
		t.Error("top-level help should not list whitelist aliases")
	}
	if !strings.Contains(out, "-out <path>") {
		t.Error("expected -out in top-level FLAGS")
	}
	if !strings.Contains(out, "options: cli, web") {
		t.Errorf("expected stable -ui options order in top-level help, got snippet around -ui: %q", extractFlagLine(out, "-ui"))
	}

	// bad argument, fs.Usage()
	out, err = run(t, "bad-arg")
	if err == nil {
		t.Errorf("expected error, got nothing. output=%q", out)
	}
	if err != nil && !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(out, usage) {
		t.Error("expected Usage() text")
	}

	// no sub-command, with help flag
	helpChoices := []string{"-h", "-help", "--help"}
	for i := range helpChoices {
		out, err = run(t, helpChoices[i])
		if err != nil {
			t.Errorf("choice %q, err=%v", helpChoices[i], err)
		}
		if !strings.Contains(out, usage) {
			t.Errorf("choice %q, expected Usage()", helpChoices[i])
		}
	}

	// sub-command, but no args
	subCommands := []string{"add", "gen-allowlist", "allowlist"}
	for i := range subCommands {
		out, err := run(t, subCommands[i])
		if err != nil && !strings.Contains(err.Error(), "exit status 1") {
			t.Errorf("sub-command %q, err=%v", subCommands[i], err)
		}
		if !strings.Contains(out, subCmdUsage(subCommands[i])) {
			t.Errorf("sub-command %q, expected sub-command usage", subCommands[i])
		}
	}

	// sub-commands, with help flag
	subCommands = []string{"add", "backup", "gen-allowlist", "list", "restore", "allowlist"}
	for i := range subCommands {
		for j := range helpChoices {
			out, err := run(t, subCommands[i], helpChoices[j])
			if err != nil && !strings.Contains(err.Error(), "exit status 1") {
				t.Errorf("sub-command %q, err=%v", subCommands[i], err)
			}
			if !strings.Contains(out, subCmdUsage(subCommands[i])) {
				t.Errorf("sub-command %q, expected sub-command usage", subCommands[i])
			}
		}
	}


	out, err = run(t, "list", "-h")
	if err != nil && !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("list -h err=%v", err)
	}
	if !strings.Contains(out, "Options: cli, web") {
		t.Errorf("list help should list UI options as cli, web; got %q", extractFlagLine(out, "Options:"))
	}

	// hidden aliases still invoke the same commands and share allowlist help
	aliases := []struct {
		name string
		want string
	}{
		{"whitelist", subCmdUsage("allowlist")},
		{"gen-whitelist", subCmdUsage("gen-allowlist")},
	}
	for i := range aliases {
		out, err := run(t, aliases[i].name)
		if err != nil && !strings.Contains(err.Error(), "exit status 1") {
			t.Errorf("alias %q, err=%v", aliases[i].name, err)
		}
		if strings.Contains(out, "SUB-COMMANDS") {
			t.Errorf("alias %q fell through to top-level help", aliases[i].name)
		}
		if !strings.Contains(out, aliases[i].want) {
			t.Errorf("alias %q, expected %q in output, got %q", aliases[i].name, aliases[i].want, out)
		}
		for j := range helpChoices {
			out, err = run(t, aliases[i].name, helpChoices[j])
			if err != nil && !strings.Contains(err.Error(), "exit status 1") {
				t.Errorf("alias %q, err=%v", aliases[i].name, err)
			}
			if strings.Contains(out, "SUB-COMMANDS") {
				t.Errorf("alias %q %s fell through to top-level help", aliases[i].name, helpChoices[j])
			}
			if !strings.Contains(out, aliases[i].want) {
				t.Errorf("alias %q %s, expected %q in output", aliases[i].name, helpChoices[j], aliases[i].want)
			}
		}
	}
}


func extractFlagLine(out, flag string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, flag) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// accepts arguments to trustprune and then returns the
// stdout/stderr response and error (or nil on success)
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()

	cmd := CertManage(args...)
	return cmd.String(), cmd.Err()
}

func TestCertManage_aliasNotice(t *testing.T) {
	src := CertManage().command
	if src == "" {
		t.Fatal("no trustprune binary path for this platform")
	}
	if _, err := os.Stat(src); err != nil {
		t.Skipf("built binary missing at %s", src)
	}

	dir := t.TempDir()
	alias := filepath.Join(dir, "cert-manage")
	if runtime.GOOS == "windows" {
		alias += ".exe"
	}
	// Write via a temp path then rename so the final path is never open for
	// writing at exec time (avoids Linux ETXTBSY).
	tmp := alias + ".tmp"
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, data, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, alias); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(alias, "version")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "renamed to trustprune") {
		t.Fatalf("stderr missing rename notice: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "alias through 0.2.x") {
		t.Fatalf("stderr missing alias window: %q", stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("expected version on stdout")
	}
}
