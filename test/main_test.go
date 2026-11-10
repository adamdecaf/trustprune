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
		return fmt.Sprintf("trustprune %s ", name)
	}

	// no args: accepted help, exit 0
	out, err := run(t)
	if err != nil {
		t.Errorf("expected exit 0 with no sub-command, got err=%v output=%q", err, out)
	}
	if strings.Contains(out, "\n\n  ") {
		t.Error("expected no blank lines between SUB-COMMANDS entries")
	}
	if !strings.Contains(out, "Restore certificate trust from a backup") {
		t.Error("expected fixed restore description")
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
	if !strings.Contains(out, "COMMANDS") {
		t.Error("expected COMMANDS in top-level help")
	}
	if !strings.Contains(out, "APPS") {
		t.Error("expected APPS in top-level help")
	}
	if !strings.Contains(out, "DEBUGGING") {
		t.Error("expected DEBUGGING in top-level help")
	}
	if !strings.Contains(out, "TRUSTPRUNE_JAVA_STOREPASS") {
		t.Error("expected TRUSTPRUNE_JAVA_STOREPASS in top-level help")
	}
	if !strings.Contains(out, "Run 'trustprune <command> --help' for that command's flags.") {
		t.Error("expected per-command flags hint in top-level help")
	}
	if strings.Contains(out, "\nFLAGS") || strings.Contains(out, "\nOUTPUT") {
		t.Error("top-level help should not list FLAGS/OUTPUT")
	}

	// unknown command is a usage error (exit 2), not full help
	out, err = run(t, "bad-arg")
	if err == nil || !strings.Contains(err.Error(), "exit status 2") {
		t.Errorf("expected exit status 2 for unknown command, got err=%v output=%q", err, out)
	}
	if !strings.Contains(out, `unknown command "bad-arg"`) {
		t.Errorf("expected unknown command message, got %q", out)
	}

	// unknown subcommand with help still prints usage, and exits 0
	out, err = run(t, "bad-arg", "-h")
	if err != nil {
		t.Errorf("bad-arg -h should exit 0, err=%v output=%q", err, out)
	}
	if !strings.Contains(out, usage) {
		t.Error("bad-arg -h expected Usage() text")
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

	// sub-command, but no args. Missing required --file is a usage error (exit 2).
	subCommands := []string{"add", "allowlist"}
	for i := range subCommands {
		out, err := run(t, subCommands[i])
		if err == nil || !strings.Contains(err.Error(), "exit status 2") {
			t.Errorf("sub-command %q, expected exit 2, err=%v output=%q", subCommands[i], err, out)
		}
		if !strings.Contains(out, "required flag --file not set") {
			t.Errorf("sub-command %q, expected required --file error, got %q", subCommands[i], out)
		}
	}

	// sub-commands, with help flag
	subCommands = []string{"add", "backup", "gen-allowlist", "list", "restore", "allowlist"}
	for i := range subCommands {
		for j := range helpChoices {
			out, err := run(t, subCommands[i], helpChoices[j])
			if err != nil {
				t.Errorf("sub-command %q %s, err=%v", subCommands[i], helpChoices[j], err)
			}
			if !strings.Contains(out, subCmdUsage(subCommands[i])) {
				t.Errorf("sub-command %q, expected sub-command usage", subCommands[i])
			}
		}
	}

	out, err = run(t, "list", "-app", "nope")
	if err == nil {
		t.Error("expected list -app nope to fail")
	}
	if !strings.Contains(out, "ERROR: unknown app nope (apps:") || !strings.Contains(out, "java") {
		t.Errorf("expected ERROR: unknown app with apps list, got %q", out)
	}

	// --store with the platform OS name is a usage error (exit 2) before listing.
	out, err = run(t, "list", "-app", runtime.GOOS, "-store", filepath.Join(t.TempDir(), "nope"))
	if err == nil || !strings.Contains(err.Error(), "exit status 2") || !strings.Contains(out, "--store with --app "+runtime.GOOS) || strings.Contains(out, "unknown app") || strings.Contains(out, "ERROR:") {
		t.Errorf("list -app %s -store err=%v output=%q", runtime.GOOS, err, out)
	}
	out, _ = run(t, "list", "-h")
	if !strings.Contains(out, "-out ") {
		t.Error("expected -out documented in list help")
	}

	out, err = run(t, "list", "-h")
	if err != nil {
		t.Errorf("list -h err=%v", err)
	}
	if !strings.Contains(out, "Options: cli, web") {
		t.Errorf("list help should list UI options as cli, web; got %q", extractFlagLine(out, "Options:"))
	}
	if strings.Contains(out, "used by -format observatory") {
		t.Error("list help still limits -out to -format observatory")
	}
	if !strings.Contains(out, "every --format") {
		t.Errorf("list help should document -out for every format, got %q", out)
	}

	out, err = run(t, "whitelist")
	if err == nil || !strings.Contains(err.Error(), "exit status 2") {
		t.Errorf("expected exit status 2 for whitelist, got err=%v output=%q", err, out)
	}
	if !strings.Contains(out, `unknown command "whitelist"`) {
		t.Errorf("expected unknown command message for whitelist, got %q", out)
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
	bin := CertManage()
	if bin == nil || bin.command == "" {
		t.Fatal("no trustprune binary path for this platform")
	}
	src := bin.command
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

func TestCertManage_genAllowlistNoFlags(t *testing.T) {
	out, err := run(t, "gen-allowlist")
	if err == nil || !strings.Contains(err.Error(), "exit status 2") {
		t.Fatalf("expected exit status 2, got err=%v output=%q", err, out)
	}
	if !strings.Contains(out, "required flag --out not set") {
		t.Errorf("expected --out error, got %q", out)
	}
	if strings.Contains(out, "Usage: trustprune gen-allowlist") {
		t.Errorf("expected no usage text, got %q", out)
	}
}
