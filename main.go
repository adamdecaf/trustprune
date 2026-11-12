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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/adamdecaf/trustprune/pkg/cmd"
	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/adamdecaf/trustprune/pkg/ui"
	"github.com/urfave/cli/v3"
)

const Version = "0.1.1-dev"

const usageExitCode = 2

// runMu serializes in-process run() calls because urfave v3's HelpPrinter
// and OsExiter are package globals. CLI tests exec a binary, so they do not
// contend; this keeps a future in-process parallel test from racing.
var runMu sync.Mutex

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

type runState struct {
	stdout       io.Writer
	stderr       io.Writer
	trace        *cmd.Trace
	traceErr     error
	traceStarted bool
}

func (s *runState) startTrace() {
	if s.traceStarted {
		return
	}
	s.traceStarted = true
	t, err := cmd.NewTrace(os.Getenv("TRACE"))
	if err != nil {
		s.traceErr = fmt.Errorf("setting up tracing: %w", err)
		return
	}
	if err := t.Start(); err != nil {
		s.traceErr = fmt.Errorf("starting trace: %w", err)
		_ = t.Stop()
		return
	}
	s.trace = t
}

func (s *runState) stopTrace() error {
	if s.trace == nil {
		return nil
	}
	err := s.trace.Stop()
	s.trace = nil
	if err != nil {
		return fmt.Errorf("stopping trace: %w", err)
	}
	return nil
}

func run(args []string, stdout, stderr io.Writer) (code int) {
	runMu.Lock()
	defer runMu.Unlock()

	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	if len(args) == 0 {
		args = []string{"trustprune"}
	}

	maybePrintCertManageAliasNotice(args[0], stderr)

	st := &runState{stdout: stdout, stderr: stderr}
	defer func() {
		if err := st.stopTrace(); err != nil {
			fmt.Fprintf(stdout, "ERROR: stopping trace: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}()

	store.SetDryRun(false)
	store.SetForceRestore(false)

	prevHelp := cli.HelpPrinter
	cli.HelpPrinter = func(w io.Writer, templ string, data any) {
		st.startTrace()
		prevHelp(w, templ, data)
	}
	prevExiter := cli.OsExiter
	cli.OsExiter = func(int) {}
	defer func() {
		cli.HelpPrinter = prevHelp
		cli.OsExiter = prevExiter
	}()

	app := newApp(st)
	applyOnUsageError(app)
	applyCommandNotFound(st, app)
	err := app.Run(context.Background(), normalizeCLIArgs(args))

	if st.traceErr != nil {
		fmt.Fprintf(stdout, "ERROR: %v\n", st.traceErr)
		return 1
	}
	if err == nil {
		return 0
	}
	if isUsageErr(err) {
		msg := strings.TrimSpace(err.Error())
		if msg != "" && !strings.Contains(msg, "--help") {
			msg = msg + "\n" + helpHint(nil)
		}
		if msg != "" {
			fmt.Fprintln(stderr, msg)
		}
		return usageExitCode
	}
	var ec cli.ExitCoder
	if errors.As(err, &ec) {
		if msg := strings.TrimSpace(err.Error()); msg != "" {
			if ec.ExitCode() == usageExitCode {
				fmt.Fprintln(stderr, msg)
			} else {
				fmt.Fprintln(stdout, msg)
			}
		}
		return ec.ExitCode()
	}
	fmt.Fprintf(stdout, "ERROR: %v\n", err)
	return 1
}

func newApp(st *runState) *cli.Command {
	return &cli.Command{
		Name:                          "trustprune",
		Usage:                         "list, backup, allowlist, and restore CA trust stores",
		HideVersion:                   true,
		Writer:                        st.stdout,
		ErrWriter:                     st.stderr,
		ExitErrHandler:                func(context.Context, *cli.Command, error) {},
		EnableShellCompletion:         false,
		CustomRootCommandHelpTemplate: rootHelpTemplate(),
		OnUsageError:                  onUsageError,
		ArgValidator:                  rejectUnknownCommand,
		Action:                        withTrace(st, rootHelpAction),
		Commands: []*cli.Command{
			addCommand(st),
			allowlistCommand(st),
			appsCommand(st),
			backupCommand(st),
			connectCommand(st),
			genAllowlistCommand(st),
			listCommand(st),
			restoreCommand(st),
			versionCommand(st),
		},
	}
}

func rootHelpAction(_ context.Context, c *cli.Command) error {
	return cli.ShowRootCommandHelp(c)
}

func withTrace(st *runState, fn cli.ActionFunc) cli.ActionFunc {
	return func(ctx context.Context, c *cli.Command) error {
		st.startTrace()
		if st.traceErr != nil {
			return st.traceErr
		}
		return fn(ctx, c)
	}
}

func applyOnUsageError(c *cli.Command) {
	if c.OnUsageError == nil {
		c.OnUsageError = onUsageError
	}
	for _, sub := range c.Commands {
		applyOnUsageError(sub)
	}
}

func applyCommandNotFound(st *runState, c *cli.Command) {
	if c.CommandNotFound == nil {
		c.CommandNotFound = func(_ context.Context, cmd *cli.Command, _ string) {
			st.startTrace()
			if cmd.Root() == cmd {
				_ = cli.ShowRootCommandHelp(cmd)
				return
			}
			_ = cli.ShowSubcommandHelp(cmd)
		}
	}
	for _, sub := range c.Commands {
		applyCommandNotFound(st, sub)
	}
}

func onUsageError(_ context.Context, c *cli.Command, err error, _ bool) error {
	return usageExit(c, rewriteUsageError(err))
}

func rewriteUsageError(err error) string {
	msg := err.Error()
	const unknownPrefix = "flag provided but not defined: "
	if strings.HasPrefix(msg, unknownPrefix) {
		name := strings.TrimLeft(strings.TrimSpace(strings.TrimPrefix(msg, unknownPrefix)), "-")
		return "unknown flag --" + name
	}
	const reqOne = `Required flag "`
	if strings.HasPrefix(msg, reqOne) {
		rest := strings.TrimPrefix(msg, reqOne)
		name, _, ok := strings.Cut(rest, `"`)
		if ok {
			return "required flag --" + name + " not set"
		}
	}
	return msg
}

func usageExit(c *cli.Command, msg string) error {
	return cli.Exit(msg+"\n"+helpHint(c), usageExitCode)
}

func helpHint(c *cli.Command) string {
	name := "trustprune"
	if c != nil {
		if full := strings.TrimSpace(c.FullName()); full != "" && full != "trustprune" {
			name = full
		}
	}
	return "run '" + name + " --help' for usage"
}

func rejectUnknownCommand(_ context.Context, c *cli.Command) error {
	args := c.Args().Slice()
	if len(args) == 0 {
		return nil
	}
	return usageExit(c, fmt.Sprintf("unknown command %q", args[0]))
}

func rejectPositionalArgs(_ context.Context, c *cli.Command) error {
	args := c.Args().Slice()
	if len(args) == 0 {
		return nil
	}
	return usageExit(c, fmt.Sprintf("unexpected argument(s): %s", strings.Join(args, " ")))
}

func connectArgValidator(_ context.Context, c *cli.Command) error {
	args := c.Args().Slice()
	if len(args) > 1 {
		return usageExit(c, fmt.Sprintf("unexpected argument(s): %s", strings.Join(args, " ")))
	}
	flagURL := strings.TrimSpace(c.String("url"))
	if flagURL != "" && len(args) == 1 && strings.TrimSpace(args[0]) != "" {
		return usageExit(c, "provide either --url or a positional URL, not both")
	}
	return nil
}

// normalizeCLIArgs lowercases the first non-flag argument so LIST matches list.
func normalizeCLIArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i := 1; i < len(out); i++ {
		a := out[i]
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		out[i] = strings.ToLower(a)
		break
	}
	return out
}

func rootHelpTemplate() string {
	return fmt.Sprintf(`Usage of trustprune version %s
COMMANDS:{{template "visibleCommandCategoryTemplate" .}}

APPS
  Supported apps: %s

Run 'trustprune <command> --help' for that command's flags.

DEBUGGING
  Alongside command line flags, trustprune reads these environment variables:
  - DEBUG=1        Enables debug logging, GODEBUG=x509roots=1 also works and enables Go's debugging
  - TRACE=<where>  Saves a binary trace file at <where> of the execution
  - TRUSTPRUNE_JAVA_STOREPASS  Java keystore password for --app java (see docs/usage.md#environment)
{{if .VisibleFlags}}
OPTIONS:{{template "visibleFlagTemplate" .}}{{end}}
`,
		getVersion(),
		store.FormatAppsHelpLine(),
	)
}

func listConfig(c *cli.Command) *ui.Config {
	return &ui.Config{
		Count:   c.Bool("count"),
		Format:  strings.ToLower(c.String("format")),
		Outfile: c.String("out"),
		UI:      c.String("ui"),
		Verbose: c.Bool("v"),
	}
}

func applyDryRun(c *cli.Command) {
	store.SetDryRun(c.Bool("dry-run"))
}

func flagString(c *cli.Command, name string) string {
	return strings.TrimSpace(c.String(name))
}

// certManageAliasNotice is printed when the binary is invoked as cert-manage.
// The cert-manage name remains a supported alias through the 0.2.x line.
const certManageAliasNotice = "note: cert-manage was renamed to trustprune; the cert-manage command remains an alias through 0.2.x\n"

func maybePrintCertManageAliasNotice(arg0 string, stderr io.Writer) {
	if !certManageAliasActive(Version) {
		return
	}
	if !invokedAsCertManage(arg0) {
		return
	}
	fmt.Fprint(stderr, certManageAliasNotice)
}

func invokedAsCertManage(arg0 string) bool {
	base := filepath.Base(arg0)
	base = strings.TrimSuffix(base, ".exe")
	return base == "cert-manage" || strings.HasPrefix(base, "cert-manage-")
}

// certManageAliasActive reports whether the cert-manage argv alias still prints
// a rename notice. Kept through the 0.2.x release line (inclusive).
func certManageAliasActive(version string) bool {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if v == "" {
		return false
	}
	// Take major.minor from versions like 0.2.0 or 0.1.1-dev.
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, minor := parts[0], parts[1]
	// Strip pre-release from minor if someone put it there; normally patch has -dev.
	if i := strings.IndexAny(minor, "-+"); i >= 0 {
		minor = minor[:i]
	}
	if major != "0" {
		return false
	}
	return minor == "0" || minor == "1" || minor == "2"
}

func getVersion() string {
	return fmt.Sprintf("%s (Go: %s)", Version, runtime.Version())
}

func parseConnectURL(flagURL string, positional []string) (*url.URL, error) {
	raw := strings.TrimSpace(flagURL)

	switch len(positional) {
	case 0:
		// URL may come from --url only.
	case 1:
		pos := strings.TrimSpace(positional[0])
		if raw != "" && pos != "" {
			return nil, errUsage("provide either --url or a positional URL, not both")
		}
		if pos != "" {
			raw = pos
		}
	default:
		return nil, errUsage(fmt.Sprintf("unexpected argument(s): %s", strings.Join(positional, " ")))
	}

	if raw == "" {
		return nil, errUsage("no url specified")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", raw, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("non-secure url scheme used: %s", u.String())
	}
	return u, nil
}

type usageErr struct {
	msg string
}

func (e usageErr) Error() string { return e.msg }

func (e usageErr) ExitCode() int { return usageExitCode }

func errUsage(msg string) error {
	return usageErr{msg: msg}
}

func isUsageErr(err error) bool {
	var u usageErr
	return errors.As(err, &u)
}
