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
	store.SetDryRunVerbose(false)
	store.SetForceRestore(false)
	store.SetAllowlistCountOnly(false)
	store.ResetAllowlistStats()

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
	// Same slice app.Run sees, so unknown-flag text can keep the typed dashes.
	cliArgs := normalizeCLIArgs(args)
	applyOnUsageError(app, cliArgs)
	applyCommandNotFound(st, app)
	err := app.Run(context.Background(), cliArgs)

	if st.traceErr != nil {
		fmt.Fprintf(stdout, "ERROR: %v\n", st.traceErr)
		return 1
	}
	return finishRun(stdout, stderr, err)
}

// finishRun prints err and returns the process exit code.
// Usage errors (usageErr and ExitCoder with usageExitCode) go to stderr
// and exit 2. Other exit codes stay on stdout. Remaining errors go to
// stdout as "ERROR: …" and exit 1.
func finishRun(stdout, stderr io.Writer, err error) int {
	if err == nil {
		return 0
	}
	if isUsageErr(err) {
		msg := strings.TrimSpace(err.Error())
		if msg != "" && !strings.Contains(msg, "--help") {
			msg += "\n" + helpHint(nil)
		}
		writeUsageError(stderr, msg)
		return usageExitCode
	}
	var ec cli.ExitCoder
	if errors.As(err, &ec) {
		if msg := strings.TrimSpace(err.Error()); msg != "" {
			if ec.ExitCode() == usageExitCode {
				writeUsageError(stderr, msg)
			} else {
				fmt.Fprintln(stdout, msg)
			}
		}
		return ec.ExitCode()
	}
	fmt.Fprintf(stdout, "ERROR: %v\n", err)
	return 1
}

// writeUsageError prints a usage error. The first line gains an "ERROR: "
// prefix unless it already starts with "ERROR:". A following help hint
// is left unchanged.
func writeUsageError(w io.Writer, msg string) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	first, rest, hasRest := strings.Cut(msg, "\n")
	if !strings.HasPrefix(first, "ERROR:") {
		first = "ERROR: " + first
	}
	if hasRest {
		fmt.Fprintln(w, first+"\n"+rest)
		return
	}
	fmt.Fprintln(w, first)
}

func newApp(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "trustprune",
		Usage: "list, backup, allowlist, restore, and create PEM bundles from CA trust stores",
		// HideVersion skips urfave's VersionFlag, which aliases -v.
		// -v/--verbose is flagVerbose. Root --version/-V is flagVersion.
		HideVersion:                   true,
		Writer:                        st.stdout,
		ErrWriter:                     st.stderr,
		ExitErrHandler:                func(context.Context, *cli.Command, error) {},
		EnableShellCompletion:         false,
		CustomRootCommandHelpTemplate: rootHelpTemplate(),
		ArgValidator:                  rejectUnknownCommand,
		Action:                        withTrace(st, rootHelpAction),
		Flags:                         []cli.Flag{flagVersion(), flagVerbose()},
		Commands: []*cli.Command{
			addCommand(st),
			allowlistCommand(st),
			appsCommand(st),
			backupCommand(st),
			chainCommand(st),
			connectCommand(st),
			createCommand(st),
			diffCommand(st),
			genAllowlistCommand(st),
			listCommand(st),
			restoreCommand(st),
			versionCommand(st),
		},
	}
}

func rootHelpAction(_ context.Context, c *cli.Command) error {
	if c.Bool("version") {
		printVersion(c.Root().Writer)
		return nil
	}
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

// applyOnUsageError installs the usage-error handler on c and its
// subcommands. args is the slice passed to app.Run so an unknown flag
// can be echoed with the dash style the user typed.
func applyOnUsageError(c *cli.Command, args []string) {
	if c.OnUsageError == nil {
		c.OnUsageError = func(ctx context.Context, cmd *cli.Command, err error, isSubcommand bool) error {
			return onUsageError(ctx, cmd, err, isSubcommand, args)
		}
	}
	for _, sub := range c.Commands {
		applyOnUsageError(sub, args)
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

func onUsageError(_ context.Context, c *cli.Command, err error, _ bool, args []string) error {
	return usageExit(c, rewriteUsageError(err, args, c))
}

// rewriteUsageError turns urfave usage errors into trustprune's wording.
// urfave always reports "flag provided but not defined: -name" with one
// leading dash. The typed form is taken from args: the first flag token
// whose name matches (leading dashes stripped, stopping at '='), skipping
// values consumed by earlier flags that take a value. A bare "--" ends
// that search. If no token matches, the message stays "unknown flag --name".
func rewriteUsageError(err error, args []string, c *cli.Command) string {
	msg := err.Error()
	const unknownPrefix = "flag provided but not defined: "
	if strings.HasPrefix(msg, unknownPrefix) {
		name := strings.TrimLeft(strings.TrimSpace(strings.TrimPrefix(msg, unknownPrefix)), "-")
		if typed := typedFlagToken(args, name, c); typed != "" {
			return "unknown flag " + typed
		}
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

// typedFlagToken returns the first flag token in args whose name equals
// name, without a "=value" suffix, keeping that token's dash prefix.
// The scan starts after the failing subcommand's name so a root flag
// written before that name is not reported. Tokens consumed as values
// of earlier flags that take a value are skipped, including when that
// value looks like a flag. --flag=value does not consume the next
// token. A bare "--" ends the search. An empty result means no match.
func typedFlagToken(args []string, name string, c *cli.Command) string {
	if name == "" {
		return ""
	}
	args = argsAfterCommand(args, c)
	takesValue := flagsTakingValue(c)
	skipValue := false
	for _, arg := range args {
		if skipValue {
			skipValue = false
			continue
		}
		if arg == "--" {
			return ""
		}
		if len(arg) < 2 || arg[0] != '-' {
			continue
		}
		token := arg
		hasEqual := false
		if i := strings.IndexByte(token, '='); i >= 0 {
			token = token[:i]
			hasEqual = true
		}
		flagName := strings.TrimLeft(token, "-")
		if takes, ok := takesValue[flagName]; ok {
			if takes && !hasEqual {
				skipValue = true
			}
			continue
		}
		if flagName != name {
			continue
		}
		return token
	}
	return ""
}

// argsAfterCommand returns the arguments after the failing subcommand's
// name, or an alias. A root command, a missing name, or a bare "--"
// before the command leaves args unchanged.
func argsAfterCommand(args []string, c *cli.Command) []string {
	if c == nil {
		return args
	}
	names := make(map[string]struct{})
	if c.Name != "" {
		names[c.Name] = struct{}{}
	}
	for _, alias := range c.Aliases {
		if alias != "" {
			names[alias] = struct{}{}
		}
	}
	if len(names) == 0 {
		return args
	}
	for i, arg := range args {
		if arg == "--" {
			return args
		}
		if _, ok := names[arg]; ok {
			return args[i+1:]
		}
	}
	return args
}

// flagsTakingValue maps flag names (no leading dashes) to whether that
// flag consumes the next argument. The map includes c's flags and
// persistent flags from its ancestors. Local flags on a parent are omitted.
func flagsTakingValue(c *cli.Command) map[string]bool {
	takes := make(map[string]bool)
	if c == nil {
		return takes
	}
	for i, cmd := range c.Lineage() {
		addFlagsTakingValue(takes, cmd.Flags, i > 0)
		for _, grp := range cmd.MutuallyExclusiveFlags {
			for _, fs := range grp.Flags {
				addFlagsTakingValue(takes, fs, i > 0)
			}
		}
	}
	return takes
}

func addFlagsTakingValue(takes map[string]bool, flags []cli.Flag, skipLocal bool) {
	for _, f := range flags {
		if skipLocal {
			if lf, ok := f.(cli.LocalFlag); ok && lf.IsLocal() {
				continue
			}
		}
		tv := false
		if df, ok := f.(cli.DocGenerationFlag); ok {
			tv = df.TakesValue()
		}
		for _, name := range f.Names() {
			takes[name] = tv
		}
	}
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

func diffArgValidator(_ context.Context, c *cli.Command) error {
	if _, err := cmd.NormalizeDiffFormat(c.String("format")); err != nil {
		return usageExit(c, err.Error())
	}
	args := c.Args().Slice()
	switch len(args) {
	case 2:
		return nil
	case 0, 1:
		return usageExit(c, "expected two certificate files")
	default:
		return usageExit(c, fmt.Sprintf("unexpected argument(s): %s", strings.Join(args[2:], " ")))
	}
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

func chainArgValidator(_ context.Context, c *cli.Command) error {
	if _, err := parseChainTarget(flagString(c, "file"), flagString(c, "url"), c.Args().Slice()); err != nil {
		return usageExit(c, err.Error())
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
	return fmt.Sprintf(`Usage: trustprune <command> [flags]
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
		store.FormatAppsHelpLine(),
	)
}

func listConfig(c *cli.Command) *ui.Config {
	return &ui.Config{
		Count:         c.Bool("count"),
		Format:        strings.ToLower(c.String("format")),
		Outfile:       c.String("out"),
		UI:            c.String("ui"),
		Verbose:       isVerbose(c),
		AllowlistPath: flagString(c, "allowlist"),
	}
}

func applyDryRun(c *cli.Command) {
	store.SetDryRun(c.Bool("dry-run"))
	// Allowlist is the only command that turns verbose dry-run details on.
	// Clear it here so add, backup, and restore cannot inherit a previous
	// in-process allowlist -v.
	store.SetDryRunVerbose(false)
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

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "%s\n", getVersion())
}

// chainTarget is the certificate file and raw URL for chain.
// A positional argument fills exactly one of them.
type chainTarget struct {
	file string
	url  string
}

// parseChainTarget resolves --file, --url, and at most one positional
// argument. A positional path that names an existing regular file is the
// file. Any other positional value is the URL, normalized later the same
// way connect normalizes a bare host. Combining a positional argument with
// --file or --url is a usage error. More than one positional is a usage error.
func parseChainTarget(fileFlag, urlFlag string, positional []string) (chainTarget, error) {
	fileFlag = strings.TrimSpace(fileFlag)
	urlFlag = strings.TrimSpace(urlFlag)

	var pos string
	switch len(positional) {
	case 0:
	case 1:
		pos = strings.TrimSpace(positional[0])
	default:
		return chainTarget{}, errUsage(fmt.Sprintf("unexpected argument(s): %s", strings.Join(positional, " ")))
	}
	if pos != "" && (fileFlag != "" || urlFlag != "") {
		return chainTarget{}, errUsage("provide either --file, --url, or one positional argument, not both")
	}
	if pos == "" {
		return chainTarget{file: fileFlag, url: urlFlag}, nil
	}
	if chainPositionalFile(pos) {
		return chainTarget{file: pos}, nil
	}
	return chainTarget{url: pos}, nil
}

// chainPositionalFile reports whether path is an existing regular file.
// A directory, a device, or a missing path is not, so that positional
// argument is taken as a URL. Stat follows symlinks.
func chainPositionalFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
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
	return cmd.NormalizeConnectURL(raw)
}

// differExit is the diff command's "fields differ" status.
// The report is already on stdout. An empty message keeps finishRun from
// adding an ERROR: line. Exit code 1 matches other failures; a difference
// is told apart from a read error by the absence of ERROR:.
type differExit struct{}

func (differExit) Error() string { return "" }
func (differExit) ExitCode() int { return 1 }

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
