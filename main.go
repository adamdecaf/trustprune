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
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/cmd"
	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/adamdecaf/trustprune/pkg/ui"
)

const Version = "0.1.1-dev"

var (
	fs = flag.NewFlagSet("flags", flag.ExitOnError)

	// incantations of "--help"
	flagHelp1 = fs.Bool("h", false, "")
	flagHelp2 = fs.Bool("help", false, "")

	// -file is used to specify an input file path
	flagFile = fs.String("file", "", "")

	// -url is used to specify an input URL
	flagURL = fs.String("url", "", "")

	// -app is used for operating on an installed application
	flagApp = fs.String("app", "", "")

	// -ui is used for choosing a different ui
	flagUI = fs.String("ui", ui.DefaultUI(), "")

	// -from is used by 'gen-allowlist' to specify url sources
	flagFrom = fs.String("from", "", "")

	// -out is used by 'gen-allowlist' to specify output file location
	flagOutFile = fs.String("out", "", "")

	// Output
	flagCount   = fs.Bool("count", false, "")
	flagFormat  = fs.String("format", ui.DefaultFormat(), "")
	flagVerbose = fs.Bool("v", false, "")

	// -dry-run previews mutating commands without writing to stores
	flagDryRun = fs.Bool("dry-run", false, "")

	// internal override to show help text
	callForHelp = false
)

func init() {
	fs.Usage = func() {
		fmt.Printf(`Usage of trustprune version %s
SUB-COMMANDS
  add           Add certificate(s) to a store

  allowlist     Remove trust from certificates which do not match the allowlist in <path>

  apps          List supported apps and whether each store was found

  backup        Take a backup of the specified certificate store

  connect       Attempt to load a remote URL with the platform (or app) store

  gen-allowlist Create an allowlist from various sources

  list          List the currently installed and trusted certificates

  restore       Revert the certificate trust back to, optionally takes -file <path>

  version       Show the version of trustprune

APPS
  Supported apps: %s

FLAGS
  -app <name>      The name of an application which to perform the given command on.
  -dry-run         Preview add/backup/restore/allowlist changes without writing to stores
  -file <path>     Local file path
  -from <type(s)>  Which sources to capture urls from. Comma separated list. (Options: browser, browsers, chrome, firefox, safari, file)
  -help            Show this help dialog
  -out <path>      Output file path, used by gen-allowlist
  -ui <type>       Method of adjusting certificates to be removed/untrusted. (default: %s, options: %s)
  -url <where>     Remote URL to download and use in a command

OUTPUT
  -count  Output the count of certificates instead of each certificate
  -format <format> Change the output format for a given command (default: %s, options: %s)
  -v      Show full fingerprints, serials, and paths in table output

DEBUGGING
  Alongside command line flags are two environment variables read by trustprune:
  - DEBUG=1        Enables debug logging, GODEBUG=x509roots=1 also works and enables Go's debugging
  - TRACE=<where>  Saves a binary trace file at <where> of the execution
`,
			getVersion(),
			store.FormatAppsHelpLine(),
			ui.DefaultUI(),
			strings.Join(ui.GetUIs(), ", "),
			ui.DefaultFormat(),
			strings.Join(ui.GetFormats(), ", "),
		)
	}
}

func calledHelp() bool {
	return callForHelp || *flagHelp1 || *flagHelp2
}

type command struct {
	fn    func() error
	appfn func(string) error

	help string
}

func trace() *cmd.Trace {
	trace, err := cmd.NewTrace(os.Getenv("TRACE"))
	if err != nil {
		fmt.Printf("ERROR: setting up tracing: %v", err)
		os.Exit(1)
	}
	err = trace.Start()
	if err != nil {
		fmt.Printf("ERROR: starting trace: %v", err)
		os.Exit(1)
	}
	return trace
}

func main() {
	maybePrintCertManageAliasNotice(os.Args[0])
	t := trace()
	defer func() {
		err := t.Stop()
		if err != nil {
			fmt.Printf("ERROR: stopping trace: %v", err)
			os.Exit(1)
		}
	}()

	// Just show help if there aren't enough arguments to do anything
	if len(os.Args) < 2 {
		fs.Usage()
		return
	}
	_ = fs.Parse(os.Args[1:])
	if len(os.Args) == 2 && calledHelp() {
		fs.Usage()
		return
	}
	_ = fs.Parse(os.Args[2:]) // reparse

	// Lift config options into a higher-level
	cfg := &ui.Config{
		Count:   *flagCount,
		Format:  *flagFormat,
		Outfile: *flagOutFile,
		UI:      *flagUI,
		Verbose: *flagVerbose,
	}
	store.SetDryRun(*flagDryRun)

	// Build up sub-commands
	commands := make(map[string]*command)
	commands["add"] = &command{
		fn: func() error {
			if *flagFile == "" {
				callForHelp = true
				return nil
			}
			return cmd.AddCertsFromFile(*flagFile)
		},
		appfn: func(a string) error {
			if *flagFile == "" {
				callForHelp = true
				return nil
			}
			return cmd.AddCertsToAppFromFile(a, *flagFile)
		},
		help: fmt.Sprintf(`Usage: trustprune add -file <path> [-app <name>] [-dry-run]

  Add a certificate to the platform store
    trustprune add -file <path>

  Add a certificate to an application's store
    trustprune add -file <path> -app <name>

APPS
  Supported apps: %s`, store.FormatAppsHelpLine()),
	}
	commands["apps"] = &command{
		fn: func() error {
			return cmd.ListApps(*flagFormat)
		},
		appfn: func(a string) error {
			return fmt.Errorf("apps does not accept -app; remove -app %q and run: trustprune apps", a)
		},
		help: `Usage: trustprune apps [-format json]

  List every supported application store plus the platform store, and show
  whether each was found on this machine along with its store path.

  Detection is read-only and never modifies certificate stores.

  Default output is one aligned line per store:
    chrome    found      /home/you/.pki/nssdb
    firefox   not-found  -
    platform  found      /etc/ssl/certs/ca-certificates.crt

  JSON output:
    trustprune apps -format json
`,
	}
	commands["backup"] = &command{
		fn: func() error {
			return cmd.BackupForPlatform()
		},
		appfn: func(a string) error {
			return cmd.BackupForApp(a)
		},
		help: fmt.Sprintf(`Usage: trustprune backup [-app <name>] [-dry-run]

  Backup a certificate store. This can be done for the platform or a given app.

APPS
  Supported apps: %s`, store.FormatAppsHelpLine()),
	}
	commands["connect"] = &command{
		fn: func() error {
			u, err := parseConnectUrl(fs)
			if err != nil {
				return err
			}
			return cmd.ConnectWithPlatformStore(u)
		},
		appfn: func(a string) error {
			u, err := parseConnectUrl(fs)
			if err != nil {
				return err
			}
			return cmd.ConnectWithAppStore(u, *flagApp)
		},
		help: fmt.Sprintf(`Usage: trustprune connect [-app <name>] (-url <url> | <url>)

Attempt an HTTP connect to a URL with the given certificate store. Pass the URL as
-url <url> or as a positional argument. If -app is provided then the certificates for
that application are loaded and used for the connection.

APPS
  Supported apps: %s`, store.FormatAppsHelpLine()),
	}
	genAllowlistCmd := &command{
		fn: func() error {
			if *flagOutFile == "" || (*flagFrom == "" && *flagFile == "") {
				callForHelp = true
				return nil
			}
			return cmd.GenerateAllowlist(*flagOutFile, *flagFrom, *flagFile)
		},
		help: fmt.Sprintf(`Usage: trustprune gen-allowlist -out <where> [-file <file>] [-from <type>]

  Generate an allowlist and write it to the filesystem. (At wherever -out points to.)
  The -out extension chooses the format: .json writes JSON; .yaml or .yml writes YAML.

  Also, you can pass -file to read newline-delimited https URLs, or a Tranco-style
  rank,domain CSV (https:// is prefixed onto each domain). Gzip files are accepted.
    trustprune gen-allowlist -file <path> -out allowlist.yaml

  Generate an allowlist from browser history
    trustprune gen-allowlist -from firefox -out allowlist.json

  Generate an allowlist from all browsers on a computer
    trustprune gen-allowlist -from browsers -out allowlist.yaml

APPS
  Supported apps: %s`, store.FormatAppsHelpLine()),
	}
	commands["gen-allowlist"] = genAllowlistCmd
	commands["gen-whitelist"] = genAllowlistCmd // hidden alias
	commands["list"] = &command{
		fn: func() error {
			if *flagFile != "" {
				return cmd.ListCertsFromFile(*flagFile, cfg)
			}
			if *flagURL != "" {
				return cmd.ListCertsFromURL(*flagURL, cfg)
			}
			return cmd.ListCertsForPlatform(cfg)
		},
		appfn: func(a string) error {
			return cmd.ListCertsForApp(a, cfg)
		},
		help: fmt.Sprintf(`Usage: trustprune list [options]

  List certificates currently installed on the platform or application.

  List certificates from an application
    trustprune list -app firefox

  List certificates from a file
    trustprune list -file <path>

  List certificates from a URL
    trustprune list -url <endpoint>

FORMATTING

  Change the output format (Default: %s, Options: %s)
    trustprune list -format openssl
    trustprune list -format json
    trustprune list -format table

  Table output adds KEY and DAYS by default; -v adds full fingerprint, serial, and path
    trustprune list -format table -v

  Only show the count of certificates found
    trustprune list -count
    trustprune list -app java -count
    trustprune list -file <path> -count

  Show the certificates on a local webpage (Default: %s, Options: %s)
    trustprune list -ui web

APPS
  Supported apps: %s`,
			ui.DefaultFormat(),
			strings.Join(ui.GetFormats(), ", "),
			ui.DefaultUI(),
			strings.Join(ui.GetUIs(), ", "),
			store.FormatAppsHelpLine()),
	}
	commands["restore"] = &command{
		fn: func() error {
			return cmd.RestoreForPlatform(*flagFile)
		},
		appfn: func(a string) error {
			return cmd.RestoreForApp(a, *flagFile)
		},
		help: fmt.Sprintf(`Usage: trustprune restore [-app <name>] [-file <path>] [-dry-run]

  Restore certificates from the latest backup
    trustprune restore

  Restore certificates for the platform from a file
    trustprune restore -file <path>

  Restore certificates for an application from the latest backup
    trustprune restore -app java

APPS
  Supported apps: %s`, store.FormatAppsHelpLine()),
	}
	allowlistCmd := &command{
		fn: func() error {
			if *flagFile == "" {
				callForHelp = true
				return nil
			}
			return cmd.AllowlistForPlatform(*flagFile)
		},
		appfn: func(a string) error {
			if *flagFile == "" {
				callForHelp = true
				return nil
			}
			return cmd.AllowlistForApp(a, *flagFile)
		},
		help: fmt.Sprintf(`Usage: trustprune allowlist [-app <name>] -file <path> [-dry-run]

  Remove untrusted certificates from a store for the platform
    trustprune allowlist -file allowlist.json

  Remove untrusted certificates in an app
    trustprune allowlist -file allowlist.json -app java

APPS
  Supported apps: %s`, store.FormatAppsHelpLine()),
	}
	commands["allowlist"] = allowlistCmd
	commands["whitelist"] = allowlistCmd // hidden alias
	commands["version"] = &command{
		fn: func() error {
			fmt.Printf("%s\n", getVersion())
			return nil
		},
		appfn: func(_ string) error {
			return nil
		},
		help: getVersion(),
	}

	// Run whatever function we've got here..
	c, ok := commands[strings.ToLower(os.Args[1])]
	if (!ok && calledHelp()) || c == nil { // sub-command wasn't found
		fs.Usage()
		os.Exit(1)
	}
	if ok && calledHelp() {
		fmt.Println(c.help)
		os.Exit(1)
	}

	// sub-command found, try and exec something off it
	if flagApp != nil && *flagApp != "" {
		err := c.appfn(*flagApp)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	err := c.fn()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}

	// some flags can set callForHelp, so let's check again
	if calledHelp() {
		fmt.Println(c.help)
		os.Exit(1)
	}
}

// certManageAliasNotice is printed when the binary is invoked as cert-manage.
// The cert-manage name remains a supported alias through the 0.2.x line.
const certManageAliasNotice = "note: cert-manage was renamed to trustprune; the cert-manage command remains an alias through 0.2.x\n"

func maybePrintCertManageAliasNotice(arg0 string) {
	if !certManageAliasActive(Version) {
		return
	}
	if !invokedAsCertManage(arg0) {
		return
	}
	fmt.Fprint(os.Stderr, certManageAliasNotice)
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

func parseConnectUrl(fs *flag.FlagSet) (*url.URL, error) {
	raw := ""
	if flagURL != nil {
		raw = strings.TrimSpace(*flagURL)
	}

	switch fs.NArg() {
	case 0:
		// URL may come from -url only.
	case 1:
		pos := strings.TrimSpace(fs.Arg(0))
		if raw != "" && pos != "" {
			return nil, errors.New("provide either -url or a positional URL, not both")
		}
		if pos != "" {
			raw = pos
		}
	default:
		return nil, fmt.Errorf("unknown arguments: %s", strings.Join(fs.Args(), ", "))
	}

	if raw == "" {
		return nil, errors.New("no url specified")
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
