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
	"context"
	"fmt"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/allowlist/preset"
	"github.com/adamdecaf/trustprune/pkg/cmd"
	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/adamdecaf/trustprune/pkg/ui"
	"github.com/urfave/cli/v3"
)

func addCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "add",
		Usage: "Add certificate(s) to a store",
		UsageText: `trustprune add --file <path> [--app <name>] [--store <path>] [--dry-run]

  Add a certificate to the platform store
    trustprune add --file <path>

  Add a certificate to an application's store
    trustprune add --file <path> --app <name>

  Add a certificate to a specific certifi bundle or Java keystore.
  --file is the certificate to import. --store is the trust store.
    trustprune add --file <path> --app certifi --store /path/to/cacert.pem
    trustprune add --file <path> --app java --store /path/to/cacerts

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagFile("certificate file to import", true),
			flagApp(),
			flagStore(),
			flagDryRun(),
		},
		ArgValidator: rejectPositionalArgs,
		Before:       addBefore,
		Action:       withTrace(st, addAction),
	}
}

func addBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	return ctx, rejectIncompatibleStore(c)
}

func addAction(_ context.Context, c *cli.Command) error {
	applyDryRun(c)
	file := flagString(c, "file")
	app := flagString(c, "app")
	path := storePath(c)
	if app == "" {
		return cmd.AddCertsFromFile(file)
	}
	if path != "" {
		return cmd.AddCertsToAppFromStore(app, path, file)
	}
	return cmd.AddCertsToAppFromFile(app, file)
}

func allowlistCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "allowlist",
		Usage: "Remove trust from certificates which do not match the allowlist in <path>",
		UsageText: `trustprune allowlist --file <path> [--app <name>] [--store <path>] [--bundle <pem>] [--dry-run]

  Remove untrusted certificates from a store for the platform
    trustprune allowlist --file allowlist.json

  Remove untrusted certificates in an app
    trustprune allowlist --file allowlist.json --app java

  --file is the allowlist. --store overrides the java or certifi store path.
    trustprune allowlist --file allowlist.yaml --app certifi --store /path/to/cacert.pem
    trustprune allowlist --file allowlist.yaml --app java --store /path/to/cacerts

  Remove untrusted certificates in an explicit OpenSSL PEM CA bundle
    trustprune allowlist --app openssl --file allowlist.json --bundle /path/to/ca-bundle.pem

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagFile("allowlist file", true),
			flagApp(),
			flagStore(),
			flagBundle(),
			flagDryRun(),
		},
		ArgValidator: rejectPositionalArgs,
		Before:       allowlistBefore,
		Action:       withTrace(st, allowlistAction),
	}
}

func allowlistBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	if err := checkBundleFlag(c); err != nil {
		return ctx, err
	}
	if err := rejectStoreWithBundle(c, "allowlist: --bundle names the openssl PEM; --store is only for java/certifi"); err != nil {
		return ctx, err
	}
	return ctx, rejectIncompatibleStore(c)
}

func allowlistAction(_ context.Context, c *cli.Command) error {
	applyDryRun(c)
	file := flagString(c, "file")
	app := flagString(c, "app")
	bundle := flagString(c, "bundle")
	path := storePath(c)
	if app == "" {
		return cmd.AllowlistForPlatform(file)
	}
	if bundle != "" {
		return cmd.AllowlistForBundle(app, file, bundle)
	}
	if path != "" {
		return cmd.AllowlistForAppWithStore(app, path, file)
	}
	return cmd.AllowlistForApp(app, file)
}

func appsCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "apps",
		Usage: "List supported apps and whether each store was found",
		UsageText: `trustprune apps [--format json]

  List every supported application store plus the system store (named for the
  OS: linux, darwin, or windows — matching backup paths under ~/.trustprune/<os>/,
  or ~/Library/trustprune/<os>/ on Darwin), and show whether each was found on
  this machine along with its store path.

  Detection is read-only and never modifies certificate stores.

  Default output is a header row then one aligned line per store:
    APP       STATUS     PATH
    chrome    found      /home/you/.pki/nssdb
    firefox   not-found  -
    linux     found      /etc/ssl/certs/ca-certificates.crt

  JSON output (same fields; the system store name is the OS name, not "platform"):
    trustprune apps --format json
`,
		Flags: []cli.Flag{
			flagFormat(),
		},
		ArgValidator: rejectPositionalArgs,
		Action:       withTrace(st, appsAction),
	}
}

func appsAction(_ context.Context, c *cli.Command) error {
	return cmd.ListApps(c.String("format"))
}

func backupCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "backup",
		Usage: "Take a backup of the specified certificate store",
		UsageText: `trustprune backup [--app <name>] [--store <path>] [--bundle <pem>] [--dry-run]

  Backup a certificate store. This can be done for the platform or a given app.

  Java: --store <cacerts> overrides trust-store search and backs up that keystore.
  Certifi: --store <cacert.pem> overrides discovery and backs up that bundle.
  OpenSSL: --bundle <ca-bundle.pem> backs up that PEM file instead of discovery.
    trustprune backup --app openssl --bundle /path/to/ca-bundle.pem

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagApp(),
			flagStore(),
			flagBundle(),
			flagDryRun(),
		},
		ArgValidator: rejectPositionalArgs,
		Before:       backupBefore,
		Action:       withTrace(st, backupAction),
	}
}

func backupBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	if err := checkBundleFlag(c); err != nil {
		return ctx, err
	}
	if err := rejectStoreWithBundle(c, "backup: --bundle names the openssl PEM; do not pass --store with --bundle"); err != nil {
		return ctx, err
	}
	return ctx, rejectIncompatibleStore(c)
}

func backupAction(_ context.Context, c *cli.Command) error {
	applyDryRun(c)
	app := flagString(c, "app")
	bundle := flagString(c, "bundle")
	path := storePath(c)
	if app == "" {
		return cmd.BackupForPlatform()
	}
	if bundle != "" {
		return cmd.BackupForBundle(bundle)
	}
	if path != "" {
		return cmd.BackupForAppWithFile(app, path)
	}
	return cmd.BackupForApp(app)
}

func connectCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "connect",
		Usage: "Attempt to load a remote URL with the platform (or app) store",
		UsageText: `trustprune connect [--app <name>] [--store <path>] (--url <url> | <url>)

Attempt an HTTP connect to a URL with the given certificate store. Pass the URL as
--url <url> or as a positional argument. If --app is provided then the certificates for
that application are loaded and used for the connection.

  --store <path> overrides discovery for --app java (cacerts) and --app certifi (cacert.pem).

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagApp(),
			flagStore(),
			flagURL("remote URL to connect to (instead of a positional URL)"),
		},
		ArgValidator: connectArgValidator,
		Before:       connectBefore,
		Action:       withTrace(st, connectAction),
	}
}

func connectBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	return ctx, rejectIncompatibleStore(c)
}

func connectAction(_ context.Context, c *cli.Command) error {
	app := flagString(c, "app")
	path := storePath(c)
	u, err := parseConnectURL(c.String("url"), c.Args().Slice())
	if err != nil {
		if isUsageErr(err) {
			return usageExit(c, err.Error())
		}
		return err
	}
	if app == "" {
		return cmd.ConnectWithPlatformStore(u)
	}
	if path != "" {
		return cmd.ConnectWithAppStoreFile(u, app, path)
	}
	return cmd.ConnectWithAppStore(u, app)
}

func genAllowlistCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "gen-allowlist",
		Usage: "Create an allowlist from various sources",
		UsageText: `trustprune gen-allowlist --out <where> [--hosts <hosts>] [--presets <names>] [--no-presets] [--file <file>] [--from <type>]

  Generate an allowlist and write it to the filesystem. (At wherever --out points to.)
  The --out extension chooses the format: .json writes JSON; .yaml or .yml writes YAML.

  Platform presets (macOS Apple/update hosts, Linux apt repos, Windows update hosts)
  are included by default when generation runs. Use --presets to target another OS,
  or --no-presets to skip them.

  Build an allowlist for a few hostnames (typical small server / PEM bundle)
    trustprune gen-allowlist --out allowlist.yaml --hosts example.com,api.example.com

  Include a Linux allowlist on another OS
    trustprune gen-allowlist --out allowlist.yaml --hosts example.com --presets linux
    trustprune gen-allowlist --out allowlist.yaml --presets linux

  Generate an allowlist from browser history
    trustprune gen-allowlist --out allowlist.yaml --from firefox

  Hosts only, without the default platform preset
    trustprune gen-allowlist --out allowlist.yaml --hosts example.com --no-presets

  Also, you can pass --file to read newline-delimited https URLs, or a Tranco-style
  rank,domain CSV (https:// is prefixed onto each domain). Gzip files are accepted.
    trustprune gen-allowlist --file <path> --out allowlist.yaml

  Generate an allowlist from all browsers on a computer
    trustprune gen-allowlist --from browsers --out allowlist.yaml

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagOut("where to write the allowlist (.json, .yaml, or .yml)", true),
			flagHosts(),
			flagPresets(),
			flagNoPresets(),
			flagFile("newline-delimited https URLs or a Tranco-style rank,domain CSV", false),
			flagFrom(),
		},
		ArgValidator: rejectPositionalArgs,
		Before:       genAllowlistBefore,
		Action:       withTrace(st, genAllowlistAction),
	}
}

func genAllowlistBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	if c.IsSet("presets") && c.Bool("no-presets") {
		return ctx, usageExit(c, "--presets and --no-presets cannot be used together")
	}
	if c.IsSet("hosts") {
		if _, err := preset.ParseHosts(c.String("hosts")); err != nil {
			return ctx, usageExit(c, err.Error())
		}
	}
	if c.IsSet("presets") {
		if _, err := preset.ParseNames(c.String("presets")); err != nil {
			return ctx, usageExit(c, err.Error())
		}
	}
	return ctx, nil
}

func genAllowlistAction(_ context.Context, c *cli.Command) error {
	from := flagString(c, "from")
	file := flagString(c, "file")
	hosts := flagString(c, "hosts")
	presets := flagString(c, "presets")
	if from == "" && file == "" && !c.IsSet("hosts") && !c.IsSet("presets") {
		return cli.ShowSubcommandHelp(c)
	}
	return cmd.GenerateAllowlist(cmd.GenerateAllowlistOptions{
		Output:    flagString(c, "out"),
		From:      from,
		File:      file,
		Hosts:     hosts,
		Presets:   presets,
		NoPresets: c.Bool("no-presets"),
	})
}

func listCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List the currently installed and trusted certificates",
		UsageText: `trustprune list [options]

  List certificates currently installed on the platform or application.

  List certificates from an application
    trustprune list --app firefox

  List certificates from a file (no --app). --file here is not a store path.
    trustprune list --file <path>

  List certificates from a Java keystore or certifi bundle (skips discovery)
    trustprune list --app java --store <cacerts>
    trustprune list --app certifi --store /path/to/cacert.pem

  List certificates in an explicit OpenSSL PEM CA bundle
    trustprune list --app openssl --bundle /path/to/ca-bundle.pem

  List certificates from a URL
    trustprune list --url <endpoint>

FORMATTING

  Change the output format (Default: ` + ui.DefaultFormat() + `, Options: ` + strings.Join(ui.GetFormats(), ", ") + `)
    trustprune list --format openssl
    trustprune list --format json
    trustprune list --format table

  Table output adds KEY and DAYS by default; -v adds full fingerprint, serial, and path
    trustprune list --format table -v

  DAYS (non-verbose table): "expired" when NotAfter is past; "N!" when 0 <= N < 90 days
  remain; plain N otherwise. -v and --format json keep numeric days (json also has expired).

  Only show the count of certificates found
    trustprune list --count
    trustprune list --app java --count
    trustprune list --file <path> --count

  Show the certificates on a local webpage (Default: ` + ui.DefaultUI() + `, Options: ` + strings.Join(ui.GetUIs(), ", ") + `)
    trustprune list --ui web

  Write formatted output to a file instead of stdout (--out <path>, every --format and --count)
    trustprune list --format json --out certs.json
    trustprune list --format observatory --out report.yaml

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagApp(),
			flagStore(),
			flagFile("PEM (or similar) file to list (without --app)", false),
			flagBundle(),
			flagURL("download and list certificates from a remote URL"),
			flagCount(),
			flagFormat(),
			flagOut("write formatted output to a file instead of stdout (every --format and --count)", false),
			flagUI(),
			flagVerbose(),
		},
		ArgValidator: rejectPositionalArgs,
		Before:       listBefore,
		Action:       withTrace(st, listAction),
	}
}

func listBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	if err := checkBundleFlag(c); err != nil {
		return ctx, err
	}
	app := flagString(c, "app")
	if app != "" && flagString(c, "file") != "" {
		return ctx, usageExit(c, "--file lists a PEM file and cannot be combined with --app; use --store to override a java or certifi path")
	}
	if err := rejectStoreWithBundle(c, "list: pass --bundle for the openssl PEM, or --store for a java/certifi path, not both"); err != nil {
		return ctx, err
	}
	return ctx, rejectIncompatibleStore(c)
}

func listAction(_ context.Context, c *cli.Command) error {
	app := flagString(c, "app")
	file := flagString(c, "file")
	bundle := flagString(c, "bundle")
	path := storePath(c)
	cfg := listConfig(c)
	if app == "" {
		if file != "" {
			return cmd.ListCertsFromFile(file, cfg)
		}
		if url := flagString(c, "url"); url != "" {
			return cmd.ListCertsFromURL(url, cfg)
		}
		return cmd.ListCertsForPlatform(cfg)
	}
	if bundle != "" {
		return cmd.ListCertsForBundle(bundle, cfg)
	}
	if path != "" {
		return cmd.ListCertsForAppWithFile(app, path, cfg)
	}
	return cmd.ListCertsForApp(app, cfg)
}

func restoreCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "restore",
		Usage: "Restore certificate trust from a backup",
		UsageText: `trustprune restore [--app <name>] [--store <path>] [--backup <path>] [--bundle <pem>] [--force] [--dry-run]

  Restore certificates from the latest backup
    trustprune restore

  Restore the platform store from an explicit backup
    trustprune restore --backup <path>

  Restore an application from its latest matching backup
    trustprune restore --app java

  Java and certifi: --store is the store to restore into (same as backup/list).
  --backup selects the backup source. A backup taken from a different path is
  refused before any write unless --force is given.
    trustprune restore --app certifi --store /path/to/venv/.../cacert.pem
    trustprune restore --app java --store /path/to/cacerts --backup /path/to/cacerts-<ts>.bck
    trustprune restore --app java --store /other/cacerts --backup <backup> --force

  OpenSSL: --bundle is the live PEM to restore into. --backup is the backup
  source. A backup recorded for a different PEM is refused unless --force.
    trustprune restore --app openssl --bundle /path/to/ca-bundle.pem
    trustprune restore --app openssl --bundle /path/to/ca-bundle.pem --backup <backup-dir>
    trustprune restore --app openssl --bundle /other/ca-bundle.pem --backup <backup-dir> --force

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagApp(),
			flagStore(),
			flagBackup(),
			flagBundle(),
			flagForce(),
			flagDryRun(),
		},
		ArgValidator: rejectPositionalArgs,
		Before:       restoreBefore,
		Action:       withTrace(st, restoreAction),
	}
}

func restoreBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	if err := checkBundleFlag(c); err != nil {
		return ctx, err
	}
	if err := rejectStoreWithBundle(c, "restore: --bundle names the openssl PEM to restore into; --store is only for java/certifi"); err != nil {
		return ctx, err
	}
	return ctx, rejectIncompatibleStore(c)
}

func restoreAction(_ context.Context, c *cli.Command) error {
	applyDryRun(c)
	store.SetForceRestore(c.Bool("force"))
	app := flagString(c, "app")
	bundle := flagString(c, "bundle")
	path := storePath(c)
	backup := flagString(c, "backup")
	if app == "" {
		// Pass path through. Before already rejects a non-empty --store with
		// no app; Restore repeats that check so a missed Before cannot fall
		// through to the platform store.
		return cmd.Restore("", path, backup)
	}
	if bundle != "" {
		return cmd.RestoreForBundle(app, backup, bundle)
	}
	if path != "" {
		if _, err := store.ForAppWithStore(app, path); err != nil {
			return err
		}
		return cmd.Restore(app, path, backup)
	}
	return cmd.Restore(app, "", backup)
}

func versionCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:         "version",
		Usage:        "Show the version of trustprune",
		UsageText:    getVersion(),
		ArgValidator: rejectPositionalArgs,
		Action: withTrace(st, func(_ context.Context, c *cli.Command) error {
			fmt.Fprintf(c.Root().Writer, "%s\n", getVersion())
			return nil
		}),
	}
}

func checkBundleFlag(c *cli.Command) error {
	if err := cmd.CheckBundleFlag(c.Name, flagString(c, "app"), flagString(c, "bundle")); err != nil {
		return usageExit(c, err.Error())
	}
	return nil
}

func rejectStoreWithBundle(c *cli.Command, msg string) error {
	if flagString(c, "bundle") != "" && storePath(c) != "" {
		return usageExit(c, msg)
	}
	return nil
}
