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
	"errors"
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

  Add a certificate to a specific certifi bundle, Java keystore, or poppler NSS db.
  --file is the certificate to import. --store is the trust store.
    trustprune add --file <path> --app certifi --store /path/to/cacert.pem
    trustprune add --file <path> --app java --store /path/to/cacerts
    trustprune add --file <path> --app poppler --store /path/to/nssdb

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
		UsageText: `trustprune allowlist --file <path> [--app <name>] [--store <path>] [--bundle <pem>] [--dry-run] [--force] [--count] [--v]

  Remove untrusted certificates from a store for the platform
    trustprune allowlist --file allowlist.json

  Remove untrusted certificates in an app
    trustprune allowlist --file allowlist.json --app java

  --file is the allowlist. --store overrides the java, certifi, or poppler store path.
    trustprune allowlist --file allowlist.yaml --app certifi --store /path/to/cacert.pem
    trustprune allowlist --file allowlist.yaml --app java --store /path/to/cacerts
    trustprune allowlist --file allowlist.yaml --app poppler --store /path/to/nssdb

  NSS allowlist (firefox, poppler, okular, and Linux chrome) refuses when this directory
  has no backup of its own and the newest backup was recorded for a different
  directory. Back up that store, or pass --force.
    trustprune allowlist --file allowlist.yaml --app poppler --store /path/to/nssdb --force

  Print only how many certificates were removed or untrusted
    trustprune allowlist --file allowlist.yaml --count
    trustprune allowlist --file allowlist.yaml --dry-run --count

  Remove untrusted certificates in an explicit OpenSSL PEM CA bundle
    trustprune allowlist --app openssl --file allowlist.json --bundle /path/to/ca-bundle.pem

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagFile("allowlist file", true),
			flagApp(),
			flagStore(),
			flagBundle(),
			flagAllowlistForce(),
			flagDryRun(),
			flagAllowlistCount(),
			flagAllowlistVerbose(),
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
	if err := rejectStoreWithBundle(c, "allowlist: --bundle names the openssl PEM; --store is only for java/certifi/poppler"); err != nil {
		return ctx, err
	}
	return ctx, rejectIncompatibleStore(c)
}

func allowlistAction(_ context.Context, c *cli.Command) error {
	applyDryRun(c)
	store.SetDryRunVerbose(c.Bool("v"))
	store.SetForceRestore(c.Bool("force"))
	store.SetAllowlistCountOnly(c.Bool("count"))
	file := flagString(c, "file")
	app := flagString(c, "app")
	bundle := flagString(c, "bundle")
	path := storePath(c)
	out := c.Root().Writer
	if app == "" {
		return cmd.AllowlistForPlatform(file, out)
	}
	if bundle != "" {
		return cmd.AllowlistForBundle(app, file, bundle, out)
	}
	if path != "" {
		return cmd.AllowlistForAppWithStore(app, path, file, out)
	}
	return cmd.AllowlistForApp(app, file, out)
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
			flagAppsFormat(),
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
  Poppler: --store <dir> is pdfsig -nssdir and backs up that NSS db.
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

func chainCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "chain",
		Usage: "Show the certificate chain for a file or URL",
		UsageText: `trustprune chain [--app <name>] [--store <path>] [--bundle <pem>] [--file <path>] [--url <url>] [--untrusted] [--expired] [--revoked] [--all] [--remote]

Show the certificate chain for a local file or a URL. The store is only listed.
Nothing is added, removed, or backed up.

The default table uses trusted, in-date certificates that are not on the
offline Chromium or Mozilla blocklists. Columns match connect -v:
INDEX, SUBJECT, ISSUER, NOT-AFTER, SHA256. The leaf is shown even when it
is not in the store. Other certificates outside the store, expired or
not-yet-valid certificates, and blocklisted certificates are omitted
unless the matching flag is set. Included certificates are labeled
(untrusted), (expired), (not yet valid), and/or (blocklisted).
--expired covers a past NotAfter and a future NotBefore.
--revoked does not use OCSP or CRLs.

  File (PEM or DER), using an explicit OpenSSL CA bundle as the trust store
    trustprune chain --file leaf.pem --app openssl --bundle /path/to/ca-bundle.pem

  Include a private CA that is not in the trusted store
    trustprune chain --file leaf.pem --untrusted

  Include expired, not-yet-valid, or blocklisted certificates
    trustprune chain --file leaf.pem --expired
    trustprune chain --file leaf.pem --revoked

  Include untrusted, expired, not-yet-valid, and blocklisted certificates
    trustprune chain --file leaf.pem --all

  Look up the TLS chain when no local certificate matches the host
    trustprune chain --url example.com --remote
    trustprune chain --url https://example.com --remote --untrusted

  --store overrides java, certifi, or poppler. --bundle requires --app openssl.

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagApp(),
			flagStore(),
			flagBundle(),
			flagFile("certificate file (PEM or DER) to show a chain for", false),
			flagURL("host or URL to show a chain for"),
			flagChainUntrusted(),
			flagChainExpired(),
			flagChainRevoked(),
			flagChainAll(),
			flagChainRemote(),
		},
		ArgValidator: rejectPositionalArgs,
		Before:       chainBefore,
		Action:       withTrace(st, chainAction),
	}
}

func chainBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	if err := checkBundleFlag(c); err != nil {
		return ctx, err
	}
	if err := rejectStoreWithBundle(c, "chain: --bundle names the openssl PEM to read; --store is only for java/certifi/poppler"); err != nil {
		return ctx, err
	}
	if err := rejectIncompatibleStore(c); err != nil {
		return ctx, err
	}
	file := flagString(c, "file")
	urlRaw := flagString(c, "url")
	if c.Bool("remote") && urlRaw == "" {
		return ctx, usageExit(c, "--remote requires a URL")
	}
	if file == "" && urlRaw == "" {
		return ctx, usageExit(c, "provide a certificate file (--file) or a URL (--url)")
	}
	return ctx, nil
}

func chainAction(_ context.Context, c *cli.Command) error {
	opts := cmd.ChainOptions{
		App:       flagString(c, "app"),
		StorePath: storePath(c),
		Bundle:    flagString(c, "bundle"),
		File:      flagString(c, "file"),
		Untrusted: c.Bool("untrusted"),
		Expired:   c.Bool("expired"),
		Revoked:   c.Bool("revoked"),
		All:       c.Bool("all"),
		Remote:    c.Bool("remote"),
	}
	if raw := flagString(c, "url"); raw != "" {
		u, err := cmd.NormalizeConnectURL(raw)
		if err != nil {
			return err
		}
		opts.URL = u
	}
	return cmd.ShowChain(c.Root().Writer, opts)
}

func connectCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "connect",
		Usage: "Attempt to load a remote URL with the platform (or app) store",
		UsageText: `trustprune connect [--app <name>] [--store <path>] [-v] [--format text|json] (--url <url> | <url>)

Attempt an HTTPS connect with the given certificate store. A bare host is accepted
and treated as https. Pass the target as --url <url> or as one positional argument.
Explicit http:// is rejected. If --app is provided then the certificates for that
application are loaded and used for the connection.

  --store <path> overrides discovery for --app java (cacerts), --app certifi (cacert.pem), and --app poppler (NSS db).
  -v, --verbose prints the verified chain after the one-line summary. When verification fails it prints the chain the server presented. It has no effect with --format json.
  --format text (default) or json. An unknown format is a usage error.

  Bare host, one-line success:
    trustprune connect google.com
    ok https://google.com tls1.3 root=<name> sha256=<16 hex> leaf-expires=<YYYY-MM-DD>

  Verified chain:
    trustprune connect -v google.com

  JSON object (full hex sha256; -v is ignored):
    trustprune connect --format json google.com

  Failure:
    ERROR: https://expired.badssl.com: certificate expired 2015-04-12

  -v after a verification failure prints the chain from that failed handshake (same columns).
  A subject ending in " (not in store)" is missing from the selected store.
  allowlist only keeps or removes certificates already in the store; it does not add a missing CA.
  Add a missing CA with add --file. After it is in the store, include its sha256 under fingerprints in an allowlist file so a later allowlist run keeps it.
    to add a missing CA, run: trustprune add --file <cert>
    after it is in the store, include sha256 <64 hex> under fingerprints in an allowlist file so a later allowlist run keeps it

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagApp(),
			flagStore(),
			flagURL("remote URL to connect to (instead of a positional URL)"),
			flagConnectVerbose(),
			flagConnectFormat(),
		},
		ArgValidator: connectArgValidator,
		Before:       connectBefore,
		Action:       withTrace(st, connectAction),
	}
}

func connectBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	if _, err := cmd.NormalizeConnectFormat(c.String("format")); err != nil {
		return ctx, usageExit(c, err.Error())
	}
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
	opts := cmd.ConnectOptions{
		Verbose: c.Bool("verbose"),
		Format:  c.String("format"),
	}
	if app == "" {
		return cmd.ConnectWithPlatformStore(u, opts)
	}
	if path != "" {
		return cmd.ConnectWithAppStoreFile(u, app, path, opts)
	}
	return cmd.ConnectWithAppStore(u, app, opts)
}

func createCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "create",
		Usage: "Write a PEM bundle or Java truststore of allowlisted certificates without changing the store",
		UsageText: `trustprune create --file <path> [--app <name>] [--store <path>] [--bundle <pem>] [--format pem|jks|pkcs12] [--out <path>]

  Write trusted certificates that match an allowlist.
  pem (the default) is a PEM bundle. jks and pkcs12 are Java truststores.
  The store is only read. Nothing is removed, added, or backed up.

  Platform store, PEM on stdout
    trustprune create --file allowlist.yaml

  Write the bundle to a file (mode 0644). Stdout stays empty.
    trustprune create --file allowlist.yaml --out ca-bundle.pem

  Java truststore. --out is required. The password defaults to changeit.
  Set TRUSTPRUNE_JAVA_STOREPASS to override it. A custom password is passed
  to keytool with -storepass:env, not argv. There is no password flag.
    trustprune create --file allowlist.yaml --format jks --out trusted.jks
    trustprune create --file allowlist.yaml --format pkcs12 --out trusted.p12

  Application store. --store overrides java, certifi, or poppler.
    trustprune create --file allowlist.yaml --app java --out java-cas.pem
    trustprune create --file allowlist.yaml --app certifi --store /path/to/cacert.pem --out kept.pem
    trustprune create --file allowlist.yaml --app poppler --store /path/to/nssdb --out kept.pem

  Read an explicit OpenSSL PEM CA bundle. The file is not modified.
    trustprune create --app openssl --file allowlist.yaml --bundle /path/to/ca-bundle.pem --out kept.pem

  --format accepts pem (the default), jks, and pkcs12. Any other value is a usage error.
    trustprune create --file allowlist.yaml --format pem

  jks and pkcs12 require --out. keytool writes the truststore (JAVA_HOME/bin,
  then PATH, then ~/.local/bin). A missing keytool is an error. Aliases are
  sha256-<fingerprint>. The truststore is written to a temp file in the
  destination directory and renamed into place.

  An allowlist that matches no trusted certificate fails before any output file is created.
  --out equal to the store path, or a path inside a directory store, is refused.

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagFile("allowlist file", true),
			flagApp(),
			flagStore(),
			flagBundle(),
			flagCreateFormat(),
			flagOut("write the PEM bundle or Java truststore to this path (mode 0644). Required for jks and pkcs12; pem defaults to stdout", false),
		},
		ArgValidator: rejectPositionalArgs,
		Before:       createBefore,
		Action:       withTrace(st, createAction),
	}
}

func createBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	format, err := cmd.NormalizeCreateFormat(c.String("format"))
	if err != nil {
		return ctx, usageExit(c, err.Error())
	}
	if cmd.CreateFormatRequiresOut(format) && flagString(c, "out") == "" {
		return ctx, usageExit(c, cmd.CreateOutRequiredError(format).Error())
	}
	if err := checkBundleFlag(c); err != nil {
		return ctx, err
	}
	if err := rejectStoreWithBundle(c, "create: --bundle names the openssl PEM to read; --store is only for java/certifi/poppler"); err != nil {
		return ctx, err
	}
	return ctx, rejectIncompatibleStore(c)
}

func createAction(_ context.Context, c *cli.Command) error {
	opts := cmd.CreateOptions{
		AllowlistPath: flagString(c, "file"),
		Format:        c.String("format"),
		Out:           flagString(c, "out"),
		Stdout:        c.Root().Writer,
	}
	app := flagString(c, "app")
	bundle := flagString(c, "bundle")
	path := storePath(c)
	if app == "" {
		return cmd.CreateForPlatform(opts)
	}
	if bundle != "" {
		return cmd.CreateForBundle(app, bundle, opts)
	}
	if path != "" {
		return cmd.CreateForAppWithStore(app, path, opts)
	}
	return cmd.CreateForApp(app, opts)
}

func diffCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "diff",
		Usage: "Compare two certificate files",
		UsageText: `trustprune diff [--format text|json] <left> <right>

Compare two certificate files and print the fields that differ.
Each file is PEM or DER and must contain exactly one certificate.
Comments around a PEM CERTIFICATE block are ignored. Other PEM block
types are ignored. The first path is the left side and the second is
the right side.

Exit status is 0 when every field matches and 1 when any field differs.
The report is on stdout and is not an ERROR: line. A file that cannot
be read, or that is not one certificate, exits 1 with ERROR: on stdout.
The wrong number of paths, or an unknown --format, is a usage error
(exit 2).

Fields, in report order: subject, issuer, serial, validity, key, sans,
sha256, signature_algorithm.

  subject and issuer are full distinguished names.
  serial is the decimal serial number.
  validity is NotBefore and NotAfter in UTC (RFC3339), joined by " .. ".
  key is the public key type and size, such as RSA-2048.
  sans are DNS names, email addresses, IP addresses, and URIs, in that order.
  sha256 is the hex SHA-256 fingerprint of the certificate.
  signature_algorithm is the signature algorithm, such as SHA256-RSA.

Text (the default) prints one line per differing field. Identical
certificates print "identical".

  trustprune diff old.pem new.pem
  subject: "CN=Old" != "CN=New"

  trustprune diff --format json old.pem new.der

JSON is one object. differences lists only fields that differ.
An unknown format is a usage error and names json and text.
`,
		Flags: []cli.Flag{
			flagDiffFormat(),
		},
		ArgValidator: diffArgValidator,
		Before:       diffBefore,
		Action:       withTrace(st, diffAction),
	}
}

func diffBefore(ctx context.Context, c *cli.Command) (context.Context, error) {
	if _, err := cmd.NormalizeDiffFormat(c.String("format")); err != nil {
		return ctx, usageExit(c, err.Error())
	}
	return ctx, nil
}

func diffAction(_ context.Context, c *cli.Command) error {
	args := c.Args().Slice()
	if len(args) != 2 {
		return usageExit(c, "expected two certificate files")
	}
	err := cmd.DiffCertificates(args[0], args[1], cmd.DiffOptions{Format: c.String("format")})
	if errors.Is(err, cmd.ErrCertificatesDiffer) {
		return differExit{}
	}
	return err
}

func genAllowlistCommand(st *runState) *cli.Command {
	return &cli.Command{
		Name:  "gen-allowlist",
		Usage: "Create an allowlist from various sources",
		UsageText: `trustprune gen-allowlist --out <where> [--hosts <hosts>] [--presets <names>] [--no-presets] [--file <file>] [--from <type>] [--stats]

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

  Print connection and timing stats to stderr
    trustprune gen-allowlist --out allowlist.yaml --hosts example.com --stats

APPS
  Supported apps: ` + store.FormatAppsHelpLine(),
		Flags: []cli.Flag{
			flagOut("where to write the allowlist (.json, .yaml, or .yml)", true),
			flagHosts(),
			flagPresets(),
			flagNoPresets(),
			flagFile("newline-delimited https URLs or a Tranco-style rank,domain CSV", false),
			flagFrom(),
			flagGenAllowlistVerbose(),
			flagGenAllowlistStats(),
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
		Verbose:   c.Bool("v"),
		Stats:     c.Bool("stats"),
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

  Acrobat prints a read-only report of AATL, EUTL, and Windows store trust
  settings. It does not list address book entries. When Acrobat is not
  installed the line is "acrobat: not installed" and the exit code is 0.
    trustprune list --app acrobat

  List certificates from a file (no --app). --file here is not a store path.
    trustprune list --file <path>

  List certificates from a Java keystore, certifi bundle, or poppler NSS db (skips discovery).
  The chosen path is included in list output.
    trustprune list --app java --store <cacerts>
    trustprune list --app certifi --store /path/to/cacert.pem
    trustprune list --app poppler --store /path/to/nssdb

  List certificates in an explicit OpenSSL PEM CA bundle
    trustprune list --app openssl --bundle /path/to/ca-bundle.pem

  List certificates from a URL
    trustprune list --url <endpoint>

FORMATTING

  Change the output format (Default: ` + ui.DefaultFormat() + `, Options: ` + strings.Join(ui.GetFormats(), ", ") + `)
    trustprune list --format long
    trustprune list --format openssl
    trustprune list --format json

  Table output (the default) adds KEY and DAYS; -v adds the full fingerprint, serial, and path
    trustprune list -v

  DAYS (non-verbose table): "expired" when NotAfter is past; "N!" when 0 <= N < 90 days
  remain; plain N otherwise. -v and --format json keep numeric days (json also has expired).

  Only show the count of certificates found
    trustprune list --count
    trustprune list --app java --count
    trustprune list --file <path> --count
    trustprune list --count --format json

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
			flagListFormat(),
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
	format := c.String("format")
	if !ui.KnownFormat(format) {
		return ctx, usageExit(c, ui.UnknownFormatError(format).Error())
	}
	if err := checkBundleFlag(c); err != nil {
		return ctx, err
	}
	app := flagString(c, "app")
	if app != "" && flagString(c, "file") != "" {
		return ctx, usageExit(c, "--file lists a PEM file and cannot be combined with --app; use --store to override a java, certifi, or poppler path")
	}
	if err := rejectStoreWithBundle(c, "list: pass --bundle for the openssl PEM, or --store for a java/certifi/poppler path, not both"); err != nil {
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

  Java, certifi, and poppler: --store is the store to restore into (same as backup/list).
  --backup selects the backup source. A backup taken from a different path is
  refused before any write unless --force is given.
    trustprune restore --app certifi --store /path/to/venv/.../cacert.pem
    trustprune restore --app java --store /path/to/cacerts --backup /path/to/cacerts-<ts>.bck
    trustprune restore --app java --store /other/cacerts --backup <backup> --force
    trustprune restore --app poppler --store /path/to/nssdb

  OpenSSL: --bundle is the live PEM to restore into. --backup is the backup
  source. A backup recorded for a different PEM is refused unless --force.
    trustprune restore --app openssl --bundle /path/to/ca-bundle.pem
    trustprune restore --app openssl --bundle /path/to/ca-bundle.pem --backup <backup-dir>
    trustprune restore --app openssl --bundle /other/ca-bundle.pem --backup <backup-dir> --force

  NSS (firefox, poppler, okular, and chrome on Linux): backups record the profile directory.
  Restore into a different profile, or from a backup with no recorded profile,
  is refused before any write unless --force.
    trustprune restore --app firefox
    trustprune restore --app firefox --backup <backup-dir> --force

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
	if err := rejectStoreWithBundle(c, "restore: --bundle names the openssl PEM to restore into; --store is only for java/certifi/poppler"); err != nil {
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
			printVersion(c.Root().Writer)
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
