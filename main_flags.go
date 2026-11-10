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
	"fmt"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/ui"
	"github.com/urfave/cli/v3"
)

func flagApp() *cli.StringFlag {
	return &cli.StringFlag{
		Name:  "app",
		Usage: "application store to operate on",
		Local: true,
	}
}

func flagStore() *cli.StringFlag {
	return &cli.StringFlag{
		Name:      "store",
		Usage:     "trust-store path for --app java (cacerts) or --app certifi (cacert.pem)",
		TakesFile: true,
		Local:     true,
	}
}

func flagFile(usage string, required bool) *cli.StringFlag {
	return &cli.StringFlag{
		Name:      "file",
		Usage:     usage,
		Required:  required,
		TakesFile: true,
		Local:     true,
	}
}

func flagBackup() *cli.StringFlag {
	return &cli.StringFlag{
		Name:      "backup",
		Usage:     "backup to restore from",
		TakesFile: true,
		Local:     true,
	}
}

func flagBundle() *cli.StringFlag {
	return &cli.StringFlag{
		Name:      "bundle",
		Usage:     "with --app openssl: explicit PEM CA bundle",
		TakesFile: true,
		Local:     true,
	}
}

func flagURL(usage string) *cli.StringFlag {
	return &cli.StringFlag{
		Name:  "url",
		Usage: usage,
		Local: true,
	}
}

func flagFrom() *cli.StringFlag {
	return &cli.StringFlag{
		Name:  "from",
		Usage: "sources to capture URLs from (comma-separated: browser, browsers, chrome, firefox, safari, file)",
		Local: true,
	}
}

func flagOut(usage string, required bool) *cli.StringFlag {
	return &cli.StringFlag{
		Name:      "out",
		Usage:     usage,
		Required:  required,
		TakesFile: true,
		Local:     true,
	}
}

func flagFormat() *cli.StringFlag {
	return &cli.StringFlag{
		Name:        "format",
		Usage:       fmt.Sprintf("output format (default: %s, options: %s)", ui.DefaultFormat(), strings.Join(ui.GetFormats(), ", ")),
		Value:       ui.DefaultFormat(),
		HideDefault: true,
		Local:       true,
	}
}

func flagUI() *cli.StringFlag {
	return &cli.StringFlag{
		Name:        "ui",
		Usage:       fmt.Sprintf("presentation (default: %s, options: %s)", ui.DefaultUI(), strings.Join(ui.GetUIs(), ", ")),
		Value:       ui.DefaultUI(),
		HideDefault: true,
		Local:       true,
	}
}

func flagCount() *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:        "count",
		Usage:       "output the count of certificates instead of each certificate",
		HideDefault: true,
		Local:       true,
	}
}

func flagVerbose() *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:        "v",
		Usage:       "show full fingerprints, serials, and paths in table output",
		HideDefault: true,
		Local:       true,
	}
}

func flagDryRun() *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:        "dry-run",
		Usage:       "preview changes without writing to stores",
		HideDefault: true,
		Local:       true,
	}
}

func flagForce() *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:        "force",
		Usage:       "allow restore into a different store path than the backup came from",
		HideDefault: true,
		Local:       true,
	}
}
