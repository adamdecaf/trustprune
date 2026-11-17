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

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/store"
)

func AllowlistForApp(app, path string, stdout io.Writer) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	return allowlistStore(s, app, path, stdout)
}

// AllowlistForAppWithStore applies the allowlist at path to app, using
// storePath as the trust-store override (java keystore or certifi bundle).
// path is the allowlist file. It is not the store path.
func AllowlistForAppWithStore(app, storePath, path string, stdout io.Writer) error {
	s, err := store.ForAppWithStore(app, storePath)
	if err != nil {
		return err
	}
	return allowlistStore(s, app, path, stdout)
}

func AllowlistForPlatform(path string, stdout io.Writer) error {
	return allowlistStore(store.Platform(), "", path, stdout)
}

// allowlistStore applies the allowlist at path to s. app is the -app name, or
// "" for the platform store. With no backup it refuses before any write,
// dry-run included.
func allowlistStore(s store.Store, app, path string, stdout io.Writer) error {
	al, err := allowlist.FromFile(path)
	if err != nil {
		return err
	}

	label := app
	if label == "" {
		label = runtime.GOOS
	}
	latest, err := s.GetLatestBackup()
	if errors.Is(err, store.ErrNoBackupFound) {
		return store.NoBackupError(app)
	}
	if err != nil {
		return fmt.Errorf("can't check for a %s backup: %w", label, err)
	}
	if latest == "" {
		return store.NoBackupError(app)
	}
	// An NSS backup recorded for a different directory does not authorize
	// changes here unless this directory has a backup of its own. --force
	// allows it, the same way restore does.
	if err := store.NSSAllowlistBackupError(s, app); err != nil {
		return err
	}

	// Drop a classification left by an earlier Remove in this process.
	// Remove records a new one when it decides what to keep.
	store.ResetAllowlistStats()
	if err := s.Remove(al); err != nil {
		return err
	}
	return printAllowlistOutcome(stdout)
}

// printAllowlistOutcome prints the real-run summary, or only the removed
// count when --count is set. Dry-run plans, including unmatched fingerprints
// and the kept/removed line, are printed by the store so that line stays last.
func printAllowlistOutcome(stdout io.Writer) error {
	if stdout == nil {
		stdout = os.Stdout
	}
	if store.AllowlistCountOnly() {
		stats, ok := store.LastAllowlistStats()
		if !ok {
			return errors.New("allowlist did not report how many certificates were removed")
		}
		fmt.Fprintln(stdout, stats.Removed)
		return nil
	}
	if store.DryRun() {
		return nil
	}
	fmt.Fprintln(stdout, "Allowlist completed successfully")
	stats, ok := store.LastAllowlistStats()
	if !ok {
		return nil
	}
	store.WriteUnmatchedAllowlist(stdout, stats.Unmatched)
	fmt.Fprintln(stdout, store.AllowlistSummaryLine(stats.Removed, stats.Kept))
	return nil
}
