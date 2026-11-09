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
	"os"
	"path/filepath"
	"strings"
)

// storePathDeprecation is printed to stderr when -file supplies a store path.
const storePathDeprecation = "WARNING: -file as a store path is deprecated; use -store instead\n"

// fileIsStorePath reports whether -file is a store-path alias for this command.
//
// list, backup, and connect use -file as a store path only when -app is set.
// restore uses -file as a store path only for java and certifi. Every other
// restore target still treats -file as a backup source. add and allowlist never
// treat -file as a store path.
func fileIsStorePath(command, app string) bool {
	app = strings.ToLower(strings.TrimSpace(app))
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "list", "backup", "connect":
		return app != ""
	case "restore":
		return app == "java" || app == "certifi"
	default:
		return false
	}
}

// resolveStorePath merges -store with the deprecated -file store-path alias.
// fileIsAlias is true when -file means a store path on this command.
// storePath wins when both are set. Values that match after trim and
// filepath.Clean are the same path (/tmp/a and /tmp/./a agree). The returned
// path stays the trimmed text the caller passed. A non-empty file alias
// sets warn even when -store has the same value.
// When fileIsAlias is false, filePath is ignored and storePath is returned as-is.
func resolveStorePath(storePath, filePath string, fileIsAlias bool) (path string, warn bool, err error) {
	storePath = strings.TrimSpace(storePath)
	filePath = strings.TrimSpace(filePath)
	if !fileIsAlias {
		return storePath, false, nil
	}
	if storePath != "" && filePath != "" && filepath.Clean(storePath) != filepath.Clean(filePath) {
		return "", false, fmt.Errorf("-store and -file disagree (%s vs %s); -file as a store path is deprecated, use -store", storePath, filePath)
	}
	warn = filePath != ""
	if storePath != "" {
		return storePath, warn, nil
	}
	return filePath, warn, nil
}

// applyStoreFlag resolves -store and the deprecated -file alias for command.
// A disagreement is printed to stderr and the process exits 1.
func applyStoreFlag(command, app string) string {
	path, warn, err := resolveStorePath(*flagStore, *flagFile, fileIsStorePath(command, app))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	if warn {
		fmt.Fprint(os.Stderr, storePathDeprecation)
	}
	return path
}

// platformStoreUnsupported rejects -store on commands that have no -app.
// The platform store has no path override. -file keeps its existing meaning.
func platformStoreUnsupported() error {
	if strings.TrimSpace(*flagStore) != "" {
		return fmt.Errorf("-store overrides the trust store path and is only supported with -app java or -app certifi")
	}
	return nil
}
