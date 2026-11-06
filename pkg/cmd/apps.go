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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/store"
)

// ListApps prints every supported app store plus the system/OS store, and
// whether each was found on this machine. Detection is read-only.
//
// format is "json" for a JSON array, or empty/"short" for terse lines.
func ListApps(format string) error {
	return printApps(os.Stdout, store.DetectAndCacheStatuses(), format)
}

func printApps(w io.Writer, statuses []store.Status, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "short":
		return printAppsTerse(w, statuses)
	case "json":
		return printAppsJSON(w, statuses)
	default:
		return fmt.Errorf("unknown -format %q for apps; use the default terse output or -format json", format)
	}
}

func printAppsTerse(w io.Writer, statuses []store.Status) error {
	const (
		headerApp    = "APP"
		headerStatus = "STATUS"
		headerPath   = "PATH"
		stateWidth   = len("not-found")
	)
	maxName := len(headerApp)
	for _, s := range statuses {
		if n := len(s.Name); n > maxName {
			maxName = n
		}
	}
	if _, err := fmt.Fprintf(w, "%-*s  %-*s  %s\n", maxName, headerApp, stateWidth, headerStatus, headerPath); err != nil {
		return fmt.Errorf("writing apps output failed: %w; retry or use -format json", err)
	}
	for _, s := range statuses {
		state := "not-found"
		path := "-"
		if s.Found {
			state = "found"
			if s.Path != "" {
				path = s.Path
			}
		}
		if _, err := fmt.Fprintf(w, "%-*s  %-*s  %s\n", maxName, s.Name, stateWidth, state, path); err != nil {
			return fmt.Errorf("writing apps output failed: %w; retry or use -format json", err)
		}
	}
	return nil
}

func printAppsJSON(w io.Writer, statuses []store.Status) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(statuses); err != nil {
		return fmt.Errorf("encoding apps as JSON failed: %w; try the default terse output instead", err)
	}
	return nil
}
