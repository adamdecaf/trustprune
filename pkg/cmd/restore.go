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
	"fmt"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/store"
)

// Restore runs restore for app (empty app is the platform store).
//
// storePath is the java/certifi store to restore into (CLI --store).
// backup is the backup source (CLI --backup; empty means latest).
func Restore(app, storePath, backup string) error {
	app = strings.ToLower(strings.TrimSpace(app))
	storePath = strings.TrimSpace(storePath)
	backup = strings.TrimSpace(backup)
	if app == "" {
		return RestoreForPlatform(backup)
	}
	if storePath != "" {
		return RestoreForAppWithFile(app, storePath, backup)
	}
	return RestoreForApp(app, backup)
}

// RestoreForBundle restores an explicit openssl PEM CA bundle (--bundle).
// backup is the backup source (CLI --backup; empty means latest).
// app must be openssl.
func RestoreForBundle(app, backup, bundle string) error {
	if strings.ToLower(strings.TrimSpace(app)) != "openssl" {
		return fmt.Errorf("--bundle requires --app openssl")
	}
	s, err := store.OpenSSLBundleAt(bundle)
	if err != nil {
		return err
	}
	return restoreStore(s, strings.TrimSpace(backup))
}

// restoreSuccessPrefix is the historical success phrase. The live store path
// is appended after ": " so existing prefix checks still match.
const restoreSuccessPrefix = "Restore completed successfully"

func restoreStore(s store.Store, where string) error {
	err := s.Restore(where)
	if err == nil {
		printRestoreSuccess(s, where)
	}
	return err
}

// printRestoreSuccess prints the dry-run notice, or the success phrase plus
// the live store path (GetInfo().Path). When that path is empty it falls
// back to the backup source, then the latest backup path.
func printRestoreSuccess(s store.Store, where string) {
	if store.DryRun() {
		fmt.Println("dry-run: no changes made")
		return
	}
	path := ""
	if info := s.GetInfo(); info != nil {
		path = strings.TrimSpace(info.Path)
	}
	if path == "" {
		path = strings.TrimSpace(where)
	}
	if path == "" {
		if latest, err := s.GetLatestBackup(); err == nil {
			path = strings.TrimSpace(latest)
		}
	}
	if path == "" {
		fmt.Println(restoreSuccessPrefix)
		return
	}
	fmt.Printf("%s: %s\n", restoreSuccessPrefix, path)
}

func RestoreForApp(app, path string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	return restoreStore(s, path)
}

func RestoreForAppWithFile(app, storePath, backupPath string) error {
	s, err := store.ForAppWithStore(app, storePath)
	if err != nil {
		return err
	}
	return restoreStore(s, backupPath)
}

func RestoreForPlatform(path string) error {
	return restoreStore(store.Platform(), path)
}
