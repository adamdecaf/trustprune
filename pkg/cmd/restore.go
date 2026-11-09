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
// file and backup are the store path and the backup source:
//   - For java and certifi, file is the store to restore into (CLI -store,
//     or the deprecated -file alias) and backup is the backup source
//     (empty means latest).
//   - For every other store, file and backup both name the backup source
//     (CLI -file and -backup). -store is rejected by the CLI for those stores.
func Restore(app, file, backup string) error {
	storeFile, backupPath, err := restoreArgs(app, file, backup)
	if err != nil {
		return err
	}
	if strings.TrimSpace(app) == "" {
		return RestoreForPlatform(backupPath)
	}
	if storeFile != "" {
		return RestoreForAppWithFile(app, storeFile, backupPath)
	}
	return RestoreForApp(app, backupPath)
}

// RestoreForBundle restores an explicit openssl PEM CA bundle (-bundle).
// file and backup keep their openssl meaning: both name the backup source.
// app must be openssl.
func RestoreForBundle(app, file, backup, bundle string) error {
	if strings.ToLower(strings.TrimSpace(app)) != "openssl" {
		return fmt.Errorf("-bundle requires -app openssl")
	}
	_, backupPath, err := restoreArgs(app, file, backup)
	if err != nil {
		return err
	}
	s, err := store.OpenSSLBundleAt(bundle)
	if err != nil {
		return err
	}
	return restoreStore(s, backupPath)
}

// restoreArgs maps CLI -file / -backup onto a store override and a backup
// source. See Restore for the per-app meanings.
func restoreArgs(app, file, backup string) (storeFile, backupPath string, err error) {
	app = strings.ToLower(strings.TrimSpace(app))
	file = strings.TrimSpace(file)
	backup = strings.TrimSpace(backup)
	switch app {
	case "java", "certifi":
		return file, backup, nil
	default:
		if file != "" && backup != "" && file != backup {
			return "", "", fmt.Errorf("restore: -file and -backup both set (%s vs %s); for this store they both name the backup source — use one", file, backup)
		}
		if backup != "" {
			return "", backup, nil
		}
		return "", file, nil
	}
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
