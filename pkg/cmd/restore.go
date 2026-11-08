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
// file and backup are the CLI -file and -backup values:
//   - For java and certifi, -file is the store to restore into (same as
//     backup/list) and -backup is the backup source (empty means latest).
//   - For every other store, -file and -backup both name the backup source.
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

func restoreStore(s store.Store, where string) error {
	err := s.Restore(where)
	if err == nil {
		if store.DryRun() {
			fmt.Println("dry-run: no changes made")
		} else {
			fmt.Println("Restore completed successfully")
		}
	}
	return err
}

func RestoreForApp(app, path string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	return restoreStore(s, path)
}

func RestoreForAppWithFile(app, filePath, backupPath string) error {
	s, err := store.ForAppWithFile(app, filePath)
	if err != nil {
		return err
	}
	return restoreStore(s, backupPath)
}

func RestoreForPlatform(path string) error {
	return restoreStore(store.Platform(), path)
}
