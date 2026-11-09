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

// backupSuccessPrefix is the historical success phrase. The written path is
// appended after ": " so existing prefix checks still match.
const backupSuccessPrefix = "Backup completed successfully"

func BackupForApp(app string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	err = s.Backup()
	if err == nil {
		printBackupSuccess(s)
	}
	return err
}

func BackupForPlatform() error {
	s := store.Platform()
	err := s.Backup()
	if err == nil {
		printBackupSuccess(s)
	}
	return err
}

func BackupForAppWithFile(app, storePath string) error {
	s, err := store.ForAppWithStore(app, storePath)
	if err != nil {
		return err
	}
	err = s.Backup()
	if err == nil {
		printBackupSuccess(s)
	}
	return err
}

// printBackupSuccess prints the dry-run notice, or the success phrase plus the
// backup path from GetLatestBackup. A backup that already succeeded still
// prints the historical phrase when that path cannot be resolved.
func printBackupSuccess(s store.Store) {
	if store.DryRun() {
		fmt.Println("dry-run: no changes made")
		return
	}
	path, err := s.GetLatestBackup()
	if err != nil || strings.TrimSpace(path) == "" {
		fmt.Println(backupSuccessPrefix)
		return
	}
	fmt.Printf("%s: %s\n", backupSuccessPrefix, path)
}
