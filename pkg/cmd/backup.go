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

	"github.com/adamdecaf/trustprune/pkg/store"
)

func BackupForApp(app string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	err = s.Backup()
	if err == nil {
		if store.DryRun() {
			fmt.Println("dry-run: no changes made")
		} else {
			fmt.Println("Backup completed successfully")
		}
	}
	return err
}

func BackupForPlatform() error {
	err := store.Platform().Backup()
	if err == nil {
		if store.DryRun() {
			fmt.Println("dry-run: no changes made")
		} else {
			fmt.Println("Backup completed successfully")
		}
	}
	return err
}

func BackupForAppWithFile(app, filePath string) error {
	s, err := store.ForAppWithFile(app, filePath)
	if err != nil {
		return err
	}
	err = s.Backup()
	if err == nil {
		if store.DryRun() {
			fmt.Println("dry-run: no changes made")
		} else {
			fmt.Println("Backup completed successfully")
		}
	}
	return err
}
