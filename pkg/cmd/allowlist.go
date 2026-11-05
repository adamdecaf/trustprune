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
	"runtime"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/store"
)

func AllowlistForApp(app, path string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	return allowlistStore(s, app, path)
}

func AllowlistForPlatform(path string) error {
	return allowlistStore(store.Platform(), "", path)
}

// allowlistStore applies the allowlist at path to s. app is the -app name, or
// "" for the platform store. With no backup it refuses before any write,
// dry-run included.
func allowlistStore(s store.Store, app, path string) error {
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

	if err := s.Remove(al); err != nil {
		return err
	}

	if store.DryRun() {
		fmt.Println("dry-run: no changes made")
	} else {
		fmt.Println("Allowlist completed successfully")
	}
	return nil
}
