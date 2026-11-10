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
	"strings"

	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/urfave/cli/v3"
)

func storePath(c *cli.Command) string {
	return strings.TrimSpace(c.String("store"))
}

// rejectIncompatibleStore rejects --store unless --app supports a trust-store
// path override. The allowed apps come from store.SupportsStoreOverride
// (java and certifi), not a second list here.
//
// No --app, and a recognized app that does not support --store (for example
// firefox, or the platform OS name), are usage errors. An unknown app keeps
// the error ForApp returns, but it is returned from Before so the action
// does not open TRACE.
func rejectIncompatibleStore(c *cli.Command) error {
	usage, err := store.CheckStoreOverride(flagString(c, "app"), storePath(c))
	if err == nil {
		return nil
	}
	if !usage {
		return err
	}
	return usageExit(c, err.Error())
}
