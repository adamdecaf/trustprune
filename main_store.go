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

	"github.com/urfave/cli/v3"
)

func storePath(c *cli.Command) string {
	return strings.TrimSpace(c.String("store"))
}

// rejectPlatformStore rejects --store when --app is not set. The platform
// store has no path override.
func rejectPlatformStore(c *cli.Command) error {
	if storePath(c) == "" {
		return nil
	}
	return usageExit(c, "--store overrides the trust store path and is only supported with --app java or --app certifi")
}
