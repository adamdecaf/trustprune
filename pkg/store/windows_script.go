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

package store

import (
	"fmt"
	"strings"
)

var (
	// C:\Users>certutil -enumstore
	// Note: Not all stores are named here, some aren't "web" related
	// e.g. 'Remote Desktop' or SmartCardRoot
	windowsStoreNames = []string{
		"My",       // Personal
		"Root",     // "Trusted Root Certification Authorities"
		"Trust",    // "Enterprise Trust"
		"CA",       // "Intermediate Certification Authorities"
		"AuthRoot", // "Third-Party Root Certification Authorities"
	}
)

// windowsListScript builds a PowerShell snippet that dumps PEM for every cert
// in Cert:\LocalMachine\<name> for the given store names into path. Single
// quotes in names and path are doubled so they can sit in PS single-quoted
// literals.
func windowsListScript(stores []string, path string) string {
	quoted := make([]string, len(stores))
	for i, name := range stores {
		quoted[i] = "'" + strings.ReplaceAll(name, "'", "''") + "'"
	}
	psPath := strings.ReplaceAll(path, "'", "''")
	return fmt.Sprintf(`
$ErrorActionPreference = 'SilentlyContinue'
$sb = New-Object System.Text.StringBuilder
foreach ($name in @(%s)) {
  Get-ChildItem -LiteralPath ('Cert:\LocalMachine\' + $name) | ForEach-Object {
    [void]$sb.AppendLine('-----BEGIN CERTIFICATE-----')
    [void]$sb.AppendLine([Convert]::ToBase64String($_.RawData))
    [void]$sb.AppendLine('-----END CERTIFICATE-----')
  }
}
[IO.File]::WriteAllText('%s', $sb.ToString(), [Text.UTF8Encoding]::new($false))
`, strings.Join(quoted, ", "), psPath)
}
