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
	"strings"
	"testing"
)

func TestWindowsListScript(t *testing.T) {
	path := `C:\Users\O'Brien\AppData\Local\Temp\cert-manage-win-store`
	script := windowsListScript(windowsStoreNames, path)
	for _, name := range windowsStoreNames {
		if !strings.Contains(script, "'"+name+"'") {
			t.Errorf("script missing quoted store %q", name)
		}
	}
	escaped := `C:\Users\O''Brien\AppData\Local\Temp\cert-manage-win-store`
	if !strings.Contains(script, escaped) {
		t.Errorf("script missing escaped path %q", escaped)
	}
	if got := windowsListScript([]string{"O'Brien"}, path); !strings.Contains(got, "'O''Brien'") {
		t.Errorf("script missing escaped store name")
	}
}
