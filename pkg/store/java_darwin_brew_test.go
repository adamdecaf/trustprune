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

//go:build darwin
// +build darwin

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHomebrewJDKHomes(t *testing.T) {
	prefix := t.TempDir()
	home := filepath.Join(prefix, "opt", "openjdk@21", "libexec", "openjdk.jdk", "Contents", "Home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	got := homebrewJDKHomes([]string{prefix})
	if len(got) != 1 || got[0] != home {
		t.Fatalf("got %v, want [%s]", got, home)
	}
}
