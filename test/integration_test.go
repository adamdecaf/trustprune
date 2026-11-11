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

package test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/cmd"
)

func TestIntegration__list(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "freebsd" {
		// Platform() is still a stub on FreeBSD; list -count is always 0.
		t.Skip("FreeBSD platform store is not implemented yet")
	}

	cmd := CertManage("list", "-count").Trim()
	cmd.CmpIntF(t, func(i int) bool { return i > 10 })
}

// high-level test of entire "gen-allowlist" code path
func TestIntegraton__genAllowlist(t *testing.T) {
	t.Parallel()

	dir, err := os.MkdirTemp("", "gen-allowlist")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "allowlist.json")

	// generate allowlist
	err = cmd.GenerateAllowlist(cmd.GenerateAllowlistOptions{
		Output:    output,
		File:      filepath.Join("..", "testdata", "file-with-urls"),
		NoPresets: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// read allowlist, loosely verify
	al, err := allowlist.FromFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) < 1 {
		t.Errorf("got %q", al.Fingerprints)
	}
}
