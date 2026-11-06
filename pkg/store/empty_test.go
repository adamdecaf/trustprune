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

package store

import (
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

func TestEmptyStoreDryRun(t *testing.T) {
	t.Parallel()
	s := emptyStore{}
	SetDryRun(true)
	t.Cleanup(func() { SetDryRun(false) })
	if err := s.Add(nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(allowlist.Allowlist{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	info := s.GetInfo()
	if info == nil || info.Name != "Empty" {
		t.Fatalf("info=%#v", info)
	}
}

func TestPlatformAndDetectCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CACHE_HOME", home)
	_ = Platform()
	statuses := DetectAndCacheStatuses()
	if len(statuses) == 0 {
		t.Fatal("expected statuses")
	}
}
