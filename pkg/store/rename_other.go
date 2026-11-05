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

//go:build !linux
// +build !linux

package store

import "os"

// renameDir renames src to dst. Linux has EXDEV/EBUSY handling in rename.go;
// other platforms use a plain rename (openssl directory restore stages into a
// sibling of the live path, so the swap stays on one filesystem).
func renameDir(src, dst string) error {
	return os.Rename(src, dst)
}

func renameAside(live, aside string) error {
	return renameDir(live, aside)
}
