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

//go:build windows
// +build windows

package store

import "runtime"

func detectPlatform() Status {
	// Windows always exposes the system certificate stores via certutil /
	// PowerShell; there is no single on-disk path, so report the Root store
	// PowerShell path used by windowsStore.
	return Status{
		Name:  runtime.GOOS,
		Found: true,
		Path:  `Cert:\LocalMachine\Root`,
	}
}
