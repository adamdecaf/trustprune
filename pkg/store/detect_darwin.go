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
	"runtime"

	"github.com/adamdecaf/trustprune/pkg/file"
)

func detectPlatform() Status {
	s := Status{Name: runtime.GOOS}
	// Prefer the login keychain (where user overrides live), then the
	// system keychain. The SystemRootCertificates keychain is SIP-protected
	// and always present on a real Mac.
	if p := loginKeychainFile(); file.Exists(p) {
		s.Found = true
		s.Path = p
		return s
	}
	if file.Exists(systemKeychain) {
		s.Found = true
		s.Path = systemKeychain
		return s
	}
	if file.Exists(systemRootCertificates) {
		s.Found = true
		s.Path = systemRootCertificates
		return s
	}
	return s
}
