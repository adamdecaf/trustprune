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

package certutil

import (
	"crypto/x509"
	"sort"
	"strings"
)

// Sort reorders certs in place. The order is case-insensitive subject
// (StringifyPKIXName), then the full SHA-256 hex fingerprint
// (GetHexSHA256Fingerprint). Nil certificates sort first. Certificates
// that compare equal keep their relative order.
func Sort(certs []*x509.Certificate) {
	sort.SliceStable(certs, func(i, j int) bool {
		return Less(certs[i], certs[j])
	})
}

// Less reports whether a sorts before b.
// A nil certificate sorts before a non-nil certificate. Otherwise the
// order is case-insensitive subject (StringifyPKIXName), then the full
// SHA-256 hex fingerprint (GetHexSHA256Fingerprint).
func Less(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return a == nil && b != nil
	}
	as := strings.ToLower(StringifyPKIXName(a.Subject))
	bs := strings.ToLower(StringifyPKIXName(b.Subject))
	if as != bs {
		return as < bs
	}
	return fingerprintHex(a) < fingerprintHex(b)
}

// fingerprintHex is the SHA-256 tiebreaker. A certificate with no raw
// encoding sorts before one that has a fingerprint.
func fingerprintHex(c *x509.Certificate) string {
	if c == nil || len(c.Raw) == 0 {
		return ""
	}
	return GetHexSHA256Fingerprint(*c)
}
