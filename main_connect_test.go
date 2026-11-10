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

package main

import (
	"strings"
	"testing"
)

func TestParseConnectURL(t *testing.T) {
	t.Run("positional", func(t *testing.T) {
		u, err := parseConnectURL("", []string{"https://example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if u.String() != "https://example.com" {
			t.Fatalf("got %s", u)
		}
	})

	t.Run("flagURL", func(t *testing.T) {
		u, err := parseConnectURL("https://example.com/via-flag", nil)
		if err != nil {
			t.Fatal(err)
		}
		if u.String() != "https://example.com/via-flag" {
			t.Fatalf("got %s", u)
		}
	})

	t.Run("both rejected", func(t *testing.T) {
		_, err := parseConnectURL("https://example.com/flag", []string{"https://example.com/pos"})
		if err == nil || !strings.Contains(err.Error(), "not both") {
			t.Fatalf("expected both-rejected error, got %v", err)
		}
		if !isUsageErr(err) {
			t.Fatalf("expected usage error, got %v", err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		_, err := parseConnectURL("", nil)
		if err == nil || !strings.Contains(err.Error(), "no url") {
			t.Fatalf("expected missing url error, got %v", err)
		}
		if !isUsageErr(err) {
			t.Fatalf("expected usage error, got %v", err)
		}
	})
}
