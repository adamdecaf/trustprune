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

package preset

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseHostsOK(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want []string
	}{
		{"example.com", []string{"https://example.com"}},
		{"example.com:8443", []string{"https://example.com:8443"}},
		{"https://example.com/foo", []string{"https://example.com/foo"}},
		{"example.com,api.example.com", []string{"https://example.com", "https://api.example.com"}},
		{" example.com , api.example.com ", []string{"https://example.com", "https://api.example.com"}},
		{"example.com,,api.example.com", []string{"https://example.com", "https://api.example.com"}},
		{"HTTPS://example.com/foo", []string{"https://example.com/foo"}},
		{"127.0.0.1:8443", []string{"https://127.0.0.1:8443"}},
	}
	for _, c := range cases {
		got, err := ParseHosts(c.in)
		if err != nil {
			t.Errorf("ParseHosts(%q): %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("ParseHosts(%q) len=%d want %d (%q)", c.in, len(got), len(c.want), urlsString(got))
			continue
		}
		for i := range got {
			if got[i].String() != c.want[i] {
				t.Errorf("ParseHosts(%q)[%d]=%q want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestParseHostsErr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{"", "no hostnames given"},
		{"   ", "no hostnames given"},
		{",,,", "no hostnames given"},
		{" , , ", "no hostnames given"},
		{"http://example.com", "unsupported URL scheme"},
		{"ftp://example.com", "unsupported URL scheme"},
		{"example.com/foo", "invalid host"},
		{"not a host", "invalid host"},
		{":8443", "invalid host"},
		{"example.com:", "invalid host"},
		{"-invalid-.com", "invalid host"},
		{"https://", "missing host"},
	}
	for _, c := range cases {
		_, err := ParseHosts(c.in)
		if err == nil {
			t.Errorf("ParseHosts(%q): expected error", c.in)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseHosts(%q) error %q, want substring %q", c.in, err, c.want)
		}
	}
}

func urlsString(urls []*url.URL) []string {
	out := make([]string, len(urls))
	for i, u := range urls {
		out[i] = u.String()
	}
	return out
}
