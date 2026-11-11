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
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseHosts parses a --hosts value: comma-separated hostnames or https URLs.
// Whitespace around tokens is trimmed. Empty tokens after trim are ignored,
// but a value that is only commas or whitespace is an error.
//
//	example.com            -> https://example.com
//	example.com:8443       -> https://example.com:8443
//	https://example.com/foo -> kept as given (https only)
func ParseHosts(value string) ([]*url.URL, error) {
	parts := splitCSV(value)
	if len(parts) == 0 {
		return nil, fmt.Errorf("no hostnames given")
	}
	out := make([]*url.URL, 0, len(parts))
	for _, tok := range parts {
		u, err := parseHostToken(tok)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// ParseNames splits a comma-separated --presets value and checks each name.
// Empty tokens after trim are ignored; a value that is only commas or
// whitespace is an error. Unknown names return the Hosts error.
func ParseNames(value string) ([]string, error) {
	names := splitCSV(value)
	if len(names) == 0 {
		return nil, fmt.Errorf("no preset names given")
	}
	for _, n := range names {
		if _, err := Hosts(n); err != nil {
			return nil, err
		}
	}
	return names, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseHostToken(tok string) (*url.URL, error) {
	if strings.Contains(tok, "://") {
		u, err := url.Parse(tok)
		if err != nil {
			return nil, fmt.Errorf("invalid URL %q: %w", tok, err)
		}
		if !strings.EqualFold(u.Scheme, "https") {
			return nil, fmt.Errorf("unsupported URL scheme %q (https required)", u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("invalid URL %q: missing host", tok)
		}
		if u.User != nil {
			return nil, fmt.Errorf("invalid URL %q: userinfo not allowed", tok)
		}
		if err := validateHostPort(u.Host); err != nil {
			return nil, fmt.Errorf("invalid URL %q: %w", tok, err)
		}
		u.Scheme = "https"
		return u, nil
	}
	if strings.ContainsAny(tok, "/?#") {
		return nil, fmt.Errorf("invalid host %q", tok)
	}
	if err := validateHostPort(tok); err != nil {
		return nil, fmt.Errorf("invalid host %q: %w", tok, err)
	}
	host := tok
	if ip := net.ParseIP(tok); ip != nil && strings.Contains(tok, ":") {
		host = "[" + tok + "]"
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("invalid host %q", tok)
	}
	return u, nil
}

func validateHostPort(hostport string) error {
	host := hostport
	port := ""
	if strings.HasPrefix(hostport, "[") {
		h, p, err := net.SplitHostPort(hostport)
		if err != nil {
			inner := strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
			if inner == hostport || net.ParseIP(inner) == nil {
				return fmt.Errorf("invalid host")
			}
			host = inner
		} else {
			if p == "" {
				return fmt.Errorf("invalid port")
			}
			host, port = h, p
		}
	} else if strings.Count(hostport, ":") == 1 {
		h, p, err := net.SplitHostPort(hostport)
		if err != nil {
			return fmt.Errorf("invalid host")
		}
		if p == "" {
			return fmt.Errorf("invalid port")
		}
		host, port = h, p
	} else if strings.Count(hostport, ":") > 1 {
		if net.ParseIP(hostport) == nil {
			return fmt.Errorf("invalid host")
		}
	}
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return fmt.Errorf("invalid port")
		}
	}
	return validateHost(host)
}

func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if strings.ContainsAny(host, " /\\?#@") {
		return fmt.Errorf("invalid host")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	return validateDNSName(host)
}

func validateDNSName(s string) error {
	if len(s) == 0 || len(s) > 253 {
		return fmt.Errorf("invalid hostname")
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid hostname")
		}
		for i, r := range label {
			if isASCIIAlnum(r) {
				continue
			}
			if r == '-' && i > 0 && i < len(label)-1 {
				continue
			}
			return fmt.Errorf("invalid hostname")
		}
	}
	return nil
}

func isASCIIAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
