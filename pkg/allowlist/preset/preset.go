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

// Package preset is a data-driven set of named hostname lists used when
// generating allowlists. Leaf presets hold bare hostnames (no scheme).
// Composite platform aliases expand to those smaller lists so hosts are
// not duplicated.
//
// FindCAs only dials https, so every host here is expected to speak HTTPS
// on 443. There is no "time" preset: OS time servers (time.apple.com,
// time.windows.com, pool.ntp.org) speak NTP on UDP/123 and would always
// fail TLS. darwin and windows therefore omit time.
package preset

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type spec struct {
	// hosts is set on leaf presets.
	hosts []string
	// parts names leaf presets that a composite expands to.
	parts []string
}

var specs = map[string]spec{
	// apple: well-known Apple HTTPS service/resource hosts. Small and
	// obvious, not an exhaustive CDN or API list.
	"apple": {hosts: []string{
		"apple.com",
		"appleid.apple.com",
		"icloud.com",
		"mzstatic.com",
		"itunes.apple.com",
	}},

	// macos-update: Apple software-update and configuration hosts that
	// use HTTPS (catalog, CDN, scan, MDM manifest, Gatekeeper).
	"macos-update": {hosts: []string{
		"mesu.apple.com",
		"swcdn.apple.com",
		"swscan.apple.com",
		"gdmf.apple.com",
		"gg.apple.com",
	}},

	// apt: Debian/Ubuntu apt HTTPS indexes, plus a couple of Fedora and
	// Rocky package-index HTTPS hosts. Not every mirror.
	"apt": {hosts: []string{
		"archive.ubuntu.com",
		"security.ubuntu.com",
		"deb.debian.org",
		"security.debian.org",
		"ppa.launchpadcontent.net",
		"download.fedoraproject.org",
		"download.rockylinux.org",
	}},

	// windows-update: Microsoft update and download HTTPS hosts, including
	// the certificate trust list endpoint. Short, well-known names only.
	"windows-update": {hosts: []string{
		"windowsupdate.com",
		"update.microsoft.com",
		"download.microsoft.com",
		"ctldl.windowsupdate.com",
	}},

	"darwin":  {parts: []string{"apple", "macos-update"}},
	"linux":   {parts: []string{"apt"}},
	"windows": {parts: []string{"windows-update"}},
}

var aliases = map[string]string{
	"macos": "darwin",
}

// Names returns every preset name, including composites and aliases, in
// sorted order.
func Names() []string {
	seen := make(map[string]struct{}, len(specs)+len(aliases))
	out := make([]string, 0, len(specs)+len(aliases))
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for name := range specs {
		add(name)
	}
	for name := range aliases {
		add(name)
	}
	sort.Strings(out)
	return out
}

// Hosts returns the hostname list for a named preset. Composites and
// aliases are expanded. The returned slice is a copy. Unknown names return
// an error so the caller can treat it as a usage error.
func Hosts(name string) ([]string, error) {
	hosts, err := hostsOf(name, nil)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(hosts))
	copy(out, hosts)
	return out, nil
}

// DefaultName returns the platform composite for a GOOS value ("darwin",
// "linux", "windows"). Other values (for example "freebsd") return "".
func DefaultName(goos string) string {
	switch goos {
	case "darwin", "linux", "windows":
		return goos
	default:
		return ""
	}
}

// Expand expands named presets (including composites and aliases),
// deduplicates hostnames, and returns them in a stable order: the order
// of names, then each name's hosts in data order, skipping duplicates.
func Expand(names []string) ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	for _, name := range names {
		hosts, err := hostsOf(name, nil)
		if err != nil {
			return nil, err
		}
		for _, h := range hosts {
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out, nil
}

// URLs expands names like Expand and returns https:// URLs, one per host,
// already deduplicated.
func URLs(names []string) ([]*url.URL, error) {
	hosts, err := Expand(names)
	if err != nil {
		return nil, err
	}
	out := make([]*url.URL, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		u, err := url.Parse("https://" + h)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("invalid preset host %q", h)
		}
		if _, ok := seen[u.Host]; ok {
			continue
		}
		seen[u.Host] = struct{}{}
		out = append(out, u)
	}
	return out, nil
}

func hostsOf(name string, stack map[string]struct{}) ([]string, error) {
	canonical, err := canonicalName(name)
	if err != nil {
		return nil, err
	}
	sp := specs[canonical]
	if len(sp.parts) == 0 {
		return sp.hosts, nil
	}
	if stack == nil {
		stack = make(map[string]struct{})
	}
	if _, ok := stack[canonical]; ok {
		return nil, fmt.Errorf("preset cycle involving %q", canonical)
	}
	stack[canonical] = struct{}{}
	var out []string
	seen := make(map[string]struct{})
	for _, part := range sp.parts {
		hosts, err := hostsOf(part, stack)
		if err != nil {
			return nil, err
		}
		for _, h := range hosts {
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	delete(stack, canonical)
	return out, nil
}

func canonicalName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "", fmt.Errorf("unknown preset %q", name)
	}
	if alias, ok := aliases[name]; ok {
		name = alias
	}
	if _, ok := specs[name]; !ok {
		return "", fmt.Errorf("unknown preset %q", name)
	}
	return name, nil
}
