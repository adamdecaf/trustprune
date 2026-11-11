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
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	t.Parallel()

	got := Names()
	if !sort.StringsAreSorted(got) {
		t.Errorf("Names not sorted: %q", got)
	}
	want := []string{
		"apple",
		"apt",
		"darwin",
		"linux",
		"macos",
		"macos-update",
		"windows",
		"windows-update",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Names()=%q want %q", got, want)
	}
	for _, name := range got {
		if name == "time" {
			t.Fatal("time preset should be omitted (OS time servers are NTP-only)")
		}
	}
}

func TestTimePresetOmitted(t *testing.T) {
	t.Parallel()

	// time.apple.com, time.windows.com, and pool.ntp.org speak NTP on
	// UDP/123, not HTTPS. FindCAs only dials https, so there is no time
	// preset and composites do not include one.
	if _, err := Hosts("time"); err == nil {
		t.Fatal("expected unknown preset time")
	}
	if DefaultName("darwin") != "darwin" || DefaultName("windows") != "windows" {
		t.Fatal("platform defaults should still exist without a time preset")
	}
}

func TestLeafHostsWellFormed(t *testing.T) {
	t.Parallel()

	leaves := []string{"apple", "macos-update", "apt", "windows-update"}
	for _, name := range leaves {
		hosts, err := Hosts(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(hosts) == 0 {
			t.Errorf("%s: empty leaf", name)
		}
		seen := make(map[string]struct{}, len(hosts))
		for _, h := range hosts {
			if _, ok := seen[h]; ok {
				t.Errorf("%s: duplicate host %q", name, h)
			}
			seen[h] = struct{}{}
			if strings.Contains(h, "://") || strings.ContainsAny(h, "/?#") {
				t.Errorf("%s: host %q has scheme or path", name, h)
			}
			if err := validateHostPort(h); err != nil {
				t.Errorf("%s: %q: %v", name, h, err)
			}
		}
	}
}

func TestLeafKeyHostsPresent(t *testing.T) {
	t.Parallel()

	must := map[string][]string{
		"apple":          {"apple.com", "appleid.apple.com", "icloud.com", "mzstatic.com"},
		"macos-update":   {"mesu.apple.com", "swcdn.apple.com", "swscan.apple.com", "gdmf.apple.com"},
		"apt":            {"archive.ubuntu.com", "security.ubuntu.com", "deb.debian.org", "security.debian.org", "ppa.launchpadcontent.net"},
		"windows-update": {"windowsupdate.com", "update.microsoft.com", "download.microsoft.com", "ctldl.windowsupdate.com"},
	}
	for name, keys := range must {
		hosts, err := Hosts(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		have := make(map[string]struct{}, len(hosts))
		for _, h := range hosts {
			have[h] = struct{}{}
		}
		for _, k := range keys {
			if _, ok := have[k]; !ok {
				t.Errorf("%s: missing %q in %q", name, k, hosts)
			}
		}
	}
}

func TestCompositesExpand(t *testing.T) {
	t.Parallel()

	darwin, err := Hosts("darwin")
	if err != nil {
		t.Fatal(err)
	}
	macos, err := Hosts("macos")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(darwin, macos) {
		t.Errorf("macos alias: darwin=%q macos=%q", darwin, macos)
	}
	fromParts, err := Expand([]string{"apple", "macos-update"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(darwin, fromParts) {
		t.Errorf("darwin=%q apple+macos-update=%q", darwin, fromParts)
	}

	linux, err := Hosts("linux")
	if err != nil {
		t.Fatal(err)
	}
	apt, err := Hosts("apt")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(linux, apt) {
		t.Errorf("linux=%q apt=%q", linux, apt)
	}

	windows, err := Hosts("windows")
	if err != nil {
		t.Fatal(err)
	}
	wu, err := Hosts("windows-update")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(windows, wu) {
		t.Errorf("windows=%q windows-update=%q", windows, wu)
	}
}

func TestExpandDedupeStableOrder(t *testing.T) {
	t.Parallel()

	got, err := Expand([]string{"darwin", "apple", "macos"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := Expand([]string{"darwin"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dedupe: got %q want %q", got, want)
	}

	mixed, err := Expand([]string{"linux", "apple"})
	if err != nil {
		t.Fatal(err)
	}
	linux, err := Hosts("linux")
	if err != nil {
		t.Fatal(err)
	}
	apple, err := Hosts("apple")
	if err != nil {
		t.Fatal(err)
	}
	wantMixed := append(append([]string{}, linux...), apple...)
	if !reflect.DeepEqual(mixed, wantMixed) {
		t.Errorf("order: got %q want %q", mixed, wantMixed)
	}
}

func TestDefaultName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		goos string
		want string
	}{
		{"darwin", "darwin"},
		{"linux", "linux"},
		{"windows", "windows"},
		{"freebsd", ""},
		{"js", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := DefaultName(c.goos); got != c.want {
			t.Errorf("DefaultName(%q)=%q want %q", c.goos, got, c.want)
		}
	}
}

func TestUnknownName(t *testing.T) {
	t.Parallel()

	if _, err := Hosts("nope"); err == nil || !strings.Contains(err.Error(), `unknown preset "nope"`) {
		t.Errorf("Hosts: %v", err)
	}
	if _, err := Expand([]string{"linux", "nope"}); err == nil || !strings.Contains(err.Error(), `unknown preset "nope"`) {
		t.Errorf("Expand: %v", err)
	}
	if _, err := URLs([]string{"nope"}); err == nil {
		t.Error("URLs: expected error")
	}
}

func TestURLs(t *testing.T) {
	t.Parallel()

	urls, err := URLs([]string{"linux", "linux"})
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := Hosts("linux")
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != len(hosts) {
		t.Fatalf("len urls=%d hosts=%d", len(urls), len(hosts))
	}
	for i, u := range urls {
		if u.Scheme != "https" || u.Host != hosts[i] || u.Path != "" {
			t.Errorf("url[%d]=%s want https://%s", i, u, hosts[i])
		}
	}
}

func TestHostsCopy(t *testing.T) {
	t.Parallel()

	a, err := Hosts("apt")
	if err != nil {
		t.Fatal(err)
	}
	a[0] = "mutated.example"
	b, err := Hosts("apt")
	if err != nil {
		t.Fatal(err)
	}
	if b[0] == "mutated.example" {
		t.Fatal("Hosts returned a shared slice")
	}
}

func TestParseNames(t *testing.T) {
	t.Parallel()

	got, err := ParseNames(" linux, DARWIN ")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"linux", "DARWIN"}) {
		t.Errorf("got %q", got)
	}
	if _, err := ParseNames(" , , "); err == nil {
		t.Fatal("expected error for commas only")
	}
	if _, err := ParseNames("linux,nope"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("unknown: %v", err)
	}
}
