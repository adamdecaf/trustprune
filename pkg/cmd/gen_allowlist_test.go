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

package cmd

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestGenAllowlist_getChoices(t *testing.T) {
	t.Parallel()

	// left off '-from file'
	choices := getChoices("", "/dev/null")
	if !reflect.DeepEqual(choices, []string{"file"}) {
		t.Errorf("got %q", choices)
	}

	// has '-from file'
	choices = getChoices("file", "/dev/null")
	if !reflect.DeepEqual(choices, []string{"file"}) {
		t.Errorf("got %q", choices)
	}

	// browser
	choices = getChoices("browser", "")
	if !reflect.DeepEqual(choices, []string{"browser"}) {
		t.Errorf("got %q", choices)
	}

	// comma separated list
	choices = getChoices("browser,file", "")
	if !reflect.DeepEqual(choices, []string{"browser", "file"}) {
		t.Errorf("got %q", choices)
	}

	// neither --from nor --file
	choices = getChoices("", "")
	if choices != nil {
		t.Errorf("got %q", choices)
	}
}

func TestGenAllowlist_accumulateUrls(t *testing.T) {
	t.Parallel()

	uacc := make(chan []*url.URL)
	eacc := make(chan error)
	wg := sync.WaitGroup{}

	// happy path
	fn := func() ([]*url.URL, error) {
		defer wg.Done()
		u, _ := url.Parse("https://github.com")
		return []*url.URL{u}, nil
	}
	wg.Add(1)
	go accumulateUrls(fn, uacc, eacc)
	wg.Wait() // just so we ensure the code finished

	select {
	case urls := <-uacc:
		if len(urls) != 1 {
			t.Errorf("got %q", urls)
		}
	case err := <-eacc:
		t.Error(err)
	}

	// unhappy path
	fn = func() ([]*url.URL, error) {
		defer wg.Done()
		return nil, errors.New("whoops")
	}
	wg.Add(1)
	go accumulateUrls(fn, uacc, eacc)
	wg.Wait() // just so we ensure the code finished

	select {
	case urls := <-uacc:
		t.Errorf("expected error, got %q", urls)
	case err := <-eacc:
		if !strings.Contains(err.Error(), "whoops") {
			t.Errorf("got %q", err)
		}
	}
}

func TestAssembleAllowlistURLs(t *testing.T) {
	t.Parallel()

	mustURL := func(s string) *url.URL {
		t.Helper()
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	fileURLs := []*url.URL{
		mustURL("https://google.com"),
		mustURL("https://yahoo.com"),
	}

	t.Run("hosts plus default GOOS linux", func(t *testing.T) {
		got, err := assembleAllowlistURLs(fileURLs, GenerateAllowlistOptions{
			Hosts: "example.com,api.example.com",
			GOOS:  "linux",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !hasURL(got, "https://google.com") || !hasURL(got, "https://example.com") || !hasURL(got, "https://archive.ubuntu.com") {
			t.Errorf("missing expected urls: %q", urlStrings(got))
		}
		if !hasURL(got, "https://api.example.com") {
			t.Errorf("missing host: %q", urlStrings(got))
		}
	})

	t.Run("explicit presets ignore GOOS", func(t *testing.T) {
		got, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Hosts:   "example.com",
			Presets: "linux",
			GOOS:    "darwin",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !hasURL(got, "https://example.com") || !hasURL(got, "https://archive.ubuntu.com") {
			t.Errorf("got %q", urlStrings(got))
		}
		if hasURL(got, "https://apple.com") {
			t.Errorf("darwin hosts leaked into linux presets: %q", urlStrings(got))
		}
	})

	t.Run("no-presets skips default GOOS", func(t *testing.T) {
		got, err := assembleAllowlistURLs(fileURLs, GenerateAllowlistOptions{
			Hosts:     "example.com",
			NoPresets: true,
			GOOS:      "linux",
		})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"https://google.com", "https://yahoo.com", "https://example.com"}
		if !reflect.DeepEqual(urlStrings(got), want) {
			t.Errorf("got %q want %q", urlStrings(got), want)
		}
	})

	t.Run("freebsd has no default preset", func(t *testing.T) {
		got, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Hosts: "example.com",
			GOOS:  "freebsd",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(urlStrings(got), []string{"https://example.com"}) {
			t.Errorf("got %q", urlStrings(got))
		}
	})

	t.Run("overlapping host is not duplicated", func(t *testing.T) {
		got, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Hosts:   "archive.ubuntu.com,https://archive.ubuntu.com/ubuntu",
			Presets: "linux",
		})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, u := range got {
			if u.Host == "archive.ubuntu.com" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("archive.ubuntu.com count=%d in %q", n, urlStrings(got))
		}
	})

	t.Run("conflicting flags", func(t *testing.T) {
		_, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Presets:   "linux",
			NoPresets: true,
		})
		if err == nil || !strings.Contains(err.Error(), "--presets") {
			t.Errorf("got %v", err)
		}
	})

	t.Run("unknown preset", func(t *testing.T) {
		_, err := assembleAllowlistURLs(nil, GenerateAllowlistOptions{
			Presets: "nope",
		})
		if err == nil || !strings.Contains(err.Error(), "unknown preset") {
			t.Errorf("got %v", err)
		}
	})
}

func TestResolvePresetNames(t *testing.T) {
	t.Parallel()

	got, err := resolvePresetNames("", false, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"linux"}) {
		t.Errorf("got %q", got)
	}

	got, err = resolvePresetNames("", true, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("no-presets got %q", got)
	}

	got, err = resolvePresetNames("apple", false, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"apple"}) {
		t.Errorf("got %q", got)
	}
}

func urlStrings(urls []*url.URL) []string {
	out := make([]string, len(urls))
	for i, u := range urls {
		out[i] = u.String()
	}
	return out
}

func hasURL(urls []*url.URL, want string) bool {
	for _, u := range urls {
		if u.String() == want {
			return true
		}
	}
	return false
}
