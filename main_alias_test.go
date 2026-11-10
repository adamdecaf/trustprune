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
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestInvokedAsCertManage(t *testing.T) {
	cases := []struct {
		arg0 string
		want bool
	}{
		{"trustprune", false},
		{"/usr/local/bin/trustprune", false},
		{"cert-manage", true},
		{"/usr/local/bin/cert-manage", true},
		{"cert-manage.exe", true},
		{filepath.Join("C:", "bin", "cert-manage.exe"), true},
		{"cert-manage-linux-amd64", true},
		{"trustprune-linux-amd64", false},
	}
	for _, tc := range cases {
		if got := invokedAsCertManage(tc.arg0); got != tc.want {
			t.Errorf("invokedAsCertManage(%q)=%v want %v", tc.arg0, got, tc.want)
		}
	}
}

func TestCertManageAliasActive(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"0.1.1-dev", true},
		{"0.2.0", true},
		{"0.2.9", true},
		{"v0.2.0", true},
		{"0.3.0", false},
		{"1.0.0", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := certManageAliasActive(tc.version); got != tc.want {
			t.Errorf("certManageAliasActive(%q)=%v want %v", tc.version, got, tc.want)
		}
	}
}

func TestCertManageAliasNoticePrinted(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	maybePrintCertManageAliasNotice("cert-manage", w)
	_ = w.Close()
	os.Stderr = old
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("renamed to trustprune")) {
		t.Fatalf("missing rename notice, got %q", out)
	}
	if !bytes.Contains(out, []byte("alias through 0.2.x")) {
		t.Fatalf("missing alias window, got %q", out)
	}
}

func TestCertManageAliasNoticeSkippedForTrustprune(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	maybePrintCertManageAliasNotice("trustprune", w)
	_ = w.Close()
	os.Stderr = old
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no notice for trustprune, got %q", out)
	}
}
