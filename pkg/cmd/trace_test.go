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
	"path/filepath"
	"testing"
)

func TestNewTraceEmpty(t *testing.T) {
	t.Parallel()
	tr, err := NewTrace("")
	if err != nil || tr != nil {
		t.Fatalf("empty path: tr=%v err=%v", tr, err)
	}
}

func TestNewTraceBadPath(t *testing.T) {
	t.Parallel()
	_, err := NewTrace(filepath.Join(t.TempDir(), "missing", "trace.out"))
	if err == nil {
		t.Fatal("expected error for missing parent dir")
	}
}

func TestTraceStartStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.out")
	tr, err := NewTrace(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestTraceNilMethods(t *testing.T) {
	t.Parallel()
	var tr *Trace
	if err := tr.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Stop(); err != nil {
		t.Fatal(err)
	}
}
