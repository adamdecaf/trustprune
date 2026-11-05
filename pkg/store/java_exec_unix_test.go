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

//go:build unix

package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJava_SudoChildHoldsStdoutTimesOut(t *testing.T) {
	javaHome := javaFailFastEnv(t)
	kpath := writeDummyCacerts(t, javaHome)
	// Child keeps stdout open after this process is killed (the sudo hang).
	writeFakeKeytool(t, javaHome, "sleep 60 &\nwait")

	sudoPath := filepath.Join(t.TempDir(), "sudo")
	// Do not exec: killing this wrapper must leave keytool running, like sudo.
	if err := os.WriteFile(sudoPath, []byte("#!/bin/sh\n\"$@\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	keytoolSudoPath = sudoPath
	keytoolTimeout = 400 * time.Millisecond

	started := time.Now()
	_, err := javaStore{}.tool().runKeytool(kpath, []string{"-list"}, true)
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("took %s, want timeout under 5s (child held stdout): %v", elapsed, err)
	}
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(started); elapsed < 200*time.Millisecond {
		t.Fatalf("timeout returned too quickly (%s); child should block until the context fires", elapsed)
	}
	assertJavaFailsFast(t, err, "timed out", started)
}
