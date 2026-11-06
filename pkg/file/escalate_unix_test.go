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

//go:build darwin || linux || freebsd
// +build darwin linux freebsd

package file

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func withElevateHooks(t *testing.T, getuid func() int, lookPath func(string) (string, error)) {
	t.Helper()
	origUID, origLook, origCmd := elevateGetuid, elevateLookPath, elevateCommand
	t.Cleanup(func() {
		elevateGetuid = origUID
		elevateLookPath = origLook
		elevateCommand = origCmd
	})
	elevateGetuid = getuid
	elevateLookPath = lookPath
	// Keep elevateCommand as exec.Command so Path/Args are real; we only
	// inspect the returned Cmd without running it.
}

func TestElevatedCommand_rootRunsDirect(t *testing.T) {
	withElevateHooks(t, func() int { return 0 }, func(string) (string, error) {
		t.Fatal("LookPath should not be called when already root")
		return "", errors.New("unused")
	})
	cmd, err := ElevatedCommand("/usr/sbin/update-ca-certificates")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != "/usr/sbin/update-ca-certificates" && filepath.Base(cmd.Path) != "update-ca-certificates" {
		// exec.Command may leave Path as the bare name when not looked up.
		if cmd.Args[0] != "/usr/sbin/update-ca-certificates" {
			t.Fatalf("args=%v", cmd.Args)
		}
	}
	if len(cmd.Args) != 1 || cmd.Args[0] != "/usr/sbin/update-ca-certificates" {
		t.Fatalf("args=%v", cmd.Args)
	}
}

func TestElevatedCommand_prefersSudo(t *testing.T) {
	withElevateHooks(t, func() int { return 1000 }, func(name string) (string, error) {
		if name == "sudo" {
			return "/usr/bin/sudo", nil
		}
		return "", exec.ErrNotFound
	})
	cmd, err := ElevatedCommand("/bin/true", "a")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Args[0] != "/usr/bin/sudo" || cmd.Args[1] != "/bin/true" || cmd.Args[2] != "a" {
		t.Fatalf("args=%v", cmd.Args)
	}
}

func TestElevatedCommand_fallsBackToSu(t *testing.T) {
	withElevateHooks(t, func() int { return 1000 }, func(name string) (string, error) {
		if name == "su" {
			return "/bin/su", nil
		}
		return "", exec.ErrNotFound
	})
	cmd, err := ElevatedCommand("/bin/true", "x y")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Args[0] != "/bin/su" || cmd.Args[1] != "-c" {
		t.Fatalf("args=%v", cmd.Args)
	}
	if !strings.Contains(cmd.Args[2], "/bin/true") || !strings.Contains(cmd.Args[2], `'x y'`) {
		t.Fatalf("su -c payload=%q", cmd.Args[2])
	}
}

func TestElevatedCommand_neitherTool(t *testing.T) {
	withElevateHooks(t, func() int { return 1000 }, func(string) (string, error) {
		return "", exec.ErrNotFound
	})
	_, err := ElevatedCommand("/bin/true")
	if err == nil || !strings.Contains(err.Error(), "sudo and su not found") {
		t.Fatalf("err=%v", err)
	}
}

func TestElevatedCommand_empty(t *testing.T) {
	_, err := ElevatedCommand()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPosixJoin(t *testing.T) {
	got := posixJoin([]string{"/bin/echo", "a'b", "c"})
	want := `'/bin/echo' 'a'"'"'b' 'c'`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
