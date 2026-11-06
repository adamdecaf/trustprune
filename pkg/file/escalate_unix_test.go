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
	"os"
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
	withElevateHooks(t, func() int { return 0 }, func(name string) (string, error) {
		if name == "/usr/sbin/update-ca-certificates" {
			return name, nil
		}
		t.Fatalf("unexpected LookPath(%q)", name)
		return "", errors.New("unused")
	})
	cmd, err := ElevatedCommand("/usr/sbin/update-ca-certificates")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Args) != 1 || cmd.Args[0] != "/usr/sbin/update-ca-certificates" {
		t.Fatalf("args=%v", cmd.Args)
	}
}

func TestElevatedCommand_prefersSudo(t *testing.T) {
	withElevateHooks(t, func() int { return 1000 }, func(name string) (string, error) {
		switch name {
		case "sudo":
			return "/usr/bin/sudo", nil
		case "/bin/true", "true":
			return "/bin/true", nil
		default:
			return "", exec.ErrNotFound
		}
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
		switch name {
		case "su":
			return "/bin/su", nil
		case "true":
			return "/usr/bin/true", nil
		default:
			return "", exec.ErrNotFound
		}
	})
	cmd, err := ElevatedCommand("true", "x y")
	if err != nil {
		t.Fatal(err)
	}
	// su root -c '<quoted argv>' ( -c after login → shell, not FreeBSD class)
	if len(cmd.Args) != 4 || cmd.Args[0] != "/bin/su" || cmd.Args[1] != "root" || cmd.Args[2] != "-c" {
		t.Fatalf("args=%v", cmd.Args)
	}
	if !strings.Contains(cmd.Args[3], "/usr/bin/true") || !strings.Contains(cmd.Args[3], `'x y'`) {
		t.Fatalf("su payload=%q", cmd.Args[3])
	}
}

func TestElevatedCommand_suExecutesPayload(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	payload := filepath.Join(dir, "payload.sh")
	if err := os.WriteFile(payload, []byte("#!/bin/sh\n echo ok > '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	suPath := filepath.Join(dir, "su")
	// Emulate FreeBSD/Darwin/Linux post-login args: su root -c '<cmd>'
	suScript := "#!/bin/sh\n" +
		"if [ \"$1\" != \"root\" ] || [ \"$2\" != \"-c\" ] || [ -z \"$3\" ]; then\n" +
		"\techo \"bad su args: $*\" >&2\n" +
		"\texit 2\n" +
		"fi\n" +
		"exec /bin/sh -c \"$3\"\n"
	if err := os.WriteFile(suPath, []byte(suScript), 0o755); err != nil {
		t.Fatal(err)
	}
	withElevateHooks(t, func() int { return 1000 }, func(name string) (string, error) {
		switch name {
		case "su":
			return suPath, nil
		case payload:
			return payload, nil
		default:
			return "", exec.ErrNotFound
		}
	})
	cmd, err := ElevatedCommand(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v out=%s", err, out)
	}
	b, err := os.ReadFile(marker)
	if err != nil || strings.TrimSpace(string(b)) != "ok" {
		t.Fatalf("marker=%q err=%v", b, err)
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
