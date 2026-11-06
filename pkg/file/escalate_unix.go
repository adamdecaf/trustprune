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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Hooks for tests. Production uses os.Getuid and exec.LookPath/Command.
var (
	elevateGetuid   = os.Getuid
	elevateLookPath = exec.LookPath
	elevateCommand  = exec.Command
)

// ElevatedCommand returns a command that runs args as root when needed.
// Already-root processes run args directly. Otherwise sudo is preferred when
// present on PATH; if sudo is missing, su -c is used. When neither tool is
// available, an error explains how to proceed. Callers must not assume sudo
// exists on every install (issue #134). Password prompts (sudo/su) use the
// controlling TTY when the process has one; non-interactive hosts need
// cached credentials or a root shell.
func ElevatedCommand(args ...string) (*exec.Cmd, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, errors.New("ElevatedCommand: empty argv")
	}
	if elevateGetuid() == 0 {
		argv := absArgv(args)
		return elevateCommand(argv[0], argv[1:]...), nil
	}
	if sudo, err := elevateLookPath("sudo"); err == nil {
		// Keep bare names so sudo can apply secure_path; leave absolute
		// paths unchanged. Never pre-resolve from the caller's PATH.
		return elevateCommand(sudo, args...), nil
	}
	if su, err := elevateLookPath("su"); err == nil {
		// Place -c after the login name so FreeBSD/Darwin pass it to the
		// target login shell (FreeBSD su -c *before* login is a class).
		// Linux util-linux likewise forwards post-login args to the shell.
		// Resolve bare names from trusted dirs only — su may reset PATH.
		argv := trustedAbsArgv(args)
		return elevateCommand(su, "root", "-c", posixJoin(argv)), nil
	}
	return nil, fmt.Errorf("need root to run %s; sudo and su not found on PATH (re-run as root, or install sudo/su)", args[0])
}

// trustedBinDirs are fixed locations used when resolving bare names for su.
// Caller's PATH is not consulted so a writable earlier entry cannot supply
// the elevated binary.
var trustedBinDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}

// absArgv copies args and replaces a bare args[0] with LookPath's result.
// Used only for already-root execution.
func absArgv(args []string) []string {
	out := append([]string{}, args...)
	if filepath.IsAbs(args[0]) {
		return out
	}
	if p, err := elevateLookPath(args[0]); err == nil {
		out[0] = p
	}
	return out
}

// trustedAbsArgv copies args and, for a bare args[0], replaces it with the
// first match under trustedBinDirs. Absolute paths are preserved as-is.
func trustedAbsArgv(args []string) []string {
	out := append([]string{}, args...)
	if filepath.IsAbs(args[0]) {
		return out
	}
	base := args[0]
	if strings.Contains(base, string(os.PathSeparator)) {
		// Relative path with a slash — do not search PATH; leave unchanged.
		return out
	}
	for _, dir := range trustedBinDirs {
		p := filepath.Join(dir, base)
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		out[0] = p
		return out
	}
	return out
}

// posixJoin quotes args for a single su -c shell command.
func posixJoin(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = "'" + strings.ReplaceAll(a, "'", `'"'"'`) + "'"
	}
	return strings.Join(parts, " ")
}
