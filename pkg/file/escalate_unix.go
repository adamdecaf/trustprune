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
// exists on every install (issue #134).
func ElevatedCommand(args ...string) (*exec.Cmd, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, errors.New("ElevatedCommand: empty argv")
	}
	if elevateGetuid() == 0 {
		return elevateCommand(args[0], args[1:]...), nil
	}
	if sudo, err := elevateLookPath("sudo"); err == nil {
		return elevateCommand(sudo, args...), nil
	}
	if su, err := elevateLookPath("su"); err == nil {
		return elevateCommand(su, "-c", posixJoin(args)), nil
	}
	return nil, fmt.Errorf("need root to run %s; sudo and su not found on PATH (re-run as root, or install sudo/su)", args[0])
}

// posixJoin quotes args for a single su -c shell command.
func posixJoin(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = "'" + strings.ReplaceAll(a, "'", `'"'"'`) + "'"
	}
	return strings.Join(parts, " ")
}
