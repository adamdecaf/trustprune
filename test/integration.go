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

package test

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Ideas
// - run command w/ matcher
// - verify arbitrary fs layer
// - debug, replay commands/output on failure

type Cmd struct {
	// Embed a `Once` so we can call `exec` only once
	sync.Once

	// Represents the arguments to `os/exec.Command`
	command string
	args    []string

	// Holder of output, always converted to a string for
	// easier comparison and print
	output string

	// Holds the error from an execution
	err error
}

func Command(cmd string, args ...string) *Cmd {
	return &Cmd{
		command: cmd,
		args:    args,
	}
}

// Quick wrapper around platform/arch specific call to trustprune
// which is located at ../bin/trustprune-GOOS-GOARCH
func CertManage(args ...string) *Cmd {
	render := func(tpl string) string {
		return fmt.Sprintf(tpl, runtime.GOARCH)
	}

	switch runtime.GOOS {
	case "darwin":
		return Command(render(filepath.Join("..", "bin", "trustprune-osx-%s")), args...)
	case "linux":
		return Command(render(filepath.Join("..", "bin", "trustprune-linux-%s")), args...)
	case "freebsd":
		return Command(render(filepath.Join("..", "bin", "trustprune-freebsd-%s")), args...)
	case "windows":
		return Command(render(filepath.Join("..", "bin", "trustprune-%s.exe")), args...)
	}
	return nil
}

func (c *Cmd) exec() {
	c.Do(func() {
		cmd := exec.Command(c.command, c.args...)

		// Set output collectors
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		err := cmd.Run()
		c.output = stdout.String()
		if err != nil {
			out := c.output
			c.output = fmt.Sprintf("Stdout:\n%s\nStderr:\n%s\n", out, stderr.String())
		}
		c.err = err
	})
}

func (c *Cmd) Trim() *Cmd {
	c.exec()
	if c.output != "" {
		c.output = strings.TrimSpace(c.output)
	}
	return c
}

func (c *Cmd) CmpInt(t *testing.T, n1 int) {
	t.Helper()
	c.exec()

	c.CmpIntF(t, func(n2 int) bool { return n1 == n2 })
}

func (c *Cmd) CmpIntF(t *testing.T, f func(int) bool) {
	t.Helper()
	c.exec()

	n, err := strconv.Atoi(c.output)
	if err != nil {
		t.Errorf("ERROR: converting %q to integer failed, err=%v", c.output, err)
	}
	if !f(n) {
		t.Errorf("ERROR: got %d", n)
	}
}

func (c *Cmd) FailedT(t *testing.T) {
	t.Helper()
	c.exec()

	if c.err == nil {
		t.Errorf("Expected failure, but seeig none.\n Output: %s", c.output)
	}
}

func (c *Cmd) EqualT(t *testing.T, ans string) {
	t.Helper()
	c.exec()
	if c.output != ans {
		t.Errorf(`ERROR: Output did not match expected answer!
Output: %q
Answer: %q`, c.output, ans)
	}
}

func (c *Cmd) Err() error {
	c.exec()
	return c.err
}

func (c *Cmd) String() string {
	c.exec()

	buf := bytes.NewBufferString(fmt.Sprintf(`Command:
  %s %s
Output:
  %s`, c.command, strings.Join(c.args, " "), c.output))
	if c.err != nil {
		fmt.Fprintf(buf, "\nError:\n  %v", c.err)
	}
	return buf.String()
}

func (c *Cmd) Success() bool {
	c.exec()
	return c.err == nil
}

func (c *Cmd) SuccessT(t *testing.T) {
	t.Helper()
	if !c.Success() {
		t.Errorf(`Expected no error, got err=%v
 Output: %s`, c.err, c.output)
	}
}

func (c *Cmd) PendingT(t *testing.T, reason string) {
	t.Helper()
	c.exec()

	if c.err == nil {
		t.Errorf("Expected failing test, got success. Pending because %s", reason)
	} else {
		t.Skip(reason)
	}
}
