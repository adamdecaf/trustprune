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

package ui

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/adamdecaf/trustprune/pkg/ui/server"
)

func Open() error {
	addr := server.Address()
	// Always print the URL so headless / no-browser environments can open it.
	fmt.Printf("Web UI: %s\n", addr)

	var command string
	switch runtime.GOOS {
	case "darwin":
		command = "open"
	case "linux":
		command = "xdg-open"
	}

	if command != "" {
		cmd := exec.Command(command, addr)
		_, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Could not open a browser (%v). Open the URL above manually.\n", err)
			// Keep serving: headless hosts and locked-down desktops still need the URL.
			return nil
		}
		return nil
	}

	fmt.Printf("WARN: automatic browser open not supported on %s yet; open the URL above\n", runtime.GOOS)
	return nil
}
