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

//go:build darwin
// +build darwin

package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/file"
)

var ktool keytool

func init() {
	ktool = keytool{
		javahome:              os.Getenv("JAVA_HOME"),
		javaInstallPaths:      darwinJavaInstallPaths(),
		relativeKeystorePaths: darwinRelativeKeystorePaths,
	}
}

var darwinRelativeKeystorePaths = []string{
	"/lib/security/cacerts",
	"/jre/lib/security/cacerts", // older JDK/JRE layouts
}

// darwinJavaInstallPaths prefers java_home output, then individual JVMs under
// /Library/Java/JavaVirtualMachines, then common Homebrew OpenJDK prefixes.
func darwinJavaInstallPaths() []string {
	var paths []string
	if home := expandKnownJavaInstall(); home != "" {
		paths = append(paths, home)
	}
	paths = append(paths, listDarwinJVMHomes()...)
	paths = append(paths, homebrewJDKHomes([]string{"/opt/homebrew", "/usr/local"})...)
	paths = append(paths,
		"/opt/homebrew/opt/openjdk",
		"/opt/homebrew/opt/openjdk@21",
		"/opt/homebrew/opt/openjdk@17",
		"/usr/local/opt/openjdk",
		"/usr/local/opt/openjdk@21",
		"/usr/local/opt/openjdk@17",
	)
	return paths
}

// homebrewJDKHomes returns Homebrew OpenJDK homes under each prefix
// (opt/openjdk*/libexec/openjdk.jdk/Contents/Home).
func homebrewJDKHomes(prefixes []string) []string {
	var out []string
	for _, prefix := range prefixes {
		matches, err := filepath.Glob(filepath.Join(prefix, "opt", "openjdk*", "libexec", "openjdk.jdk", "Contents", "Home"))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && st.IsDir() {
				out = append(out, m)
			}
		}
	}
	return out
}

func listDarwinJVMHomes() []string {
	root := "/Library/Java/JavaVirtualMachines"
	matches, err := filepath.Glob(filepath.Join(root, "*", "Contents", "Home"))
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range matches {
		if st, err := os.Stat(m); err == nil && st.IsDir() {
			out = append(out, m)
		}
	}
	return out
}

func expandKnownJavaInstall() string {
	candidates := []string{
		"/usr/libexec/java_home",
		"/System/Library/Frameworks/JavaVM.framework/Versions/Current/Commands/java_home",
	}
	for _, full := range candidates {
		if !(file.Exists(full) && file.IsExecutable(full)) {
			continue
		}
		out, err := exec.Command(full).Output()
		if err != nil {
			continue
		}
		home := filepath.Clean(strings.TrimSpace(string(out)))
		if home != "" {
			return home
		}
	}
	return ""
}
