// Copyright 2026 Adam Shannon
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
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

const (
	// javaStorePassEnv is the keystore password override. It matches
	// pkg/store/java.go: a non-empty trimmed value replaces "changeit".
	// There is no CLI flag, so the secret is not on trustprune's argv.
	javaStorePassEnv = "TRUSTPRUNE_JAVA_STOREPASS"

	// defaultJavaStorePassword is Java's standard cacerts password.
	defaultJavaStorePassword = "changeit"
)

// createKeytoolTimeout bounds every keytool process so a password prompt
// or a hung child cannot block forever. Tests shorten it.
var createKeytoolTimeout = 30 * time.Second

// createKeytoolWaitDelay bounds how long Run waits for I/O after the
// process is canceled.
var createKeytoolWaitDelay = 2 * time.Second

// writeJavaTruststore writes certs into a new JKS or PKCS12 truststore at
// path. keytool creates the file. golang.org/x/crypto/pkcs12 in this module
// only decodes a PKCS#12, and nothing here writes JKS, so both formats go
// through keytool -importcert -storetype.
//
// The store password matches pkg/store/java.go: "changeit" is passed as
// -storepass, and any other password is passed as -storepass:env
// TRUSTPRUNE_JAVA_STOREPASS with the trimmed value only in the child
// environment. The password is not logged.
//
// Bytes land in a sibling temp file. path is replaced only after every
// import and the chmod succeed, so a failure leaves an existing path
// untouched. No source store is opened for writing.
func writeJavaTruststore(path, format string, certs []*x509.Certificate) error {
	if strings.TrimSpace(path) == "" {
		return CreateOutRequiredError(format)
	}
	storeType, err := javaTruststoreType(format)
	if err != nil {
		return err
	}
	bin, err := findCreateKeytool()
	if err != nil {
		return err
	}
	passFlags, extraEnv, pass := createStorepass()

	dir := filepath.Dir(path)
	// #nosec G301 -- private scratch dir for PEM inputs; removed before return
	work, err := os.MkdirTemp(dir, ".trustprune-create-certs-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()

	// keytool refuses an empty file ("Keystore file exists, but is empty"),
	// so take a unique name in the destination directory and remove the
	// placeholder. The rename stays on one filesystem.
	// #nosec G304 -- --out's directory is the user-requested destination
	tmp, err := os.CreateTemp(dir, ".trustprune-create-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = os.Remove(tmpName)
		}
	}()

	imported := 0
	seen := make(map[string]struct{}, len(certs))
	for i := range certs {
		cert := certs[i]
		if cert == nil {
			continue
		}
		alias := javaTruststoreAlias(cert)
		if _, ok := seen[alias]; ok {
			continue
		}
		seen[alias] = struct{}{}
		pemPath := filepath.Join(work, fmt.Sprintf("%d.pem", imported))
		body, err := certutil.EncodePEMEntries([]certutil.PEMEntry{{Cert: cert}})
		if err != nil {
			return err
		}
		// #nosec G306 -- temp cert is removed with the scratch dir; 0600 keeps it private
		if err := os.WriteFile(pemPath, body, 0o600); err != nil {
			return err
		}
		args := []string{
			"-importcert",
			"-noprompt",
			"-alias", alias,
			"-file", pemPath,
			"-keystore", tmpName,
			"-storetype", storeType,
		}
		args = append(args, passFlags...)
		if err := runCreateKeytool(bin, args, extraEnv, pass); err != nil {
			return err
		}
		imported++
	}
	if imported == 0 {
		return ErrNoMatchingCerts
	}
	st, err := os.Stat(tmpName)
	if err != nil {
		return fmt.Errorf("keytool did not write a truststore: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return errors.New("keytool did not write a truststore")
	}
	// CreateTemp's placeholder was removed. keytool's umask may be tighter
	// than 0644. CA truststores are public certificates, same as PEM bundles.
	if err := os.Chmod(tmpName, createFilePerm); err != nil { //nolint:gosec // G302: truststores hold public CA certificates and are world-readable by design
		return err
	}
	// #nosec G304 -- --out is the user-requested truststore path
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	published = true
	return nil
}

func javaTruststoreType(format string) (string, error) {
	switch format {
	case createFormatJKS:
		return "JKS", nil
	case createFormatPKCS12:
		return "PKCS12", nil
	default:
		return "", fmt.Errorf("unknown format %q (formats: %s)", format, CreateFormats)
	}
}

// javaTruststoreAlias is stable and unique for a certificate. keytool
// treats aliases as case-insensitive, so the fingerprint is lowercase hex.
func javaTruststoreAlias(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return "sha256-" + certutil.GetHexSHA256Fingerprint(*cert)
}

// createStorepass matches pkg/store.prepareStorepass. The default
// "changeit" stays on argv as -storepass. A custom password uses
// -storepass:env so it is not on the keytool command line.
func createStorepass() (flags []string, env []string, pass string) {
	pass = defaultJavaStorePassword
	if v := strings.TrimSpace(os.Getenv(javaStorePassEnv)); v != "" {
		pass = v
	}
	if pass == defaultJavaStorePassword {
		return []string{"-storepass", defaultJavaStorePassword}, nil, pass
	}
	return []string{"-storepass:env", javaStorePassEnv},
		[]string{javaStorePassEnv + "=" + pass}, pass
}

// findCreateKeytool resolves keytool the way pkg/store/java.go does
// (JAVA_HOME/bin, then PATH) and also checks ~/.local/bin, which is where
// a user-local JDK is installed when it is not on PATH.
func findCreateKeytool() (string, error) {
	if home := strings.TrimSpace(os.Getenv("JAVA_HOME")); home != "" {
		if p := keytoolInDir(filepath.Join(home, "bin")); p != "" {
			return p, nil
		}
	}
	if p, err := exec.LookPath("keytool"); err == nil {
		return p, nil
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		if p := keytoolInDir(filepath.Join(home, ".local", "bin")); p != "" {
			return p, nil
		}
	}
	return "", errors.New("keytool not found; install a JDK, set JAVA_HOME, or put keytool on PATH (also checked ~/.local/bin) to write a Java truststore")
}

func keytoolInDir(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	names := []string{"keytool"}
	if runtime.GOOS == "windows" {
		names = []string{"keytool.exe", "keytool.bat", "keytool.cmd", "keytool"}
	}
	for _, name := range names {
		p := filepath.Join(dir, name)
		// Directory is JAVA_HOME/bin or ~/.local/bin. The file name is a fixed keytool candidate.
		st, err := os.Stat(p) //nolint:gosec // G703: not a user-controlled relative path; keytool lookup only
		if err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func mergeCreateEnviron(base, overrides []string) []string {
	if len(overrides) == 0 {
		return base
	}
	if base == nil {
		base = os.Environ()
	}
	drop := make(map[string]struct{}, len(overrides))
	for _, o := range overrides {
		if i := strings.IndexByte(o, '='); i > 0 {
			drop[o[:i]] = struct{}{}
		}
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, e := range base {
		if i := strings.IndexByte(e, '='); i > 0 {
			if _, ok := drop[e[:i]]; ok {
				continue
			}
		}
		out = append(out, e)
	}
	return append(out, overrides...)
}

func runCreateKeytool(bin string, args, extraEnv []string, pass string) error {
	ctx, cancel := context.WithTimeout(context.Background(), createKeytoolTimeout)
	defer cancel()
	// Custom store password is not in args. bin is JAVA_HOME/bin, PATH, or ~/.local/bin.
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: keytool path is resolved from JAVA_HOME, PATH, or ~/.local/bin; arguments are fixed flags plus paths this process created
	if len(extraEnv) > 0 {
		cmd.Env = mergeCreateEnviron(os.Environ(), extraEnv)
	}
	// nil Stdin is the null device; keytool must never inherit a TTY.
	cmd.Stdin = nil
	cmd.WaitDelay = createKeytoolWaitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("keytool timed out after %s", createKeytoolTimeout)
	}
	detail := strings.TrimSpace(stderr.String())
	if detail == "" {
		detail = strings.TrimSpace(stdout.String())
	}
	detail = redactCreateSecret(detail, pass)
	if detail != "" {
		return fmt.Errorf("keytool: %w: %s", err, detail)
	}
	return fmt.Errorf("keytool: %w", err)
}

func redactCreateSecret(msg, secret string) string {
	if secret == "" || msg == "" {
		return msg
	}
	return strings.ReplaceAll(msg, secret, "***")
}
