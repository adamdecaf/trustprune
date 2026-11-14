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

//go:build windows
// +build windows

package store

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

// Docs:
// https://msdn.microsoft.com/en-us/library/e78byta0(v=vs.110).aspx
// https://social.technet.microsoft.com/wiki/contents/articles/31633.microsoft-trusted-root-program-requirements.aspx
// https://social.technet.microsoft.com/wiki/contents/articles/31680.microsoft-trusted-root-certificate-program-updates.aspx

// https://blogs.technet.microsoft.com/yuridiogenes/2011/04/20/exporting-certificates-using-certutil/
// https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732443(v=ws.11)

// Certificate store locations:
// - https://superuser.com/questions/411909/where-is-the-certificate-folder-in-windows-7
// - https://msdn.microsoft.com/en-us/library/windows/desktop/aa388136(v=vs.85).aspx

type windowsStore struct{}

func platform() Store {
	return windowsStore{}
}

func (s windowsStore) Add(certs []*x509.Certificate) error {
	if DryRun() {
		reportDryRun("add certificates to", "windows", "", reportDryRunCerts("add", certs)...)
		return nil
	}
	return nil
}

func (s windowsStore) Backup() error {
	if DryRun() {
		reportDryRun("backup", "windows", "")
		return nil
	}
	return nil
}

func (s windowsStore) GetLatestBackup() (string, error) {
	return "", nil
}

func (s windowsStore) GetInfo() *Info {
	// From https://stackoverflow.com/a/42778990
	out, err := exec.Command("systeminfo").CombinedOutput()
	if err != nil {
		return &Info{
			Name: "Windows",
			Path: `Cert:\LocalMachine\Root`,
		}
	}
	info := string(out)

	nameRegex := regexp.MustCompile(`OS Name:\s*([\w\s]*)`)
	versionRegex := regexp.MustCompile(`OS Version:\s*([\w\s\.\/]*)`)

	name := strings.TrimPrefix(nameRegex.FindString(info), "OS Name:")
	version := strings.TrimPrefix(versionRegex.FindString(info), "OS Version:")

	return &Info{
		Name:    strings.TrimSpace(name),
		Version: strings.TrimSpace(version),
		Path:    `Cert:\LocalMachine\Root`,
	}
}

func (s windowsStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	// Trust-store certs have no private key, so certutil -exportPFX cannot
	// represent them (PKCS#12 parse fails, list returns 0). Dump DER via
	// one PowerShell invocation across all stores instead of one certutil per cert.
	tmp, err := os.CreateTemp("", "cert-manage-win-store")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file, err=%w", err)
	}
	path := tmp.Name()
	tmp.Close()
	defer os.Remove(path)

	script := windowsListScript(windowsStoreNames, path)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error reading windows certificate stores: %v: %s", err, strings.TrimSpace(string(out)))
	}

	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading exported windows stores: %w", err)
	}
	pool := certutil.Pool{}
	pool.AddCertificates(parseWindowsPEM(bs))
	return pool.GetCertificates(), nil
}

// parseWindowsPEM extracts certificates from a PEM blob and skips entries Go
// cannot parse (legacy negative serials, etc.) so one bad root cannot empty
// the whole store.
func parseWindowsPEM(blob []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, blob = pem.Decode(blob)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			if debug {
				fmt.Printf("store/windows: skipping unparsable cert: %v\n", err)
			}
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}

func (s windowsStore) certSerialsFromStore(store string) ([]string, error) {
	cmd := exec.Command("certutil", "-store", store)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("error reading serials from store %s err=%w", store, err)
	}
	return s.readCertSerials(string(stdout.Bytes()))
}

var (
	// C:\Users>certutil -store Root
	// Root "Trusted Root Certification Authorities"
	// ================ Certificate 0 ================
	// Serial Number: 72696afcd5edce864658141cb588a3a8
	winSerialNumberPrefix = "Serial Number:"
	winSerialNumberRegex  = regexp.MustCompile(fmt.Sprintf(`%s ([0-9a-f]+)\r?\n?`, winSerialNumberPrefix))
)

func (s windowsStore) readCertSerials(out string) ([]string, error) {
	matches := winSerialNumberRegex.FindAllString(out, -1)
	for i := range matches {
		matches[i] = strings.TrimSpace(strings.ReplaceAll(matches[i], winSerialNumberPrefix, ""))
	}
	return matches, nil
}

var (
	pfxPassword = "password"
)

func (s windowsStore) exportCertFromStore(serial, store string) (*x509.Certificate, error) {
	tmp, err := os.CreateTemp("", "cert-manage-windows")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file, err=%w", err)
	}

	// close and rm file, we got a unique name
	// This avoids: "The process cannot access the file because it is being used by another process."
	err = tmp.Close()
	if err != nil {
		return nil, err
	}
	err = os.Remove(tmp.Name())
	if err != nil {
		return nil, err
	}
	defer func() { // then make sure it's gone afterwords
		if file.Exists(tmp.Name()) {
			os.Remove(tmp.Name())
		}
	}()

	// export cert into PKCS #12 format
	out, err := exec.Command("certutil", "-exportPFX", "-f", "-p", pfxPassword, store, serial, tmp.Name()).CombinedOutput()
	if debug {
		fmt.Printf("%q\n", string(out))
	}
	if err != nil {
		if skipWindowsExport(string(out), err) {
			if debug {
				fmt.Printf("store/windows: skipping cert %s from %s: %s\n", serial, store, string(out))
			}
			return nil, nil
		}
		return nil, fmt.Errorf("error exporting cert %q (from %s) to PKCS #12: %w", serial, store, err)
	}

	bs, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("error reading temp file, err=%w", err)
	}
	cert, err := certutil.DecodePKCS12(bs, pfxPassword)
	if err != nil {
		if skipWindowsPKCS12(err) {
			if debug {
				fmt.Printf("store/windows: skipping PKCS#12 parse for %s from %s: %v\n", serial, store, err)
			}
			return nil, nil
		}
		return nil, fmt.Errorf("error parsing PKCS #12 of serial %q from %s: %w", serial, store, err)
	}
	return cert, nil
}

func skipWindowsPKCS12(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "expected exactly two items in the authenticated safe") ||
		strings.Contains(s, "OID 1.3.6.1.4.1.311.17.2")
}

func skipWindowsExport(out string, err error) bool {
	if err == nil {
		return false
	}
	s := out + err.Error()
	for _, n := range []string{
		"Keyset does not exist",
		"Cannot find object or property.",
		"0x8009000b",
		"NTE_BAD_KEY_STATE",
		"CRYPT_E_NOT_FOUND",
	} {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func (s windowsStore) Remove(al allowlist.Allowlist) error {
	if DryRun() {
		reportDryRun("remove certificates from", "windows", "")
		return nil
	}
	return nil
}

func (s windowsStore) Restore(where string) error {
	if where == "" {
		return fmt.Errorf("no backup for windows; restore is not supported for this store")
	}
	if DryRun() {
		details := []string{}
		if where != "" {
			details = append(details, fmt.Sprintf("source %s", where))
		}
		reportDryRun("restore", "windows", "", details...)
		return nil
	}
	return nil
}
