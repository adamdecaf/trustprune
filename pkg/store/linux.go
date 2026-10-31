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

//go:build linux
// +build linux

package store

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

type cadir struct {
	// directory for new/custom certificates
	add string

	// base dir for all ca certs
	dir string

	// the filepath containing all certs (optional)
	all string

	// reload/refresh command
	refresh string
}

func (ca *cadir) empty() bool {
	if ca == nil {
		return false
	}
	path, err := filepath.Abs(ca.all)
	return err != nil || !file.Exists(path)
}

var (
	// From Go's source, src/crypto/x509/root_linux.go
	cadirs = []cadir{
		// Debian/Ubuntu/Alpine/Gentoo
		{
			add:     "/usr/local/share/ca-certificates",
			dir:     "/usr/share/ca-certificates",
			all:     "/etc/ssl/certs/ca-certificates.crt",
			refresh: "/usr/sbin/update-ca-certificates",
		},
		// Fedora/RHEL/CentOS
		{
			add:     "/etc/pki/ca-trust/source/anchors",
			dir:     "/etc/pki/ca-trust/source/anchors",
			all:     "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			refresh: "/usr/bin/update-ca-trust",
		},
	}

	linuxBackupDir = "linux"
)

type linuxStore struct {
	ca cadir
}

func platform() Store {
	for _, ca := range cadirs {
		if !ca.empty() {
			return linuxStore{ca: ca}
		}
	}
	return linuxStore{}
}

func (s linuxStore) Add(certs []*x509.Certificate) error {
	if s.ca.empty() {
		return errors.New("unable to find certificate directory")
	}

	if DryRun() {
		details := []string{fmt.Sprintf("add directory %s", s.ca.add)}
		details = append(details, reportDryRunCerts("add", certs)...)
		if len(certs) > 0 {
			details = append(details, fmt.Sprintf("then run %s", s.ca.refresh))
		}
		reportDryRun("add certificates to", "linux", s.ca.dir, details...)
		return nil
	}

	// install each certificate
	for i := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		path := filepath.Join(s.ca.add, fmt.Sprintf("%s.crt", fp))

		err := certutil.ToFile(path, certs[i:i+1])
		if err != nil {
			return err
		}
	}

	if len(certs) > 0 {
		return s.rebundleCerts()
	}
	return nil
}

// Backup takes a snapshot of the current set of CA certificates and
// saves them to another location. It will overwrite any previous backup.
func (s linuxStore) Backup() error {
	if DryRun() {
		names, err := listDirBasenames(s.ca.dir)
		if err != nil {
			return err
		}
		details := []string{fmt.Sprintf("mirror %s into %s/%s/<timestamp>", s.ca.dir, backupParentDisplay(), linuxBackupDir)}
		for _, name := range names {
			details = append(details, fmt.Sprintf("include %s", name))
		}
		reportDryRun("backup", "linux", s.ca.dir, details...)
		return nil
	}
	dir, err := getCertManageDir(fmt.Sprintf("%s/%d", linuxBackupDir, time.Now().Unix()))
	if err != nil {
		return err
	}
	return file.MirrorDir(s.ca.dir, dir)
}

func (s linuxStore) GetLatestBackup() (string, error) {
	dir, err := getLatestStoreBackup(linuxBackupDir)
	if err != nil {
		return "", fmt.Errorf("getLatestBackup: error getting linux backup directory, err=%w", err)
	}
	return dir, nil
}

func (s linuxStore) uname(args ...string) string {
	out, err := exec.Command("uname", args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (s linuxStore) GetInfo() *Info {
	path := s.ca.all
	if path == "" {
		path = s.ca.dir
	}
	return &Info{
		Name:    s.uname("-o"), // GNU/Linux,
		Version: s.uname("-r"), // 4.9.60-linuxkit-aufs
		Path:    path,
	}
}

// List returns the x509 Certificates trusted on a Linux system
//
// Note: Linux does not offer support for "untrusting" a certificate
// it must be removed instead.
func (s linuxStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	if s.ca.empty() {
		return nil, nil
	}

	bytes, err := os.ReadFile(s.ca.all)
	if err != nil {
		return nil, err
	}

	// TODO(adam): Filter out expired and revoked certs, based on ListOptions
	certs, err := certutil.ParsePEM(bytes)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// Remove walks through the installed CA certificates on a linux based
// machine and deactivates those that are not to be trusted.
//
// Steps
// 1. Walk through the dir (/etc/ssl/certs/) and chmod 000 the certs we aren't trusting
// 2. Run `update-ca-certificates` to re-create the ca-certificates.crt file
func (s linuxStore) Remove(al allowlist.Allowlist) error {
	if DryRun() {
		var details []string
		err := filepath.Walk(s.ca.dir, func(path string, info os.FileInfo, err error) error {
			if (err != nil && !errors.Is(err, filepath.SkipDir)) || info.IsDir() {
				return nil
			}
			parsed, err := certutil.FromFileResult(path)
			if err != nil {
				return err
			}
			kept, removed := parsed.KeepMatching(al.Matches)
			for i := range removed {
				details = append(details, fmt.Sprintf("remove %s from %s", formatCertLine(removed[i]), path))
			}
			details = append(details, reportKeptRawPEMIn(path, kept.Entries)...)
			return nil
		})
		if err != nil {
			return err
		}
		details = append(details, fmt.Sprintf("then run %s", s.ca.refresh))
		reportDryRun("remove certificates from", "linux", s.ca.dir, details...)
		return nil
	}

	// Check each CA cert file and optionally disable
	walk := func(path string, info os.FileInfo, err error) error {
		// Ignore SkipDir and directories
		if (err != nil && !errors.Is(err, filepath.SkipDir)) || info.IsDir() {
			return nil
		}

		parsed, err := certutil.FromFileResult(path)
		if err != nil {
			return err
		}
		kept, _ := parsed.KeepMatching(al.Matches)
		return certutil.ToFileEntries(path, kept.Entries)
	}

	// Walk the fs and deactivate each cert
	err := filepath.Walk(s.ca.dir, walk)
	if err != nil {
		return err
	}

	return s.rebundleCerts()
}

func (s linuxStore) Restore(where string) error {
	dir := where
	var err error
	if dir == "" {
		dir, err = s.GetLatestBackup()
		if err != nil {
			return err
		}
	}
	if debug {
		fmt.Printf("store/linux: restoring from backup dir %s\n", dir)
	}

	if DryRun() {
		names, err := listDirBasenames(dir)
		if err != nil {
			return err
		}
		details := restoreFileDetails(dir, s.ca.dir, names)
		details = append(details, fmt.Sprintf("then run %s", s.ca.refresh))
		reportDryRun("restore", "linux", s.ca.dir, details...)
		return nil
	}

	// Mirror into a sibling temp dir, then swap into place. A failed copy
	// must leave the live CA directory untouched.
	tmp := s.ca.dir + ".restore-tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	err = file.MirrorDir(dir, tmp)
	if err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}

	aside := s.ca.dir + ".restore-old"
	liveExists := file.Exists(s.ca.dir)
	if liveExists {
		if err := os.RemoveAll(aside); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
		if err := os.Rename(s.ca.dir, aside); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
	}

	if err := os.Rename(tmp, s.ca.dir); err != nil {
		_ = os.RemoveAll(tmp)
		if liveExists {
			if rerr := os.Rename(aside, s.ca.dir); rerr != nil {
				fmt.Printf("store/linux: previous CA directory moved aside to %s\n", aside)
				return fmt.Errorf("%w (previous CA dir still at %s)", err, aside)
			}
		}
		return err
	}

	// Keep aside until update-ca-certificates (rebundleCerts) succeeds so
	// a refresh failure can roll the live directory back.
	if err := s.rebundleCerts(); err != nil {
		if liveExists {
			failed := s.ca.dir + ".restore-failed"
			_ = os.RemoveAll(failed)
			if rerr := os.Rename(s.ca.dir, failed); rerr != nil {
				// Aside still holds the previous CA dir; tell the operator where.
				fmt.Printf("store/linux: previous CA directory moved aside to %s\n", aside)
				return fmt.Errorf("%w (previous CA dir still at %s)", err, aside)
			}
			if rerr := os.Rename(aside, s.ca.dir); rerr != nil {
				_ = os.Rename(failed, s.ca.dir)
				fmt.Printf("store/linux: previous CA directory moved aside to %s\n", aside)
				return fmt.Errorf("failed to restore previous CA dir from %s: %w", aside, errors.Join(err, rerr))
			}
			_ = os.RemoveAll(failed)
		}
		return err
	}

	if liveExists {
		if err := os.RemoveAll(aside); err != nil {
			// Restore already applied; warn about leftover path (contents may be partial).
			fmt.Printf("store/linux: warning: could not fully remove %s after restore: %v (remaining contents may be incomplete)\n", aside, err)
		}
	}
	return nil
}

// Update the certs trust system-wide
func (s linuxStore) rebundleCerts() error {
	var out bytes.Buffer

	cmd := exec.Command("sudo", s.ca.refresh)
	if os.Getuid() == 0 {
		// drop sudo if we're already root
		cmd = exec.Command(s.ca.refresh)
	}
	cmd.Stdout = &out

	if debug {
		fmt.Println("store/linux: updated CA certificates")
	}

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error updating trust status: err=%w, out=%s", err, out.String())
	}
	return nil
}
