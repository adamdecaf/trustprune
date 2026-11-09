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

package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
	"github.com/adamdecaf/trustprune/pkg/store"
)

var (
	// used to serialize _add and allowlist/restore tests
	// _add goes first, followed by allowlist/restore test,
	// but this serializes access
	darwinKeychainWG = sync.WaitGroup{}
)

func init() {
	darwinKeychainWG.Add(1)
}

func TestIntegration__date(t *testing.T) {
	t.Parallel()

	cmd := Command("date", "-u", "-r", "0").Trim()
	cmd.EqualT(t, "Thu Jan  1 00:00:00 UTC 1970")

	ans := `Command:
  date -u -r 0
Output:
  Thu Jan  1 00:00:00 UTC 1970`
	if cmd.String() != ans {
		t.Errorf("cmd.String() = %q", cmd.String())
	}
}

func TestIntegration__unknown(t *testing.T) {
	t.Parallel()

	cmd := CertManage("other").Trim()
	cmd.FailedT(t)
}

func TestIntegration__listFromFile(t *testing.T) {
	t.Parallel()

	cmd := CertManage("list", "-file", "../testdata/lots.crt", "-count").Trim()
	cmd.CmpIntF(t, func(i int) bool { return i == 5 })
}

func TestIntegration__add(t *testing.T) {
	t.Parallel()

	// don't signal we're done until this test completes
	defer darwinKeychainWG.Done()

	if !inCI() {
		t.Skip("not mutating non-CI login keychain")
	}
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("delaying darwin integration tests, since we're running all tests right now")
	}
	setupKeychain(t)

	where := "../testdata/example.crt"
	certs, err := certutil.FromFile(where)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs", len(certs))
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	// verify cert doesn't exist already
	if inPlatformStore(t, fp) {
		name := certutil.StringifyPKIXName(certs[0].Subject)
		t.Fatalf("cert already in our store, please remove, %s", name)
	}

	// add cert and verify
	CertManage("add", "-file", where).SuccessT(t)
	if !inPlatformStore(t, fp) {
		t.Errorf("didn't find added cert, fp=%q", fp)
	}

	// TODO(adam): delete the certificate we added
}

func inPlatformStore(t *testing.T, fp string) bool {
	t.Helper()

	// Grab platform certs and verify ours is added
	found, err := store.Platform().List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range found {
		ffp := certutil.GetHexSHA256Fingerprint(*found[i])
		if fp == ffp {
			return true
		}
	}
	return false
}

// Create a 'login.keychain' if it doesn't exist, only in CI
func setupKeychain(t *testing.T) {
	if !inCI() {
		return
	}
	t.Helper()

	// Copy our 'empty.keychain' over to the path..
	// I've tried creating it, but runnint into an error
	//
	// exec.Command("security", "create-keychain", "-p", `''`).CombinedOutput()
	//
	// The error is: 'Error exit status 255'
	// I think this is a problem where the security cli is trying to find a TTY

	where := filepath.Join(file.HomeDir(), "/Library/Keychains/login.keychain")
	if !file.Exists(where) {
		src := "../testdata/empty.keychain"
		if err := file.CopyFile(src, where); err != nil {
			t.Error(err)
		}
	}
}

// Don't run this test byitself, there's a .Wait()
// instead call `go test ... -run TestIntegration__`
func TestIntegration__AllowlistAndRemove(t *testing.T) {
	t.Parallel()

	// wait until _add test finishes, so we don't clobber the keychain
	darwinKeychainWG.Wait()

	// only run if we're on CI
	if !inCI() {
		t.Skip("not mutating non-CI login keychain")
	}
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("delaying darwin integration tests, since we're running all tests right now")
	}
	t.Helper()

	// get cert count
	certsBefore, err := store.Platform().List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// verify we can load our test site
	if err := loadTestSite(t); online(t) && err != nil {
		t.Fatalf("expected to be able to load our test site, err=%v", err)
	}

	// take a backup
	cmd := CertManage("backup").Trim()
	if !strings.HasPrefix(cmd.output, "Backup completed successfully:") {
		t.Errorf("backup output %q", cmd.output)
	}
	cmd.SuccessT(t)

	// allowlist
	cmd = CertManage("allowlist", "-file", "../testdata/us-whitelist.yaml")
	cmd.SuccessT(t)

	// verify cert count
	certsAfter, err := store.Platform().List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(certsBefore) <= len(certsAfter) {
		t.Fatalf("certsBefore=%d, certsAfter=%d", len(certsBefore), len(certsAfter))
	}

	// verify we can't load our test site
	if err := loadTestSite(t); online(t) && err != nil {
		// Go 1.10 calls 'security verify-cert' without -p ssl, which doesn't see the cert as untrusted.
		t.Fatal("has golang/go#24084 been fixed? - https://github.com/golang/go/issues/24084")
	}

	// restore
	cmd = CertManage("restore").Trim()
	if !strings.HasPrefix(cmd.output, "Restore completed successfully:") {
		t.Errorf("restore output %q", cmd.output)
	}
	cmd.SuccessT(t)

	// verify cert count
	certsAfterRestore, err := store.Platform().List(&store.ListOptions{
		Trusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(certsBefore) != len(certsAfterRestore) {
		t.Fatalf("certsBefore=%d, certsAfter=%d, certsAfterRestore=%d", len(certsBefore), len(certsAfter), len(certsAfterRestore))
	}

	// verify we can load our test site
	if err := loadTestSite(t); online(t) && err != nil {
		t.Fatalf("expected to be able to load our test site, err=%v", err)
	}
}

var loadTestSiteSourceCode = []byte(`package main
import "net/http"

func main() {
	// test site, anything without a US root
	req, err := http.NewRequest("GET", "https://fnb.co.za", nil)
	if err != nil {
		defer panic("A: " + err.Error())
	}
	req.Close = true
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		defer panic("B: " + err.Error())
	}
	if resp != nil && resp.Body != nil {
		if err := resp.Body.Close(); err != nil {
			panic("C: " + err.Error())
		}
	}
}`)

// loadTestSite needs to drop down back into a shell and then run some Go code,
// which on darwin uses the platform certs (Keychain), to attempt a connection
// against the target host.
//
// We can't just call `x509.SystemCertPool()` again, because under the hood it
// is protected by a `sync.Once`, so our changes aren't reflected until the next run.
func loadTestSite(t *testing.T) error {
	t.Helper()

	// render our Go code to another file and then `go run` it.
	tmp, err := os.CreateTemp("", "load-our test site")
	if err != nil {
		t.Fatalf("error creating temp dir for loadTestSite, err=%v", err)
	}
	err = os.WriteFile(tmp.Name(), loadTestSiteSourceCode, 0644)
	if err != nil {
		t.Fatalf("error writing loadTestSite source code to %s, err=%v", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		t.Fatalf("error syncing loadTestSite source code to %s, err=%v", tmp.Name(), err)
	}
	// go requires files have a .go suffix, but symlinks work just as fine too
	dir, _ := filepath.Split(tmp.Name())
	filename := filepath.Join(dir, fmt.Sprintf("our test site%d.go", time.Now().Unix()))
	err = os.Symlink(tmp.Name(), filename)
	if err != nil {
		t.Fatalf("error symlinking our test site source file, err=%v", err)
	}
	defer os.Remove(filename)

	cmd := exec.Command("go", "run", filename)
	cmd.Env = []string{
		// Running this with cgo doesn't seem to work because of a cache around the trustd deamon.
		// Chrome doesn't seem to have the same problem, but I haven't tracked down what they're doing.
		//
		// I looked into clearing this cache with a cgo specific wrapper (i.e. SecTrustSettingsPurgeUserAdminCertsCache)
		// but couldn't get it working. There are some Sec*Priv.h header files which don't seem to be symlinked in with the
		// rest of #include <Security/Security.h> files.
		//
		// Either way we compile trustprune without cgo so it doesn't seem like a big leap to run this test without cgo.
		//
		// https://github.com/practicalswift/osx/blob/27f6b27ca6e76018240c126c94059d859760981d/src/security/OSX/trustd/trustd.c#L628
		// https://github.com/practicalswift/osx/blob/27f6b27ca6e76018240c126c94059d859760981d/src/security/OSX/libsecurity_keychain/lib/SecTrustSettings.cpp#L936-L940
		"CGO_ENABLED=0",
	}
	if debug {
		cmd.Env = append(cmd.Env, "GODEBUG=x509roots=1")
	}
	out, err := cmd.CombinedOutput()
	if debug {
		fmt.Printf(`Command: %s
Output:
%s`, strings.Join(cmd.Args, " "), string(out))
	}
	if err != nil {
		return fmt.Errorf("error running loadTestSite code, err=%v, output=%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func TestIntegration__loadTestSite(t *testing.T) {
	t.Skip("TODO(adam): fix")
	t.Parallel()

	if online(t) {
		if err := loadTestSite(t); err != nil {
			t.Fatal(err)
		}
	}
}

// Firefox tests
// func TestIntegration__firefox(t *testing.T) {
// 	if !online(t) {
// 		t.Skip("offline, can't run firefox tests (no NSS setup)")
// 	}

// 	// Make a request using the Keychain to get it ready
// 	// travis needs this
// 	cmd := Command("timeout", strings.Split("15s firefox --headless https://google.com 2>&1 >> /var/log/firefox.log", " ")...)
// 	cmd.SuccessT(t)

// 	// Verify firefox has found certificates
// 	cmd = CertManage("list", "-app", "firefox", "-count").Trim()
// 	cmd.SuccessT(t)
// 	cmd.CmpIntF(t, func(i int) bool { return i > 1 })
// }
