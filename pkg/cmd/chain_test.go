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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

var chainTestNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestBuildChainDefaultMatchesConnectTable(t *testing.T) {
	t.Parallel()
	leaf, ca := mintLeafAndCA(t, "leaf.example", "ca.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	out, err := buildChain(chainInput{
		leaf:    leaf,
		trusted: []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := formatConnectChainTable([]*x509.Certificate{leaf, ca})
	if err != nil {
		t.Fatal(err)
	}
	if out != want {
		t.Fatalf("default chain table:\n got:\n%s\nwant:\n%s", out, want)
	}
	if strings.Contains(out, "(untrusted)") || strings.Contains(out, "(expired)") || strings.Contains(out, "(blocklisted)") || strings.Contains(out, "incomplete:") {
		t.Fatalf("default chain has a label or incomplete note:\n%s", out)
	}
}

func TestBuildChainUntrusted(t *testing.T) {
	t.Parallel()
	leaf, ca := mintLeafAndCA(t, "leaf.example", "priv.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	in := chainInput{
		leaf:    leaf,
		extras:  []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	}
	out, err := buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "priv.example (untrusted)") {
		t.Fatalf("private CA included without --untrusted:\n%s", out)
	}
	if !strings.Contains(out, "incomplete: no issuer for leaf.example; pass --untrusted") {
		t.Fatalf("missing untrusted hint:\n%s", out)
	}
	if lines := chainDataLines(out); len(lines) != 1 {
		t.Fatalf("rows = %d, want 1:\n%s", len(lines), out)
	}

	in.opts.Untrusted = true
	out, err = buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "priv.example (untrusted)") {
		t.Fatalf("private CA not labeled untrusted:\n%s", out)
	}
	if strings.Contains(out, "incomplete:") {
		t.Fatalf("complete private chain marked incomplete:\n%s", out)
	}
	if strings.Contains(out, "leaf.example (untrusted)") {
		t.Fatalf("leaf labeled untrusted:\n%s", out)
	}
}

func TestBuildChainExpired(t *testing.T) {
	t.Parallel()
	notBefore := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	expiredAt := time.Date(2015, 4, 12, 0, 0, 0, 0, time.UTC)
	ca, key := mintCA(t, "old.example", notBefore, expiredAt)
	leaf := mintChild(t, "leaf.example", ca, key, chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour), false)

	in := chainInput{
		leaf:    leaf,
		trusted: []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	}
	out, err := buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "old.example") && strings.Contains(chainDataLines(out)[0], "old.example (expired)") {
		t.Fatal("expired CA row present")
	}
	lines := chainDataLines(out)
	if len(lines) != 1 {
		t.Fatalf("rows = %d, want 1:\n%s", len(lines), out)
	}
	if !strings.Contains(out, "incomplete: no issuer for leaf.example; pass --expired") {
		t.Fatalf("missing expired hint:\n%s", out)
	}

	in.opts.Expired = true
	out, err = buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "old.example (expired)") {
		t.Fatalf("expired CA not labeled:\n%s", out)
	}
	if strings.Contains(out, "incomplete:") {
		t.Fatalf("expired chain marked incomplete:\n%s", out)
	}
}

func TestBuildChainExpiredLeaf(t *testing.T) {
	t.Parallel()
	notBefore := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	expiredAt := time.Date(2015, 4, 12, 0, 0, 0, 0, time.UTC)
	ca, key := mintCA(t, "ca.example", notBefore, chainTestNow.Add(365*24*time.Hour))
	leaf := mintChild(t, "old-leaf.example", ca, key, notBefore, expiredAt, false)
	in := chainInput{
		leaf:    leaf,
		trusted: []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	}
	_, err := buildChain(in)
	if err == nil || err.Error() != "leaf certificate expired 2015-04-12; pass --expired to include it" {
		t.Fatalf("err = %v", err)
	}
	in.opts.Expired = true
	out, err := buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "old-leaf.example (expired)") {
		t.Fatalf("leaf not labeled expired:\n%s", out)
	}
	if strings.Contains(out, "old-leaf.example (untrusted") {
		t.Fatalf("expired leaf labeled untrusted:\n%s", out)
	}
}

func TestBuildChainNotYetValid(t *testing.T) {
	t.Parallel()
	future := time.Date(2099, 1, 2, 0, 0, 0, 0, time.UTC)
	ca, key := mintCA(t, "future.example", future, future.Add(365*24*time.Hour))
	leaf := mintChild(t, "leaf.example", ca, key, chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour), false)
	in := chainInput{
		leaf:    leaf,
		trusted: []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	}
	out, err := buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	// The leaf row names its issuer. The CA itself is a second row.
	if lines := chainDataLines(out); len(lines) != 1 {
		t.Fatalf("rows = %d, want 1:\n%s", len(lines), out)
	}
	if strings.Contains(out, "(not yet valid)") || strings.Contains(out, "(expired)") {
		t.Fatalf("not-yet-valid CA included:\n%s", out)
	}
	if !strings.Contains(out, "incomplete: no issuer for leaf.example; pass --expired") {
		t.Fatalf("missing not-yet-valid hint:\n%s", out)
	}

	in.opts.Expired = true
	out, err = buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "future.example (not yet valid)") {
		t.Fatalf("not-yet-valid CA not labeled:\n%s", out)
	}
	if strings.Contains(out, "future.example (expired)") || strings.Contains(out, "incomplete:") {
		t.Fatalf("not-yet-valid chain:\n%s", out)
	}

	// NotBefore equal to now is already valid.
	currentCA, currentKey := mintCA(t, "ca.example", chainTestNow, chainTestNow.Add(365*24*time.Hour))
	currentLeaf := mintChild(t, "leaf.example", currentCA, currentKey, chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour), false)
	out, err = buildChain(chainInput{
		leaf:    currentLeaf,
		trusted: []*x509.Certificate{currentCA},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "not yet valid") || strings.Contains(out, "(expired)") || strings.Contains(out, "incomplete:") {
		t.Fatalf("NotBefore == now treated as not yet valid:\n%s", out)
	}

	futureLeaf := mintChild(t, "future-leaf.example", currentCA, currentKey, future, future.Add(24*time.Hour), false)
	_, err = buildChain(chainInput{
		leaf:    futureLeaf,
		trusted: []*x509.Certificate{currentCA},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	})
	if err == nil || err.Error() != "leaf certificate not yet valid until 2099-01-02; pass --expired to include it" {
		t.Fatalf("err = %v", err)
	}
	out, err = buildChain(chainInput{
		leaf:    futureLeaf,
		trusted: []*x509.Certificate{currentCA},
		opts:    ChainOptions{Now: chainTestNow, Expired: true},
		blocked: func(*x509.Certificate) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "future-leaf.example (not yet valid)") {
		t.Fatalf("leaf not labeled not yet valid:\n%s", out)
	}
	if strings.Contains(out, "incomplete:") || strings.Contains(out, "future-leaf.example (expired)") {
		t.Fatalf("not-yet-valid leaf:\n%s", out)
	}
}

func TestBuildChainNotAfterEqualToNowIsCurrent(t *testing.T) {
	t.Parallel()
	leaf, ca := mintLeafAndCA(t, "leaf.example", "ca.example", chainTestNow.Add(-time.Hour), chainTestNow)
	out, err := buildChain(chainInput{
		leaf:    leaf,
		trusted: []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "incomplete:") || strings.Contains(out, "(expired)") {
		t.Fatalf("NotAfter == now treated as expired:\n%s", out)
	}
}

func TestBuildChainBlocklisted(t *testing.T) {
	t.Parallel()
	leaf, ca := mintLeafAndCA(t, "leaf.example", "blocked.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	blocked := map[string]bool{chainFP(ca): true}
	in := chainInput{
		leaf:    leaf,
		trusted: []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(c *x509.Certificate) bool { return blocked[chainFP(c)] },
	}
	out, err := buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "(blocklisted)") {
		t.Fatalf("blocklisted CA included without --revoked:\n%s", out)
	}
	if !strings.Contains(out, "incomplete: no issuer for leaf.example; pass --revoked") {
		t.Fatalf("missing blocklist hint:\n%s", out)
	}
	lines := chainDataLines(out)
	if len(lines) != 1 {
		t.Fatalf("rows = %d, want 1:\n%s", len(lines), out)
	}

	in.opts.Revoked = true
	out, err = buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "blocked.example (blocklisted)") {
		t.Fatalf("CA not labeled blocklisted:\n%s", out)
	}
	if strings.Contains(out, "(revoked)") {
		t.Fatalf("label should be blocklisted, not revoked:\n%s", out)
	}
	if strings.Contains(out, "incomplete:") {
		t.Fatalf("blocklisted chain marked incomplete:\n%s", out)
	}
}

func TestBuildChainBlocklistedLeaf(t *testing.T) {
	t.Parallel()
	leaf, ca := mintLeafAndCA(t, "leaf.example", "ca.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	in := chainInput{
		leaf:    leaf,
		trusted: []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(c *x509.Certificate) bool { return chainFP(c) == chainFP(leaf) },
	}
	_, err := buildChain(in)
	if err == nil || err.Error() != "leaf certificate is blocklisted; pass --revoked to include it" {
		t.Fatalf("err = %v", err)
	}
	in.opts.Revoked = true
	out, err := buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "leaf.example (blocklisted)") {
		t.Fatalf("leaf not labeled blocklisted:\n%s", out)
	}
}

func TestBuildChainAllShorthand(t *testing.T) {
	t.Parallel()
	notBefore := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	ca, key := mintCA(t, "priv.example", notBefore, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	leaf := mintChild(t, "leaf.example", ca, key, chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour), false)
	out, err := buildChain(chainInput{
		leaf:    leaf,
		extras:  []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow, All: true},
		blocked: func(c *x509.Certificate) bool { return chainFP(c) == chainFP(ca) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "priv.example (untrusted, expired, blocklisted)") {
		t.Fatalf("all shorthand missing combined label:\n%s", out)
	}
}

func TestBuildChainAllLabels(t *testing.T) {
	t.Parallel()
	notBefore := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	ca, key := mintCA(t, "priv.example", notBefore, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	leaf := mintChild(t, "leaf.example", ca, key, chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour), false)
	in := chainInput{
		leaf:    leaf,
		extras:  []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow, Untrusted: true, Expired: true, Revoked: true},
		blocked: func(c *x509.Certificate) bool { return chainFP(c) == chainFP(ca) },
	}
	out, err := buildChain(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "priv.example (untrusted, expired, blocklisted)") {
		t.Fatalf("combined label missing:\n%s", out)
	}
}

func TestBuildChainSkippedIssuerNamesEveryFlag(t *testing.T) {
	t.Parallel()
	notBefore := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	ca, key := mintCA(t, "priv.example", notBefore, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	leaf := mintChild(t, "leaf.example", ca, key, chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour), false)
	out, err := buildChain(chainInput{
		leaf:    leaf,
		extras:  []*x509.Certificate{ca},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(c *x509.Certificate) bool { return chainFP(c) == chainFP(ca) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "incomplete: no issuer for leaf.example; pass --untrusted --expired --revoked") {
		t.Fatalf("hint = %q\n%s", out, out)
	}
}

func TestBuildChainPrefersCurrentIssuer(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current := mintCAWithKey(t, key, "ca.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	old := mintCAWithKey(t, key, "ca.example", time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2015, 4, 12, 0, 0, 0, 0, time.UTC))
	leaf := mintChild(t, "leaf.example", current, key, chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour), false)
	out, err := buildChain(chainInput{
		leaf:    leaf,
		trusted: []*x509.Certificate{old, current},
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "2030") && !strings.Contains(out, current.NotAfter.UTC().Format(connectDateLayout)) {
		t.Fatalf("current issuer not chosen:\n%s", out)
	}
	if strings.Contains(out, "2015-04-12") {
		t.Fatalf("expired duplicate chosen:\n%s", out)
	}
	if strings.Contains(out, "(expired)") || strings.Contains(out, "incomplete:") {
		t.Fatalf("chain:\n%s", out)
	}
}

func TestBuildChainSelfSignedNonCALeaf(t *testing.T) {
	t.Parallel()
	leaf := mintSelfSignedLeaf(t, "leaf.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour))
	if leaf.IsCA {
		t.Fatal("leaf is a CA")
	}
	if !bytes.Equal(leaf.RawSubject, leaf.RawIssuer) {
		t.Fatal("subject and issuer differ")
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatal(err)
	}
	// CheckSignatureFrom enforces CA constraints, so it must reject this leaf.
	// The chain walk has to accept it anyway.
	if err := leaf.CheckSignatureFrom(leaf); err == nil {
		t.Fatal("CheckSignatureFrom accepted a non-CA leaf")
	}
	out, err := buildChain(chainInput{
		leaf:    leaf,
		opts:    ChainOptions{Now: chainTestNow},
		blocked: func(*x509.Certificate) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "incomplete:") {
		t.Fatalf("self-signed non-CA leaf marked incomplete:\n%s", out)
	}
	if lines := chainDataLines(out); len(lines) != 1 || !strings.Contains(out, "leaf.example") {
		t.Fatalf("chain:\n%s", out)
	}
}

func TestBuildChainCycle(t *testing.T) {
	t.Parallel()
	aSelf, aKey := mintCA(t, "a.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour))
	bSelf, bKey := mintCA(t, "b.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour))
	// Each certificate is signed by the other, so the walk has no self-signed end.
	a := mintSigned(t, "a.example", bSelf, bKey, &aKey.PublicKey)
	b := mintSigned(t, "b.example", aSelf, aKey, &bKey.PublicKey)
	out, err := buildChain(chainInput{
		leaf:    a,
		extras:  []*x509.Certificate{b},
		opts:    ChainOptions{Now: chainTestNow, Untrusted: true},
		blocked: func(*x509.Certificate) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "incomplete: cycle at a.example") {
		t.Fatalf("cycle note missing:\n%s", out)
	}
}

func TestResolveChainLeafLocalSkipsRemote(t *testing.T) {
	t.Parallel()
	leaf, ca := mintLeafAndCA(t, "leaf.example", "ca.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	u := mustURL(t, "https://leaf.example")
	opts := ChainOptions{
		URL:    u,
		Remote: true,
		Now:    chainTestNow,
		Fetch: func(*url.URL) ([]*x509.Certificate, error) {
			t.Fatal("remote lookup ran")
			return nil, errors.New("remote")
		},
	}
	got, extras, err := resolveChainLeaf(opts, []*x509.Certificate{leaf}, []*x509.Certificate{ca}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if chainFP(got) != chainFP(leaf) {
		t.Fatalf("leaf = %s", got.Subject.CommonName)
	}
	if len(extras) != 0 {
		t.Fatalf("extras = %d", len(extras))
	}
}

func TestResolveChainLeafRemoteFallback(t *testing.T) {
	t.Parallel()
	leaf, ca := mintLeafAndCA(t, "leaf.example", "ca.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	u := mustURL(t, "https://leaf.example")
	opts := ChainOptions{URL: u, Now: chainTestNow}
	_, _, err := resolveChainLeaf(opts, nil, nil, nil)
	if err == nil || err.Error() != "no local chain for https://leaf.example; pass --remote to look up the TLS chain" {
		t.Fatalf("err = %v", err)
	}
	opts.Remote = true
	opts.Fetch = func(got *url.URL) ([]*x509.Certificate, error) {
		if got.String() != u.String() {
			t.Fatalf("fetch url = %s", got)
		}
		return []*x509.Certificate{leaf, ca}, nil
	}
	got, extras, err := resolveChainLeaf(opts, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if chainFP(got) != chainFP(leaf) {
		t.Fatalf("leaf = %s", got.Subject.CommonName)
	}
	if len(extras) != 1 || chainFP(extras[0]) != chainFP(ca) {
		t.Fatalf("extras = %#v", extras)
	}
}

func TestResolveChainLeafRedactsURL(t *testing.T) {
	t.Parallel()
	u := mustURL(t, "https://alice:s3cret@leaf.example:8443/hidden?token=sekrit#frag")
	opts := ChainOptions{URL: u, Now: chainTestNow}
	_, _, err := resolveChainLeaf(opts, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	assertChainURLRedacted(t, err.Error(), "https://leaf.example:8443")
	if err.Error() != "no local chain for https://leaf.example:8443; pass --remote to look up the TLS chain" {
		t.Fatalf("err = %v", err)
	}

	opts.Remote = true
	opts.Fetch = func(*url.URL) ([]*x509.Certificate, error) {
		return nil, nil
	}
	_, _, err = resolveChainLeaf(opts, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	assertChainURLRedacted(t, err.Error(), "https://leaf.example:8443")
	if err.Error() != "remote lookup for https://leaf.example:8443: server presented no certificates" {
		t.Fatalf("err = %v", err)
	}

	// Empty host fails before any dial.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	bare := &url.URL{
		Scheme:   "https",
		User:     url.UserPassword("alice", "s3cret"),
		Path:     "/hidden",
		RawQuery: "token=sekrit",
		Fragment: "frag",
	}
	_, err = readChainCertificates(ctx, bare, 120*time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
	assertChainURLRedacted(t, err.Error(), "https://")
	if strings.Contains(err.Error(), u.User.String()) || strings.Contains(err.Error(), "token=sekrit") {
		t.Fatalf("full url in error: %v", err)
	}
}

func assertChainURLRedacted(t *testing.T, msg, host string) {
	t.Helper()
	if !strings.Contains(msg, host) {
		t.Fatalf("error missing %q: %s", host, msg)
	}
	for _, secret := range []string{"alice", "s3cret", "token", "sekrit", "hidden", "frag", "user:pass", "alice:s3cret"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error text contains %q: %s", secret, msg)
		}
	}
}

func TestChainHostnameCNFallback(t *testing.T) {
	t.Parallel()
	ca, _ := mintCA(t, "only-cn.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(time.Hour))
	// mintCA sets DNSNames. Strip them so only the CN remains.
	ca.DNSNames = nil
	if !chainHostname(ca, "only-cn.example") {
		t.Fatal("CN-only certificate did not match")
	}
	if chainHostname(ca, "other.example") {
		t.Fatal("CN matched a different host")
	}
}

func TestShowChainReadOnlyBundle(t *testing.T) {
	leaf, ca := mintLeafAndCA(t, "leaf.example", "ca.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	leafPath := filepath.Join(dir, "leaf.pem")
	if err := certutil.ToFile(bundle, []*x509.Certificate{ca}); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(leafPath, []*x509.Certificate{leaf}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = ShowChain(&buf, ChainOptions{
		App:    "openssl",
		Bundle: bundle,
		File:   leafPath,
		Now:    chainTestNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("bundle was modified")
	}
	want, err := formatConnectChainTable([]*x509.Certificate{leaf, ca})
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != want {
		t.Fatalf("show:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestShowChainAllIncludesPrivateCA(t *testing.T) {
	notBefore := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	ca, key := mintCA(t, "priv.example", notBefore, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	leaf := mintChild(t, "leaf.example", ca, key, chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour), false)
	other, _ := mintCA(t, "other.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	leafPath := filepath.Join(dir, "chain.pem")
	if err := certutil.ToFile(bundle, []*x509.Certificate{other}); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(leafPath, []*x509.Certificate{leaf, ca}); err != nil {
		t.Fatal(err)
	}

	var plain bytes.Buffer
	err := ShowChain(&plain, ChainOptions{App: "openssl", Bundle: bundle, File: leafPath, Now: chainTestNow})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain.String(), "pass --untrusted --expired") {
		t.Fatalf("expected include hint:\n%s", plain.String())
	}
	if lines := chainDataLines(plain.String()); len(lines) != 1 {
		t.Fatalf("rows = %d, want 1:\n%s", len(lines), plain.String())
	}

	var buf bytes.Buffer
	err = ShowChain(&buf, ChainOptions{App: "openssl", Bundle: bundle, File: leafPath, All: true, Now: chainTestNow})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "priv.example (untrusted, expired)") {
		t.Fatalf("all shorthand:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "incomplete:") {
		t.Fatalf("complete private chain marked incomplete:\n%s", buf.String())
	}
}

func TestShowChainDERFile(t *testing.T) {
	leaf, ca := mintLeafAndCA(t, "leaf.example", "ca.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	leafPath := filepath.Join(dir, "leaf.der")
	if err := certutil.ToFile(bundle, []*x509.Certificate{ca}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafPath, leaf.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ShowChain(&buf, ChainOptions{App: "openssl", Bundle: bundle, File: leafPath, Now: chainTestNow}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "leaf.example") || !strings.Contains(buf.String(), "ca.example") {
		t.Fatalf("der chain:\n%s", buf.String())
	}
}

func TestShowChainRemoteHTTPTLS(t *testing.T) {
	leaf, ca, server := mintTLSChain(t, "leaf.example", "ca.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	srv := newChainServer(t, server)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	if err := certutil.ToFile(bundle, []*x509.Certificate{ca}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}

	var quiet bytes.Buffer
	err = ShowChain(&quiet, ChainOptions{App: "openssl", Bundle: bundle, URL: u, Now: chainTestNow})
	if err == nil || !strings.Contains(err.Error(), "pass --remote") {
		t.Fatalf("err = %v", err)
	}
	if quiet.Len() != 0 {
		t.Fatalf("wrote output on error: %s", quiet.String())
	}

	var buf bytes.Buffer
	err = ShowChain(&buf, ChainOptions{App: "openssl", Bundle: bundle, URL: u, Remote: true, Untrusted: true, Now: chainTestNow})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, leaf.Subject.CommonName) || !strings.Contains(out, "ca.example") {
		t.Fatalf("remote chain:\n%s", out)
	}
	// The leaf is not in the store. The CA is. Only a non-leaf outside
	// the store is labeled untrusted. This chain's CA is in the bundle.
	if strings.Contains(out, "(untrusted)") || strings.Contains(out, "incomplete:") {
		t.Fatalf("remote chain:\n%s", out)
	}
	after, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("bundle was modified")
	}
	assertSkipVerifyOff(t)
}

func TestShowChainRemoteUntrustedIntermediate(t *testing.T) {
	root, rootKey := mintCA(t, "root.example", chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	// The server sends leaf + intermediate. The root stays in the bundle.
	_, _, server := mintTLSChainUnder(t, root, rootKey, "leaf.example", "mid.example")
	srv := newChainServer(t, server)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	if err := certutil.ToFile(bundle, []*x509.Certificate{root}); err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	err = ShowChain(&plain, ChainOptions{App: "openssl", Bundle: bundle, URL: u, Remote: true, Now: chainTestNow})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain.String(), "pass --untrusted") {
		t.Fatalf("expected untrusted hint:\n%s", plain.String())
	}
	if strings.Contains(plain.String(), "mid.example (untrusted)") {
		t.Fatalf("intermediate included without --untrusted:\n%s", plain.String())
	}

	var buf bytes.Buffer
	err = ShowChain(&buf, ChainOptions{App: "openssl", Bundle: bundle, URL: u, Remote: true, Untrusted: true, Now: chainTestNow})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "mid.example (untrusted)") || !strings.Contains(out, "root.example") {
		t.Fatalf("remote chain:\n%s", out)
	}
	if strings.Contains(out, "root.example (untrusted)") || strings.Contains(out, "incomplete:") {
		t.Fatalf("root should be trusted and the chain complete:\n%s", out)
	}
	assertSkipVerifyOff(t)
}

func TestReadChainCertificatesTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})

	u := &url.URL{Scheme: "https", Host: ln.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err = readChainCertificates(ctx, u, 200*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !chainTimeout(err) {
		t.Fatalf("err = %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("dial took %s, want a short timeout", elapsed)
	}
	if !strings.Contains(err.Error(), "remote lookup for https://") {
		t.Fatalf("err = %v", err)
	}
}

func TestChainRemoteTimeoutConstant(t *testing.T) {
	t.Parallel()
	if chainRemoteTimeout != 30*time.Second {
		t.Fatalf("chainRemoteTimeout = %s", chainRemoteTimeout)
	}
}

func TestReadChainFileMissing(t *testing.T) {
	t.Parallel()
	_, err := readChainFile("no-such-chain-cert.pem")
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadChainFileDERTrailingWhitespace(t *testing.T) {
	t.Parallel()
	der := mintDEREndingInWhitespace(t)
	path := filepath.Join(t.TempDir(), "leaf.der")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatal(err)
	}
	certs, err := readChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0] == nil {
		t.Fatalf("certs = %d", len(certs))
	}
	if !bytes.Equal(certs[0].Raw, der) {
		t.Fatal("parsed certificate dropped trailing bytes")
	}
	trimmed := bytes.TrimSpace(der)
	if len(trimmed) >= len(der) {
		t.Fatalf("last byte %#x was not removed by TrimSpace", der[len(der)-1])
	}
	if _, err := x509.ParseCertificate(trimmed); err == nil {
		t.Fatalf("trimmed DER still parsed (last byte %#x)", der[len(der)-1])
	}
}

func chainTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func chainDataLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "INDEX") || line == "" || strings.HasPrefix(line, "incomplete:") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// mintDEREndingInWhitespace returns a certificate whose DER encoding ends
// in a whitespace byte (for example 0x20, 0x0a, or 0x09). The search is
// bounded and anything that could hang is wrapped in a 120s timeout.
func mintDEREndingInWhitespace(t *testing.T) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	type result struct {
		der []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		der, err := searchDEREndingInWhitespace(ctx)
		ch <- result{der, err}
	}()
	select {
	case <-ctx.Done():
		t.Fatalf("minting DER certificate: %v", ctx.Err())
	case res := <-ch:
		if res.err != nil {
			t.Fatal(res.err)
		}
		return res.der
	}
	return nil
}

func searchDEREndingInWhitespace(ctx context.Context) ([]byte, error) {
	const maxAttempts = 8192
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	notBefore := chainTestNow.Add(-time.Hour)
	notAfter := chainTestNow.Add(24 * time.Hour)
	for i := 1; i <= maxAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tmpl := caTemplate("ws.example", notBefore, notAfter)
		tmpl.SerialNumber = big.NewInt(int64(i))
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		if len(der) > 0 && derEndsWithWhitespace(der[len(der)-1]) {
			return der, nil
		}
	}
	return nil, errors.New("no DER certificate ended in whitespace after 8192 attempts")
}

// derEndsWithWhitespace reports bytes that bytes.TrimSpace removes from
// arbitrary binary. 0x85 and 0xA0 are Unicode spaces only as UTF-8
// sequences, so a lone signature byte of those values is left in place.
func derEndsWithWhitespace(b byte) bool {
	switch b {
	case 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20:
		return true
	default:
		return false
	}
}

func mintLeafAndCA(t *testing.T, leafCN, caCN string, notBefore, notAfter time.Time) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	ca, key := mintCA(t, caCN, notBefore, notAfter)
	leaf := mintChild(t, leafCN, ca, key, notBefore, notAfter, true)
	return leaf, ca
}

func mintSelfSignedLeaf(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mintCA(t *testing.T, cn string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return mintCAWithKey(t, key, cn, notBefore, notAfter), key
}

func mintCAWithKey(t *testing.T, key *ecdsa.PrivateKey, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := caTemplate(cn, notBefore, notAfter)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mintChild(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time, ipSAN bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}
	if ipSAN {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func caTemplate(cn string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}
}

func testSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	if n.Sign() == 0 {
		return big.NewInt(1)
	}
	return n
}

func mintSigned(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey) *x509.Certificate {
	t.Helper()
	tmpl := caTemplate(cn, chainTestNow.Add(-time.Hour), chainTestNow.Add(24*time.Hour))
	tmpl.SerialNumber = testSerial(t)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mintTLSChain(t *testing.T, leafCN, caCN string, notBefore, notAfter time.Time) (*x509.Certificate, *x509.Certificate, tls.Certificate) {
	t.Helper()
	ca, caKey := mintCA(t, caCN, notBefore, notAfter)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: leafCN},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{leafCN},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	server := tls.Certificate{Certificate: [][]byte{leafDER, ca.Raw}, PrivateKey: leafKey}
	return leaf, ca, server
}

func mintTLSChainUnder(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, leafCN, midCN string) (*x509.Certificate, *x509.Certificate, tls.Certificate) {
	t.Helper()
	midKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	midTmpl := caTemplate(midCN, chainTestNow.Add(-time.Hour), chainTestNow.Add(365*24*time.Hour))
	midTmpl.SerialNumber = testSerial(t)
	midDER, err := x509.CreateCertificate(rand.Reader, midTmpl, root, &midKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	mid, err := x509.ParseCertificate(midDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: leafCN},
		NotBefore:             chainTestNow.Add(-time.Hour),
		NotAfter:              chainTestNow.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{leafCN},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, mid, &leafKey.PublicKey, midKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	server := tls.Certificate{Certificate: [][]byte{leafDER, midDER}, PrivateKey: leafKey}
	return leaf, mid, server
}
