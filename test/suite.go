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
	"fmt"
	"testing"
)

func linuxSuite(t *testing.T, img *dockerfile) {
	if debug {
		fmt.Println("Linux start")
	}

	img.Run("sh", "-c", `total=$(/bin/trustprune list -count); echo "$total" > /tmp/total; echo "linux certs=$total"; test "$total" -gt 10`)
	img.CertManage("backup")
	img.Run("sh", "-c", `test "$(ls -1 ~/.trustprune/linux | wc -l | tr -d ' ')" -ge 1`)
	img.CertManage("allowlist", "-file", "/allowlist.json")
	img.Run("sh", "-c", `after=$(/bin/trustprune list -count); test "$after" -lt "$(cat /tmp/total)"`)
	// Probe TLS only. Do not use -f/-I: GitHub Actions IPs get HTTP 429 from
	// large sites, which curl -f treats as failure even when TLS succeeded.
	img.Run("sh", "-c", `set +e; curl -sS -o /dev/null --max-time 20 https://example.com/; code=$?; set -e; echo "allowlist_curl=$code"; test "$code" -ne 0`)
	img.CertManage("restore")
	img.Run("sh", "-c", `test "$(/bin/trustprune list -count)" -eq "$(cat /tmp/total)"`)
	img.Run("sh", "-c", `curl -sS -o /dev/null --max-time 20 https://example.com/`)
	img.CertManage("add", "-file", "/localcert.pem")
	img.Run("sh", "-c", `test "$(/bin/trustprune list -count)" -eq $(( $(cat /tmp/total) + 1 ))`)
	img.SuccessT(t)

	if debug {
		fmt.Println("Linux end")
	}
}

func javaSuite(t *testing.T, img *dockerfile) {
	if debug {
		fmt.Println("Java start")
	}

	img.Run("sh", "-c", `total=$(/bin/trustprune list -count -app java); echo "$total" > /tmp/jtotal; echo "java certs=$total"; test "$total" -gt 10`)
	javaKeystoreByteRoundTrip(img)
	img.RunSplit("cd / && java Download")
	// Exercise the hidden whitelist alias against the Java store.
	img.CertManage("whitelist", "-app", "java", "-file", "/allowlist.yaml")
	img.Run("sh", "-c", `after=$(/bin/trustprune list -count -app java); test "$after" -lt "$(cat /tmp/jtotal)"`)
	img.CertManage("restore", "-app", "java")
	img.Run("sh", "-c", `test "$(/bin/trustprune list -count -app java)" -eq "$(cat /tmp/jtotal)"`)
	img.RunSplit("cd / && java Download")
	img.CertManage("add", "-file", "/localcert.pem", "-app", "java")
	img.Run("sh", "-c", `test "$(/bin/trustprune list -count -app java)" -eq $(( $(cat /tmp/jtotal) + 1 ))`)
	img.SuccessT(t)

	if debug {
		fmt.Println("Java end")
	}
}

// javaKeystoreByteRoundTrip copies, mutates, and restores the container Java
// cacerts file. Layouts match pkg/store/java_linux.go ($JAVA_HOME/lib/security/cacerts
// then alpine's $JAVA_HOME/jre/lib/security/cacerts). Only the container store
// is touched; this helper is invoked from docker distro tests, never the host.
func javaKeystoreByteRoundTrip(img *dockerfile) {
	img.Run("sh", "-c", `test -n "$JAVA_HOME"; if [ -f "$JAVA_HOME/lib/security/cacerts" ]; then cacerts="$JAVA_HOME/lib/security/cacerts"; elif [ -f "$JAVA_HOME/jre/lib/security/cacerts" ]; then cacerts="$JAVA_HOME/jre/lib/security/cacerts"; else echo "java cacerts not found under JAVA_HOME=$JAVA_HOME (tried lib/security/cacerts and jre/lib/security/cacerts)" >&2; exit 1; fi; echo "$cacerts" > /tmp/jcacerts; echo "java cacerts=$cacerts"; test -s "$cacerts"; cp "$cacerts" /tmp/java-cacerts.orig; test -s /tmp/java-cacerts.orig`)
	img.CertManage("backup", "-app", "java")
	img.Run("sh", "-c", `bck=$(ls -1 ~/.trustprune/java | grep '\.bck$' | sort | tail -1); test -n "$bck"; test -f ~/.trustprune/java/"$bck"; test -s ~/.trustprune/java/"$bck".source; cmp /tmp/java-cacerts.orig ~/.trustprune/java/"$bck"`)
	img.Run("sh", "-c", `printf %s MUTATED-JAVA-CACERTS > "$(cat /tmp/jcacerts)"; o=$(cksum < /tmp/java-cacerts.orig); n=$(cksum < "$(cat /tmp/jcacerts)"); echo "java cacerts orig=$o mutated=$n"; test "$o" != "$n"`)
	img.CertManage("restore", "-app", "java")
	img.Run("sh", "-c", `cmp /tmp/java-cacerts.orig "$(cat /tmp/jcacerts)"`)
	img.Run("sh", "-c", `test "$(/bin/trustprune list -count -app java)" -eq "$(cat /tmp/jtotal)"`)
}

func firefoxSuite(t *testing.T, img *dockerfile, total, after string) {
	if total == "" || after == "" {
		t.Fatalf("total=%q or after=%q is blank", total, after)
	}
	if debug {
		fmt.Println("Firefox start")
	}

	img.RunSplit("ls -al ~/")
	img.SuccessT(t)

	if debug {
		fmt.Println("Firefox end")
	}
}

func certifiSuite(t *testing.T, img *dockerfile) {
	if debug {
		fmt.Println("Certifi start")
	}

	// Distro images install a venv with upstream certifi at /opt/trustprune-certifi.
	// Put it first on PATH so discovery hits a real cacert.pem, not a distro-patched
	// where() that points at the system CA bundle.
	img.Run("sh", "-c", `export PATH=/opt/trustprune-certifi/bin:$PATH; test -f "$(python3 -c 'import certifi; print(certifi.where())')"; total=$(/bin/trustprune list -count -app certifi); echo "$total" > /tmp/ctotal; echo "certifi certs=$total path=$(python3 -c 'import certifi; print(certifi.where())')"; test "$total" -gt 10`)
	img.Run("sh", "-c", `export PATH=/opt/trustprune-certifi/bin:$PATH; /bin/trustprune backup -app certifi; test "$(ls -1 ~/.trustprune/certifi | wc -l | tr -d ' ')" -ge 1`)
	img.Run("sh", "-c", `export PATH=/opt/trustprune-certifi/bin:$PATH; /bin/trustprune allowlist -app certifi -file /allowlist.json; after=$(/bin/trustprune list -count -app certifi); test "$after" -lt "$(cat /tmp/ctotal)"`)
	img.Run("sh", "-c", `export PATH=/opt/trustprune-certifi/bin:$PATH; /bin/trustprune restore -app certifi; test "$(/bin/trustprune list -count -app certifi)" -eq "$(cat /tmp/ctotal)"`)
	img.Run("sh", "-c", `export PATH=/opt/trustprune-certifi/bin:$PATH; /bin/trustprune add -file /localcert.pem -app certifi; test "$(/bin/trustprune list -count -app certifi)" -eq $(( $(cat /tmp/ctotal) + 1 ))`)
	img.SuccessT(t)

	if debug {
		fmt.Println("Certifi end")
	}
}
