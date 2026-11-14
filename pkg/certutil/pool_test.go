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

package certutil

import (
	"crypto/x509"
	"testing"
)

func TestCertUtil__pool(t *testing.T) {
	certs, err := FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("found no certs")
	}

	pool := Pool{}
	pool.Add(certs[0])
	pool.Add(certs[0])

	found := pool.GetCertificates()
	if len(found) != 1 {
		t.Fatalf("found %d certs", len(found))
	}

	// add more
	certs, err = FromFile("../../testdata/lots.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("found no certs")
	}
	pool.AddCertificates(certs)

	found = pool.GetCertificates()
	if len(found) != 1+len(certs) {
		t.Fatalf("found %d certs expected %d", len(found), 1+len(certs))
	}
}

func TestCertUtil__nil(t *testing.T) {
	pool := Pool{}

	pool.Add(nil)
	if n := len(pool.GetCertificates()); n != 0 {
		t.Errorf("got %d", n)
	}

	pool.AddCertificates(nil)
	if n := len(pool.GetCertificates()); n != 0 {
		t.Errorf("got %d", n)
	}

	pool.AddCertificates([]*x509.Certificate{nil})
	if n := len(pool.GetCertificates()); n != 0 {
		t.Errorf("got %d", n)
	}
}

func TestCertUtil__poolDedupesBatch(t *testing.T) {
	certs, err := FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("found no certs")
	}

	pool := Pool{}
	pool.AddCertificates([]*x509.Certificate{certs[0], certs[0]})
	if n := len(pool.GetCertificates()); n != 1 {
		t.Fatalf("found %d certs, want 1", n)
	}
}
