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
	"compress/gzip"
	"io"
	"os"
	"testing"
)

func TestCertUtil__decodePEM(t *testing.T) {
	bs, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d", len(certs))
	}
}

func TestCertUtil__decodeNSS(t *testing.T) {
	f, err := os.Open("../../testdata/certdata.txt.gz")
	if err != nil {
		t.Fatal(err)
	}
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 113 {
		t.Errorf("got %d", len(certs))
	}
}

func TestCertUtil__decodeLots(t *testing.T) {
	bs, err := os.ReadFile("../../testdata/lots.crt")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 5 {
		t.Fatalf("got %d certs, want 5", len(certs))
	}
	// First cert is the Entrust.net 2048 CA from the fixture.
	if got := GetHexSHA256Fingerprint(*certs[0]); got == "" {
		t.Fatal("empty sha256 fingerprint")
	}
	algo, bits := PublicKeyInfo(certs[0])
	if algo != "RSA" || bits != 2048 {
		t.Fatalf("key info = %s-%d, want RSA-2048", algo, bits)
	}
	if !certs[0].IsCA {
		t.Fatal("expected first lots.crt cert to be a CA")
	}
}
