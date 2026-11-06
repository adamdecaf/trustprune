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

package cmd

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist/gen"
)

func TestSortCAsByDNSNameCountDescending(t *testing.T) {
	t.Parallel()
	cas := []*gen.CA{
		{DNSNames: []string{"a.example"}},
		{DNSNames: []string{"b.example", "c.example", "d.example"}},
		{DNSNames: []string{"e.example", "f.example"}},
	}
	sortCAs(cas)
	if len(cas[0].DNSNames) != 3 || len(cas[1].DNSNames) != 2 || len(cas[2].DNSNames) != 1 {
		t.Fatalf("order by DNSNames len: %#v %#v %#v", cas[0].DNSNames, cas[1].DNSNames, cas[2].DNSNames)
	}
}

func TestAddCertsToPool(t *testing.T) {
	t.Parallel()
	pool := x509.NewCertPool()
	addCertsToPool(pool, func() ([]*x509.Certificate, error) {
		return nil, errors.New("skip")
	})
	addCertsToPool(pool, func() ([]*x509.Certificate, error) {
		return nil, nil
	})
}
