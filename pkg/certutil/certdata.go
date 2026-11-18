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

package certutil

import (
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: NSS trust records are keyed by CKA_CERT_SHA1_HASH
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// certdata.txt parsing follows the object model in mozilla/OneCRL-Tools/certdata
// (https://github.com/mozilla/OneCRL-Tools/blob/master/certdata/certdata.go),
// which is licensed under MPL-2.0. That package is not imported. Current
// releases of the module no longer contain it, and the last revision that
// does sets go 1.14 and pulls a large module graph, including cgo packages.
// This file is original Apache-2.0 code; the upstream sources were not copied.
//
// A certificate is trusted for TLS when its CKO_NSS_TRUST object sets
// CKA_TRUST_SERVER_AUTH to CKT_NSS_TRUSTED_DELEGATOR. Other server-auth
// values, including CKT_NSS_NOT_TRUSTED, CKT_NSS_MUST_VERIFY_TRUST,
// CKT_NSS_TRUST_UNKNOWN, and the combined
// "(CKT_NSS_MUST_VERIFY_TRUST|CKT_NSS_NOT_TRUSTED)" form, are not trusted.
// DER fields are MULTILINE_OCTAL. Current certdata.txt also stores
// CKA_NSS_SERVER_DISTRUST_AFTER as a UTCTime string YYMMDDHHMMSSZ when it
// is MULTILINE_OCTAL, and as CK_FALSE when the root has no such date.
// The date does not remove the root: Mozilla still trusts it, and rejects
// certificates it issues after that instant.

const serverDistrustAfterAttr = "CKA_NSS_SERVER_DISTRUST_AFTER"

// nssDistrustTime is the Go layout for an NSS YYMMDDHHMMSSZ timestamp.
// The numeric zone is optional; certdata.txt uses a literal Z.
const nssDistrustTime = "060102150405Z0700"

type certDataEntry struct {
	cert                *x509.Certificate
	serverDistrustAfter time.Time // zero when the certificate has no date
}

type nssAttr struct {
	kind  string
	value []byte
}

type nssObject struct {
	line  int
	attrs map[string]nssAttr
}

type certDataParser struct {
	r      *bufio.Reader
	lineNo int
}

// parseCertData reads a Mozilla certdata.txt document and returns the
// certificates trusted for TLS server authentication.
func parseCertData(r io.Reader) ([]certDataEntry, error) {
	objects, err := parseNSSObjects(&certDataParser{r: bufio.NewReader(r)})
	if err != nil {
		return nil, err
	}
	return trustedServerAuthCerts(objects)
}

func parseNSSObjects(p *certDataParser) ([]nssObject, error) {
	var objects []nssObject
	var current *nssObject
	sawData := false
	for {
		line, err := p.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if !sawData {
			if line == "BEGINDATA" {
				sawData = true
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "CVS_ID ") {
			continue
		}

		name, attr, err := p.parseAttr(line)
		if err != nil {
			return nil, err
		}
		if name == "CKA_CLASS" {
			if current != nil {
				objects = append(objects, *current)
			}
			current = &nssObject{
				line:  p.lineNo,
				attrs: make(map[string]nssAttr),
			}
		}
		if current == nil {
			return nil, fmt.Errorf("certdata: line %d: attribute %s is outside an object", p.lineNo, name)
		}
		current.attrs[name] = attr
	}
	if !sawData {
		return nil, errors.New("certdata: BEGINDATA not found")
	}
	if current != nil {
		objects = append(objects, *current)
	}
	return objects, nil
}

func (p *certDataParser) parseAttr(line string) (string, nssAttr, error) {
	words := strings.Fields(line)
	if len(words) == 2 && words[1] == "MULTILINE_OCTAL" {
		value, err := p.readMultilineOctal()
		if err != nil {
			return "", nssAttr{}, err
		}
		return words[0], nssAttr{kind: words[1], value: value}, nil
	}
	if len(words) < 3 {
		return "", nssAttr{}, fmt.Errorf("certdata: line %d: expected name, type, and value", p.lineNo)
	}
	return words[0], nssAttr{kind: words[1], value: []byte(strings.Join(words[2:], " "))}, nil
}

func (p *certDataParser) readMultilineOctal() ([]byte, error) {
	start := p.lineNo
	var lines []string
	for {
		line, err := p.next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("certdata: line %d: MULTILINE_OCTAL missing END", start)
		}
		if err != nil {
			return nil, err
		}
		if line == "END" {
			value, err := decodeOctalLines(lines)
			if err != nil {
				return nil, fmt.Errorf("certdata: line %d: MULTILINE_OCTAL: %w", start, err)
			}
			return value, nil
		}
		lines = append(lines, line)
	}
}

func decodeOctalLines(lines []string) ([]byte, error) {
	var out []byte
	for _, line := range lines {
		for _, part := range strings.Split(line, `\`) {
			if part == "" {
				continue
			}
			v, err := strconv.ParseUint(part, 8, 8)
			if err != nil {
				return nil, err
			}
			out = append(out, byte(v))
		}
	}
	return out, nil
}

func (p *certDataParser) next() (string, error) {
	line, err := p.r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("certdata: line %d: %w", p.lineNo+1, err)
	}
	if len(line) == 0 {
		return "", io.EOF
	}
	p.lineNo++
	return strings.TrimRight(line, "\r\n"), nil
}

func trustedServerAuthCerts(objects []nssObject) ([]certDataEntry, error) {
	var certs []nssObject
	var trusts []nssObject
	for _, object := range objects {
		switch object.class() {
		case "CKO_CERTIFICATE":
			certs = append(certs, object)
		case "CKO_NSS_TRUST":
			trusts = append(trusts, object)
		}
	}

	var out []certDataEntry
	for _, cert := range certs {
		distrustAfter, err := cert.serverDistrustAfter()
		if err != nil {
			return nil, fmt.Errorf("certdata: line %d: %w", cert.line, err)
		}
		derAttr, ok := cert.attrs["CKA_VALUE"]
		if !ok || derAttr.kind != "MULTILINE_OCTAL" {
			continue
		}
		if !serverAuthTrusted(trusts, derAttr.value) {
			continue
		}
		// crypto/x509 rejects at least one historical NSS builtin certificate
		// (bug 707995). Skip that object and keep reading the rest of the file.
		parsed, err := x509.ParseCertificate(derAttr.value)
		if err != nil {
			continue
		}
		out = append(out, certDataEntry{cert: parsed, serverDistrustAfter: distrustAfter})
	}
	return out, nil
}

func (o nssObject) class() string {
	return string(o.attrs["CKA_CLASS"].value)
}

func (o nssObject) serverDistrustAfter() (time.Time, error) {
	attr, ok := o.attrs[serverDistrustAfterAttr]
	if !ok || attr.kind != "MULTILINE_OCTAL" {
		return time.Time{}, nil
	}
	t, err := time.Parse(nssDistrustTime, string(attr.value))
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", serverDistrustAfterAttr, err)
	}
	return t, nil
}

func serverAuthTrusted(trusts []nssObject, der []byte) bool {
	sum := sha1.Sum(der) //nolint:gosec // G401: match CKA_CERT_SHA1_HASH, not a signature
	for _, trust := range trusts {
		hash, ok := trust.attrs["CKA_CERT_SHA1_HASH"]
		if !ok || !bytes.Equal(sum[:], hash.value) {
			continue
		}
		return string(trust.attrs["CKA_TRUST_SERVER_AUTH"].value) == "CKT_NSS_TRUSTED_DELEGATOR"
	}
	return false
}
