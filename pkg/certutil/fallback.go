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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ParseCertificate is crypto/x509.ParseCertificate with a cryptobyte fallback
// only for certificates rejected because of a negative serial number. The
// fallback fills Raw, SerialNumber, Issuer, Subject, NotBefore, and NotAfter
// so list, allowlist, and fingerprinting treat the cert like any other. Other
// parse failures still return the original x509 error. It does not set GODEBUG
// and does not verify signatures.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err == nil {
		return cert, nil
	}
	fb, fbErr := parseCertificateFallback(der)
	if fbErr == nil && fb.SerialNumber != nil && fb.SerialNumber.Sign() < 0 {
		return fb, nil
	}
	return nil, err
}

// parseCertificateFallback reads a partial Certificate from DER using
// cryptobyte. It accepts negative serial numbers that crypto/x509 refuses.
func parseCertificateFallback(der []byte) (*x509.Certificate, error) {
	input := cryptobyte.String(der)

	var certSeq cryptobyte.String
	if !input.ReadASN1Element(&certSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("certutil: malformed certificate")
	}
	raw := []byte(certSeq)
	if !certSeq.ReadASN1(&certSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("certutil: malformed certificate")
	}

	var tbs cryptobyte.String
	if !certSeq.ReadASN1Element(&tbs, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("certutil: malformed tbs certificate")
	}
	rawTBS := []byte(tbs)
	if !tbs.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("certutil: malformed tbs certificate")
	}

	// version [0] EXPLICIT INTEGER DEFAULT v1 — skip if present
	if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, errors.New("certutil: malformed version")
	}

	serial := new(big.Int)
	if !tbs.ReadASN1Integer(serial) {
		return nil, errors.New("certutil: malformed serial number")
	}

	// signature AlgorithmIdentifier
	if !tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("certutil: malformed signature algorithm")
	}

	var issuerSeq cryptobyte.String
	if !tbs.ReadASN1Element(&issuerSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("certutil: malformed issuer")
	}
	issuer, err := parseName(issuerSeq)
	if err != nil {
		return nil, fmt.Errorf("certutil: issuer: %w", err)
	}

	var validity cryptobyte.String
	if !tbs.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("certutil: malformed validity")
	}
	notBefore, notAfter, err := parseValidity(validity)
	if err != nil {
		return nil, err
	}

	var subjectSeq cryptobyte.String
	if !tbs.ReadASN1Element(&subjectSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("certutil: malformed subject")
	}
	subject, err := parseName(subjectSeq)
	if err != nil {
		return nil, fmt.Errorf("certutil: subject: %w", err)
	}

	return &x509.Certificate{
		Raw:               append([]byte(nil), raw...),
		RawTBSCertificate: append([]byte(nil), rawTBS...),
		RawIssuer:         append([]byte(nil), issuerSeq...),
		RawSubject:        append([]byte(nil), subjectSeq...),
		SerialNumber:      serial,
		Issuer:            issuer,
		Subject:           subject,
		NotBefore:         notBefore,
		NotAfter:          notAfter,
	}, nil
}

func parseName(der cryptobyte.String) (pkix.Name, error) {
	var name pkix.Name
	var rdn pkix.RDNSequence
	rest, err := asn1.Unmarshal([]byte(der), &rdn)
	if err != nil {
		return name, err
	}
	if len(rest) != 0 {
		return name, errors.New("trailing data in name")
	}
	name.FillFromRDNSequence(&rdn)
	return name, nil
}

func parseValidity(der cryptobyte.String) (notBefore, notAfter time.Time, err error) {
	notBefore, err = readASN1Time(&der)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("certutil: notBefore: %w", err)
	}
	notAfter, err = readASN1Time(&der)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("certutil: notAfter: %w", err)
	}
	return notBefore, notAfter, nil
}

func readASN1Time(s *cryptobyte.String) (time.Time, error) {
	var t time.Time
	switch {
	case s.PeekASN1Tag(cryptobyte_asn1.UTCTime):
		if !s.ReadASN1UTCTime(&t) {
			return time.Time{}, errors.New("malformed UTCTime")
		}
	case s.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime):
		if !s.ReadASN1GeneralizedTime(&t) {
			return time.Time{}, errors.New("malformed GeneralizedTime")
		}
	default:
		return time.Time{}, errors.New("unsupported time tag")
	}
	return t, nil
}
