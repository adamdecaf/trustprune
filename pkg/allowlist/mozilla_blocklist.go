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

// Fingerprints are derived from Mozilla certdata.txt,
// https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/nss/lib/ckfw/builtins/certdata.txt
// Mozilla Public License, v. 2.0. See NOTICE.
// A certificate is included when CKA_TRUST_SERVER_AUTH is CKT_NSS_NOT_TRUSTED,
// or when CKA_NSS_SERVER_DISTRUST_AFTER had passed at generation time.
// The distrust-after date is recorded on that entry.
// Generated on 2026-11-18T04:07:25Z by box, any modifications will be overwritten
package allowlist

var mozillaBlocklistedFingerprints = []string{
	// CN=Entrust.net Certification Authority (2048),OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.)+OU=(c) 1999 Entrust.net Limited,O=Entrust.net
	// CKA_NSS_SERVER_DISTRUST_AFTER 2024-11-30T23:59:59Z
	`6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177`,
	// CN=Izenpe.com,O=IZENPE S.A.,C=ES
	// CKA_NSS_SERVER_DISTRUST_AFTER 2026-04-15T23:59:59Z
	`2530cc8e98321502bad96f9b1fba1b099e2d299e0f4548bb914f363bc0d4531f`,
	// CN=DigiCert Trusted Root G4,OU=www.digicert.com,O=DigiCert Inc,C=US
	// CKA_NSS_SERVER_DISTRUST_AFTER 2026-09-14T23:59:59Z
	`552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988`,
	// CN=Entrust Root Certification Authority - G2,OU=See www.entrust.net/legal-terms+OU=(c) 2009 Entrust\, Inc. - for authorized use only,O=Entrust\, Inc.,C=US
	// CKA_NSS_SERVER_DISTRUST_AFTER 2024-11-30T23:59:59Z
	`43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339`,
	// CN=Entrust Root Certification Authority - EC1,OU=See www.entrust.net/legal-terms+OU=(c) 2012 Entrust\, Inc. - for authorized use only,O=Entrust\, Inc.,C=US
	// CKA_NSS_SERVER_DISTRUST_AFTER 2024-11-30T23:59:59Z
	`02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5`,
	// CN=emSign Root CA - G1,OU=emSign PKI,O=eMudhra Technologies Limited,C=IN
	// CKA_NSS_SERVER_DISTRUST_AFTER 2026-11-16T23:59:59Z
	`40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367`,
	// CN=Autoridad de Certificacion Firmaprofesional CIF A62634068,C=ES
	// CKA_NSS_SERVER_DISTRUST_AFTER 2026-08-06T07:01:00Z
	`57de0583efd2b26e0361da99da9df4648def7ee8441c3b728afa9bcde0f9b26a`,
}
