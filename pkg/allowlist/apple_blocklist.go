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

// Fingerprints are the SHA-256 values Apple published in the
// "Blocked Certificates" table of:
// https://support.apple.com/en-us/103255
// Constrained certificates on that page are not included.
// HT204132 is the earlier Apple support article that described these lists.
// Generated on 2026-11-26T07:35:13Z, any modifications will be overwritten
package allowlist

var appleBlocklistedFingerprints = []string{
	// Qaznet Trust Network
	`00309c736dd661da6f1eb24173aa849944c168a43a15bffd192eecfdb6f8dbd2`,
	// Chambers of Commerce Root
	`0c258a12a5674aef25f28ba7dcfaeceea348e541e6f5cc4ee63b71b361606ac3`,
	// DigiNotar Root CA
	`0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217`,
	// Autoridad de Certificacion Raiz del Estado Venezolano
	`0ed3ffab6c149c8b4e71058e8668d429abfda681c2fff508207641f0d751a3e5`,
	// Apple Worldwide Developer Relations CA - G7
	`0f570d7502373a2102e2106faaa8fa4844944a07ee676198484f4d6ce15bea47`,
	// Certplus Root CA G1
	`152a402bfcdf2cd548054d2275b39c7fca3ec0978078b0f0ea76e561a6c7433e`,
	// Network Solutions Certificate Authority
	`15f0ba00a3ac7af3ac884c072b1011a077bd77c097f40164b2f8598abd83860c`,
	// DigiNotar Public CA 2025
	`1685ba27fdf24cece203fd829ac3fed5c85460ed0735b2d15751019e951540c0`,
	// Swisscom Root CA 1
	`21db20123660bb2ed418205da11ee7a85a65e2bc6e55b5af7e7899c8a266d92e`,
	// VeriSign Universal Root Certification Authority
	`2399561127a57125de8cefea610ddf2fa078b5c8067f4e828290bfb860e84b3c`,
	// OpenTrust Root CA G2
	`27995829fe6a7515c1bfe848f9c4761db16c225929257bf40d0894f29ea8baf2`,
	// DigiNotar Root CA G2
	`294f55ef3bd7244c6ff8a68ab797e9186ec27582751a791515e3292e48372d61`,
	// Certinomis - Root CA
	`2a99f5bc1174b73cbb1d620884e01c34e51ccb3978da125f0e33268883bf4158`,
	// Symantec Class 1 Public Primary Certification Authority - G4
	`363f3c849eab03b0a2a0f636d7b86d04d3ac7fcfe26a0a9121ab9795f6e176df`,
	// GeoTrust Primary Certification Authority
	`37d51006c512eaab626421f1ec8c92013fc5f82ae98ee533eb4619b8deb4d06c`,
	// SwissSign Platinum CA - G2
	`3b222e566711e992300dc0b15ab9473dafdef8c84d0cef7d3317b4c1821d1436`,
	// Staat der Nederlanden Root CA - G3
	`3c4fb0b95ab8b30032f432b86f535fe172c185d0fd39865837cf36187fa6f428`,
	// WoSign CA Free SSL Certificate G2
	`41a235ab60f0643e752a2db4e914d68c0542167de9ca28df25fd79a693c29072`,
	// Secure Global CA
	`4200f5043ac8590ebb527d209ed1503029fbcbd41ca1b506ec27f15ade7dac69`,
	// thawte Primary Root CA - G3
	`4b03f45807ad70f21bfc2cae71c9fde4604c064cf5ffb686bae5dbaad7fdd34c`,
	// VoiceFive
	`4b15a4ee04f0bdb6c7ef1a15b63c72006688f7ca3d8ccdc0133b90a739e1aa55`,
	// ComSign Secured CA
	`507941c74460a0b47086220d4e9932572ab5d1b5bbcb8980ab1cb17651a844d2`,
	// Symantec Class 3 Public Primary Certification Authority - G4
	`53dfdfa4e297fcfe07594e8c62d5b8ab06b32c7549f38a163094fd6429d5da43`,
	// OpenTrust Root CA G1
	`56c77128d98c18d91b4cfdffbc25ee9103d4758ea2abad826a90f3457d460eb4`,
	// DigiNotar Qualified CA
	`5bf3a3b793465f3767d7c7b4a03d80367c8957c498299c29b903f33fe340af7a`,
	// TMRG
	`61dab17b03b2c239ae41d6a0712882d1484b821d0eb895d52f0fec634db713b8`,
	// Echoworx Root CA2
	`6639d13cab85df1ad9a23c443b3a60901e2b138d456fa71183578108884ec6bf`,
	// VeriSign Class 3 Public Primary Certification Authority - G4
	`69ddd7ea90bb57c93e135dc85ea6fcd5480b603239bdc454fc758b2a26cf7f79`,
	// DigiNotar Root CA
	`6bf5533d0ddeaf023d58e401277c26442b1f1af1a0f2dbbd9b2e3ba3a292fb23`,
	// Certplus Root CA G2
	`6cc05041e6445e74696c4cfbc9f80f543b7eabbb44b4ce6f787c6a9971c42f17`,
	// KISA RootCA 1
	`6fdb3f76c8b801a75338d8a50a7c02879f6198b57e594d318d3832900fedcd79`,
	// Government Root Certification Authority
	`70b922bfda0e3f4a342e4ee22d579ae598d071cc5ec9c30f123680340388aea5`,
	// DigiNotar Services 1024 CA
	`71253459e5e64d1f9077a5c458999b67d7d9e70706af680b045eb1d27b79e38f`,
	// Trustwave Organization Issuing CA, Level 2
	`77dece8000964a74aeed685c0c9301f081a29b6f1803b14230dbd0bac7a39cfc`,
	// Cisco Root CA 2048
	`8327bc8c9d69947b3de3c27511537267f59c21b9fa7b613fafbccd53b7024000`,
	// thawte Primary Root CA
	`8d722f81a9c113c0791df136a2966db26c950a971db46b4199f4ea54b78bfb9f`,
	// SenncomRootCA
	`91e5cc32910686c5cac25c18cc805696c7b33868c280caf0c72844a2a8eb91e2`,
	// VeriSign Class 2 Public Primary Certification Authority - G3
	`92a9d9833fe1944db366e8bfae7a95b6480c2d6c6c2a1be65d4236b608fca1bb`,
	// TRUST2408 OCES Primary CA
	`92d8092ee77bc9208f0897dc05271894e63ef27933ae537fb983eef0eae3eec8`,
	// Symantec Class 1 Public Primary Certification Authority - G6
	`9d190b2e314566685be8a889e27aa8c7d7ae1d8aaddba3c1ecf9d24863cd34b9`,
	// SECOM Trust Systems CO.,LTD./Security Communication EV RootCA1
	`a22dba681e97376e2d397d728aae3a9b6296b9fdba60bc2e11f647f2c675fb37`,
	// thawte Primary Root CA - G2
	`a4310d50af18a6447190372a86afaf8b951ffb431d837f1e5688b45971ed1557`,
	// VeriSign Class 3 Public Primary Certification Authority
	`a4b6b3996fc2f306b3fd8681bd63413d8c5009cc4fa329c2ccf0e2fa1b140305`,
	// DigiNotar Services CA
	`a6a2217c1d192fe71fce87870167011c26e1a9b8582f5f08d8ecb9b3209f5fdb`,
	// Facebook Research
	`abd055c297005a89e4458ae34d4bc77e67db0fe1be575842c4efb7e8c3e05839`,
	// ComSign CA
	`ae4457b40d9eda96677b0d3c92d57b5177abd7ac1037958356d1e094518be5f2`,
	// Symantec Class 3 Public Primary Certification Authority - G6
	`b32396746453442f353e616292bb20bbaa5d23b546450fdb9c54b8386167d529`,
	// GeoTrust Primary Certification Authority - G3
	`b478b812250df878635c2aa7ec7d155eaa625ee82916e2cd294361886cd1fbd4`,
	// OpenTrust Root CA G3
	`b7c36231706e81078c367cb896198f1e3208dd926949dd8f5709a410f75b6292`,
	// Hellenic Academic and Research Institutions RootCA 2011
	`bc104f15a48be709dca542a7e1d4b9df6f054527e802eaa92d595444258afe71`,
	// Trustis Limited/Trustis FPS Root CA
	`c1b48299aba5208fe9630ace55ca68a03eda5a519c8802a0d3a673be8f8e557d`,
	// StartCom Certification Authority
	`c766a9bef2d4071c863a31aa4920e813b2d198608cb7b7cfe21143b836df09ea`,
	// StartCom Certification Authority G2
	`c7ba6567de93a798ae1faa791e712d378fae1f93c4397fea441bb7cbe6fd5995`,
	// Symantec Class 2 Public Primary Certification Authority - G6
	`cb627d18b58ad56dde331a30456bc65c601a4e9b18dedcea08e7daaa07815ff0`,
	// VeriSign Class 1 Public Primary Certification Authority - G3
	`cbb5af185e942a2402f9eacbc0ed5bb876eea3c1223623d00447e4f3ba554b65`,
	// Swisscom Root EV CA 2
	`d95fea3ca4eedce74cd76e75fc6d1ff62c441f0fa8bc77f034b19e5db258015d`,
	// StartCom Certification Authority
	`e17890ee09a3fbf4f48b9c414a17d637b7a50647e9bc752322727fcc1742a911`,
	// CNNIC ROOT
	`e28393773da845a679f2080cc7fb44a3b7a1c3792cb7eb7729fdcb6a8d99aea7`,
	// ANF Global Root CA
	`e3268f6106ba8b665a1a962ddea1459d2a46972f1f2440329b390b895749ad45`,
	// VeriSign Class 3 Public Primary Certification Authority - G3
	`eb04cf5eb1f39afa762f2bb120f296cba520c1b97db1589565b81cb9a17b7244`,
	// Global Chambersign Root
	`ef3cb417fc8ebf6f97876c9e4ece39de1ea5fe649141d1028b7d11c0b2298ced`,
	// Swisscom Root CA 2
	`f09b122c7114f4a09bd4ea4f4a99d558b46e4c25cd81140d29c05613914c3841`,
	// CA Disig Root R1
	`f96f23f4c3e79c077a46988d5af5900676a0f039cb645dd17549b216c82440ce`,
	// SZAFIR ROOT CA
	`fabcf5197cdd7f458ac33832d3284021db2425fd6bea7a2e69b7486e8f51f9cc`,
	// Certinomis - Autorité Racine
	`fcbfe2886206f72b27593c8b070297e12d769ed10ed7930705a8098effc14d17`,
	// Symantec Class 2 Public Primary Certification Authority - G4
	`fe863d0822fe7a2353fa484d5924e875656d3dc9fb58771f6f616f9d571bc592`,
}
