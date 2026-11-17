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

package store

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func setAcrobatTrustRead(t *testing.T, fn func() ([]acrobatTrustProduct, error)) {
	t.Helper()
	prev := acrobatTrustRead
	acrobatTrustRead = fn
	t.Cleanup(func() { acrobatTrustRead = prev })
}

func TestAcrobatTrustReportNotInstalled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	setAcrobatFixture(t, acrobatSearch{goos: "linux"}, nil)
	setAcrobatTrustRead(t, func() ([]acrobatTrustProduct, error) {
		return nil, nil
	})

	got, err := AcrobatTrustReport()
	if err != nil {
		t.Fatal(err)
	}
	if got != AcrobatNotInstalledReport {
		t.Fatalf("report=%q", got)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("report wrote into HOME: %v", entries)
	}
}

func TestAcrobatTrustReportFakeValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	appData := t.TempDir()
	book := acrobatBook(appData, "DC")
	writeAcrobatFile(t, book, []byte("book"))
	setAcrobatFixture(t, acrobatSearch{goos: "windows", appData: appData}, nil)
	setAcrobatTrustRead(t, func() ([]acrobatTrustProduct, error) {
		return []acrobatTrustProduct{
			{
				Product: acrobatProductReader,
				Version: "11.0",
				Source:  `HKCU\Software\Adobe\Acrobat Reader\11.0\Security\cDigSig`,
				AATL:    acrobatTrustValue{Found: true, Raw: 1, Key: `cAdobeDownload\bLoadSettingsFromURL`},
				EUTL:    acrobatTrustValue{Found: true, Raw: 0, Key: `cEUTLDownload\bLoadSettingsFromURL`},
				MSStore: acrobatTrustValue{Found: true, Raw: 0x62, Key: `cCustomDownload\iMSStoreTrusted`},
			},
			{
				Product: acrobatProductAcrobat,
				Version: "DC",
				Source:  `HKCU\Software\Adobe\Adobe Acrobat\DC\Security\cDigSig`,
				AATL:    acrobatTrustValue{Found: true, Raw: 0, Key: "bLoadSettingsFromURL"},
				EUTL:    acrobatTrustValue{},
				MSStore: acrobatTrustValue{Found: true, Raw: 0x60, Key: "iMSStoreTrusted"},
			},
		}, nil
	})

	got, err := AcrobatTrustReport()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"acrobat trust settings (read only):",
		`Adobe Acrobat DC (HKCU\Software\Adobe\Adobe Acrobat\DC\Security\cDigSig):`,
		"  AATL download (bLoadSettingsFromURL): 0 (off)",
		"  EUTL download (cEUTLDownload): not set",
		"  Windows store trust (iMSStoreTrusted): 0x60 (signatures)",
		`Acrobat Reader 11.0 (HKCU\Software\Adobe\Acrobat Reader\11.0\Security\cDigSig):`,
		`  AATL download (cAdobeDownload\bLoadSettingsFromURL): 1 (on)`,
		`  EUTL download (cEUTLDownload\bLoadSettingsFromURL): 0 (off)`,
		`  Windows store trust (cCustomDownload\iMSStoreTrusted): 0x62 (signatures and certified documents)`,
		"address book: " + book,
	}, "\n")
	if got != want {
		t.Fatalf("report=\n%s\nwant=\n%s", got, want)
	}
	if strings.Contains(got, AcrobatNotInstalledReport) {
		t.Fatalf("installed report says not installed:\n%s", got)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("report wrote into HOME: %v", entries)
	}
}

func TestAcrobatTrustReportAddressBookOnly(t *testing.T) {
	appData := t.TempDir()
	book := acrobatBook(appData, "11.0")
	writeAcrobatFile(t, book, []byte("book"))
	setAcrobatFixture(t, acrobatSearch{goos: "windows", appData: appData}, nil)
	setAcrobatTrustRead(t, func() ([]acrobatTrustProduct, error) {
		return nil, nil
	})

	got, err := AcrobatTrustReport()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"acrobat trust settings (read only):",
		"  AATL download (cAdobeDownload or bLoadSettingsFromURL): not set",
		"  EUTL download (cEUTLDownload): not set",
		"  Windows store trust (iMSStoreTrusted): not set",
		"address book: " + book,
	}, "\n")
	if got != want {
		t.Fatalf("report=\n%s\nwant=\n%s", got, want)
	}
}

func TestAcrobatTrustReportReadError(t *testing.T) {
	setAcrobatFixture(t, acrobatSearch{goos: "linux"}, nil)
	setAcrobatTrustRead(t, func() ([]acrobatTrustProduct, error) {
		return nil, errors.New("boom")
	})
	_, err := AcrobatTrustReport()
	if err == nil || strings.Contains(err.Error(), "not installed") {
		t.Fatalf("err=%v", err)
	}
}

func TestPlatformAcrobatTrustReadSkipsOtherOS(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("platform reader is the live registry or plist")
	}
	products, err := platformAcrobatTrustRead()
	if err != nil || len(products) != 0 {
		t.Fatalf("products=%v err=%v", products, err)
	}
}

func TestSortAcrobatTrustProductsNewestFirst(t *testing.T) {
	ps := []acrobatTrustProduct{
		{Product: acrobatProductAcrobat, Version: "10.0"},
		{Product: acrobatProductReader, Version: "DC"},
		{Product: acrobatProductAcrobat, Version: "DC"},
		{Product: acrobatProductAcrobat, Version: "11.0"},
	}
	sortAcrobatTrustProducts(ps)
	var got []string
	for _, p := range ps {
		got = append(got, p.Product+" "+p.Version)
	}
	want := []string{
		"Adobe Acrobat DC",
		"Adobe Acrobat 11.0",
		"Adobe Acrobat 10.0",
		"Acrobat Reader DC",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("order=\n%s", strings.Join(got, "\n"))
	}
}

func TestAcrobatDefaultsTrustSettings(t *testing.T) {
	text := `
{
    DC =     {
        Security =         {
            cDigSig =             {
                cAdobeDownload =                 {
                    bAskBeforeInstalling = 1;
                    bLoadSettingsFromURL = 1;
                };
                cEUTLDownload =                 {
                    bLoadSettingsFromURL = 0;
                };
                cCustomDownload =                 {
                    iMSStoreTrusted = 98;
                };
            };
            cASPKI =             {
                cMSCAPI_DirectoryProvider =                 {
                    iMSStoreTrusted = 96;
                };
            };
        };
    };
    "11.0" =     {
        Security =         {
            cDigSig =             {
                bLoadSettingsFromURL = false;
                cEUTLDownload = 1;
                iMSStoreTrusted = 0;
            };
        };
    };
}
`
	root, err := parseDefaultsPlist(text)
	if err != nil {
		t.Fatal(err)
	}
	products := acrobatProductsFromDefaults(acrobatProductAcrobat, "com.adobe.Acrobat.Pro.plist", root)
	if len(products) != 2 {
		t.Fatalf("products=%d", len(products))
	}
	byVer := map[string]acrobatTrustProduct{}
	for _, p := range products {
		byVer[p.Version] = p
	}
	dc := byVer["DC"]
	if !dc.AATL.Found || dc.AATL.Raw != 1 || dc.AATL.Key != `cAdobeDownload\bLoadSettingsFromURL` {
		t.Fatalf("DC AATL=%+v", dc.AATL)
	}
	if !dc.EUTL.Found || dc.EUTL.Raw != 0 || dc.EUTL.Key != `cEUTLDownload\bLoadSettingsFromURL` {
		t.Fatalf("DC EUTL=%+v", dc.EUTL)
	}
	// cDigSig\cCustomDownload wins over the PrefRef cASPKI value.
	if !dc.MSStore.Found || dc.MSStore.Raw != 0x62 || dc.MSStore.Key != `cCustomDownload\iMSStoreTrusted` {
		t.Fatalf("DC MSStore=%+v", dc.MSStore)
	}
	v11 := byVer["11.0"]
	if !v11.AATL.Found || v11.AATL.Raw != 0 || v11.AATL.Key != "bLoadSettingsFromURL" {
		t.Fatalf("11.0 AATL=%+v", v11.AATL)
	}
	if !v11.EUTL.Found || v11.EUTL.Raw != 1 || v11.EUTL.Key != "cEUTLDownload" {
		t.Fatalf("11.0 EUTL=%+v", v11.EUTL)
	}
	if !v11.MSStore.Found || v11.MSStore.Raw != 0 || v11.MSStore.Key != "iMSStoreTrusted" {
		t.Fatalf("11.0 MSStore=%+v", v11.MSStore)
	}

	onlyASPKI := `
{
    DC = {
        Security = {
            cDigSig = {
                cAdobeDownload = 1;
            };
            cASPKI = {
                cMSCAPI_DirectoryProvider = {
                    iMSStoreTrusted = 96;
                };
            };
        };
    };
}
`
	root, err = parseDefaultsPlist(onlyASPKI)
	if err != nil {
		t.Fatal(err)
	}
	products = acrobatProductsFromDefaults(acrobatProductReader, "com.adobe.Reader.plist", root)
	if len(products) != 1 {
		t.Fatalf("aspki products=%d", len(products))
	}
	p := products[0]
	if !p.AATL.Found || p.AATL.Raw != 1 || p.AATL.Key != "cAdobeDownload" {
		t.Fatalf("AATL=%+v", p.AATL)
	}
	if p.EUTL.Found {
		t.Fatalf("EUTL=%+v", p.EUTL)
	}
	if !p.MSStore.Found || p.MSStore.Raw != 0x60 || p.MSStore.Key != `cASPKI\cMSCAPI_DirectoryProvider\iMSStoreTrusted` {
		t.Fatalf("MSStore=%+v", p.MSStore)
	}
	rendered := renderAcrobatTrustReport(products, "")
	if strings.Contains(rendered, AcrobatNotInstalledReport) || !strings.Contains(rendered, "0x60 (signatures)") || !strings.Contains(rendered, "address book: not found") {
		t.Fatalf("rendered=\n%s", rendered)
	}

	if _, err := parseDefaultsPlist("{"); err == nil {
		t.Fatal("expected parse error")
	}
	arr := `{ DC = { Security = { cDigSig = { bLoadSettingsFromURL = 1; }; }; names = ( en, "x", ); }; }`
	if _, err := parseDefaultsPlist(arr); err != nil {
		t.Fatal(err)
	}
}

func TestAcrobatMacintoshPrefNames(t *testing.T) {
	text := `
{
    DC = {
        Security = {
            DigSig = {
                AdobeDownload = {
                    LoadSettingsFromURL = 1;
                };
                EUTLDownload = {
                    LoadSettingsFromURL = 0;
                };
            };
            ASPKI = {
                MSCAPI_DirectoryProvider = {
                    MSStoreTrusted = 96;
                };
            };
        };
    };
}
`
	root, err := parseDefaultsPlist(text)
	if err != nil {
		t.Fatal(err)
	}
	products := acrobatProductsFromDefaults(acrobatProductAcrobat, "com.adobe.Acrobat.Pro.plist", root)
	if len(products) != 1 {
		t.Fatalf("products=%d", len(products))
	}
	p := products[0]
	if !p.AATL.Found || p.AATL.Raw != 1 || p.AATL.Key != `cAdobeDownload\bLoadSettingsFromURL` {
		t.Fatalf("AATL=%+v", p.AATL)
	}
	if !p.EUTL.Found || p.EUTL.Raw != 0 || p.EUTL.Key != `cEUTLDownload\bLoadSettingsFromURL` {
		t.Fatalf("EUTL=%+v", p.EUTL)
	}
	if !p.MSStore.Found || p.MSStore.Raw != 0x60 || p.MSStore.Key != `cASPKI\cMSCAPI_DirectoryProvider\iMSStoreTrusted` {
		t.Fatalf("MSStore=%+v", p.MSStore)
	}
}

func TestAcrobatWindowsPrefNameCase(t *testing.T) {
	security := map[string]any{
		"cdigsig": map[string]any{
			"cadobedownload": map[string]any{
				"bloadsettingsfromurl": uint64(1),
			},
			"ceutldownload": map[string]any{
				"BLOADSETTINGSFROMURL": uint64(0),
			},
			"ccustomdownload": map[string]any{
				"imsstoretrusted": uint64(0x62),
			},
		},
	}
	p := acrobatProductFromSecurity(acrobatProductAcrobat, "DC", "HKCU\\example", security)
	if !p.AATL.Found || p.AATL.Raw != 1 || p.AATL.Key != `cAdobeDownload\bLoadSettingsFromURL` {
		t.Fatalf("AATL=%+v", p.AATL)
	}
	if !p.EUTL.Found || p.EUTL.Raw != 0 || p.EUTL.Key != `cEUTLDownload\bLoadSettingsFromURL` {
		t.Fatalf("EUTL=%+v", p.EUTL)
	}
	if !p.MSStore.Found || p.MSStore.Raw != 0x62 || p.MSStore.Key != `cCustomDownload\iMSStoreTrusted` {
		t.Fatalf("MSStore=%+v", p.MSStore)
	}
}

func TestAcrobatTypedMacintoshArray(t *testing.T) {
	text := `
{
    DC = {
        Security = {
            cDigSig = {
                cAdobeDownload = {
                    bLoadSettingsFromURL = ( 0, 1 );
                };
                cEUTLDownload = {
                    bLoadSettingsFromURL = ( 0, 0 );
                };
                cCustomDownload = {
                    iMSStoreTrusted = ( 1, 98 );
                };
            };
        };
    };
}
`
	root, err := parseDefaultsPlist(text)
	if err != nil {
		t.Fatal(err)
	}
	products := acrobatProductsFromDefaults(acrobatProductAcrobat, "com.adobe.Acrobat.Pro.plist", root)
	if len(products) != 1 {
		t.Fatalf("products=%d", len(products))
	}
	p := products[0]
	if !p.AATL.Found || p.AATL.Raw != 1 || p.AATL.Key != `cAdobeDownload\bLoadSettingsFromURL` {
		t.Fatalf("AATL=%+v", p.AATL)
	}
	if !p.EUTL.Found || p.EUTL.Raw != 0 {
		t.Fatalf("EUTL=%+v", p.EUTL)
	}
	if !p.MSStore.Found || p.MSStore.Raw != 0x62 {
		t.Fatalf("MSStore=%+v", p.MSStore)
	}

	// Type 0 is boolean: a non-0/1 value is not a trust setting.
	if v, ok := asAcrobatUint([]any{uint64(0), uint64(96)}); ok {
		t.Fatalf("boolean type with 96 should be rejected, got %d", v)
	}
}

func TestAcrobatDataBlobIsNotATrustSetting(t *testing.T) {
	text := `
{
    DC = {
        Security = {
            cDigSig = {
                bLoadSettingsFromURL = <01>;
            };
        };
    };
}
`
	root, err := parseDefaultsPlist(text)
	if err != nil {
		t.Fatal(err)
	}
	products := acrobatProductsFromDefaults(acrobatProductAcrobat, "plist", root)
	if len(products) != 1 {
		t.Fatalf("products=%d", len(products))
	}
	if products[0].AATL.Found {
		t.Fatalf("data blob should not be a trust setting: %+v", products[0].AATL)
	}
	dc, ok := asAcrobatMap(root["DC"])
	if !ok {
		t.Fatalf("DC=%T", root["DC"])
	}
	sec, ok := asAcrobatMap(dc["Security"])
	if !ok {
		t.Fatalf("Security=%T", dc["Security"])
	}
	dig, ok := asAcrobatMap(sec["cDigSig"])
	if !ok {
		t.Fatalf("cDigSig=%T", sec["cDigSig"])
	}
	if _, isData := dig["bLoadSettingsFromURL"].(acrobatPlistData); !isData {
		t.Fatalf("want acrobatPlistData, got %T %v", dig["bLoadSettingsFromURL"], dig["bLoadSettingsFromURL"])
	}
}

func TestAcrobatPrefSubkeyWinsCaseCollision(t *testing.T) {
	// A canonical value name and a differently cased subkey of the same
	// setting: the subkey replaces the value, as the Windows reader does.
	security := map[string]any{
		"cDigSig": map[string]any{
			"cAdobeDownload": uint64(1),
			"cadobedownload": map[string]any{
				"bLoadSettingsFromURL": uint64(0),
			},
			"cEUTLDownload": uint64(1),
			"CEUTLDOWNLOAD": map[string]any{
				"bLoadSettingsFromURL": uint64(0),
			},
		},
	}
	p := acrobatProductFromSecurity(acrobatProductAcrobat, "DC", "example", security)
	if !p.AATL.Found || p.AATL.Raw != 0 || p.AATL.Key != `cAdobeDownload\bLoadSettingsFromURL` {
		t.Fatalf("AATL should come from the subkey, got %+v", p.AATL)
	}
	if !p.EUTL.Found || p.EUTL.Raw != 0 || p.EUTL.Key != `cEUTLDownload\bLoadSettingsFromURL` {
		t.Fatalf("EUTL should come from the subkey, got %+v", p.EUTL)
	}
}
