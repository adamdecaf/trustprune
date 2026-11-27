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
	"crypto/x509"
	"errors"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

// ErrAndroidGuideOnly is returned for every Android operation that would
// read or write a device store. trustprune cannot change an Android
// device's certificate store, so add, allowlist, backup, restore, and
// create print these Settings and adb steps instead of writing.
var ErrAndroidGuideOnly = errors.New(androidGuideMessage)

// androidGuideMessage is the pruning guide printed for --app android
// mutating commands. list --app android --file --allowlist keeps its
// own disable report and prints the same Settings and adb steps.
const androidGuideMessage = `android is guide only: trustprune cannot change an Android device's certificate store. add, allowlist, backup, restore, and create do not write to the device.

To disable a system CA, open Settings > Security > Encryption & credentials > Trusted credentials, tap the certificate, and choose Disable. To uninstall a user CA, use the User tab and Uninstall.

On a rooted device or emulator, adb can pull a copy of the store for a list report (for example adb pull /system/etc/security/cacerts or adb pull /apex/com.android.conscrypt/cacerts). Use trustprune list --app android --file <dir> --allowlist <path> on the copied directory. trustprune does not write to the device`

const androidAppName = "android"

// AndroidStore is the Android certificate store. Every trust operation
// returns ErrAndroidGuideOnly, including under --dry-run. Nothing is
// read from or written to a device.
func AndroidStore() Store {
	return androidStore{}
}

type androidStore struct{}

var (
	_ Store    = androidStore{}
	_ Lister   = androidStore{}
	_ Modifier = androidStore{}
	_ Saver    = androidStore{}
	_ Informer = androidStore{}
)

func detectAndroid() Status {
	return Status{Name: androidAppName, Found: true, GuideOnly: true}
}

func (androidStore) GetInfo() *Info {
	return &Info{Name: "Android"}
}

func (androidStore) List(*ListOptions) ([]*x509.Certificate, error) {
	return nil, ErrAndroidGuideOnly
}

func (androidStore) Add([]*x509.Certificate) error {
	return ErrAndroidGuideOnly
}

func (androidStore) Remove(allowlist.Allowlist) error {
	return ErrAndroidGuideOnly
}

func (androidStore) Backup() error {
	return ErrAndroidGuideOnly
}

func (androidStore) GetLatestBackup() (string, error) {
	return "", ErrAndroidGuideOnly
}

func (androidStore) Restore(string) error {
	return ErrAndroidGuideOnly
}
