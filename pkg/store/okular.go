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
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/file"
)

const (
	okularAppName           = "okular"
	okularConfigFileName    = "okular-generator-popplerrc"
	okularSignaturesGrp     = "Signatures"
	okularBackendNSS        = "NSS"
	okularBackendGPG        = "GPG"
	okularBackendUnresolved = "unresolved"
)

// OkularCompiledSignatureBackend is used when SignatureBackend is unset and
// POPPLER_SIGNATURE_BACKEND is unset. It is NSS, matching poppler's usual
// compiled default (NSS is built first). A prebuilt trustprune binary cannot
// read the host poppler compile-time default; set SignatureBackend or
// POPPLER_SIGNATURE_BACKEND when that default is GPG. Tests may set this to
// "GPG".
var OkularCompiledSignatureBackend = okularBackendNSS

// ErrOkularGPG is returned for every Okular operation when the effective
// signature backend is GPG. trustprune does not read or write gpgsm stores.
var ErrOkularGPG = errors.New("okular: signature backend is GPG; trustprune does not list, back up, or change GPG (gpgsm) stores")

// ErrOkularUnresolvedBackend is returned when a [$e] SignatureBackend value
// cannot be expanded to NSS or GPG. The store does not fall back to NSS.
var ErrOkularUnresolvedBackend = errors.New("okular: SignatureBackend could not be expanded; refusing NSS operations")

// OkularStore returns the store Okular's poppler generator uses for PDF
// signatures. The effective backend is SignatureBackend in
// okular-generator-popplerrc [Signatures], else POPPLER_SIGNATURE_BACKEND,
// else OkularCompiledSignatureBackend. NSS uses DBCertificatePath when
// UseDefaultCertDB is false, otherwise the same directory poppler uses.
func OkularStore() Store {
	return newOkularStore(resolveOkular(file.HomeDir(), os.Getenv, popplerNSSDir))
}

func newOkularStore(backend, dir string) Store {
	return okularStore{
		nssStore: NssStore(okularAppName, "", dir).(nssStore),
		backend:  backend,
	}
}

// okularStore is Okular's signature trust store. When the backend is NSS it
// is the poppler NSS store at the configured directory. When the backend is
// GPG, every mutating and listing operation reports that and makes no change.
type okularStore struct {
	nssStore
	backend string
}

var (
	_ Store    = okularStore{}
	_ Lister   = okularStore{}
	_ Modifier = okularStore{}
	_ Saver    = okularStore{}
	_ Informer = okularStore{}
)

func (s okularStore) gpg() bool {
	return s.backend == okularBackendGPG
}

func (s okularStore) refuseNonNSS() error {
	switch s.backend {
	case okularBackendGPG:
		return ErrOkularGPG
	case okularBackendUnresolved:
		return ErrOkularUnresolvedBackend
	default:
		return nil
	}
}

func (s okularStore) GetInfo() *Info {
	if s.gpg() {
		return &Info{Name: titleASCII(okularAppName), Path: okularBackendGPG}
	}
	if s.backend == okularBackendUnresolved {
		return &Info{Name: titleASCII(okularAppName)}
	}
	return s.nssStore.GetInfo()
}

func (s okularStore) List(opts *ListOptions) ([]*x509.Certificate, error) {
	if err := s.refuseNonNSS(); err != nil {
		return nil, err
	}
	if err := s.requireCert9(); err != nil {
		return nil, err
	}
	return s.nssStore.List(opts)
}

func (s okularStore) Add(certs []*x509.Certificate) error {
	if err := s.refuseNonNSS(); err != nil {
		return err
	}
	if err := s.requireCert9(); err != nil {
		return err
	}
	return s.nssStore.Add(certs)
}

func (s okularStore) Backup() error {
	if err := s.refuseNonNSS(); err != nil {
		return err
	}
	if err := s.requireCert9(); err != nil {
		return err
	}
	return s.nssStore.Backup()
}

func (s okularStore) Remove(al allowlist.Allowlist) error {
	if err := s.refuseNonNSS(); err != nil {
		return err
	}
	if err := s.requireCert9(); err != nil {
		return err
	}
	return s.nssStore.Remove(al)
}

func (s okularStore) GetLatestBackup() (string, error) {
	if err := s.refuseNonNSS(); err != nil {
		return "", err
	}
	return s.nssStore.GetLatestBackup()
}

func (s okularStore) Restore(where string) error {
	if err := s.refuseNonNSS(); err != nil {
		return err
	}
	return s.nssStore.Restore(where)
}

func (s okularStore) requireCert9() error {
	return requireNSSCert9(okularAppName, s.foundCertdbLocation)
}

// resolveOkular returns the effective signature backend and NSS directory.
// getenv supplies XDG_CONFIG_HOME and POPPLER_SIGNATURE_BACKEND. defaultNSS
// is poppler's directory when UseDefaultCertDB is true or unset.
func resolveOkular(home string, getenv func(string) string, defaultNSS func() string) (backend, dir string) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	settings := readOkularSignatures(home, getenv)
	backend = okularEffectiveBackend(settings, getenv)
	if backend == okularBackendGPG || backend == okularBackendUnresolved {
		return backend, ""
	}
	return backend, okularNSSDir(settings, defaultNSS)
}

func okularConfigPath(home string, getenv func(string) string) string {
	if getenv != nil {
		if xdg := strings.TrimSpace(getenv("XDG_CONFIG_HOME")); xdg != "" && filepath.IsAbs(xdg) {
			return filepath.Join(xdg, okularConfigFileName)
		}
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".config", okularConfigFileName)
}

// okularSystemConfigDirs returns XDG_CONFIG_DIRS in documented preference
// order (first is highest among system dirs). An unset or empty value defaults
// to /etc/xdg on non-Windows systems.
func okularSystemConfigDirs(getenv func(string) string) []string {
	raw := ""
	if getenv != nil {
		raw = strings.TrimSpace(getenv("XDG_CONFIG_DIRS"))
	}
	if raw == "" {
		if runtime.GOOS == "windows" {
			return nil
		}
		return []string{"/etc/xdg"}
	}
	var dirs []string
	for _, d := range strings.Split(raw, string(os.PathListSeparator)) {
		d = strings.TrimSpace(d)
		if d != "" && filepath.IsAbs(d) {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// okularConfigSearchPaths is lowest precedence first: XDG_CONFIG_DIRS in
// reverse, then the user file from okularConfigPath.
func okularConfigSearchPaths(home string, getenv func(string) string) []string {
	dirs := okularSystemConfigDirs(getenv)
	paths := make([]string, 0, len(dirs)+1)
	for i := len(dirs) - 1; i >= 0; i-- {
		paths = append(paths, filepath.Join(dirs[i], okularConfigFileName))
	}
	if user := okularConfigPath(home, getenv); user != "" {
		paths = append(paths, user)
	}
	return paths
}

// okularSettings is a merged [Signatures] section. unresolved is kept
// separate from values so a literal setting such as SignatureBackend=unresolved
// is not treated as a failed [$e] expansion.
type okularSettings struct {
	values     map[string]string
	unresolved map[string]bool
}

func (s okularSettings) hasUnresolved(key string) bool {
	return s.unresolved[key]
}

func (s okularSettings) value(key string) (string, bool) {
	if s.unresolved[key] {
		return "", false
	}
	v, ok := s.values[key]
	return v, ok
}

func readOkularSignatures(home string, getenv func(string) string) okularSettings {
	out := okularSettings{
		values:     make(map[string]string),
		unresolved: make(map[string]bool),
	}
	for _, path := range okularConfigSearchPaths(home, getenv) {
		// #nosec G703 -- path is a KConfig file under XDG or ~/.config
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		part, partUnresolved := parseKConfigSection(string(b), okularSignaturesGrp, getenv)
		for k, v := range part {
			out.values[k] = v
			if partUnresolved[k] {
				out.unresolved[k] = true
			} else {
				delete(out.unresolved, k)
			}
		}
	}
	return out
}

func okularEffectiveBackend(settings okularSettings, getenv func(string) string) string {
	if settings.hasUnresolved("SignatureBackend") {
		return okularBackendUnresolved
	}
	if v, ok := settings.value("SignatureBackend"); ok && strings.TrimSpace(v) != "" {
		return canonicalOkularBackend(v)
	}
	if getenv != nil {
		if v := strings.TrimSpace(getenv("POPPLER_SIGNATURE_BACKEND")); v != "" {
			return canonicalOkularBackend(v)
		}
	}
	return canonicalOkularBackend(OkularCompiledSignatureBackend)
}

func canonicalOkularBackend(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case okularBackendGPG, "GPGME":
		return okularBackendGPG
	default:
		return okularBackendNSS
	}
}

func okularUseDefaultCertDB(settings okularSettings) bool {
	if settings.hasUnresolved("UseDefaultCertDB") {
		return true
	}
	v, ok := settings.value("UseDefaultCertDB")
	if !ok {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

func okularNSSDir(settings okularSettings, defaultNSS func() string) string {
	if okularUseDefaultCertDB(settings) {
		if defaultNSS == nil {
			return ""
		}
		return defaultNSS()
	}
	if settings.hasUnresolved("DBCertificatePath") {
		return ""
	}
	path, _ := settings.value("DBCertificatePath")
	return okularLocalFilePath(strings.TrimSpace(path))
}

// okularLocalFilePath converts a file URL the way Okular does
// (QUrl(...).toLocalFile()), including percent-encoded characters.
// Plain filesystem paths are returned unchanged.
func okularLocalFilePath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "file") {
		return raw
	}
	p := u.Path
	if p == "" {
		p = u.Opaque
	}
	host := u.Hostname()
	if host != "" && !strings.EqualFold(host, "localhost") {
		if len(host) >= 2 && unicode.IsLetter(rune(host[0])) && host[1] == ':' {
			rest := strings.TrimLeft(p, `/\`)
			p = host
			if rest != "" {
				p = host + "/" + rest
			}
		}
	}
	if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && unicode.IsLetter(rune(p[1])) && p[2] == ':' {
		p = p[1:]
	}
	if p == "" {
		return raw
	}
	if runtime.GOOS == "windows" {
		p = filepath.Clean(filepath.FromSlash(p))
	}
	return p
}

// parseKConfigSection reads a KConfig INI file and returns keys from section.
// Group and key suffixes such as [$i] and [$e] are stripped. Values whose key
// listed [$e] are environment-expanded. Comments and other sections are ignored.
// unresolved marks keys whose [$e] value could not be expanded to a concrete
// string (including an unset variable).
func parseKConfigSection(content, section string, getenv func(string) string) (map[string]string, map[string]bool) {
	out := make(map[string]string)
	unresolved := make(map[string]bool)
	content = strings.TrimPrefix(content, "\ufeff")
	current := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			name := strings.TrimPrefix(line, "[")
			if i := strings.Index(name, "]"); i >= 0 {
				name = name[:i]
			}
			current = strings.TrimSpace(name)
			continue
		}
		if !strings.EqualFold(current, section) {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		expandable := false
		if i := strings.Index(key, "[$"); i >= 0 {
			expandable = strings.Contains(key[i:], "e")
			key = strings.TrimSpace(key[:i])
		}
		if key == "" {
			continue
		}
		val = kconfigValue(strings.TrimSpace(val))
		if expandable {
			expanded, ok := kconfigExpand(val, getenv)
			if !ok {
				unresolved[key] = true
				out[key] = val
				continue
			}
			val = expanded
		}
		out[key] = val
		delete(unresolved, key)
	}
	return out, unresolved
}

// kconfigExpand expands $VAR and ${VAR} the way KConfig [$e] does.
// "$$" is a literal dollar. An unset or empty variable, or a malformed
// reference, is not a successful expansion.
func kconfigExpand(v string, getenv func(string) string) (string, bool) {
	if !strings.Contains(v, "$") {
		return v, true
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	var b strings.Builder
	i := 0
	for i < len(v) {
		if v[i] != '$' {
			b.WriteByte(v[i])
			i++
			continue
		}
		if i+1 < len(v) && v[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		name, next, ok := kconfigEnvName(v, i+1)
		if !ok {
			return v, false
		}
		val := getenv(name)
		if val == "" {
			return v, false
		}
		b.WriteString(val)
		i = next
	}
	return b.String(), true
}

func kconfigEnvName(v string, i int) (name string, next int, ok bool) {
	if i >= len(v) {
		return "", i, false
	}
	if v[i] == '{' {
		end := strings.IndexByte(v[i+1:], '}')
		if end < 0 {
			return "", i, false
		}
		name = v[i+1 : i+1+end]
		if !kconfigEnvNameOK(name) {
			return "", i, false
		}
		return name, i + 2 + end, true
	}
	start := i
	if !isEnvFirst(v[i]) {
		return "", i, false
	}
	i++
	for i < len(v) && isEnvRest(v[i]) {
		i++
	}
	return v[start:i], i, true
}

func kconfigEnvNameOK(name string) bool {
	if name == "" || !isEnvFirst(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isEnvRest(name[i]) {
			return false
		}
	}
	return true
}

func isEnvFirst(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isEnvRest(b byte) bool {
	return isEnvFirst(b) || (b >= '0' && b <= '9')
}

func kconfigValue(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

func requireNSSCert9(app, dir string) error {
	if dir == "" {
		return fmt.Errorf("%s: no NSS database found (looked in %s); run Firefox once or create one with certutil -N -d sql:%s", app, dir, dir)
	}
	fi, err := os.Stat(filepath.Join(dir, "cert9.db")) // #nosec G703 -- dir is the resolved NSS store directory
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s: no NSS database found (looked in %s); run Firefox once or create one with certutil -N -d sql:%s", app, dir, dir)
		}
		return fmt.Errorf("%s: checking NSS database in %s: %w", app, dir, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() == 0 {
		return fmt.Errorf("%s: no NSS database found (looked in %s); run Firefox once or create one with certutil -N -d sql:%s", app, dir, dir)
	}
	return nil
}
