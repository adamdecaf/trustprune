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
	"fmt"
	"strconv"
	"strings"
)

// parseDefaultsPlist parses the old-style plist text printed by
// `/usr/bin/defaults read`. It accepts dictionaries, arrays, quoted
// strings, integers (including 0x), booleans, and hex data blobs.
// Data blobs are kept as strings and are not trust settings.
func parseDefaultsPlist(text string) (map[string]any, error) {
	p := &defaultsParser{s: text}
	p.skip()
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.i != len(p.s) {
		rest := p.s[p.i:]
		if len(rest) > 24 {
			rest = rest[:24]
		}
		return nil, fmt.Errorf("defaults: trailing %q", rest)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("defaults: top level is %T", v)
	}
	return m, nil
}

type defaultsParser struct {
	s string
	i int
}

func (p *defaultsParser) skip() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *defaultsParser) parseValue() (any, error) {
	p.skip()
	if p.i >= len(p.s) {
		return nil, fmt.Errorf("defaults: unexpected end")
	}
	switch p.s[p.i] {
	case '{':
		return p.parseDict()
	case '(':
		return p.parseArray()
	case '"':
		return p.parseString()
	case '<':
		return p.parseData()
	default:
		return p.parseToken()
	}
}

func (p *defaultsParser) parseDict() (map[string]any, error) {
	p.i++ // {
	out := map[string]any{}
	for {
		p.skip()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("defaults: unclosed dictionary")
		}
		if p.s[p.i] == '}' {
			p.i++
			return out, nil
		}
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != '=' {
			return nil, fmt.Errorf("defaults: expected = after %s", key)
		}
		p.i++
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ';' {
			return nil, fmt.Errorf("defaults: expected ; after %s", key)
		}
		p.i++
		out[key] = val
	}
}

func (p *defaultsParser) parseArray() ([]any, error) {
	p.i++ // (
	var out []any
	for {
		p.skip()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("defaults: unclosed array")
		}
		if p.s[p.i] == ')' {
			p.i++
			return out, nil
		}
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		out = append(out, val)
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
		}
	}
}

func (p *defaultsParser) parseKey() (string, error) {
	p.skip()
	if p.i >= len(p.s) {
		return "", fmt.Errorf("defaults: missing key")
	}
	if p.s[p.i] == '"' {
		return p.parseString()
	}
	start := p.i
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case '=', ' ', '\t', '\n', '\r', ';', ',', '}', ')':
			if start == p.i {
				return "", fmt.Errorf("defaults: missing key")
			}
			return p.s[start:p.i], nil
		default:
			p.i++
		}
	}
	if start == p.i {
		return "", fmt.Errorf("defaults: missing key")
	}
	return p.s[start:p.i], nil
}

func (p *defaultsParser) parseString() (string, error) {
	if p.i >= len(p.s) || p.s[p.i] != '"' {
		return "", fmt.Errorf("defaults: expected quote")
	}
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		p.i++
		if c == '"' {
			return b.String(), nil
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if p.i >= len(p.s) {
			return "", fmt.Errorf("defaults: truncated escape")
		}
		esc := p.s[p.i]
		p.i++
		switch esc {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		default:
			b.WriteByte(esc)
		}
	}
	return "", fmt.Errorf("defaults: unterminated string")
}

func (p *defaultsParser) parseData() (string, error) {
	p.i++ // <
	start := p.i
	for p.i < len(p.s) && p.s[p.i] != '>' {
		p.i++
	}
	if p.i >= len(p.s) {
		return "", fmt.Errorf("defaults: unterminated data")
	}
	s := p.s[start:p.i]
	p.i++ // >
	return s, nil
}

func (p *defaultsParser) parseToken() (any, error) {
	start := p.i
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r', ';', ',', '}', ')':
			return p.tokenValue(p.s[start:p.i])
		default:
			p.i++
		}
	}
	return p.tokenValue(p.s[start:p.i])
}

func (p *defaultsParser) tokenValue(tok string) (any, error) {
	if tok == "" {
		return nil, fmt.Errorf("defaults: missing value")
	}
	if tok[0] != '-' {
		if n, err := strconv.ParseUint(tok, 0, 64); err == nil {
			return n, nil
		}
	} else if n, err := strconv.ParseInt(tok, 0, 64); err == nil {
		return n, nil
	}
	switch strings.ToLower(tok) {
	case "true", "yes":
		return true, nil
	case "false", "no":
		return false, nil
	default:
		return tok, nil
	}
}
