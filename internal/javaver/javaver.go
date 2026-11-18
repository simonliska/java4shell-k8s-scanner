// Package javaver parses and compares Java runtime version strings.
package javaver

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed Java version: [feature, interim, update, patch, ...].
// Oracle builds can have five parts, e.g. 17.0.21.0.3.
type Version []int

// Parse reads a version as printed by `java -version`, for example
// "21.0.13", "17.0.21.0.3", "27", "21.0.13+9-LTS" or the legacy "1.8.0_511" (major 8).
func Parse(s string) (Version, error) {
	orig := s
	s = strings.TrimSpace(s)

	// Legacy scheme: 1.8.0_511 means Java 8, update 511.
	if strings.HasPrefix(s, "1.") {
		s = strings.Replace(s[2:], "_", ".", 1)
	}

	// Drop build/suffix info: "+9-LTS", "-ea", " 2026-10-20".
	if end := strings.IndexFunc(s, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }); end >= 0 {
		s = s[:end]
	}
	s = strings.Trim(s, ".")
	if s == "" {
		return nil, fmt.Errorf("no version number in %q", orig)
	}

	parts := strings.Split(s, ".")
	v := make(Version, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid version %q: %w", orig, err)
		}
		v[i] = n
	}
	return v, nil
}

// MustParse is Parse for constants; it panics on error.
func MustParse(s string) Version {
	v, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

// Major returns the feature release, e.g. 21 for 21.0.13.
func (v Version) Major() int {
	if len(v) == 0 {
		return 0
	}
	return v[0]
}

// Compare returns -1, 0 or 1. Missing parts count as 0, so 21.0.13 == 21.0.13.0.
func Compare(a, b Version) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		x, y := part(a, i), part(b, i)
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

func (v Version) String() string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ".")
}

func part(v Version, i int) int {
	if i < len(v) {
		return v[i]
	}
	return 0
}
