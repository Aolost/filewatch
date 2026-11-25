// Package repocheck enforces repository hygiene as a portable test, so it
// runs identically on every OS without shell or grep dialect differences.
package repocheck

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func repoFiles(t *testing.T, fn func(rel string, data []byte)) {
	t.Helper()
	root := moduleRoot(t)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fn(filepath.ToSlash(rel), data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func isBidi(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// TestNoRawBidiControls rejects "Trojan Source" style invisible characters;
// tests must spell them as \u escapes.
func TestNoRawBidiControls(t *testing.T) {
	repoFiles(t, func(rel string, data []byte) {
		if !utf8.Valid(data) {
			return
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, r := range line {
				if isBidi(r) {
					t.Errorf("%s:%d: raw bidirectional control %U (use a \\u escape)", rel, i+1, r)
				}
			}
		}
	})
}

// TestNoExecutableSamples rejects files that start like native executables:
// fixtures must be generated, harmless text.
func TestNoExecutableSamples(t *testing.T) {
	magics := [][]byte{
		{0x7f, 'E', 'L', 'F'}, {'M', 'Z'},
		{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf},
		{0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
	}
	repoFiles(t, func(rel string, data []byte) {
		for _, m := range magics {
			if bytes.HasPrefix(data, m) {
				t.Errorf("%s: looks like an executable; the repository must not contain binaries or samples", rel)
			}
		}
	})
}
