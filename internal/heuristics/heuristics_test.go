package heuristics

import (
	"encoding/binary"
	"strings"
	"testing"
)

// peHeader builds a harmless 512-byte buffer with only the DOS and PE
// signatures set; it is not a runnable program.
func peHeader(off uint32) []byte {
	h := make([]byte, 512)
	h[0], h[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(h[0x3c:], off)
	if int(off)+4 <= len(h) {
		copy(h[off:], "PE\x00\x00")
	}
	return h
}

func rules(fs []Finding) string {
	var r []string
	for _, f := range fs {
		r = append(r, f.Rule)
	}
	return strings.Join(r, ",")
}

func TestCheck(t *testing.T) {
	elf := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}
	cases := []struct {
		name   string
		header []byte
		want   string
	}{
		{"notes.txt", []byte("hello"), ""},
		{"tool", elf, RuleExecutableHeader},
		{"setup.exe", peHeader(0x80), RuleExecutableHeader},
		{"mz.txt", []byte("MZ is just text here"), ""},
		{"mz-no-pe.bin", peHeader(0x1000), ""},
		{"lib.dylib", []byte{0xcf, 0xfa, 0xed, 0xfe}, RuleExecutableHeader},
		{"run.sh", []byte("#!/bin/sh\n"), RuleExecutableHeader},
		{"invoice.pdf.exe", []byte("plain"), RuleDoubleExtension},
		{"INVOICE.PDF.EXE", []byte("plain"), RuleDoubleExtension},
		{"archive.tar.gz", nil, ""},
		{"photo.jpg", elf, RuleExecutableHeader + "," + RuleExtensionMismatch},
		{"photo.pdf.scr", peHeader(0x40), RuleExecutableHeader + "," + RuleDoubleExtension},
		{"report\u202efdp.exe", nil, RuleDeceptiveName},
		{".hidden.exe", nil, ""},
		{".pdf.exe", nil, ""},
		{"", nil, ""},
	}
	for _, tc := range cases {
		if got := rules(Check(tc.name, tc.header)); got != tc.want {
			t.Errorf("Check(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestFindingsExplainEvidence(t *testing.T) {
	for _, f := range Check("x.pdf.exe", peHeader(0x80)) {
		if f.Explanation == "" || f.Evidence == "" {
			t.Errorf("finding %s lacks explanation or evidence", f.Rule)
		}
	}
}

func FuzzCheck(f *testing.F) {
	f.Add("invoice.pdf.exe", []byte("MZ"))
	f.Add("a\u202eb", []byte{0x7f, 'E', 'L', 'F'})
	f.Add("\xff.\xfe", peHeader(0x3c))
	f.Fuzz(func(t *testing.T, name string, header []byte) {
		if len(header) > 512 {
			header = header[:512]
		}
		for _, fd := range Check(name, header) {
			if fd.Rule == "" || fd.Explanation == "" || fd.Evidence == "" {
				t.Fatalf("incomplete finding %+v", fd)
			}
			// Evidence is a short structural description, never a content dump.
			if len(fd.Evidence) > 120 {
				t.Fatalf("evidence too long: %d bytes", len(fd.Evidence))
			}
		}
	})
}
