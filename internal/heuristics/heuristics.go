// Package heuristics implements a small set of transparent structural checks.
// Every finding is a lead for human review, never a malware verdict: each rule
// fires on plenty of legitimate files, and its absence proves nothing.
package heuristics

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Rule identifiers. They are part of the stable report schema.
const (
	RuleExecutableHeader  = "executable-header"
	RuleDoubleExtension   = "double-extension"
	RuleExtensionMismatch = "extension-mismatch"
	RuleDeceptiveName     = "deceptive-name-characters"
)

// Finding is one heuristic lead with its evidence.
type Finding struct {
	Rule        string
	Explanation string
	Evidence    string
}

// Extensions that run code when opened on common desktop systems.
var executableExt = set("exe", "scr", "com", "pif", "bat", "cmd", "cpl", "msi", "msc",
	"js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "lnk", "jar", "reg", "app", "command")

// Extensions users tend to trust as inert documents or media.
var documentExt = set("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv",
	"odt", "ods", "jpg", "jpeg", "png", "gif", "bmp", "webp", "mp3", "mp4", "mov", "avi",
	"wav", "zip", "rar", "7z", "html", "htm")

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Check evaluates all rules for one file. name is the base name; header is
// up to the first 512 bytes of content. Results are in a fixed rule order.
func Check(name string, header []byte) []Finding {
	var out []Finding
	format, magic := nativeExecutable(header)
	if format != "" {
		out = append(out, Finding{
			Rule:        RuleExecutableHeader,
			Explanation: "Content begins with a " + format + " header, so it is a native program or library. Most such files are legitimate software.",
			Evidence:    "leading bytes " + magic,
		})
	} else if bytes.HasPrefix(header, []byte("#!")) {
		out = append(out, Finding{
			Rule:        RuleExecutableHeader,
			Explanation: "Content begins with an interpreter directive (#!), so it is a script that can be executed directly. Most such files are legitimate scripts.",
			Evidence:    "leading bytes 23 21 (\"#!\")",
		})
	}
	exts := extensions(name)
	if n := len(exts); n >= 2 && executableExt[exts[n-1]] && documentExt[exts[n-2]] {
		out = append(out, Finding{
			Rule:        RuleDoubleExtension,
			Explanation: "Name ends with a document/media extension followed by an executable one; systems that hide known extensions would display it as a ." + exts[n-2] + " file.",
			Evidence:    fmt.Sprintf("extensions .%s.%s", exts[n-2], exts[n-1]),
		})
	}
	if n := len(exts); format != "" && n >= 1 && documentExt[exts[n-1]] {
		out = append(out, Finding{
			Rule:        RuleExtensionMismatch,
			Explanation: "Name claims a document/media type but content is a " + format + " executable.",
			Evidence:    fmt.Sprintf("extension .%s, leading bytes %s", exts[n-1], magic),
		})
	}
	if cps := deceptiveRunes(name); len(cps) > 0 {
		out = append(out, Finding{
			Rule:        RuleDeceptiveName,
			Explanation: "Name contains invisible bidirectional-control characters, which can make the displayed name (and apparent extension) differ from the real one.",
			Evidence:    "code points " + strings.Join(cps, " "),
		})
	}
	return out
}

// nativeExecutable recognises ELF, PE and Mach-O headers. A bare "MZ" is not
// enough (it is a common text prefix); the PE signature must be present at the
// offset given by e_lfanew within the captured header.
func nativeExecutable(h []byte) (format, magic string) {
	switch {
	case bytes.HasPrefix(h, []byte{0x7f, 'E', 'L', 'F'}):
		return "ELF", "7F 45 4C 46"
	case len(h) >= 0x40 && h[0] == 'M' && h[1] == 'Z':
		off := binary.LittleEndian.Uint32(h[0x3c:0x40])
		if uint64(off)+4 <= uint64(len(h)) && bytes.Equal(h[off:off+4], []byte("PE\x00\x00")) {
			return "PE (Windows)", fmt.Sprintf("4D 5A, PE signature at offset 0x%x", off)
		}
	case len(h) >= 4:
		switch m := binary.BigEndian.Uint32(h[:4]); m {
		case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
			return "Mach-O", fmt.Sprintf("% X", h[:4])
		}
	}
	return "", ""
}

// extensions returns the lowercase dot-separated suffixes of name, ignoring a
// leading dot (Unix hidden files) and requiring a non-empty stem.
func extensions(name string) []string {
	trimmed := strings.TrimLeft(name, ".")
	parts := strings.Split(trimmed, ".")
	if len(parts) < 2 || parts[0] == "" {
		return nil
	}
	exts := parts[1:]
	for i, e := range exts {
		exts[i] = strings.ToLower(e)
	}
	return exts
}

func deceptiveRunes(name string) []string {
	var cps []string
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		i += size
		switch {
		case r == 0x061c, r == 0x200e, r == 0x200f,
			r >= 0x202a && r <= 0x202e,
			r >= 0x2066 && r <= 0x2069:
			cps = append(cps, fmt.Sprintf("U+%04X", r))
		}
	}
	return cps
}
