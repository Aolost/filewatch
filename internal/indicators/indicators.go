// Package indicators parses and queries the local, versioned indicator file.
//
// Format (version 1), UTF-8 text, LF or CRLF line endings:
//
//	filewatch-indicators v1
//	# comment lines start with '#' in column 1; blank lines are ignored
//	sha256:<64 hex digits>
//	sha256:<64 hex digits> <label>
//
// The header must be the first line. Every record is validated; any invalid
// record rejects the whole file (fail closed). Duplicate hashes are rejected.
// Labels are optional, at most MaxLabelBytes, and may contain only printable
// characters (no control or bidirectional-override characters).
// Indicators are never fetched from the network.
package indicators

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Aolost/filewatch/internal/safeopen"
)

// Header is the required first line of a version 1 indicator file.
const Header = "filewatch-indicators v1"

// FormatVersion is the indicator format version this package parses.
const FormatVersion = 1

// Parser limits. They bound memory and CPU for hostile inputs.
const (
	MaxFileBytes  = 64 << 20
	MaxLineBytes  = 1024
	MaxRecords    = 1_000_000
	MaxLabelBytes = 200
)

const hashPrefix = "sha256:"

// Digest is a raw SHA-256 digest.
type Digest [sha256.Size]byte

// Hex returns the lowercase hexadecimal form.
func (d Digest) Hex() string { return hex.EncodeToString(d[:]) }

// Set is an immutable collection of indicator records.
type Set struct {
	labels map[Digest]string
	// SourceSHA256 is the digest of the indicator file bytes, for provenance.
	SourceSHA256 Digest
}

// Len returns the number of records.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.labels)
}

// Lookup reports whether d is listed and returns its (possibly empty) label.
func (s *Set) Lookup(d Digest) (label string, ok bool) {
	if s == nil {
		return "", false
	}
	label, ok = s.labels[d]
	return label, ok
}

// ParseError describes an invalid indicator file. It never echoes raw input,
// which is attacker-controlled.
type ParseError struct {
	Line int // 1-based; 0 when not line-specific
	Msg  string
}

func (e *ParseError) Error() string {
	if e.Line == 0 {
		return "indicator file: " + e.Msg
	}
	return fmt.Sprintf("indicator file line %d: %s", e.Line, e.Msg)
}

func perr(line int, format string, args ...any) error {
	return &ParseError{Line: line, Msg: fmt.Sprintf(format, args...)}
}

// Parse reads a version 1 indicator file from r.
func Parse(r io.Reader) (*Set, error) {
	digest := sha256.New()
	counted := &countingReader{r: io.LimitReader(r, MaxFileBytes+1)}
	br := bufio.NewReaderSize(io.TeeReader(counted, digest), MaxLineBytes+2)
	set := &Set{labels: make(map[Digest]string)}

	for lineNo := 1; ; lineNo++ {
		raw, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, perr(lineNo, "line longer than %d bytes", MaxLineBytes)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, perr(0, "read error: %v", err)
		}
		if counted.n > MaxFileBytes {
			return nil, perr(0, "file larger than %d bytes", MaxFileBytes)
		}
		eof := errors.Is(err, io.EOF)
		if eof && len(raw) == 0 {
			if lineNo == 1 {
				return nil, perr(1, "missing header %q", Header)
			}
			break
		}
		line := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
		if len(line) > MaxLineBytes {
			return nil, perr(lineNo, "line longer than %d bytes", MaxLineBytes)
		}
		if err := parseLine(set, lineNo, line); err != nil {
			return nil, err
		}
		if eof {
			break
		}
	}
	digest.Sum(set.SourceSHA256[:0])
	return set, nil
}

func parseLine(set *Set, lineNo int, line []byte) error {
	if !utf8.Valid(line) {
		return perr(lineNo, "invalid UTF-8")
	}
	if bytes.IndexByte(line, 0) >= 0 {
		return perr(lineNo, "contains NUL byte")
	}
	s := string(line)
	if lineNo == 1 {
		if s != Header {
			if strings.HasPrefix(s, "filewatch-indicators ") {
				return perr(1, "unsupported indicator format version (this build reads v%d only)", FormatVersion)
			}
			return perr(1, "first line must be %q", Header)
		}
		return nil
	}
	if strings.TrimSpace(s) == "" || strings.HasPrefix(s, "#") {
		return nil
	}
	if !strings.HasPrefix(s, hashPrefix) {
		return perr(lineNo, "record must start with %q", hashPrefix)
	}
	rest := s[len(hashPrefix):]
	hexPart, label, _ := strings.Cut(rest, " ")
	if h, l, ok := strings.Cut(rest, "\t"); ok && len(h) < len(hexPart) {
		hexPart, label = h, l
	}
	if len(hexPart) != 2*sha256.Size {
		return perr(lineNo, "hash must be exactly %d hex digits", 2*sha256.Size)
	}
	var d Digest
	if _, err := hex.Decode(d[:], []byte(hexPart)); err != nil {
		return perr(lineNo, "hash is not valid hexadecimal")
	}
	label = strings.Trim(label, " \t")
	if len(label) > MaxLabelBytes {
		return perr(lineNo, "label longer than %d bytes", MaxLabelBytes)
	}
	for _, r := range label {
		// strconv.IsPrint excludes control characters, bidi overrides and
		// other format characters that could make reports misleading.
		if r == '\t' || !strconv.IsPrint(r) {
			return perr(lineNo, "label contains non-printable character %U", r)
		}
	}
	if _, dup := set.labels[d]; dup {
		return perr(lineNo, "duplicate hash")
	}
	if len(set.labels) >= MaxRecords {
		return perr(lineNo, "more than %d records", MaxRecords)
	}
	set.labels[d] = label
	return nil
}

// Load opens and parses the indicator file at path. The path is chosen by the
// user; it must name a regular file (a FIFO or device is rejected without
// blocking).
func Load(path string) (*Set, error) {
	f, fi, err := safeopen.File(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > MaxFileBytes {
		return nil, perr(0, "file larger than %d bytes", MaxFileBytes)
	}
	return Parse(f)
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
