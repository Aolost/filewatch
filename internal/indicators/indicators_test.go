package indicators

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func digestOf(s string) Digest { return Digest(sha256.Sum256([]byte(s))) }

func hexOf(s string) string { return digestOf(s).Hex() }

func TestParseValid(t *testing.T) {
	in := Header + "\r\n" +
		"# harmless test fixtures\n" +
		"\n" +
		"sha256:" + hexOf("alpha") + "\n" +
		"sha256:" + strings.ToUpper(hexOf("beta")) + "   Test label: beta  \n" +
		"sha256:" + hexOf("gamma") + "\tTabbed label" // no trailing newline
	set, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 3 {
		t.Fatalf("Len = %d", set.Len())
	}
	for name, want := range map[string]string{"alpha": "", "beta": "Test label: beta", "gamma": "Tabbed label"} {
		got, ok := set.Lookup(digestOf(name))
		if !ok || got != want {
			t.Errorf("Lookup(%s) = %q,%v want %q", name, got, ok, want)
		}
	}
	if _, ok := set.Lookup(digestOf("delta")); ok {
		t.Error("unexpected match")
	}
	if set.SourceSHA256 != Digest(sha256.Sum256([]byte(in))) {
		t.Error("SourceSHA256 does not cover the file bytes")
	}
}

func TestParseHeaderOnly(t *testing.T) {
	set, err := Parse(strings.NewReader(Header + "\n"))
	if err != nil || set.Len() != 0 {
		t.Fatalf("got %v, %v", set, err)
	}
}

func TestParseRejects(t *testing.T) {
	good := "sha256:" + hexOf("x")
	cases := map[string]string{
		"empty":           "",
		"no header":       good + "\n",
		"wrong version":   "filewatch-indicators v2\n",
		"header spaces":   Header + " \n",
		"short hash":      Header + "\nsha256:abcd\n",
		"long hash":       Header + "\n" + good + "00\n",
		"bad hex":         Header + "\nsha256:" + strings.Repeat("zz", 32) + "\n",
		"no prefix":       Header + "\n" + hexOf("x") + "\n",
		"md5 prefix":      Header + "\nmd5:" + hexOf("x") + "\n",
		"duplicate":       Header + "\n" + good + "\n" + good + " again\n",
		"dup case":        Header + "\n" + good + "\nsha256:" + strings.ToUpper(hexOf("x")) + "\n",
		"control label":   Header + "\n" + good + " bad\x1blabel\n",
		"bidi label":      Header + "\n" + good + " exe\u202etxt\n",
		"tab in label":    Header + "\n" + good + " a\tb\n",
		"long label":      Header + "\n" + good + " " + strings.Repeat("a", MaxLabelBytes+1) + "\n",
		"invalid utf8":    Header + "\n" + good + " \xff\n",
		"nul":             Header + "\n" + good + "\x00\n",
		"long line":       Header + "\n# " + strings.Repeat("a", MaxLineBytes) + "\n",
		"indented record": Header + "\n " + good + "\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(in))
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("got %v, want ParseError", err)
			}
		})
	}
}

func TestErrorDoesNotEchoInput(t *testing.T) {
	_, err := Parse(strings.NewReader(Header + "\nSECRET-CONTENT-XYZ\n"))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error must not echo record contents: %v", err)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error should name the line: %v", err)
	}
}

func TestParseTooLarge(t *testing.T) {
	// A stream larger than MaxFileBytes made of valid comment lines.
	line := "#" + strings.Repeat("a", 1000) + "\n"
	r := &repeatReader{prefix: Header + "\n", line: line, total: MaxFileBytes + 4096}
	if _, err := Parse(r); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

type repeatReader struct {
	prefix, line string
	total, n     int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.n >= r.total {
		return 0, os.ErrClosed // never reached: LimitReader stops first
	}
	var src string
	if r.n < len(r.prefix) {
		src = r.prefix[r.n:]
	} else {
		off := (r.n - len(r.prefix)) % len(r.line)
		src = r.line[off:]
	}
	k := copy(p, src)
	r.n += k
	return k, nil
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ind.txt")
	if err := os.WriteFile(p, []byte(Header+"\nsha256:"+hexOf("x")+" x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := Load(p)
	if err != nil || set.Len() != 1 {
		t.Fatalf("Load = %v, %v", set, err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("directory accepted as indicator file")
	}
	if _, err := Load(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestReadmeExampleParses(t *testing.T) {
	set, err := Load(filepath.Join("..", "..", "testdata", "indicators.example.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() == 0 {
		t.Fatal("example has no records")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(Header + "\nsha256:" + hexOf("a") + " label\n")
	f.Add(Header + "\r\n# c\r\n\r\nsha256:" + hexOf("b") + "\r\n")
	f.Add("filewatch-indicators v2\n")
	f.Add(Header + "\nsha256:" + hexOf("a") + "\nsha256:" + hexOf("a"))
	f.Add("\xff\x00\n\n")
	f.Fuzz(func(t *testing.T, in string) {
		set, err := Parse(strings.NewReader(in))
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("non-ParseError: %T %v", err, err)
			}
			if set != nil {
				t.Fatal("set returned with error")
			}
			return
		}
		if !strings.HasPrefix(in, Header) {
			t.Fatal("accepted input without header")
		}
		if set.Len() > strings.Count(in, hashPrefix) {
			t.Fatal("more records than hash prefixes")
		}
		for d, label := range set.labels {
			if len(label) > MaxLabelBytes {
				t.Fatalf("label too long for %s", d.Hex())
			}
			for _, r := range label {
				if r < 0x20 || r == 0x7f || r == '\u202e' {
					t.Fatalf("unsafe rune %U in label", r)
				}
			}
		}
	})
}
