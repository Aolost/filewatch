package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func newTest() *Report {
	return New("0.0.0-test", "/scan/root", Limits{MaxFiles: 1}, 100)
}

func TestStatusPrecedence(t *testing.T) {
	r := newTest()
	r.Finalize(0)
	if r.Status != StatusNoMatches || !r.Complete {
		t.Fatalf("empty: %s", r.Status)
	}

	r = newTest()
	r.AddSkip("x", ReasonSymlink, "policy", false)
	r.Finalize(1)
	if r.Status != StatusNoMatches {
		t.Fatalf("policy skip: %s", r.Status)
	}

	r = newTest()
	r.AddSkip("x", ReasonReadError, "io", true)
	r.Finalize(1)
	if r.Status != StatusIncomplete || r.Complete {
		t.Fatalf("incomplete: %s", r.Status)
	}

	r = newTest()
	r.AddSkip("x", ReasonReadError, "io", true)
	r.AddMatch("y", "00", "")
	r.Finalize(2)
	if r.Status != StatusMatch || r.Complete {
		t.Fatalf("match+incomplete: %s complete=%v", r.Status, r.Complete)
	}
}

// The tool must never describe files as clean or safe, except to deny it.
func TestNeverClaimsClean(t *testing.T) {
	bad := regexp.MustCompile(`(?i)\b(clean|safe)\b`)
	for _, s := range []Status{StatusNoMatches, StatusMatch, StatusIncomplete} {
		m := StatusMeaning(s)
		for _, loc := range bad.FindAllStringIndex(m, -1) {
			if !strings.Contains(m[:loc[0]], "not") {
				t.Errorf("%s meaning asserts clean/safe: %q", s, m)
			}
		}
	}
}

func TestJSONShapeIsStable(t *testing.T) {
	r := newTest()
	r.Finalize(0)
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "schema_version", "tool_version", "status", "complete", "root",
		"indicators", "limits", "summary", "matches", "heuristic_findings", "skipped", "files", "notes"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	for _, k := range []string{"matches", "heuristic_findings", "skipped", "files"} {
		if _, ok := m[k].([]any); !ok {
			t.Errorf("%s should be an array, not null", k)
		}
	}
	if m["schema"] != SchemaName || m["schema_version"] != float64(SchemaVersion) {
		t.Errorf("schema header %v %v", m["schema"], m["schema_version"])
	}
}

func TestSkipCountsIncludeOmitted(t *testing.T) {
	r := New("t", "/", Limits{}, 1)
	r.AddSkip("a", ReasonSymlink, "", false)
	r.AddSkip("b", ReasonSymlink, "", false)
	r.Finalize(2)
	if len(r.Skipped) != 1 || r.Summary.Skipped != 2 || r.Summary.SkipRecordsOmitted != 1 || r.Summary.SkippedByReason[ReasonSymlink] != 2 {
		t.Fatalf("%+v", r.Summary)
	}
}

func TestSafeText(t *testing.T) {
	for in, want := range map[string]string{
		"plain/path.txt": "plain/path.txt",
		"with space":     "with space",
		"ünïcode":        "ünïcode",
		"a\nb":           `"a\nb"`,
		"\x1b[2J":        `"\x1b[2J"`,
		"x\u202ey":       "\"x\\u202ey\"",
		"\xff":           `"\xff"`,
		`"q"`:            `"\"q\""`,
	} {
		if got := SafeText(in); got != want {
			t.Errorf("SafeText(%q) = %s, want %s", in, got, want)
		}
	}
}

func FuzzSafeText(f *testing.F) {
	for _, s := range []string{"a", "a\nb", "\xff", "\u202e", `"`, "\x1b]0;title\x07"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := SafeText(s)
		if !utf8.ValidString(out) {
			t.Fatal("invalid UTF-8 in output")
		}
		for _, r := range out {
			if !strconv.IsPrint(r) {
				t.Fatalf("non-printable %U in output", r)
			}
		}
		if out != s {
			back, err := strconv.Unquote(out)
			if err != nil || back != s {
				t.Fatalf("escaped form does not round-trip: %q", out)
			}
		}
		enc, escaped := EncodePath(s)
		if escaped {
			if back, err := strconv.Unquote(enc); err != nil || back != s {
				t.Fatal("EncodePath does not round-trip")
			}
		} else if enc != s || !utf8.ValidString(enc) {
			t.Fatal("EncodePath altered valid UTF-8")
		}
	})
}
