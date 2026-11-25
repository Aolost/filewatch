package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Aolost/filewatch/internal/indicators"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func runCLI(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = Run(context.Background(), args, &o, &e)
	return code, o.String(), e.String()
}

// fixture builds a harmless tree plus an indicator file listing "abc".
func fixture(t *testing.T) (root, ind string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	for name, c := range map[string]string{"a.txt": "abc", "b.txt": "hello", "sub/invoice.pdf.exe": "not a program"} {
		p := filepath.Join(root, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ind = filepath.Join(base, "ind.txt")
	data := indicators.Header + "\nsha256:" + sha("abc") + " Example label\n"
	if err := os.WriteFile(ind, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, ind
}

func TestExitCodes(t *testing.T) {
	root, ind := fixture(t)
	if code, out, _ := runCLI("scan", root, "--indicators", ind); code != ExitMatch || !strings.Contains(out, "MATCH_FOUND") {
		t.Fatalf("match: code %d\n%s", code, out)
	}
	if code, out, _ := runCLI("scan", filepath.Join(root, "b.txt"), "--indicators", ind); code != ExitNoMatches || !strings.Contains(out, "NO_MATCHES_FOUND") {
		t.Fatalf("no match: code %d\n%s", code, out)
	}
	if code, _, _ := runCLI("scan", root, "--indicators", ind, "--max-files", "1"); code != ExitMatch {
		t.Fatalf("match+incomplete should still exit %d, got %d", ExitMatch, code)
	}
	if code, out, _ := runCLI("scan", filepath.Join(root, "sub"), "--indicators", ind, "--max-file-bytes", "4"); code != ExitIncomplete || !strings.Contains(out, "SCAN_INCOMPLETE") {
		t.Fatalf("incomplete: code %d\n%s", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	root, ind := fixture(t)
	bad := filepath.Join(t.TempDir(), "bad.txt")
	os.WriteFile(bad, []byte("not an indicator file\n"), 0o644)
	for name, args := range map[string][]string{
		"no args":         {},
		"unknown cmd":     {"frobnicate"},
		"no path":         {"scan"},
		"two paths":       {"scan", root, root},
		"bad flag":        {"scan", root, "--nope"},
		"bad size":        {"scan", root, "--max-bytes", "lots"},
		"zero size":       {"scan", root, "--max-file-bytes", "0"},
		"overflow size":   {"scan", root, "--max-bytes", "99999999999G"},
		"negative depth":  {"scan", root, "--max-depth", "-1"},
		"missing path":    {"scan", filepath.Join(root, "missing")},
		"missing ind":     {"scan", root, "--indicators", filepath.Join(root, "nope")},
		"malformed ind":   {"scan", root, "--indicators", bad},
		"dir as ind":      {"scan", root, "--indicators", root},
		"ind needs value": {"scan", root, "--indicators"},
	} {
		code, out, errOut := runCLI(args...)
		if code != ExitUsage {
			t.Errorf("%s: code %d, want %d", name, code, ExitUsage)
		}
		if out != "" {
			t.Errorf("%s: wrote to stdout on error: %q", name, out)
		}
		if errOut == "" {
			t.Errorf("%s: no error message", name)
		}
	}
	_ = ind
}

func TestFlagsAnywhereAndDoubleDash(t *testing.T) {
	root, ind := fixture(t)
	dashDir := filepath.Join(root, "-dash")
	os.Mkdir(dashDir, 0o755)
	os.WriteFile(filepath.Join(dashDir, "x"), []byte("abc"), 0o644)
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(root)
	for _, args := range [][]string{
		{"scan", "--json", "--indicators", ind, "a.txt"},
		{"scan", "a.txt", "--indicators", ind, "--json"},
		{"scan", "--indicators", ind, "--json", "--", "-dash"},
	} {
		code, out, errOut := runCLI(args...)
		if code != ExitMatch {
			t.Fatalf("%v: code %d %s", args, code, errOut)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("%v: invalid JSON: %v", args, err)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"1": 1, "2K": 2048, "3KiB": 3072, "1M": 1 << 20, "4GiB": 4 << 30} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "-1", "0", "1KB", "1.5M", "G", "9223372036854775807K"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) accepted", in)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := runCLI("version"); code != 0 || !strings.Contains(out, "0.1.0") {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, out, _ := runCLI("help"); code != 0 || !strings.Contains(out, "SCAN_INCOMPLETE") {
		t.Fatalf("help: %d", code)
	}
	if code, out, _ := runCLI("scan", "-h"); code != 0 || !strings.Contains(out, "Usage") {
		t.Fatalf("scan -h: %d", code)
	}
}

// TestGoldenJSON pins the v1 JSON schema. Paths that vary per run are
// normalised; everything else must match byte for byte.
func TestGoldenJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("golden paths are normalised with forward slashes")
	}
	root, ind := fixture(t)
	code, out, errOut := runCLI("scan", root, "--indicators", ind, "--json")
	if code != ExitMatch {
		t.Fatalf("code %d: %s", code, errOut)
	}
	out = strings.ReplaceAll(out, ind, "<INDICATORS>")
	out = strings.ReplaceAll(out, root, "<ROOT>")
	golden := filepath.Join("testdata", "report.golden.json")
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if out != string(want) {
		t.Fatalf("JSON report differs from golden file:\n%s", out)
	}
}

func TestTextMakesNoVerdict(t *testing.T) {
	root, ind := fixture(t)
	_, out, _ := runCLI("scan", filepath.Join(root, "b.txt"), "--indicators", ind)
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(line)
		if (strings.Contains(l, "clean") || strings.Contains(l, "safe")) && !strings.Contains(l, "not") {
			t.Fatalf("output asserts clean/safe: %q", line)
		}
	}
}
