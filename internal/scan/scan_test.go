package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Aolost/filewatch/internal/indicators"
	"github.com/Aolost/filewatch/internal/report"
)

// All fixtures are harmless generated text. The "indicator" content is the
// string "abc", whose SHA-256 is well known.
const markerContent = "abc"

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func indicatorSet(t *testing.T, contents ...string) *indicators.Set {
	t.Helper()
	var b strings.Builder
	b.WriteString(indicators.Header + "\n")
	for _, c := range contents {
		b.WriteString("sha256:" + sha(c) + " test-label\n")
	}
	set, err := indicators.Parse(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

type entryState struct {
	mode    fs.FileMode
	size    int64
	mtime   time.Time
	content string
	link    string
}

// snapshot records every entry under dir without following symlinks, so tests
// can prove that scanning left fixtures byte-for-byte and metadata unchanged.
func snapshot(t *testing.T, dir string) map[string]entryState {
	t.Helper()
	out := map[string]entryState{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable fixtures are recorded by their parent only
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := entryState{mode: fi.Mode(), size: fi.Size(), mtime: fi.ModTime()}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			st.link, _ = os.Readlink(p)
		case fi.Mode().IsRegular():
			if b, err := os.ReadFile(p); err == nil {
				st.content = string(b)
			}
		}
		if !fi.IsDir() {
			out[p] = st
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertUnchanged(t *testing.T, before, after map[string]entryState) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("entry count changed: %d -> %d", len(before), len(after))
	}
	for p, b := range before {
		a, ok := after[p]
		if !ok || a.mode != b.mode || a.size != b.size || !a.mtime.Equal(b.mtime) || a.content != b.content || a.link != b.link {
			t.Fatalf("fixture %s changed by scan", p)
		}
	}
}

func run(t *testing.T, path string, opts Options) *report.Report {
	t.Helper()
	rep, err := Run(context.Background(), path, opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func reasons(rep *report.Report) map[string]string {
	m := map[string]string{}
	for _, s := range rep.Skipped {
		m[s.Path] = s.Reason
	}
	return m
}

func hashed(rep *report.Report) map[string]string {
	m := map[string]string{}
	for _, f := range rep.Files {
		m[f.Path] = f.SHA256
	}
	return m
}

func assertNoHash(t *testing.T, rep *report.Report, content string) {
	t.Helper()
	for _, f := range rep.Files {
		if f.SHA256 == sha(content) {
			t.Fatalf("content reachable only outside the root was hashed via %q", f.Path)
		}
	}
	if len(rep.Matches) != 0 {
		t.Fatalf("unexpected matches: %+v", rep.Matches)
	}
}

func TestMatchFound(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": markerContent, "b.txt": "other", "sub/c.txt": markerContent})
	before := snapshot(t, dir)
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	opts.IndicatorsPath = "ind.txt"
	rep := run(t, dir, opts)
	assertUnchanged(t, before, snapshot(t, dir))

	if rep.Status != report.StatusMatch || !rep.Complete {
		t.Fatalf("status %s complete=%v", rep.Status, rep.Complete)
	}
	if len(rep.Matches) != 2 || rep.Matches[0].Path != "a.txt" || rep.Matches[1].Path != "sub/c.txt" {
		t.Fatalf("matches %+v", rep.Matches)
	}
	if rep.Matches[0].Label != "test-label" || rep.Matches[0].SHA256 != sha(markerContent) {
		t.Fatalf("match detail %+v", rep.Matches[0])
	}
	if rep.Summary.FilesHashed != 3 || rep.Summary.BytesHashed != int64(2*len(markerContent)+len("other")) {
		t.Fatalf("summary %+v", rep.Summary)
	}
}

func TestNoMatchesFound(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "one", "b/c.txt": "two"})
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	rep := run(t, dir, opts)
	if rep.Status != report.StatusNoMatches || !rep.Complete || rep.Summary.FilesHashed != 2 {
		t.Fatalf("status %s %+v", rep.Status, rep.Summary)
	}
}

func TestNoIndicatorsNote(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": markerContent})
	rep := run(t, dir, DefaultOptions())
	if rep.Status != report.StatusNoMatches || rep.Indicators != nil {
		t.Fatalf("status %s", rep.Status)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "No indicator file was loaded") {
		t.Fatalf("missing vacuous-result note: %v", rep.Notes)
	}
}

func TestSingleFileRoot(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"one.txt": markerContent, "two.txt": markerContent})
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	rep := run(t, filepath.Join(dir, "one.txt"), opts)
	if rep.Status != report.StatusMatch || len(rep.Files) != 1 || rep.Files[0].Path != "one.txt" {
		t.Fatalf("status %s files %+v", rep.Status, rep.Files)
	}
}

func TestSymlinksNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	root := filepath.Join(base, "root")
	writeTree(t, outside, map[string]string{"secret.txt": markerContent})
	writeTree(t, root, map[string]string{"plain.txt": "plain", "inner/x.txt": "x"})
	for name, target := range map[string]string{
		"rel-file":   "../outside/secret.txt",
		"rel-dir":    "../outside",
		"abs-file":   filepath.Join(outside, "secret.txt"),
		"in-root":    "plain.txt",
		"inner-loop": "..",
		"dangling":   "does-not-exist",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshot(t, base)
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	rep := run(t, root, opts)
	assertUnchanged(t, before, snapshot(t, base))
	assertNoHash(t, rep, markerContent)

	r := reasons(rep)
	for _, name := range []string{"rel-file", "rel-dir", "abs-file", "in-root", "inner-loop", "dangling"} {
		if r[name] != report.ReasonSymlink {
			t.Errorf("%s: reason %q, want %s", name, r[name], report.ReasonSymlink)
		}
	}
	// Symlink skips are policy, so the scan is still complete.
	if rep.Status != report.StatusNoMatches || !rep.Complete {
		t.Fatalf("status %s complete=%v", rep.Status, rep.Complete)
	}
	if len(rep.Files) != 2 {
		t.Fatalf("files %+v", rep.Files)
	}
}

func TestRootIsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	writeTree(t, base, map[string]string{"real/a.txt": markerContent})
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "real"), link); err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	rep := run(t, link, opts)
	if rep.Status != report.StatusIncomplete || len(rep.Files) != 0 {
		t.Fatalf("status %s files %d", rep.Status, len(rep.Files))
	}
}

func TestPathTraversalArgumentIsResolved(t *testing.T) {
	base := t.TempDir()
	writeTree(t, base, map[string]string{"a/x.txt": "x", "b/y.txt": markerContent})
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	// "a/../b" is the user's explicit choice and resolves to b; the report
	// must show the resolved absolute root, not a misleading one.
	rep := run(t, filepath.Join(base, "a", "..", "b"), opts)
	if rep.Root != filepath.Join(base, "b") || rep.Status != report.StatusMatch {
		t.Fatalf("root %q status %s", rep.Root, rep.Status)
	}
}

// swap replaces the entry at p with a symlink to target.
func swap(t *testing.T, p, target string) {
	if err := os.RemoveAll(p); err != nil {
		t.Error(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Error(err)
	}
}

func TestRaceFileSwappedForOutsideSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	root := filepath.Join(base, "root")
	writeTree(t, outside, map[string]string{"secret.txt": markerContent})
	writeTree(t, root, map[string]string{"victim.txt": "harmless"})
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	opts.hooks = &testHooks{afterLstat: func(rel string) {
		if rel == "victim.txt" {
			swap(t, filepath.Join(root, rel), filepath.Join(outside, "secret.txt"))
		}
	}}
	rep := run(t, root, opts)
	assertNoHash(t, rep, markerContent)
	if r := reasons(rep)["victim.txt"]; r != report.ReasonPathOutsideRoot && r != report.ReasonChanged {
		t.Fatalf("victim reason %q", r)
	}
	if rep.Status != report.StatusIncomplete {
		t.Fatalf("status %s", rep.Status)
	}
}

func TestRaceDirSwappedForOutsideSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	root := filepath.Join(base, "root")
	writeTree(t, outside, map[string]string{"secret.txt": markerContent})
	writeTree(t, root, map[string]string{"d/inner.txt": "harmless"})
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	opts.hooks = &testHooks{afterLstat: func(rel string) {
		if rel == "d" {
			swap(t, filepath.Join(root, "d"), outside)
		}
	}}
	rep := run(t, root, opts)
	assertNoHash(t, rep, markerContent)
	if rep.Status != report.StatusIncomplete {
		t.Fatalf("status %s", rep.Status)
	}
}

func TestRaceFileSwappedForInRootSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{"marker.txt": markerContent, "victim.txt": "harmless"})
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	opts.hooks = &testHooks{afterLstat: func(rel string) {
		if rel == "victim.txt" {
			swap(t, filepath.Join(root, rel), "marker.txt")
		}
	}}
	rep := run(t, root, opts)
	// os.Root would follow the in-root link; the identity check must refuse it
	// so victim.txt is not misreported with marker.txt's digest.
	if reasons(rep)["victim.txt"] != report.ReasonChanged {
		t.Fatalf("reasons %v", reasons(rep))
	}
	if _, ok := hashed(rep)["victim.txt"]; ok {
		t.Fatal("swapped entry was hashed")
	}
}

func TestPermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits not enforced")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{"locked.txt": "x", "lockdir/y.txt": "y", "ok.txt": "ok"})
	for _, p := range []string{"locked.txt", "lockdir"} {
		if err := os.Chmod(filepath.Join(root, p), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(filepath.Join(root, p), 0o755) })
	}
	rep := run(t, root, DefaultOptions())
	r := reasons(rep)
	if r["locked.txt"] != report.ReasonPermission || r["lockdir"] != report.ReasonPermission {
		t.Fatalf("reasons %v", r)
	}
	if rep.Status != report.StatusIncomplete || rep.Summary.FilesHashed != 1 {
		t.Fatalf("status %s hashed %d", rep.Status, rep.Summary.FilesHashed)
	}
}

func TestFileGrowsDuringRead(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"grow.txt": "start"})
	opts := DefaultOptions()
	opts.hooks = &testHooks{afterOpen: func(rel string) {
		f, err := os.OpenFile(filepath.Join(root, rel), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		f.WriteString(" and more")
		f.Close()
	}}
	rep := run(t, root, opts)
	if reasons(rep)["grow.txt"] != report.ReasonChanged || len(rep.Files) != 0 || rep.Complete {
		t.Fatalf("reasons %v files %v", reasons(rep), rep.Files)
	}
}

func TestFileShrinksDuringRead(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"shrink.txt": "some content"})
	opts := DefaultOptions()
	opts.hooks = &testHooks{afterOpen: func(rel string) {
		if err := os.Truncate(filepath.Join(root, rel), 2); err != nil {
			t.Error(err)
		}
	}}
	rep := run(t, root, opts)
	if reasons(rep)["shrink.txt"] != report.ReasonChanged || len(rep.Files) != 0 {
		t.Fatalf("reasons %v", reasons(rep))
	}
}

func TestSameSizeRewriteWithRestoredMtime(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("ctime check not available")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{"f.txt": "xyz"})
	p := filepath.Join(root, "f.txt")
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	opts.hooks = &testHooks{afterOpen: func(string) {
		fi, _ := os.Stat(p)
		time.Sleep(10 * time.Millisecond) // ensure ctime moves on coarse clocks
		if err := os.WriteFile(p, []byte(markerContent), 0o644); err != nil {
			t.Error(err)
		}
		os.Chtimes(p, fi.ModTime(), fi.ModTime())
	}}
	rep := run(t, root, opts)
	if reasons(rep)["f.txt"] != report.ReasonChanged || len(rep.Matches) != 0 {
		t.Fatalf("reasons %v matches %v", reasons(rep), rep.Matches)
	}
}

func TestPerFileByteLimit(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"exact.bin": strings.Repeat("a", 1024)})
	// A sparse 4 GiB file: large logical size, no disk usage, never read.
	f, err := os.Create(filepath.Join(root, "huge.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(4 << 30); err != nil {
		t.Skipf("sparse files unsupported: %v", err)
	}
	f.Close()
	opts := DefaultOptions()
	opts.MaxFileBytes = 1024
	start := time.Now()
	rep := run(t, root, opts)
	if time.Since(start) > 5*time.Second {
		t.Fatal("oversized file appears to have been read")
	}
	if reasons(rep)["huge.bin"] != report.ReasonFileTooLarge {
		t.Fatalf("reasons %v", reasons(rep))
	}
	if _, ok := hashed(rep)["exact.bin"]; !ok {
		t.Fatal("file exactly at the limit was not hashed")
	}
	if rep.Status != report.StatusIncomplete {
		t.Fatalf("status %s", rep.Status)
	}
}

func TestTotalByteLimit(t *testing.T) {
	root := t.TempDir()
	c := strings.Repeat("z", 600)
	writeTree(t, root, map[string]string{"1.txt": c, "2.txt": c, "3.txt": c})
	opts := DefaultOptions()
	opts.MaxTotalBytes = 1000
	rep := run(t, root, opts)
	if rep.Summary.BytesHashed > opts.MaxTotalBytes || rep.Summary.FilesHashed != 1 {
		t.Fatalf("summary %+v", rep.Summary)
	}
	if reasons(rep)["2.txt"] != report.ReasonByteLimit || rep.Status != report.StatusIncomplete {
		t.Fatalf("reasons %v status %s", reasons(rep), rep.Status)
	}
	if _, ok := reasons(rep)["3.txt"]; ok {
		t.Fatal("scan continued after the byte limit halted it")
	}
}

func TestFileCountLimit(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"})
	opts := DefaultOptions()
	opts.MaxFiles = 2
	rep := run(t, root, opts)
	if rep.Summary.EntriesExamined != 2 || reasons(rep)["c"] != report.ReasonFileLimit || rep.Complete {
		t.Fatalf("summary %+v reasons %v", rep.Summary, reasons(rep))
	}
}

func TestDepthLimit(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"top.txt": "t", "a/mid.txt": "m", "a/b/deep.txt": "d"})
	opts := DefaultOptions()
	opts.MaxDepth = 1
	rep := run(t, root, opts)
	h := hashed(rep)
	if _, ok := h["a/mid.txt"]; !ok || len(h) != 2 {
		t.Fatalf("hashed %v", h)
	}
	if reasons(rep)["a/b"] != report.ReasonDepthLimit || rep.Complete {
		t.Fatalf("reasons %v", reasons(rep))
	}
}

func TestDirectoryEntryLimit(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"big/1": "", "big/2": "", "big/3": "", "small/1": ""})
	opts := DefaultOptions()
	opts.MaxDirEntries = 2
	rep := run(t, root, opts)
	if reasons(rep)["big"] != report.ReasonDirTooLarge || rep.Complete {
		t.Fatalf("reasons %v", reasons(rep))
	}
	if _, ok := hashed(rep)["small/1"]; !ok {
		t.Fatal("sibling directory not scanned")
	}
}

func TestInterruptedScan(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"1.txt": "1", "2.txt": "2", "3.txt": markerContent})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	opts.hooks = &testHooks{afterOpen: func(rel string) {
		if rel == "1.txt" {
			cancel()
		}
	}}
	rep, err := Run(ctx, root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != report.StatusIncomplete || reasons(rep)["1.txt"] != report.ReasonInterrupted {
		t.Fatalf("status %s reasons %v", rep.Status, reasons(rep))
	}
	if len(rep.Files) != 0 {
		t.Fatalf("files after interruption: %v", rep.Files)
	}
}

func TestTimeLimit(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"1.txt": "1"})
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	rep, err := Run(ctx, root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != report.StatusIncomplete || !strings.Contains(strings.Join(rep.Summary.IncompleteReasons, ","), report.ReasonTimeLimit) {
		t.Fatalf("status %s %+v", rep.Status, rep.Summary)
	}
}

func TestMatchTakesPrecedenceOverIncomplete(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a.txt": markerContent, "b/c/d.txt": "deep"})
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	opts.MaxDepth = 1
	rep := run(t, root, opts)
	if rep.Status != report.StatusMatch || rep.Complete {
		t.Fatalf("status %s complete=%v", rep.Status, rep.Complete)
	}
}

func TestDeterministicOutput(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{}
	for i := range 50 {
		files["d"+strconv.Itoa(i%7)+"/f"+strconv.Itoa(i)+".pdf.exe"] = strconv.Itoa(i)
	}
	files["m.txt"] = markerContent
	writeTree(t, root, files)
	opts := DefaultOptions()
	opts.Indicators = indicatorSet(t, markerContent)
	opts.IndicatorsPath = "ind"
	var outs [3]bytes.Buffer
	for i := range outs {
		if err := run(t, root, opts).WriteJSON(&outs[i]); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(outs[0].Bytes(), outs[1].Bytes()) || !bytes.Equal(outs[1].Bytes(), outs[2].Bytes()) {
		t.Fatal("JSON output is not deterministic")
	}
}

func TestHostileNames(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("filesystem rejects these names")
	}
	root := t.TempDir()
	names := []string{"line\nbreak.txt", "bad\xffutf8.txt", "esc\x1b[31mred.txt", "invoice\u202efdp.exe", "-rf", `"quoted"`}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(root, n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep := run(t, root, DefaultOptions())
	if len(rep.Files) != len(names) {
		t.Fatalf("hashed %d of %d", len(rep.Files), len(names))
	}
	var js bytes.Buffer
	if err := rep.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Files []struct {
			Path        string `json:"path"`
			PathEscaped bool   `json:"path_escaped"`
		} `json:"files"`
	}
	if err := json.Unmarshal(js.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range decoded.Files {
		p := f.Path
		if f.PathEscaped {
			var err error
			if p, err = strconv.Unquote(p); err != nil {
				t.Fatal(err)
			}
		}
		got[p] = true
	}
	for _, n := range names {
		if !got[n] {
			t.Errorf("name %q not recoverable from JSON", n)
		}
	}
	var txt bytes.Buffer
	if err := rep.WriteText(&txt); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(txt.String(), "\x1b\u202e\xff") || strings.Contains(txt.String(), "line\nbreak") {
		t.Fatal("text output contains raw control, bidi or invalid bytes from file names")
	}
	if !strings.Contains(js.String(), "deceptive-name-characters") {
		t.Fatal("bidi name not flagged")
	}
}

func TestInvalidOptions(t *testing.T) {
	dir := t.TempDir()
	for _, mut := range []func(*Options){
		func(o *Options) { o.MaxFiles = 0 },
		func(o *Options) { o.MaxTotalBytes = -1 },
		func(o *Options) { o.MaxFileBytes = 0 },
		func(o *Options) { o.MaxDepth = -1 },
		func(o *Options) { o.MaxDirEntries = 0 },
		func(o *Options) { o.Timeout = -time.Second },
	} {
		o := DefaultOptions()
		mut(&o)
		if _, err := Run(context.Background(), dir, o); err == nil {
			t.Error("invalid options accepted")
		}
	}
	if _, err := Run(context.Background(), filepath.Join(dir, "missing"), DefaultOptions()); err == nil {
		t.Error("missing root accepted")
	}
}

func TestSkipRecordCap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	for i := range 20 {
		os.Symlink("x", filepath.Join(root, "l"+strconv.Itoa(i)))
	}
	opts := DefaultOptions()
	opts.MaxSkipRecords = 5
	rep := run(t, root, opts)
	if len(rep.Skipped) != 5 || rep.Summary.SkipRecordsOmitted != 15 || rep.Summary.Skipped != 20 {
		t.Fatalf("skipped %d omitted %d total %d", len(rep.Skipped), rep.Summary.SkipRecordsOmitted, rep.Summary.Skipped)
	}
}

// FuzzScanName creates one file with a fuzzed name (confined with os.Root so
// the fuzzer can never write outside its temp dir) and checks that the scan
// reports it under exactly that name, stays inside the root, and leaves it
// unchanged.
func FuzzScanName(f *testing.F) {
	for _, s := range []string{"a.txt", "..", "x/../../y", "invoice.pdf.exe", "\u202e", "\xff", "a\nb", " ", "-"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || len(name) > 200 {
			return
		}
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		w, err := root.Create(name)
		if err != nil {
			return // name not representable on this filesystem
		}
		w.WriteString(markerContent)
		w.Close()
		// The filesystem may store a different name than requested (Windows
		// maps invalid UTF-8 to U+FFFD; some filesystems normalise Unicode),
		// so the expected name is what the directory actually holds.
		ents, err := os.ReadDir(dir)
		if err != nil || len(ents) != 1 {
			t.Fatalf("readdir: %v (%d entries)", err, len(ents))
		}
		stored := ents[0].Name()
		before := snapshot(t, dir)
		opts := DefaultOptions()
		opts.Indicators = indicatorSet(t, markerContent)
		rep, err := Run(context.Background(), dir, opts)
		if err != nil {
			t.Fatal(err)
		}
		assertUnchanged(t, before, snapshot(t, dir))
		if len(rep.Files) != 1 || rep.Status != report.StatusMatch {
			t.Fatalf("files %+v status %s", rep.Files, rep.Status)
		}
		p := rep.Files[0].Path
		if rep.Files[0].PathEscaped {
			if p, err = strconv.Unquote(p); err != nil {
				t.Fatal(err)
			}
		}
		if p != stored {
			t.Fatalf("reported %q for stored name %q (requested %q)", p, stored, name)
		}
	})
}
