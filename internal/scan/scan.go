// Package scan walks a user-selected root read-only, hashes regular files with
// bounded resources, and assembles a report.
//
// Safety properties:
//   - All access goes through os.Root, so no path can resolve outside the
//     selected root, even if directories are swapped for symlinks mid-scan.
//   - Symlinks are never followed: entries are classified with Lstat, and
//     every opened descriptor is fstat'ed and compared (os.SameFile) with the
//     Lstat result, so a swapped-in symlink or file is detected and skipped.
//   - Only regular files are opened for reading, with O_NONBLOCK on Unix so a
//     FIFO swapped in after classification cannot hang the scan.
//   - Size and change checks use fstat on the open descriptor, never the stale
//     directory listing. A file whose size, mtime or ctime changes while it is
//     read, or whose byte count differs from its fstat size, is reported as
//     changed_during_scan and its digest is discarded.
//   - Nothing is ever written, renamed, deleted or executed.
package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Aolost/filewatch/internal/hashing"
	"github.com/Aolost/filewatch/internal/heuristics"
	"github.com/Aolost/filewatch/internal/indicators"
	"github.com/Aolost/filewatch/internal/report"
	"github.com/Aolost/filewatch/internal/safeopen"
	"github.com/Aolost/filewatch/internal/version"
)

// Options configures a scan. Use DefaultOptions and override fields.
type Options struct {
	Indicators     *indicators.Set
	IndicatorsPath string
	MaxFiles       int64 // every directory entry visited counts
	MaxTotalBytes  int64
	MaxFileBytes   int64
	MaxDepth       int // directory levels below the root to descend
	MaxDirEntries  int // entries read from a single directory
	Timeout        time.Duration
	MaxSkipRecords int

	hooks *testHooks
}

// testHooks lets tests inject filesystem changes at race-sensitive points.
type testHooks struct {
	afterLstat func(rel string) // after an entry is classified, before it is opened
	afterOpen  func(rel string) // after a file is opened and fstat'ed, before reading
}

// DefaultOptions returns conservative defaults.
func DefaultOptions() Options {
	return Options{
		MaxFiles:       100_000,
		MaxTotalBytes:  4 << 30,
		MaxFileBytes:   1 << 30,
		MaxDepth:       64,
		MaxDirEntries:  100_000,
		Timeout:        10 * time.Minute,
		MaxSkipRecords: 10_000,
	}
}

func (o Options) validate() error {
	switch {
	case o.MaxFiles <= 0:
		return errors.New("max files must be positive")
	case o.MaxTotalBytes <= 0:
		return errors.New("max total bytes must be positive")
	case o.MaxFileBytes <= 0:
		return errors.New("max file bytes must be positive")
	case o.MaxDepth < 0:
		return errors.New("max depth must not be negative")
	case o.MaxDirEntries <= 0:
		return errors.New("max directory entries must be positive")
	case o.Timeout < 0:
		return errors.New("timeout must not be negative")
	case o.MaxSkipRecords < 0:
		return errors.New("max skip records must not be negative")
	}
	return nil
}

type scanner struct {
	ctx     context.Context
	opts    Options
	root    *os.Root
	rep     *report.Report
	hasher  *hashing.Hasher
	entries int64
	bytes   int64
	halted  bool
}

// Run scans path. It returns an error only when the scan cannot start at all
// (invalid options, path missing or unreadable); everything else is reported.
func Run(ctx context.Context, path string, opts Options) (*report.Report, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	li, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	rep := report.New(version.Version, abs, report.Limits{
		MaxFiles:       opts.MaxFiles,
		MaxTotalBytes:  opts.MaxTotalBytes,
		MaxFileBytes:   opts.MaxFileBytes,
		MaxDepth:       opts.MaxDepth,
		MaxDirEntries:  opts.MaxDirEntries,
		TimeoutSeconds: int64(opts.Timeout / time.Second),
		Symlinks:       "not_followed",
	}, opts.MaxSkipRecords)
	if opts.Indicators != nil {
		rep.SetIndicators(opts.IndicatorsPath, opts.Indicators.Len(), opts.Indicators.SourceSHA256.Hex())
	}
	s := &scanner{ctx: ctx, opts: opts, rep: rep, hasher: hashing.NewHasher()}

	switch {
	case li.Mode()&fs.ModeSymlink != 0:
		rep.AddSkip(".", report.ReasonRootNotDirOrFile, "the scan path is a symbolic link; symlinks are not followed (pass the target path instead)", true)
	case li.IsDir():
		root, err := os.OpenRoot(abs)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		s.root = root
		ri, err := root.Stat(".")
		if err != nil {
			return nil, err
		}
		if !os.SameFile(li, ri) {
			rep.AddSkip(".", report.ReasonChanged, "the scan root was replaced while opening it", true)
			break
		}
		s.walkDir(".", 0, ri)
	case li.Mode().IsRegular():
		root, err := os.OpenRoot(filepath.Dir(abs))
		if err != nil {
			return nil, err
		}
		defer root.Close()
		s.root = root
		name := filepath.Base(abs)
		if s.count(name) {
			s.scanFile(name, li)
		}
	default:
		rep.AddSkip(".", report.ReasonRootNotDirOrFile, "the scan path is a "+typeName(li.Mode())+", not a regular file or directory", true)
	}
	rep.Finalize(s.entries)
	return rep, nil
}

// stopped reports whether scanning must stop, recording why the first time.
func (s *scanner) stopped(next string) bool {
	if s.halted {
		return true
	}
	if err := s.ctx.Err(); err != nil {
		s.halt(next, ctxReason(err), "scan stopped before this entry: "+ctxDetail(err))
		return true
	}
	return false
}

func (s *scanner) halt(rel, reason, detail string) {
	s.halted = true
	s.rep.AddSkip(display(rel), reason, detail, true)
}

// count charges one entry against MaxFiles.
func (s *scanner) count(rel string) bool {
	if s.stopped(rel) {
		return false
	}
	if s.entries >= s.opts.MaxFiles {
		s.halt(rel, report.ReasonFileLimit, fmt.Sprintf("entry limit of %d reached; this and remaining entries were not examined", s.opts.MaxFiles))
		return false
	}
	s.entries++
	return true
}

func (s *scanner) walkDir(rel string, depth int, want fs.FileInfo) {
	names, err := s.readDir(rel, want)
	if err != nil {
		var se *skipError
		if errors.As(err, &se) {
			s.rep.AddSkip(display(rel), se.reason, se.detail, true)
		} else {
			s.skipErr(rel, err)
		}
		return
	}
	for _, name := range names {
		child := name
		if rel != "." {
			child = filepath.Join(rel, name)
		}
		if !s.count(child) {
			return
		}
		ci, err := s.root.Lstat(child)
		if err != nil {
			s.skipErr(child, err)
			continue
		}
		if s.opts.hooks != nil && s.opts.hooks.afterLstat != nil {
			s.opts.hooks.afterLstat(child)
		}
		mode := ci.Mode()
		switch {
		case mode&fs.ModeSymlink != 0:
			s.rep.AddSkip(display(child), report.ReasonSymlink, "symbolic links are never followed", false)
		case mode.IsDir():
			if depth+1 > s.opts.MaxDepth {
				s.rep.AddSkip(display(child), report.ReasonDepthLimit, fmt.Sprintf("directory is deeper than the depth limit of %d", s.opts.MaxDepth), true)
				continue
			}
			s.walkDir(child, depth+1, ci)
			if s.halted {
				return
			}
		case mode.IsRegular():
			s.scanFile(child, ci)
		default:
			s.rep.AddSkip(display(child), report.ReasonNotRegular, typeName(mode)+" is not a regular file and is never opened", false)
		}
	}
}

type skipError struct{ reason, detail string }

func (e *skipError) Error() string { return e.reason + ": " + e.detail }

// readDir lists a directory's names, sorted for deterministic output. The
// directory is closed before recursion so open descriptors stay O(1).
func (s *scanner) readDir(rel string, want fs.FileInfo) ([]string, error) {
	f, err := s.root.Open(rel)
	if err != nil {
		reason, detail := classify(err)
		return nil, &skipError{reason, detail}
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		reason, detail := classify(err)
		return nil, &skipError{reason, detail}
	}
	if !got.IsDir() || !os.SameFile(want, got) {
		return nil, &skipError{report.ReasonChanged, "directory was replaced between listing and opening"}
	}
	var names []string
	for {
		batch, err := f.Readdirnames(1024)
		names = append(names, batch...)
		if len(names) > s.opts.MaxDirEntries {
			return nil, &skipError{report.ReasonDirTooLarge,
				fmt.Sprintf("directory has more than %d entries; none of its entries were examined", s.opts.MaxDirEntries)}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			reason, detail := classify(err)
			return nil, &skipError{reason, "listing failed: " + detail}
		}
		if len(batch) == 0 {
			break
		}
		if err := s.ctx.Err(); err != nil {
			break // the caller's stopped() check records the interruption
		}
	}
	sort.Strings(names)
	return names, nil
}

func (s *scanner) scanFile(rel string, want fs.FileInfo) {
	f, err := safeopen.InRoot(s.root, rel)
	if err != nil {
		s.skipErr(rel, err)
		return
	}
	defer f.Close()
	pre, err := f.Stat()
	if err != nil {
		s.skipErr(rel, err)
		return
	}
	if !pre.Mode().IsRegular() || !os.SameFile(want, pre) {
		s.rep.AddSkip(display(rel), report.ReasonChanged, "entry was replaced between listing and opening; not read", true)
		return
	}
	size := pre.Size()
	if size > s.opts.MaxFileBytes {
		s.rep.AddSkip(display(rel), report.ReasonFileTooLarge, fmt.Sprintf("size %d exceeds per-file limit %d; not read", size, s.opts.MaxFileBytes), true)
		return
	}
	if size > s.opts.MaxTotalBytes-s.bytes {
		s.halt(rel, report.ReasonByteLimit, fmt.Sprintf("total byte limit of %d reached; this and remaining entries were not examined", s.opts.MaxTotalBytes))
		return
	}
	s.bytes += size // reserve before reading so the budget bounds work done
	if s.opts.hooks != nil && s.opts.hooks.afterOpen != nil {
		s.opts.hooks.afterOpen(rel)
	}
	res, err := s.hasher.Sum(s.ctx, f, size)
	switch {
	case errors.Is(err, hashing.ErrTooLarge):
		s.rep.AddSkip(display(rel), report.ReasonChanged, "file grew while being read; digest discarded", true)
		return
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.halt(rel, ctxReason(err), "scan stopped while reading this file: "+ctxDetail(err))
		return
	case err != nil:
		s.skipErr(rel, err)
		return
	}
	post, err := f.Stat()
	if err != nil {
		s.skipErr(rel, err)
		return
	}
	if res.Bytes != size || !unchanged(pre, post) {
		s.rep.AddSkip(display(rel), report.ReasonChanged, "file changed while being read; digest discarded", true)
		return
	}
	shaHex := res.Hex()
	p := display(rel)
	s.rep.AddFile(p, res.Bytes, shaHex)
	if label, ok := s.opts.Indicators.Lookup(indicators.Digest(res.SHA256)); ok {
		s.rep.AddMatch(p, shaHex, label)
	}
	for _, fd := range heuristics.Check(filepath.Base(rel), res.Header) {
		s.rep.AddFinding(p, fd.Rule, fd.Explanation, fd.Evidence)
	}
}

func (s *scanner) skipErr(rel string, err error) {
	reason, detail := classify(err)
	s.rep.AddSkip(display(rel), reason, detail, true)
}

// classify maps an error to a stable reason and a detail that never includes
// file contents. The detail omits the path, which the record already carries.
func classify(err error) (reason, detail string) {
	var pe *fs.PathError
	msg := err.Error()
	if errors.As(err, &pe) {
		msg = pe.Err.Error()
	}
	switch {
	case errors.Is(err, fs.ErrPermission):
		return report.ReasonPermission, "permission denied"
	case errors.Is(err, fs.ErrNotExist):
		return report.ReasonVanished, "entry disappeared during the scan"
	case strings.Contains(msg, "escapes from parent"):
		// Only reachable if an entry was swapped for a symlink after Lstat.
		return report.ReasonPathOutsideRoot, "entry resolved outside the scan root (likely swapped for a symlink); refused"
	}
	return report.ReasonReadError, msg
}

func unchanged(a, b fs.FileInfo) bool {
	return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && ctimeEqual(a, b) && os.SameFile(a, b)
}

func ctxReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return report.ReasonTimeLimit
	}
	return report.ReasonInterrupted
}

func ctxDetail(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "runtime limit reached"
	}
	return "scan was interrupted"
}

// display converts an OS-relative path to the report's slash-separated form.
func display(rel string) string { return filepath.ToSlash(rel) }

func typeName(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "symbolic link"
	case m&fs.ModeNamedPipe != 0:
		return "named pipe"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeCharDevice != 0:
		return "character device"
	case m&fs.ModeDevice != 0:
		return "device"
	case m&fs.ModeIrregular != 0:
		return "irregular file"
	}
	return "special file"
}
