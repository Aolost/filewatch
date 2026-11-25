// Package cli implements the filewatch command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Aolost/filewatch/internal/indicators"
	"github.com/Aolost/filewatch/internal/report"
	"github.com/Aolost/filewatch/internal/scan"
	"github.com/Aolost/filewatch/internal/version"
)

// Exit codes. They are part of the stable interface.
const (
	ExitNoMatches  = 0 // NO_MATCHES_FOUND
	ExitMatch      = 1 // MATCH_FOUND
	ExitUsage      = 2 // usage error or fatal error; no report produced
	ExitIncomplete = 3 // SCAN_INCOMPLETE
)

const usageText = `filewatch: conservative local file triage scanner (not an antivirus)

Usage:
  filewatch scan PATH [--indicators FILE] [--json] [limits]
  filewatch version
  filewatch help

Scan flags:
  --indicators FILE      local indicator file (format: filewatch-indicators v1)
  --json                 write the versioned JSON report to stdout
  --max-files N          max directory entries examined (default 100000)
  --max-bytes SIZE       max total bytes read (default 4GiB)
  --max-file-bytes SIZE  files larger than this are skipped, unread (default 1GiB)
  --max-depth N          max directory levels below PATH (default 64)
  --timeout DURATION     max scan runtime, e.g. 90s, 10m (default 10m; 0 = none)
  SIZE accepts a plain byte count or a K/M/G/KiB/MiB/GiB suffix (binary units).

Exit codes:
  0  NO_MATCHES_FOUND  no examined file matched an indicator (NOT "clean")
  1  MATCH_FOUND       an indicator matched (NOT proof of maliciousness)
  2  usage or fatal error; no report
  3  SCAN_INCOMPLETE   some content was not examined; no indicator matched

Symlinks are never followed. Nothing is modified, executed or sent anywhere.
`

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		io.WriteString(stderr, usageText)
		return ExitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintf(stdout, "filewatch %s (report schema %d, indicator format v%d)\n",
			version.Version, report.SchemaVersion, indicators.FormatVersion)
		return ExitNoMatches
	case "help", "-h", "--help":
		io.WriteString(stdout, usageText)
		return ExitNoMatches
	}
	fmt.Fprintf(stderr, "filewatch: unknown command %s\n\n%s", report.SafeText(args[0]), usageText)
	return ExitUsage
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	opts := scan.DefaultOptions()
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	indPath := fs.String("indicators", "", "")
	jsonOut := fs.Bool("json", false, "")
	fs.Int64Var(&opts.MaxFiles, "max-files", opts.MaxFiles, "")
	maxBytes := byteSize(opts.MaxTotalBytes)
	fs.Var(&maxBytes, "max-bytes", "")
	maxFileBytes := byteSize(opts.MaxFileBytes)
	fs.Var(&maxFileBytes, "max-file-bytes", "")
	fs.IntVar(&opts.MaxDepth, "max-depth", opts.MaxDepth, "")
	fs.DurationVar(&opts.Timeout, "timeout", opts.Timeout, "")

	positional, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		io.WriteString(stdout, usageText)
		return ExitNoMatches
	}
	if err != nil {
		return usageErr(stderr, err.Error())
	}
	if len(positional) != 1 {
		return usageErr(stderr, "scan needs exactly one PATH")
	}
	opts.MaxTotalBytes = int64(maxBytes)
	opts.MaxFileBytes = int64(maxFileBytes)

	if *indPath != "" {
		set, err := indicators.Load(*indPath)
		if err != nil {
			return fatal(stderr, "cannot load indicators: "+err.Error())
		}
		opts.Indicators = set
		opts.IndicatorsPath = *indPath
	}

	rep, err := scan.Run(ctx, positional[0], opts)
	if err != nil {
		return fatal(stderr, "cannot scan: "+err.Error())
	}
	if *jsonOut {
		err = rep.WriteJSON(stdout)
	} else {
		err = rep.WriteText(stdout)
	}
	if err != nil {
		return fatal(stderr, "cannot write report: "+err.Error())
	}
	return ExitCode(rep.Status)
}

// ExitCode maps a status to the process exit code.
func ExitCode(s report.Status) int {
	switch s {
	case report.StatusMatch:
		return ExitMatch
	case report.StatusIncomplete:
		return ExitIncomplete
	}
	return ExitNoMatches
}

// parseInterspersed allows flags before and after the positional PATH, as in
// "scan PATH --json". Everything after a literal "--" is positional, so paths
// beginning with "-" can be scanned.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var tail []string
	for i, a := range args {
		if a == "--" {
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	return append(positional, tail...), nil
}

func usageErr(w io.Writer, msg string) int {
	fmt.Fprintf(w, "filewatch: %s\nRun 'filewatch help' for usage.\n", report.SafeText(msg))
	return ExitUsage
}

func fatal(w io.Writer, msg string) int {
	fmt.Fprintf(w, "filewatch: %s\n", report.SafeText(msg))
	return ExitUsage
}

// byteSize is a flag.Value accepting sizes like 1048576, 512K, 64MiB, 4G.
type byteSize int64

func (b *byteSize) String() string { return strconv.FormatInt(int64(*b), 10) }

func (b *byteSize) Set(s string) error {
	v, err := parseSize(s)
	if err != nil {
		return err
	}
	*b = byteSize(v)
	return nil
}

func parseSize(s string) (int64, error) {
	units := []struct {
		suffix string
		mult   int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}}
	mult := int64(1)
	num := s
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			num, mult = strings.TrimSuffix(s, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	if n > (1<<63-1)/mult {
		return 0, fmt.Errorf("size %q overflows", s)
	}
	return n * mult, nil
}
