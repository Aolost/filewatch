// Package report defines the versioned scan report and its JSON and
// human-readable renderings. The JSON schema is stable within a
// schema_version: fields are only ever added, never renamed or removed.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Schema identifiers.
const (
	SchemaName    = "filewatch.report"
	SchemaVersion = 1
)

// Status is the overall scan outcome. There is deliberately no "clean" status.
type Status string

// Statuses.
const (
	// StatusNoMatches: the scan completed and no file's SHA-256 was in the
	// indicator set. It does NOT mean the files are safe.
	StatusNoMatches Status = "NO_MATCHES_FOUND"
	// StatusMatch: at least one file's SHA-256 is in the indicator set. That
	// is an indicator match, not proof of maliciousness.
	StatusMatch Status = "MATCH_FOUND"
	// StatusIncomplete: some content could not be examined (limit, error,
	// change during scan, interruption) and there was no indicator match.
	StatusIncomplete Status = "SCAN_INCOMPLETE"
)

// Skip reasons. They are part of the stable schema.
const (
	ReasonSymlink          = "symlink_not_followed"
	ReasonNotRegular       = "not_regular_file"
	ReasonPermission       = "permission_denied"
	ReasonReadError        = "read_error"
	ReasonVanished         = "vanished"
	ReasonChanged          = "changed_during_scan"
	ReasonFileTooLarge     = "file_too_large"
	ReasonDepthLimit       = "depth_limit"
	ReasonDirTooLarge      = "directory_too_large"
	ReasonFileLimit        = "file_limit"
	ReasonByteLimit        = "byte_limit"
	ReasonTimeLimit        = "time_limit"
	ReasonInterrupted      = "interrupted"
	ReasonPathOutsideRoot  = "outside_root"
	ReasonRootNotDirOrFile = "root_not_scannable"
)

// Report is the full scan result.
type Report struct {
	Schema        string          `json:"schema"`
	SchemaVersion int             `json:"schema_version"`
	ToolVersion   string          `json:"tool_version"`
	Status        Status          `json:"status"`
	Complete      bool            `json:"complete"`
	Root          string          `json:"root"`
	RootEscaped   bool            `json:"root_escaped,omitempty"`
	Indicators    *IndicatorInfo  `json:"indicators"`
	Limits        Limits          `json:"limits"`
	Summary       Summary         `json:"summary"`
	Matches       []Match         `json:"matches"`
	Findings      []Finding       `json:"heuristic_findings"`
	Skipped       []Skip          `json:"skipped"`
	Files         []File          `json:"files"`
	Notes         []string        `json:"notes"`
	rawRoot       string          // unescaped, for text output
	skipCounts    map[string]int  // all skips, including omitted records
	incomplete    map[string]bool // reasons that made the scan incomplete
	maxSkipRecord int
}

// IndicatorInfo describes the loaded indicator file.
type IndicatorInfo struct {
	Path          string `json:"path"`
	PathEscaped   bool   `json:"path_escaped,omitempty"`
	FormatVersion int    `json:"format_version"`
	Records       int    `json:"records"`
	SHA256        string `json:"sha256"`
	rawPath       string
}

// Limits records the bounds the scan ran under.
type Limits struct {
	MaxFiles       int64  `json:"max_files"`
	MaxTotalBytes  int64  `json:"max_total_bytes"`
	MaxFileBytes   int64  `json:"max_file_bytes"`
	MaxDepth       int    `json:"max_depth"`
	MaxDirEntries  int    `json:"max_dir_entries"`
	TimeoutSeconds int64  `json:"timeout_seconds"`
	Symlinks       string `json:"symlinks"`
}

// Summary holds counters.
type Summary struct {
	EntriesExamined    int64          `json:"entries_examined"`
	FilesHashed        int64          `json:"files_hashed"`
	BytesHashed        int64          `json:"bytes_hashed"`
	IndicatorMatches   int            `json:"indicator_matches"`
	HeuristicFindings  int            `json:"heuristic_findings"`
	Skipped            int            `json:"skipped"`
	SkippedByReason    map[string]int `json:"skipped_by_reason"`
	SkipRecordsOmitted int            `json:"skip_records_omitted"`
	IncompleteReasons  []string       `json:"incomplete_reasons"`
}

// File is one successfully hashed regular file.
type File struct {
	Path        string `json:"path"`
	PathEscaped bool   `json:"path_escaped,omitempty"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

// Match is an indicator match.
type Match struct {
	Path        string `json:"path"`
	PathEscaped bool   `json:"path_escaped,omitempty"`
	SHA256      string `json:"sha256"`
	Label       string `json:"label"`
	raw         string
}

// Finding is a heuristic lead.
type Finding struct {
	Path        string `json:"path"`
	PathEscaped bool   `json:"path_escaped,omitempty"`
	Rule        string `json:"rule"`
	Kind        string `json:"kind"` // always "lead"
	Explanation string `json:"explanation"`
	Evidence    string `json:"evidence"`
	raw         string
}

// Skip is an entry that was not (fully) examined.
type Skip struct {
	Path                string `json:"path"`
	PathEscaped         bool   `json:"path_escaped,omitempty"`
	Reason              string `json:"reason"`
	Detail              string `json:"detail"`
	AffectsCompleteness bool   `json:"affects_completeness"`
	raw                 string
}

// New creates an empty report.
func New(toolVersion, root string, limits Limits, maxSkipRecords int) *Report {
	r := &Report{
		Schema:        SchemaName,
		SchemaVersion: SchemaVersion,
		ToolVersion:   toolVersion,
		Limits:        limits,
		Matches:       []Match{},
		Findings:      []Finding{},
		Skipped:       []Skip{},
		Files:         []File{},
		Notes:         []string{},
		rawRoot:       root,
		skipCounts:    map[string]int{},
		incomplete:    map[string]bool{},
		maxSkipRecord: maxSkipRecords,
	}
	r.Root, r.RootEscaped = EncodePath(root)
	return r
}

// SetIndicators records indicator provenance.
func (r *Report) SetIndicators(path string, records int, sha256Hex string) {
	info := &IndicatorInfo{FormatVersion: 1, Records: records, SHA256: sha256Hex, rawPath: path}
	info.Path, info.PathEscaped = EncodePath(path)
	r.Indicators = info
}

// AddFile records a hashed file.
func (r *Report) AddFile(path string, size int64, sha string) {
	f := File{Size: size, SHA256: sha}
	f.Path, f.PathEscaped = EncodePath(path)
	r.Files = append(r.Files, f)
	r.Summary.FilesHashed++
	r.Summary.BytesHashed += size
}

// AddMatch records an indicator match.
func (r *Report) AddMatch(path, sha, label string) {
	m := Match{SHA256: sha, Label: label, raw: path}
	m.Path, m.PathEscaped = EncodePath(path)
	r.Matches = append(r.Matches, m)
}

// AddFinding records a heuristic lead.
func (r *Report) AddFinding(path, rule, explanation, evidence string) {
	f := Finding{Rule: rule, Kind: "lead", Explanation: explanation, Evidence: evidence, raw: path}
	f.Path, f.PathEscaped = EncodePath(path)
	r.Findings = append(r.Findings, f)
}

// AddSkip records an entry that was not examined. Records beyond the
// configured cap are counted but not stored, bounding memory.
func (r *Report) AddSkip(path, reason, detail string, affectsCompleteness bool) {
	r.skipCounts[reason]++
	if affectsCompleteness {
		r.incomplete[reason] = true
	}
	if len(r.Skipped) >= r.maxSkipRecord {
		r.Summary.SkipRecordsOmitted++
		return
	}
	s := Skip{Reason: reason, Detail: detail, AffectsCompleteness: affectsCompleteness, raw: path}
	s.Path, s.PathEscaped = EncodePath(path)
	r.Skipped = append(r.Skipped, s)
}

// AddNote appends a human-readable note.
func (r *Report) AddNote(n string) { r.Notes = append(r.Notes, n) }

// Finalize computes status and summary. Call once, after scanning.
func (r *Report) Finalize(examined int64) {
	r.Summary.EntriesExamined = examined
	r.Summary.IndicatorMatches = len(r.Matches)
	r.Summary.HeuristicFindings = len(r.Findings)
	r.Summary.SkippedByReason = r.skipCounts
	r.Summary.Skipped = 0
	for _, n := range r.skipCounts {
		r.Summary.Skipped += n
	}
	r.Summary.IncompleteReasons = make([]string, 0, len(r.incomplete))
	for reason := range r.incomplete {
		r.Summary.IncompleteReasons = append(r.Summary.IncompleteReasons, reason)
	}
	sort.Strings(r.Summary.IncompleteReasons)
	r.Complete = len(r.incomplete) == 0
	switch {
	case len(r.Matches) > 0:
		r.Status = StatusMatch
	case !r.Complete:
		r.Status = StatusIncomplete
	default:
		r.Status = StatusNoMatches
	}
	if r.Indicators == nil {
		r.AddNote("No indicator file was loaded, so no indicator matching was performed; NO_MATCHES_FOUND is vacuous.")
	} else if r.Indicators.Records == 0 {
		r.AddNote("The indicator file contains no records, so no file can match; NO_MATCHES_FOUND is vacuous.")
	}
	if r.Status == StatusMatch && !r.Complete {
		r.AddNote("The scan was also incomplete: files that were not examined may match too.")
	}
	r.AddNote(StatusMeaning(r.Status))
	r.AddNote("Heuristic findings are leads for review, not malware verdicts.")
}

// StatusMeaning explains a status in one sentence.
func StatusMeaning(s Status) string {
	switch s {
	case StatusMatch:
		return "MATCH_FOUND: at least one file's SHA-256 is listed in the indicator file. This is an indicator match, not proof that the file is malicious."
	case StatusIncomplete:
		return "SCAN_INCOMPLETE: some content could not be examined and no indicator matched in what was examined. Nothing can be concluded about unexamined content."
	default:
		return "NO_MATCHES_FOUND: no examined file's SHA-256 is listed in the indicator file. This does not mean the files are clean or safe."
	}
}

// WriteJSON writes the report as indented JSON with a trailing newline.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// WriteText writes a human-readable report. Every attacker-controlled string
// (paths, labels) passes through SafeText.
func (r *Report) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "filewatch %s: local indicator and heuristic triage (not an antivirus)\n", r.ToolVersion)
	fmt.Fprintf(&b, "Root:        %s\n", SafeText(r.rawRoot))
	if r.Indicators != nil {
		fmt.Fprintf(&b, "Indicators:  %s (%d records, sha256 %s)\n", SafeText(r.Indicators.rawPath), r.Indicators.Records, r.Indicators.SHA256)
	} else {
		b.WriteString("Indicators:  none loaded\n")
	}
	fmt.Fprintf(&b, "Status:      %s\n", r.Status)

	if len(r.Matches) > 0 {
		fmt.Fprintf(&b, "\nIndicator matches (%d):\n", len(r.Matches))
		for _, m := range r.Matches {
			label := m.Label
			if label == "" {
				label = "(no label)"
			}
			fmt.Fprintf(&b, "  %s\n    sha256 %s  label: %s\n", SafeText(m.raw), m.SHA256, SafeText(label))
		}
	}
	if len(r.Findings) > 0 {
		fmt.Fprintf(&b, "\nHeuristic leads (%d), for review; not verdicts:\n", len(r.Findings))
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "  %s  [%s]\n    %s\n    evidence: %s\n", SafeText(f.raw), f.Rule, f.Explanation, f.Evidence)
		}
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(&b, "\nSkipped (%d):\n", r.Summary.Skipped)
		for _, s := range r.Skipped {
			mark := ""
			if s.AffectsCompleteness {
				mark = " *"
			}
			fmt.Fprintf(&b, "  %s  %s%s: %s\n", SafeText(s.raw), s.Reason, mark, s.Detail)
		}
		if r.Summary.SkipRecordsOmitted > 0 {
			fmt.Fprintf(&b, "  ... %d more skip records omitted\n", r.Summary.SkipRecordsOmitted)
		}
		if !r.Complete {
			b.WriteString("  (* = makes the scan incomplete)\n")
		}
	}
	fmt.Fprintf(&b, "\nSummary: %d entries examined, %d files hashed (%d bytes), %d indicator matches, %d heuristic leads, %d skipped\n",
		r.Summary.EntriesExamined, r.Summary.FilesHashed, r.Summary.BytesHashed,
		r.Summary.IndicatorMatches, r.Summary.HeuristicFindings, r.Summary.Skipped)
	if !r.Complete {
		fmt.Fprintf(&b, "Incomplete because: %s\n", strings.Join(r.Summary.IncompleteReasons, ", "))
	}
	b.WriteString("\n")
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "Note: %s\n", n)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// SafeText returns s unchanged if it is valid UTF-8 made only of printable
// characters; otherwise a Go-quoted form in which control characters,
// bidirectional overrides and invalid bytes are visibly escaped. This keeps
// attacker-chosen names from forging terminal output.
func SafeText(s string) string {
	if utf8.ValidString(s) {
		ok := true
		for _, r := range s {
			if !strconv.IsPrint(r) {
				ok = false
				break
			}
		}
		if ok && !strings.HasPrefix(s, `"`) {
			return s
		}
	}
	return strconv.Quote(s)
}

// EncodePath prepares a path for JSON. Valid UTF-8 is emitted as-is (the JSON
// encoder escapes control characters). Invalid UTF-8, which JSON cannot carry
// losslessly, is emitted as a Go-quoted string literal with escaped=true;
// recover the original bytes with strconv.Unquote.
func EncodePath(p string) (encoded string, escaped bool) {
	if utf8.ValidString(p) {
		return p, false
	}
	return strconv.Quote(p), true
}
