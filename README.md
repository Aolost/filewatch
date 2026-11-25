# filewatch

A conservative, local, read-only file triage scanner.

filewatch walks the files and directories you name and computes the SHA-256 of
every regular file. It reports any file whose digest appears in **your own
local indicator file**, plus a few transparent structural heuristics.

**filewatch is not an antivirus.** It never says a file is clean or safe, and
it cannot tell you a file is malicious. It answers one narrow question: "do any
of these files have exactly the bytes of something on my list?" It also points
out a few structural oddities worth a human look.

```bash
go install github.com/Aolost/filewatch/cmd/filewatch@v0.1.1
```

Or build from a checkout:

```bash
go build -o bin/filewatch ./cmd/filewatch
```

```bash
bin/filewatch scan ~/Downloads --indicators my-indicators.txt
```

```bash
bin/filewatch scan ~/Downloads --indicators my-indicators.txt --json > report.json
```

## Statuses and exit codes

| Exit | Status             | Meaning |
|-----:|--------------------|---------|
| 0    | `NO_MATCHES_FOUND` | Every file the scan examined was hashed, and none of the digests is in the indicator file. **This does not mean the files are clean or safe.** It only means none of them is a byte-for-byte copy of a listed item. If no indicator file was loaded, or the file has no records, the result is vacuous, and the report says so in `notes`. |
| 1    | `MATCH_FOUND`      | At least one file's SHA-256 is in the indicator file. **This is an indicator match, not proof of maliciousness.** It is only as accurate as the list, which may contain mistakes or harmless files. If the scan was also incomplete, `complete` is `false` and a note says unexamined files may match too. |
| 3    | `SCAN_INCOMPLETE`  | Some content could not be examined, and nothing that was examined matched. Causes include a limit being reached, a permission or read error, a file changing mid-read, a timeout, or an interruption. Nothing can be concluded about the unexamined content. `summary.incomplete_reasons` and the `skipped` records say what was missed and why. |
| 2    | *(none)*           | Usage error, or a fatal error before scanning: bad flags, a missing path, an invalid indicator file. A message goes to stderr and no report is written. |

`MATCH_FOUND` takes precedence over `SCAN_INCOMPLETE`, because a confirmed
indicator match is the more actionable fact. Interrupting the scan (Ctrl-C or
SIGTERM) still writes a partial report with status `SCAN_INCOMPLETE`.

## Detection model

### Indicator matching (the only thing that sets `MATCH_FOUND`)

An indicator is a SHA-256 digest you supply. A file matches when its full
contents hash to a listed digest.

* **False negatives are expected and common.** Changing a single byte of a file
  changes its hash, and that includes re-packing, re-signing, appending data,
  or recompressing. Content you have no indicator for is never detected.
  Archives are not unpacked, so a listed file inside a `.zip` will not match.
  Files skipped by a limit, by a permission error, or as symlinks or special
  files are not checked.
* **False positives come from the list.** If the list contains a common
  harmless file, every copy matches. The empty-file digest
  (`e3b0c442…b855`) is the classic example. filewatch adds no false positives
  of its own: SHA-256 collisions are not a practical concern.

### Heuristics (leads only; they never change the status)

Each finding names its rule, explains why it fired, and gives the evidence:
header bytes or name parts, never file contents. Every rule fires on plenty of
legitimate files.

| Rule | Fires when | Typical false positives | Typical false negatives |
|------|-----------|-------------------------|-------------------------|
| `executable-header` | The content starts with an ELF, PE (an `MZ` header plus a `PE\0\0` signature within the first 512 bytes) or Mach-O header, or with `#!` | Every program, library and script | Programs in archives or installers; PE files whose header lies beyond byte 512 |
| `double-extension` | The name ends in a document or media extension followed by an executable one, e.g. `invoice.pdf.exe` | Deliberately named tools and test files | Any name not on the built-in extension lists |
| `extension-mismatch` | Native executable content behind a document or media extension, e.g. ELF bytes in `photo.jpg` | Rare; misnamed downloads | Scripts, and any extension not on the list |
| `deceptive-name-characters` | The name contains Unicode bidirectional control characters (U+202A–U+202E, U+2066–U+2069, U+200E, U+200F, U+061C) | Legitimate right-to-left file names | Look-alike characters (homoglyphs) |

## Indicator file format (version 1)

The file is UTF-8 text with LF or CRLF line endings. The first line must be the
header, exactly as shown below:

```text
filewatch-indicators v1
# Comments start with '#' in column 1. Blank lines are ignored.
sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 Optional label text
```

* Records are `sha256:` followed by exactly 64 hex digits (any case). An
  optional label can follow after a space or tab.
* Labels can be up to 200 bytes of printable characters. Control and
  bidirectional-override characters are rejected, because labels are printed
  in reports.
* Limits: 64 MiB per file, 1024 bytes per line, 1,000,000 records.
* **Every record is validated, and one bad record rejects the whole file**
  (exit 2). Duplicate digests are rejected. Error messages give the line
  number but never echo the offending content.
* The file is read only from local disk, never from the network. Its own
  SHA-256 is recorded in the report (`indicators.sha256`) so you can tell
  which list produced a result.

See [testdata/indicators.example.txt](testdata/indicators.example.txt).

## Command line

```text
filewatch scan PATH [--indicators FILE] [--json] [limits]
filewatch version
filewatch help
```

Flags may come before or after `PATH`. Put `--` before a path that starts with
`-`.

| Flag | Default | Meaning |
|------|---------|---------|
| `--indicators FILE` | none | Local indicator file |
| `--json` | off | Write the JSON report to stdout instead of text |
| `--max-files N` | 100000 | Maximum directory entries examined. Every entry counts: files, directories, links, special files |
| `--max-bytes SIZE` | 4GiB | Maximum total bytes read. The scan stops when the next file would exceed it |
| `--max-file-bytes SIZE` | 1GiB | Larger files are skipped without being read |
| `--max-depth N` | 64 | Maximum directory levels below `PATH` |
| `--timeout DURATION` | 10m | Maximum runtime (`0` means no limit) |

`SIZE` is a byte count with an optional `K`/`M`/`G` (or `KiB`/`MiB`/`GiB`)
suffix, in binary units. A directory with more than 100,000 entries is skipped
as a whole. At most 10,000 skip records are stored; the counts in `summary`
always include all of them.

## JSON report (schema version 1)

The top-level keys are always present, and arrays are `[]`, never `null`.
Within `schema_version: 1`, fields may be added but are never renamed or
removed. Output is deterministic for an unchanged tree: entries are sorted by
name and there are no timestamps.

```text
schema            "filewatch.report"
schema_version    1
tool_version      "0.1.1"
status            NO_MATCHES_FOUND | MATCH_FOUND | SCAN_INCOMPLETE
complete          bool: false if anything that affects completeness was skipped
root              absolute path that was scanned
indicators        null | {path, format_version, records, sha256}
limits            {max_files, max_total_bytes, max_file_bytes, max_depth,
                   max_dir_entries, timeout_seconds, symlinks: "not_followed"}
summary           {entries_examined, files_hashed, bytes_hashed, indicator_matches,
                   heuristic_findings, skipped, skipped_by_reason{}, skip_records_omitted,
                   incomplete_reasons[]}
matches[]         {path, sha256, label}
heuristic_findings[] {path, rule, kind: "lead", explanation, evidence}
skipped[]         {path, reason, detail, affects_completeness}
files[]           {path, size, sha256}: every file that was fully hashed
notes[]           human-readable caveats
```

Paths are relative to the root and use `/` separators. A path that is not
valid UTF-8 cannot be carried losslessly in JSON. It is emitted as a Go-quoted
string literal with `"path_escaped": true`; decode it with `strconv.Unquote`
or an equivalent. In text output, any name containing control characters,
bidi controls or invalid bytes is shown quoted and escaped, so a file name
cannot forge or hide report lines.

The skip reasons are `symlink_not_followed` and `not_regular_file` (policy
skips that do not affect completeness), plus `permission_denied`, `read_error`,
`vanished`, `changed_during_scan`, `outside_root`, `file_too_large`,
`depth_limit`, `directory_too_large`, `file_limit`, `byte_limit`, `time_limit`,
`interrupted` and `root_not_scannable`, all of which make the scan incomplete.
An example report is in
[internal/cli/testdata/report.golden.json](internal/cli/testdata/report.golden.json).

## Safety properties

* **Read-only.** filewatch never writes, renames, deletes, quarantines,
  extracts or executes scanned content. On Linux it opens files with
  `O_NOATIME` when permitted, so even access times are left alone. The tests
  snapshot their fixtures and check that a scan leaves every byte and
  timestamp unchanged.
* **Confined to the root.** All access goes through Go's `os.Root`
  (openat-based on Unix), so no path can resolve outside the chosen root, even
  if a directory is swapped for a symlink mid-scan.
* **No symlinks followed.** Symlinks are reported as skipped and never
  followed. There is deliberately no option to follow them. If the scan path
  itself is a symlink, the scan reports `SCAN_INCOMPLETE`; pass the real path
  instead.
* **Only regular files are opened.** FIFOs, sockets and devices are reported
  and never opened. Each opened descriptor is checked with `fstat`. If its
  identity differs from what the directory listing showed (a swapped file or
  symlink), the entry is skipped as `changed_during_scan`. Opening uses
  `O_NONBLOCK`, so a FIFO swapped in mid-scan cannot hang the scan.
* **Metadata from the open file only.** Size limits and change detection use
  `fstat` on the open descriptor, never the directory listing. A file is
  marked `changed_during_scan` and its digest discarded if its size, mtime or
  ctime (Linux and macOS) changes while it is read, or if the bytes read
  differ from its size.
* **Bounded resources.** Limits cover entries, total bytes, bytes per file,
  depth, entries per directory, runtime and stored skip records. Hashing
  streams through a 64 KiB buffer, with only the first 512 bytes kept for
  heuristics. Memory grows only with the number of files listed in the
  report, which is capped by `--max-files`.
* **Nothing leaves the machine.** filewatch makes no network access, collects
  no telemetry and never asks for privileges. It has no dependencies beyond
  the Go standard library. Errors and reports never include file contents.

### Platform notes

* **Linux and macOS** are the primary platforms. ctime change detection is
  available on Linux and macOS only; elsewhere filewatch relies on size,
  mtime and file identity.
* **Windows** builds and its tests run in CI, but symlink and special-file
  coverage there is reduced. `os.Root` also refuses reserved device names
  such as `NUL`.
* **Remaining limits.** `os.Root` does not stop traversal across mount points,
  bind mounts or `/proc`. Avoid scanning `/proc`, `/sys` or `/dev`: the
  entries there are not regular files, and some report sizes that do not
  match their contents (they show up as `changed_during_scan`). A process with
  write access can still change a file between the final `fstat` and the
  report being written; the result reflects the bytes that were actually read.
* **Go version.** filewatch requires Go 1.24 or newer, the first release with
  `os.Root`.

## Development

```bash
make check
```

`make check` runs gofmt, `go vet`, then `go test -race`. The tests include a
repository check (`internal/repocheck`) that rejects raw bidi characters in
sources and any executable-looking file in the repo. After that it runs each fuzz target for `FUZZTIME` (10s by
default). The fuzz targets are the indicator parser, the name heuristics,
output escaping, and scanning a file with a fuzzed name. Everything runs
offline (`GOPROXY=off`, `GOTOOLCHAIN=local`). If Go is managed by mise and has
no global version:

```bash
mise x go@1.24 -- make check
```

All test fixtures are harmless, generated at test time in temporary
directories, with known digests such as `sha256("abc")`. The repository
contains no malware, exploit code or live samples. The PE, ELF and Mach-O
"headers" used in heuristic tests are a few signature bytes in otherwise empty
buffers, built in memory.

To regenerate the golden JSON after an intentional schema addition:

```bash
go test ./internal/cli -update
```

## Licence

[MIT](LICENSE) © 2026 Skepta.
