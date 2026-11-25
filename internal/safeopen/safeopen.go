// Package safeopen opens files read-only in ways that cannot block on FIFOs,
// do not update access times where the platform allows, and never create or
// truncate anything.
package safeopen

import (
	"errors"
	"os"
)

// ErrNotRegular is returned when an opened path is not a regular file.
var ErrNotRegular = errors.New("not a regular file")

// File opens path read-only and verifies, via fstat on the open descriptor,
// that it is a regular file. It is used for user-chosen inputs such as the
// indicator file, where following a symlink named by the user is expected.
func File(path string) (*os.File, os.FileInfo, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, ErrNotRegular
	}
	return f, fi, nil
}

// InRoot opens name read-only beneath root. os.Root guarantees the result is
// inside the root even if path components are swapped concurrently. Callers
// must still fstat the result: os.Root follows in-root symlinks.
func InRoot(root *os.Root, name string) (*os.File, error) {
	return openInRoot(root, name)
}
