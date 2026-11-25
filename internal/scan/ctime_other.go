//go:build !linux && !darwin

package scan

import "io/fs"

// ctimeEqual is unavailable here; size, mtime and identity checks still apply.
func ctimeEqual(a, b fs.FileInfo) bool { return true }
