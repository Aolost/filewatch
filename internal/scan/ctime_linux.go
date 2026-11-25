//go:build linux

package scan

import (
	"io/fs"
	"syscall"
)

// ctimeEqual compares inode change times. Unlike mtime, ctime cannot be set
// back by an unprivileged writer, so it catches "write then restore mtime".
func ctimeEqual(a, b fs.FileInfo) bool {
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return true
	}
	return sa.Ctim == sb.Ctim
}
