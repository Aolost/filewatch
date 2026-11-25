//go:build darwin

package scan

import (
	"io/fs"
	"syscall"
)

// ctimeEqual compares inode change times; see ctime_linux.go.
func ctimeEqual(a, b fs.FileInfo) bool {
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return true
	}
	return sa.Ctimespec == sb.Ctimespec
}
