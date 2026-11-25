//go:build linux

package safeopen

import (
	"errors"
	"os"
	"syscall"
)

// O_NONBLOCK keeps a FIFO swapped in mid-scan from blocking the open.
// O_NOATIME avoids touching access times; it is only permitted for the file
// owner (or CAP_FOWNER), so fall back without it on EPERM.
const (
	baseFlags   = os.O_RDONLY | syscall.O_NONBLOCK
	noatimeFlag = syscall.O_NOATIME
)

func openFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, baseFlags|noatimeFlag, 0)
	if errors.Is(err, syscall.EPERM) {
		f, err = os.OpenFile(path, baseFlags, 0)
	}
	return f, err
}

func openInRoot(root *os.Root, name string) (*os.File, error) {
	f, err := root.OpenFile(name, baseFlags|noatimeFlag, 0)
	if errors.Is(err, syscall.EPERM) {
		f, err = root.OpenFile(name, baseFlags, 0)
	}
	return f, err
}
