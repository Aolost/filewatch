//go:build unix && !linux

package safeopen

import (
	"os"
	"syscall"
)

const baseFlags = os.O_RDONLY | syscall.O_NONBLOCK

func openFile(path string) (*os.File, error) { return os.OpenFile(path, baseFlags, 0) }

func openInRoot(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, baseFlags, 0)
}
