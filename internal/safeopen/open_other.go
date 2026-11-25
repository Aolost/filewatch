//go:build !unix

package safeopen

import "os"

func openFile(path string) (*os.File, error) { return os.OpenFile(path, os.O_RDONLY, 0) }

func openInRoot(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY, 0)
}
