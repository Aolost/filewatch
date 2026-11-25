//go:build unix

package indicators

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestLoadFIFODoesNotBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("FIFO accepted as indicator file")
	}
}
