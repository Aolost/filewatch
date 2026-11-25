//go:build unix

package scan

import (
	"context"
	"github.com/Aolost/filewatch/internal/report"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSpecialFilesSkippedWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a.txt": "a"})
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("", "fws") // short path for sun_path limits
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	var haveSock bool
	if l, err := net.Listen("unix", filepath.Join(sockDir, "s")); err == nil {
		defer l.Close()
		if err := os.Rename(filepath.Join(sockDir, "s"), filepath.Join(root, "sock")); err == nil {
			haveSock = true
		}
	}
	done := make(chan *report.Report, 1)
	go func() { r, _ := Run(context.Background(), root, DefaultOptions()); done <- r }()
	select {
	case rep := <-done:
		r := reasons(rep)
		if r["fifo"] != report.ReasonNotRegular || (haveSock && r["sock"] != report.ReasonNotRegular) {
			t.Fatalf("reasons %v", r)
		}
		if !rep.Complete {
			t.Fatal("special-file skips should not make the scan incomplete")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("scan blocked on a special file")
	}
}

func TestRaceFileSwappedForFIFODoesNotBlock(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"victim.txt": "harmless"})
	opts := DefaultOptions()
	opts.hooks = &testHooks{afterLstat: func(rel string) {
		p := filepath.Join(root, rel)
		os.Remove(p)
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Error(err)
		}
	}}
	done := make(chan *report.Report, 1)
	go func() { r, _ := Run(context.Background(), root, opts); done <- r }()
	select {
	case rep := <-done:
		if reasons(rep)["victim.txt"] != report.ReasonChanged {
			t.Fatalf("reasons %v", reasons(rep))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("scan blocked opening a swapped-in FIFO")
	}
}
