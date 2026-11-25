// Command filewatch is a conservative local file triage scanner.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Aolost/filewatch/internal/cli"
)

func main() {
	// Ctrl-C or SIGTERM stops the scan; a partial report with status
	// SCAN_INCOMPLETE is still written.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
