// Command harness is the Java client library's test harness: it holds a client written in another language to what
// the Go side of this repository defines.
//
//	harness conformance -- <adapter argv>
//
// runs the conformance kit (spec/vectors) on an adapter program — the Java library's ConformanceAdapter — through
// conformance.Exec and conformance.Run, prints the report, and exits 1 unless every case passed (no kind answered
// unsupported: the Java library implements every kind).
//
//	harness fake
//
// serves cipherontest's fake cipheron for the Java library's integration tests (fake.go).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: harness conformance -- <adapter argv> | harness fake [flags]")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "conformance":
		return runConformance(ctx, args[1:])
	case "fake":
		return runFake(ctx, args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}
