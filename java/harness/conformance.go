package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/nnicora/cipheron/conformance"
)

// runConformance runs every case of the kit on the adapter args names (after an optional "--") and fails unless
// every case passed: the Java library answers no kind unsupported.
func runConformance(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return errors.New("usage: harness conformance -- <adapter argv>")
	}
	suite, err := conformance.Load()
	if err != nil {
		return err
	}
	p, err := conformance.Exec(ctx, os.Stderr, args...)
	if err != nil {
		return err
	}
	report, runErr := conformance.Run(ctx, p, suite)
	closeErr := p.Close()
	if runErr != nil {
		return runErr
	}
	fmt.Print(report.String())
	switch {
	case !report.OK():
		return fmt.Errorf("%d of %d cases failed", report.Failed, report.Passed+report.Failed)
	case report.Unsupported > 0:
		return fmt.Errorf("%d cases were answered unsupported; the Java library implements every kind",
			report.Unsupported)
	}
	if closeErr != nil {
		return fmt.Errorf("the adapter did not exit cleanly: %w", closeErr)
	}
	return nil
}
