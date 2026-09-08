//go:build !linux

package ppforward

import (
	"fmt"
	"os"
)

// AcquireLock prevents multiple pp-forward daemons from running at once.
func AcquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o644)
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return f, nil
}
