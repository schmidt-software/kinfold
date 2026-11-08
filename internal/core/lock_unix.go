//go:build linux || darwin

package core

import (
	"fmt"
	"os"
	"syscall"
)

// LockState serializes cooperating CLI writers by locking the data directory
// itself. Unlike a separate lock file, the directory cannot be deleted while
// a writer holds it without also deleting the state (review C-06).
func LockState(dir string) (*os.File, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open state directory for locking: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrStateLocked, err)
	}
	return f, nil
}
