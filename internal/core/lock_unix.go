//go:build linux || darwin

package core

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// LockState serializes cooperating CLI writers. The lock file must not be removed.
func LockState(dir string) (*os.File, error) {
	path := filepath.Join(dir, ".state.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("controller state is locked by another writer: %w", err)
	}
	return f, nil
}
