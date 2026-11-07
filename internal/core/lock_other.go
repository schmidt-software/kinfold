//go:build !linux && !darwin

package core

import (
	"errors"
	"os"
)

func LockState(dir string) (*os.File, error) {
	return nil, errors.New("controller state locking is supported only on Linux and macOS")
}
