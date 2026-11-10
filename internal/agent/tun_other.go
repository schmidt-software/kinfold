//go:build !linux && !darwin

package agent

import (
	"errors"
	"io"
)

func OpenTunnel(name string, addresses []string) (io.ReadWriteCloser, error) {
	return nil, errors.New("TUN client is supported only on Linux and macOS")
}
