//go:build linux

package agent

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const tunSetIFF = 0x400454ca
const iffTun = 0x0001
const iffNoPI = 0x1000

func OpenTunnel(name string, addresses []string) (io.ReadWriteCloser, error) {
	if len(name) == 0 || len(name) >= 16 {
		return nil, fmt.Errorf("interface name must be 1-15 bytes")
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, fmt.Errorf("interface %q already exists", name)
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var ifreq [40]byte
	copy(ifreq[:16], name)
	*(*uint16)(unsafe.Pointer(&ifreq[16])) = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIFF, uintptr(unsafe.Pointer(&ifreq[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("create TUN: %w", errno)
	}
	// Register the descriptor with Go's poller only after TUNSETIFF makes it pollable.
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	commands := make([][]string, 0, len(addresses)+1)
	for _, address := range addresses {
		commands = append(commands, []string{"address", "add", address, "dev", name})
	}
	commands = append(commands, []string{"link", "set", "dev", name, "mtu", strconv.Itoa(tunnelMTU), "up"})
	for _, args := range commands {
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("ip %v: %w: %s", args, err, out)
		}
	}
	return f, nil
}
