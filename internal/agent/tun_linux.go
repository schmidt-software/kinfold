//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTun    = 0x0001
	iffNoPI   = 0x1000
	// iffTunExcl makes TUNSETIFF fail if the interface already exists, so
	// the kernel, not a racy name lookup, guarantees a fresh device
	// (review A-09).
	iffTunExcl = 0x8000
)

// ipCandidates are the only locations the root client executes `ip` from;
// PATH is not consulted (review A-08).
var ipCandidates = []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"}

const ipCommandTimeout = 10 * time.Second

func findIP(candidates []string) (string, error) {
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("ip command not found in %s", strings.Join(candidates, ", "))
}

func runIP(ctx context.Context, ipPath string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, ipCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ipPath, args...)
	cmd.Env = []string{"LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %w: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func OpenTunnel(name string, addresses []string) (io.ReadWriteCloser, error) {
	if len(name) == 0 || len(name) >= 16 {
		return nil, fmt.Errorf("interface name must be 1-15 bytes")
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, fmt.Errorf("interface %q already exists", name)
	}
	ipPath, err := findIP(ipCandidates)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var ifreq [40]byte
	copy(ifreq[:16], name)
	*(*uint16)(unsafe.Pointer(&ifreq[16])) = iffTun | iffNoPI | iffTunExcl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIFF, uintptr(unsafe.Pointer(&ifreq[0])))
	if errno != 0 {
		syscall.Close(fd)
		if errno == syscall.EBUSY || errno == syscall.EEXIST {
			return nil, fmt.Errorf("interface %q already exists: %w", name, errno)
		}
		return nil, fmt.Errorf("create TUN: %w", errno)
	}
	// Register the descriptor with Go's poller only after TUNSETIFF makes it pollable.
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	disableDAD(name)
	ctx := context.Background()
	for _, address := range addresses {
		if err := runIP(ctx, ipPath, "address", "add", address, "dev", name); err != nil {
			f.Close()
			return nil, err
		}
	}
	if err := runIP(ctx, ipPath, "link", "set", "dev", name, "mtu", strconv.Itoa(tunnelMTU), "up"); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// disableDAD turns off duplicate address detection on the new interface.
// Addresses are assigned exclusively by the controller, and DAD would keep a
// new ULA tentative for about a second after every tunnel (re)start
// (review A-10). Failure is not fatal: containers often mount /proc/sys
// read-only, and the address then just becomes usable after DAD.
func disableDAD(name string) {
	path := "/proc/sys/net/ipv6/conf/" + name + "/accept_dad"
	if err := os.WriteFile(path, []byte("0"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Debug("could not disable IPv6 duplicate address detection", "interface", name, "error", err)
	}
}
