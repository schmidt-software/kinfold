//go:build darwin

package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// macOS client tunnel (D-029): a utun interface opened through the kernel
// control socket "com.apple.net.utun_control", using only package syscall.
// The kernel chooses the interface name (utunN); the name requested by the
// caller is ignored. Every packet carries a 4-byte address family header.

const (
	afSystem        = 32         // AF_SYSTEM
	sysprotoControl = 2          // SYSPROTO_CONTROL
	afSysControl    = 2          // AF_SYS_CONTROL
	ctlIOCGInfo     = 0xc0644e03 // CTLIOCGINFO
	utunOptIfname   = 2          // UTUN_OPT_IFNAME
	utunControlName = "com.apple.net.utun_control"
	darwinAFInet6   = 30
)

type ctlInfo struct {
	id   uint32
	name [96]byte
}

type sockaddrCtl struct {
	len      uint8
	family   uint8
	sysaddr  uint16
	id       uint32
	unit     uint32
	reserved [5]uint32
}

// darwinCommands are the only places the client executes ifconfig and route
// from; PATH is not consulted.
var darwinCommands = map[string]string{"ifconfig": "/sbin/ifconfig", "route": "/sbin/route"}

func runDarwin(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ipCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, darwinCommands[name], args...)
	cmd.Env = []string{"LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

const ipCommandTimeout = 10 * time.Second

// OpenTunnel creates a utun interface with the given addresses (CIDR).
func OpenTunnel(_ string, addresses []string) (io.ReadWriteCloser, error) {
	fd, err := syscall.Socket(afSystem, syscall.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("open utun control socket: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			syscall.Close(fd)
		}
	}()
	var info ctlInfo
	copy(info.name[:], utunControlName)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ctlIOCGInfo, uintptr(unsafe.Pointer(&info))); errno != 0 {
		return nil, fmt.Errorf("look up utun control: %w", errno)
	}
	addr := sockaddrCtl{len: uint8(unsafe.Sizeof(sockaddrCtl{})), family: afSystem, sysaddr: afSysControl, id: info.id, unit: 0}
	if _, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Sizeof(addr))); errno != 0 {
		return nil, fmt.Errorf("create utun interface (root required): %w", errno)
	}
	var nameBuf [32]byte
	nameLen := uint32(len(nameBuf))
	if _, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), sysprotoControl, utunOptIfname, uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)), 0); errno != 0 {
		return nil, fmt.Errorf("read utun interface name: %w", errno)
	}
	ifname := strings.TrimRight(string(nameBuf[:nameLen]), "\x00")
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return nil, err
		}
		ip := prefix.Addr().String()
		if prefix.Addr().Is4() {
			if err := runDarwin("ifconfig", ifname, "inet", ip, ip, "netmask", netmaskString(prefix.Bits()), "mtu", strconv.Itoa(tunnelMTU), "up"); err != nil {
				return nil, err
			}
			if err := runDarwin("route", "-q", "-n", "add", "-net", prefix.Masked().String(), "-interface", ifname); err != nil {
				return nil, err
			}
		} else {
			if err := runDarwin("ifconfig", ifname, "inet6", ip, "prefixlen", strconv.Itoa(prefix.Bits()), "up"); err != nil {
				return nil, err
			}
			if err := runDarwin("route", "-q", "-n", "add", "-inet6", prefix.Masked().String(), "-interface", ifname); err != nil {
				return nil, err
			}
		}
	}
	ok = true
	slog.Info("utun interface created", "interface", ifname, "addresses", addresses)
	return &utun{File: os.NewFile(uintptr(fd), ifname), name: ifname}, nil
}

func netmaskString(bits int) string {
	m := ^uint32(0) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d", m>>24, m>>16&0xff, m>>8&0xff, m&0xff)
}

// utun adds and strips the 4-byte address family header of utun packets.
type utun struct {
	*os.File
	name string
	rbuf [4 + 65535]byte
	wbuf [4 + 65535]byte
}

func (u *utun) Read(p []byte) (int, error) {
	n, err := u.File.Read(u.rbuf[:])
	if err != nil {
		return 0, err
	}
	return stripFamily(u.rbuf[:n], p)
}

func (u *utun) Write(p []byte) (int, error) {
	frame, err := addFamily(u.wbuf[:0], p)
	if err != nil {
		return 0, err
	}
	n, err := u.File.Write(frame)
	if n >= 4 {
		n -= 4
	} else {
		n = 0
	}
	return n, err
}

// stripFamily removes the utun header without looking at the family: the
// agent validates every packet's IP version and addresses itself. Frames
// shorter than the header become zero-length reads, which the agent ignores.
func stripFamily(frame, p []byte) (int, error) {
	if len(frame) < 4 {
		return 0, nil
	}
	return copy(p, frame[4:]), nil
}

func addFamily(dst, packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, fmt.Errorf("empty packet")
	}
	var family uint32
	switch packet[0] >> 4 {
	case 4:
		family = syscall.AF_INET
	case 6:
		family = darwinAFInet6
	default:
		return nil, fmt.Errorf("not an IP packet")
	}
	dst = binary.BigEndian.AppendUint32(dst, family)
	return append(dst, packet...), nil
}
