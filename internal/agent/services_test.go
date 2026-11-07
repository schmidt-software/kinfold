package agent

import (
	"encoding/binary"
	"testing"

	"my-zerotier/internal/core"
)

func serviceTestPacket(v6 bool, protocol byte, port uint16) []byte {
	var packet []byte
	offset := 20
	if v6 {
		packet = make([]byte, 40)
		packet[0], packet[6] = 0x60, protocol
		offset = 40
	} else {
		packet = make([]byte, 20)
		packet[0], packet[9] = 0x45, protocol
	}
	switch protocol {
	case 6:
		packet = append(packet, make([]byte, 20)...)
		packet[offset+12] = 0x50
	case 17:
		packet = append(packet, make([]byte, 8)...)
		binary.BigEndian.PutUint16(packet[offset+4:], 8)
	default:
		packet = append(packet, make([]byte, 4)...)
	}
	binary.BigEndian.PutUint16(packet[offset+2:], port)
	if v6 {
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	} else {
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	}
	return packet
}

func TestServicePacketFiltering(t *testing.T) {
	rules := compileServices([]core.ServiceRule{{Protocol: "tcp", Port: 443}, {Protocol: "udp", Port: 53}, {Protocol: "icmp"}, {Protocol: "icmp6"}}, "", "")
	for _, v6 := range []bool{false, true} {
		for _, tc := range []struct {
			proto byte
			port  uint16
			want  bool
		}{{6, 443, true}, {6, 22, false}, {17, 53, true}, {17, 443, false}, {1, 0, !v6}, {58, 0, v6}, {44, 0, false}} {
			p := serviceTestPacket(v6, tc.proto, tc.port)
			if got := servicePacket(p, rules); got != tc.want {
				t.Errorf("IPv6=%v protocol=%d port=%d got %v", v6, tc.proto, tc.port, got)
			}
			if servicePacket(p, nil) {
				t.Error("empty policy allowed packet")
			}
		}
	}
	for _, flags := range []uint16{0x8000, 0x2000, 1} {
		p := serviceTestPacket(false, 6, 443)
		binary.BigEndian.PutUint16(p[6:8], flags)
		if servicePacket(p, rules) {
			t.Errorf("allowed fragmented or reserved flags %#x", flags)
		}
	}
	p := serviceTestPacket(false, 6, 443)
	binary.BigEndian.PutUint16(p[6:8], 0x4000)
	if !servicePacket(p, rules) {
		t.Error("valid don't-fragment packet denied")
	}
	p[0] = 0x46
	if servicePacket(p, rules) {
		t.Error("IPv4 options accepted")
	}
	p = serviceTestPacket(true, 6, 443)
	p[52] = 0x40
	if servicePacket(p, rules) {
		t.Error("invalid TCP header accepted")
	}
	p = serviceTestPacket(false, 17, 53)
	binary.BigEndian.PutUint16(p[24:26], 9)
	if servicePacket(p, rules) {
		t.Error("invalid UDP length accepted")
	}
}
