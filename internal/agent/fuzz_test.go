package agent

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func FuzzPacketAddresses(f *testing.F) {
	f.Add(ipv4(1, 2))
	f.Add(ipv6("fd77::1", "fd77::2"))
	f.Add([]byte{})
	f.Add([]byte{0x60})
	f.Fuzz(func(t *testing.T, packet []byte) {
		src, dst, err := packetAddresses(packet)
		if err != nil {
			return
		}
		if !src.IsValid() || !dst.IsValid() || len(packet) == 0 {
			t.Fatal("accepted packet without valid addresses")
		}
		switch packet[0] >> 4 {
		case 4:
			if len(packet) < 20 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
				int(packet[0]&15)*4 < 20 || int(packet[0]&15)*4 > len(packet) ||
				!bytes.Equal(src.AsSlice(), packet[12:16]) || !bytes.Equal(dst.AsSlice(), packet[16:20]) {
				t.Fatal("invalid IPv4 packet accepted")
			}
		case 6:
			if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) ||
				!bytes.Equal(src.AsSlice(), packet[8:24]) || !bytes.Equal(dst.AsSlice(), packet[24:40]) {
				t.Fatal("invalid IPv6 packet accepted")
			}
		default:
			t.Fatal("unknown IP version accepted")
		}
	})
}

func FuzzPacketFraming(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 3, 1, 2, 3})
	f.Add([]byte{0, 4, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bytes.NewReader(data)
		packet, err := readPacketLimited(reader, 65535)
		if len(data) < 2 {
			if err == nil {
				t.Fatal("accepted missing frame header")
			}
			return
		}
		length := int(binary.BigEndian.Uint16(data[:2]))
		if length == 0 || len(data)-2 < length {
			if err == nil {
				t.Fatal("accepted empty or truncated frame")
			}
			return
		}
		if err != nil || !bytes.Equal(packet, data[2:2+length]) {
			t.Fatalf("frame mismatch: %v", err)
		}
		if reader.Len() != len(data)-2-length {
			t.Fatal("read beyond the first frame")
		}
		var out bytes.Buffer
		if err := WritePacket(&out, packet); err != nil {
			t.Fatal(err)
		}
		roundTrip, err := io.ReadAll(&out)
		if err != nil || !bytes.Equal(roundTrip, data[:2+length]) {
			t.Fatalf("frame round trip failed: %v", err)
		}
	})
}
