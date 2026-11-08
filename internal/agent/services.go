package agent

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/schmidt-software/kinfold/internal/core"
)

type serviceKey struct {
	protocol string
	port     uint16
}

type serviceSet map[serviceKey]struct{}

func compileServices(rules []core.ServiceRule, from, to string) serviceSet {
	set := make(serviceSet)
	for _, rule := range rules {
		if rule.From == from && rule.To == to {
			set[serviceKey{protocol: rule.Protocol, port: rule.Port}] = struct{}{}
		}
	}
	return set
}

// servicePacket matches only complete, unfragmented packets without IP options
// or IPv6 extension headers. No implicit stateful return traffic is allowed.
func servicePacket(packet []byte, rules serviceSet) bool {
	if len(packet) == 0 {
		return false
	}
	var proto byte
	var payload []byte
	var family byte
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || packet[0] != 0x45 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
			binary.BigEndian.Uint16(packet[6:8])&0xbfff != 0 {
			return false
		}
		family, proto, payload = 4, packet[9], packet[20:]
	case 6:
		if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return false
		}
		family, proto, payload = 6, packet[6], packet[40:]
	default:
		return false
	}
	var protocol string
	var port uint16
	switch proto {
	case 6:
		if len(payload) < 20 || int(payload[12]>>4)*4 < 20 || int(payload[12]>>4)*4 > len(payload) {
			return false
		}
		protocol, port = "tcp", binary.BigEndian.Uint16(payload[2:4])
	case 17:
		if len(payload) < 8 || int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
			return false
		}
		protocol, port = "udp", binary.BigEndian.Uint16(payload[2:4])
	case 1:
		if family != 4 || len(payload) < 4 {
			return false
		}
		protocol = "icmp"
	case 58:
		if family != 6 || len(payload) < 4 {
			return false
		}
		protocol = "icmp6"
	default:
		return false
	}
	_, ok := rules[serviceKey{protocol: protocol, port: port}]
	return ok
}

// keys lists the set's members in a stable order.
func (s serviceSet) keys() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, fmt.Sprintf("%s/%d", k.protocol, k.port))
	}
	sort.Strings(out)
	return out
}
