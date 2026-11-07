package agent

import (
	"testing"

	"my-zerotier/internal/core"
)

func FuzzServicePacket(f *testing.F) {
	f.Add(serviceTestPacket(false, 6, 443))
	f.Add(serviceTestPacket(true, 17, 53))
	f.Add([]byte{})
	rules := compileServices([]core.ServiceRule{{Protocol: "tcp", Port: 443}, {Protocol: "udp", Port: 53}, {Protocol: "icmp"}, {Protocol: "icmp6"}}, "", "")
	f.Fuzz(func(t *testing.T, data []byte) {
		if servicePacket(data, nil) {
			t.Fatal("empty service policy allowed a packet")
		}
		servicePacket(data, rules)
	})
}
