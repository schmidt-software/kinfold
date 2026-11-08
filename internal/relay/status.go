package relay

import (
	"time"

	"github.com/schmidt-software/kinfold/internal/metrics"
)

// Live device status (D-036): per device, the time of its last
// configuration fetch and its current relay endpoints, exported as metrics.
// Series are added and removed with the members of the configuration.

const (
	lastSeenMetric       = "kinfold_device_last_seen_timestamp_seconds"
	deviceEndpointMetric = "kinfold_device_relay_endpoints"
)

// statusChanges records which devices joined or left the configuration
// since the last call and forgets the status of devices that left. Caller
// holds s.mu; the metric series are changed by syncStatusMetrics after the
// lock is released, because a scrape holds a family lock while it calls
// the series functions, which take s.mu.
func (s *Server) statusChanges() (added, removed []string) {
	current := make(map[string]bool, len(s.config.Peers))
	for _, p := range s.config.Peers {
		current[p.ID] = true
		if !s.statusPeers[p.ID] {
			added = append(added, p.ID)
		}
	}
	for id := range s.statusPeers {
		if !current[id] {
			removed = append(removed, id)
			delete(s.lastSeen, id)
		}
	}
	s.statusPeers = current
	return added, removed
}

func (s *Server) syncStatusMetrics(added, removed []string) {
	for _, id := range removed {
		labels := metrics.Labels{"peer": id}
		s.metrics.Remove(lastSeenMetric, labels)
		s.metrics.Remove(deviceEndpointMetric, labels)
	}
	for _, id := range added {
		labels := metrics.Labels{"peer": id}
		s.metrics.GaugeFunc(lastSeenMetric, "Unix time of the device's last configuration fetch from this controller (0: not since start).", labels, func() float64 {
			s.mu.Lock()
			defer s.mu.Unlock()
			if t, ok := s.lastSeen[id]; ok {
				return float64(t.Unix())
			}
			return 0
		})
		s.metrics.GaugeFunc(deviceEndpointMetric, "Relay endpoints of the device currently waiting or bridged.", labels, func() float64 {
			s.mu.Lock()
			defer s.mu.Unlock()
			n := 0
			for _, e := range s.active {
				if e.from == id {
					n++
				}
			}
			return float64(n)
		})
	}
}

// seen records a configuration fetch. Caller holds s.mu.
func (s *Server) seen(id string, now time.Time) { s.lastSeen[id] = now }
