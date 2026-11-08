// Package metrics is a minimal registry that renders counters and gauges in
// the Prometheus text exposition format. It has no dependencies beyond the
// standard library (D-007).
package metrics

import (
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a monotonically increasing value.
type Counter struct{ v atomic.Uint64 }

func (c *Counter) Inc()          { c.v.Add(1) }
func (c *Counter) Add(n uint64)  { c.v.Add(n) }
func (c *Counter) Value() uint64 { return c.v.Load() }

// Gauge is a value that can go up and down.
type Gauge struct{ v atomic.Int64 }

func (g *Gauge) Set(n int64)  { g.v.Store(n) }
func (g *Gauge) Add(n int64)  { g.v.Add(n) }
func (g *Gauge) Value() int64 { return g.v.Load() }

type family struct {
	name, help, kind string
	mu               sync.Mutex
	series           map[string]func() float64 // rendered label set -> value
	owners           map[string]any            // rendered label set -> *Counter or *Gauge
}

// Registry holds metric families. The zero value is not usable; use New.
type Registry struct {
	mu       sync.Mutex
	families map[string]*family
}

func New() *Registry { return &Registry{families: make(map[string]*family)} }

func (r *Registry) family(name, help, kind string) *family {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.families[name]
	if f == nil {
		f = &family{name: name, help: help, kind: kind, series: make(map[string]func() float64), owners: make(map[string]any)}
		r.families[name] = f
	} else if f.kind != kind {
		panic(fmt.Sprintf("metric %s registered as %s and %s", name, f.kind, kind))
	}
	return f
}

// labelEscaper applies the Prometheus text-format escaping for label values:
// only backslash, double quote and line feed are escaped.
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// Labels are rendered in key order.
type Labels map[string]string

func (l Labels) String() string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+`="`+labelEscaper.Replace(l[k])+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Counter returns the counter for name and labels, creating it on first use.
func (r *Registry) Counter(name, help string, labels Labels) *Counter {
	f := r.family(name, help, "counter")
	key := labels.String()
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.owners[key].(*Counter); ok {
		return c
	}
	c := &Counter{}
	f.series[key] = func() float64 { return float64(c.Value()) }
	f.owners[key] = c
	return c
}

// Gauge returns the gauge for name and labels, creating it on first use.
func (r *Registry) Gauge(name, help string, labels Labels) *Gauge {
	f := r.family(name, help, "gauge")
	key := labels.String()
	f.mu.Lock()
	defer f.mu.Unlock()
	if g, ok := f.owners[key].(*Gauge); ok {
		return g
	}
	g := &Gauge{}
	f.series[key] = func() float64 { return float64(g.Value()) }
	f.owners[key] = g
	return g
}

// GaugeFunc registers a gauge whose value is computed at scrape time.
func (r *Registry) GaugeFunc(name, help string, labels Labels, fn func() float64) {
	f := r.family(name, help, "gauge")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.series[labels.String()] = fn
}

// Remove drops one series, e.g. for a peer that left the configuration.
func (r *Registry) Remove(name string, labels Labels) {
	r.mu.Lock()
	f := r.families[name]
	r.mu.Unlock()
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.series, labels.String())
	delete(f.owners, labels.String())
}

// WritePrometheus renders all families in the text exposition format.
func (r *Registry) WritePrometheus(w io.Writer) error {
	r.mu.Lock()
	names := make([]string, 0, len(r.families))
	for n := range r.families {
		names = append(names, n)
	}
	r.mu.Unlock()
	sort.Strings(names)
	for _, n := range names {
		r.mu.Lock()
		f := r.families[n]
		r.mu.Unlock()
		f.mu.Lock()
		keys := make([]string, 0, len(f.series))
		for k := range f.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		values := make([]float64, len(keys))
		for i, k := range keys {
			values[i] = f.series[k]()
		}
		f.mu.Unlock()
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.kind); err != nil {
			return err
		}
		for i, k := range keys {
			if _, err := fmt.Fprintf(w, "%s%s %s\n", f.name, k, formatValue(values[i])); err != nil {
				return err
			}
		}
	}
	return nil
}

func formatValue(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Handler serves the registry at any path.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.WritePrometheus(w)
	})
}

// CheckLoopback refuses metrics listeners that are reachable from other
// hosts; the metrics expose device names and traffic volumes (D-021).
func CheckLoopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("metrics address must be host:port: %w", err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("metrics address %q must be a loopback address such as 127.0.0.1:9100", address)
	}
	return nil
}

// Serve runs a plain HTTP metrics server until done is closed.
func Serve(address string, r *Registry, done <-chan struct{}) (net.Addr, error) {
	if err := CheckLoopback(address); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: r.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	go func() { _ = server.Serve(ln) }()
	go func() {
		<-done
		server.Close()
	}()
	return ln.Addr(), nil
}
