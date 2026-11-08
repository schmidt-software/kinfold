package metrics

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRegistryRendersPrometheusText(t *testing.T) {
	r := New()
	r.Counter("kinfold_test_total", "Test counter.", Labels{"result": "ok"}).Add(3)
	r.Counter("kinfold_test_total", "Test counter.", Labels{"result": "ok"}).Inc()
	r.Counter("kinfold_test_total", "Test counter.", Labels{"result": "bad\"x"}).Inc()
	r.Gauge("kinfold_label_escape", "Escaping.", Labels{"v": "a\\b\nc\td ä"}).Set(1)
	r.Gauge("kinfold_gauge", "Test gauge.", nil).Set(-2)
	r.GaugeFunc("kinfold_func", "Computed.", Labels{"b": "2", "a": "1"}, func() float64 { return 1.5 })
	var out bytes.Buffer
	if err := r.WritePrometheus(&out); err != nil {
		t.Fatal(err)
	}
	want := `# HELP kinfold_func Computed.
# TYPE kinfold_func gauge
kinfold_func{a="1",b="2"} 1.5
# HELP kinfold_gauge Test gauge.
# TYPE kinfold_gauge gauge
kinfold_gauge -2
# HELP kinfold_label_escape Escaping.
# TYPE kinfold_label_escape gauge
kinfold_label_escape{v="a\\b\nc	d ä"} 1
# HELP kinfold_test_total Test counter.
# TYPE kinfold_test_total counter
kinfold_test_total{result="bad\"x"} 1
kinfold_test_total{result="ok"} 4
`
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out.String(), want)
	}
	r.Remove("kinfold_test_total", Labels{"result": "ok"})
	out.Reset()
	r.WritePrometheus(&out)
	if strings.Contains(out.String(), `result="ok"`) {
		t.Fatal("removed series still rendered")
	}
}

func TestCheckLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:9100", "[::1]:9100", "localhost:9100"} {
		if err := CheckLoopback(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{":9100", "0.0.0.0:9100", "10.0.0.1:9100", "example.com:9100", "127.0.0.1"} {
		if err := CheckLoopback(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestServe(t *testing.T) {
	r := New()
	r.Gauge("kinfold_up", "Up.", nil).Set(1)
	done := make(chan struct{})
	defer close(done)
	addr, err := Serve("127.0.0.1:0", r, done)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + addr.String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "kinfold_up 1") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("unexpected response %q %q", resp.Header.Get("Content-Type"), body)
	}
	if _, err := Serve("0.0.0.0:0", r, done); err == nil {
		t.Fatal("non-loopback metrics address accepted")
	}
}
