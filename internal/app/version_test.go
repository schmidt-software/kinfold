package app

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestPrintVersionIncludesAllFields(t *testing.T) {
	var out bytes.Buffer
	printVersion(&out, buildInfo{Version: "v9.9.9", Revision: "abc123", Time: "2026-01-02T03:04:05Z", Modified: true, Go: "go1.26.10", Platform: "linux/arm64"})
	got := out.String()
	for _, want := range []string{"kinfold v9.9.9", "commit:   abc123 (modified working tree)", "built:    2026-01-02T03:04:05Z", "go:       go1.26.10", "platform: linux/arm64"} {
		if !strings.Contains(got, want) {
			t.Errorf("version output missing %q:\n%s", want, got)
		}
	}
}

func TestPrintVersionWithoutVCS(t *testing.T) {
	var out bytes.Buffer
	printVersion(&out, buildInfo{Version: "dev", Go: "go1.26.10", Platform: "darwin/arm64"})
	got := out.String()
	if !strings.Contains(got, "commit:   unknown") || strings.Contains(got, "built:") {
		t.Errorf("unexpected output without VCS info:\n%s", got)
	}
}

func TestBuildInfoShort(t *testing.T) {
	b := buildInfo{Version: "v1", Revision: "0123456789abcdef0123", Modified: true}
	if got, want := b.short(), "v1 (0123456789ab-dirty)"; got != want {
		t.Errorf("short() = %q, want %q", got, want)
	}
	if got, want := (buildInfo{Version: "dev"}).short(), "dev (unknown)"; got != want {
		t.Errorf("short() = %q, want %q", got, want)
	}
}

func TestVersionCommandPrintsVersion(t *testing.T) {
	if err := Run([]string{"version"}); err != nil {
		t.Fatalf("version: %v", err)
	}
	if err := Run([]string{"version", "extra"}); err == nil {
		t.Fatal("version accepted unexpected argument")
	}
}

func TestNewLogHandlerLevelsAndFormats(t *testing.T) {
	var out bytes.Buffer
	h, err := newLogHandler(&out, "json", "warn")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(h)
	logger.Info("hidden")
	logger.Warn("shown", "peer", "alice")
	got := out.String()
	if strings.Contains(got, "hidden") || !strings.Contains(got, `"peer":"alice"`) {
		t.Errorf("unexpected JSON log output: %s", got)
	}
	if _, err := newLogHandler(&out, "xml", "info"); err == nil {
		t.Error("unknown format accepted")
	}
	if _, err := newLogHandler(&out, "text", "loud"); err == nil {
		t.Error("unknown level accepted")
	}
	if _, err := newLogHandler(&out, "text", "debug"); err != nil {
		t.Errorf("text/debug rejected: %v", err)
	}
}
