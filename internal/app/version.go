package app

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// Version is the release version. Release builds set it with
// -ldflags "-X github.com/schmidt-software/kinfold/internal/app.Version=v0.2.0".
var Version = "dev"

// buildInfo describes the running binary for `kinfold version` and the
// startup log line of long-running commands.
type buildInfo struct {
	Version  string
	Revision string
	Time     string
	Modified bool
	Go       string
	Platform string
}

func readBuildInfo() buildInfo {
	info := buildInfo{Version: Version, Go: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			info.Revision = s.Value
		case "vcs.time":
			info.Time = s.Value
		case "vcs.modified":
			info.Modified = s.Value == "true"
		}
	}
	return info
}

func (b buildInfo) short() string {
	rev := b.Revision
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev == "" {
		rev = "unknown"
	}
	if b.Modified {
		rev += "-dirty"
	}
	return fmt.Sprintf("%s (%s)", b.Version, rev)
}

func printVersion(w io.Writer, b buildInfo) {
	fmt.Fprintf(w, "kinfold %s\n", b.Version)
	rev := b.Revision
	if rev == "" {
		rev = "unknown"
	}
	if b.Modified {
		rev += " (modified working tree)"
	}
	fmt.Fprintf(w, "commit:   %s\n", rev)
	if b.Time != "" {
		fmt.Fprintf(w, "built:    %s\n", b.Time)
	}
	fmt.Fprintf(w, "go:       %s\n", b.Go)
	fmt.Fprintf(w, "platform: %s\n", b.Platform)
}
