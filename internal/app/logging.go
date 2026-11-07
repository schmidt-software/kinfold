package app

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// logFlags registers the logging options shared by long-running commands.
type logFlags struct {
	format *string
	level  *string
}

func addLogFlags(f *flag.FlagSet) logFlags {
	return logFlags{
		format: f.String("log-format", "text", "log format: text or json"),
		level:  f.String("log-level", "info", "minimum log level: debug, info, warn or error"),
	}
}

// configure installs the process-wide slog handler. Logs always go to
// stderr so stdout stays reserved for command results.
func (l logFlags) configure() error {
	handler, err := newLogHandler(os.Stderr, *l.format, *l.level)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(handler))
	return nil
}

func newLogHandler(w io.Writer, format, level string) (slog.Handler, error) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown log level %q (debug, info, warn or error)", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch format {
	case "text":
		return slog.NewTextHandler(w, opts), nil
	case "json":
		return slog.NewJSONHandler(w, opts), nil
	}
	return nil, fmt.Errorf("unknown log format %q (text or json)", format)
}
