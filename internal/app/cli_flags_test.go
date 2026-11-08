package app

import (
	"strings"
	"testing"
)

// status only reads the configuration: the tunnel options of run are not
// accepted there (#109).
func TestStatusRejectsRunOnlyFlags(t *testing.T) {
	for _, flag := range []string{"-interface", "-metrics", "-direct-listen", "-log-format"} {
		if err := Run([]string{"status", "-credential", "x.json", flag, "x"}); err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Errorf("status accepted %s: %v", flag, err)
		}
	}
}
