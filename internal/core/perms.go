package core

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
)

// InsecurePermissionsEnv disables the permission checks for setups where
// file modes are not meaningful (some container volume drivers). Set it to 1.
const InsecurePermissionsEnv = "KINFOLD_INSECURE_PERMISSIONS"

// CheckPrivate refuses files and directories holding private keys that are
// accessible by group or others (review C-05).
func CheckPrivate(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return nil
	}
	if os.Getenv(InsecurePermissionsEnv) == "1" {
		slog.Warn("private file is accessible by other users; permission check overridden", "path", path, "mode", fmt.Sprintf("%04o", perm))
		return nil
	}
	fix := "chmod 600"
	if info.IsDir() {
		fix = "chmod 700"
	}
	return fmt.Errorf("%s contains private key material but is accessible by other users (mode %04o); restrict it with %s %s, or set %s=1 to override", path, perm, fix, path, InsecurePermissionsEnv)
}
