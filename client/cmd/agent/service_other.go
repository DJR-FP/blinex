//go:build !windows

package main

import (
	"fmt"
	"runtime"
)

func isWindowsService() bool { return false }

func runAsService() {}

func installService(_, _, _, _, _, _ string) error {
	return fmt.Errorf("service install is only supported on Windows (this is %s) — on Linux, use the systemd unit instead", runtime.GOOS)
}

func uninstallService() error {
	return fmt.Errorf("service uninstall is only supported on Windows (this is %s)", runtime.GOOS)
}
