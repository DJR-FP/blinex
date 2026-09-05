//go:build windows

package controlapi

import "os/exec"

// grantSocketAccess extends access to the control socket to the built-in
// Administrators group (SID S-1-5-32-544, locale-independent unlike the
// group's display name). The daemon normally runs as the BlinexAgent
// Windows Service under LocalSystem, whose default file ACLs don't include
// other accounts — without this, `blinex-agent status` run by an
// Administrator fails with "access forbidden by its access permissions"
// even though the daemon is running fine, which made a real connectivity
// problem impossible to diagnose from an interactive session.
func grantSocketAccess(path string) {
	_ = exec.Command("icacls", path, "/grant", "*S-1-5-32-544:(F)").Run()
}
