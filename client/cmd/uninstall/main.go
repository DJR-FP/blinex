package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func info(msg string)  { fmt.Printf("\033[0;32m[blinex]\033[0m %s\n", msg) }
func warn(msg string)  { fmt.Printf("\033[1;33m[blinex]\033[0m %s\n", msg) }
func fatal(msg string) { fmt.Fprintf(os.Stderr, "\033[0;31m[blinex]\033[0m %s\n", msg); os.Exit(1) }

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runSilent(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func main() {
	switch runtime.GOOS {
	case "windows":
		uninstallWindows()
	case "darwin":
		uninstallDarwin()
	case "linux":
		uninstallLinux()
	default:
		fatal("Unsupported OS: " + runtime.GOOS)
	}

	info("Done. The device will remain listed in the dashboard until you remove it there.")
}

func uninstallWindows() {
	programFiles := os.Getenv("ProgramFiles")
	programData := os.Getenv("ProgramData")
	installDir := filepath.Join(programFiles, "Bline-X")
	configDir := filepath.Join(programData, "Bline-X")

	// Stop and remove Windows service
	if err := runSilent("sc", "query", "BlinexAgent"); err == nil {
		info("Stopping BlinexAgent service...")
		runSilent("sc", "stop", "BlinexAgent")
		info("Removing BlinexAgent service...")
		runSilent("sc", "delete", "BlinexAgent")
	}

	// Remove install directory
	if _, err := os.Stat(installDir); err == nil {
		info("Removing install directory (" + installDir + ")...")
		os.RemoveAll(installDir)
	}

	// Remove config/state directory
	if _, err := os.Stat(configDir); err == nil {
		info("Removing config/state directory (" + configDir + ")...")
		os.RemoveAll(configDir)
	}

	// Remove from PATH
	out, err := exec.Command("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "/v", "Path").Output()
	if err == nil {
		pathStr := string(out)
		lines := strings.Split(pathStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, "REG_") {
				parts := strings.SplitN(strings.TrimSpace(line), "REG_EXPAND_SZ", 2)
				if len(parts) < 2 {
					parts = strings.SplitN(strings.TrimSpace(line), "REG_SZ", 2)
				}
				if len(parts) == 2 {
					currentPath := strings.TrimSpace(parts[1])
					entries := strings.Split(currentPath, ";")
					var filtered []string
					for _, e := range entries {
						if !strings.Contains(strings.ToLower(e), "bline-x") {
							filtered = append(filtered, e)
						}
					}
					newPath := strings.Join(filtered, ";")
					if newPath != currentPath {
						info("Removing Bline-X from system PATH...")
						runSilent("reg", "add", `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "/v", "Path", "/t", "REG_EXPAND_SZ", "/d", newPath, "/f")
					}
				}
			}
		}
	}

	// Remove firewall rules
	info("Removing firewall rules...")
	runSilent("netsh", "advfirewall", "firewall", "delete", "rule", "name=Bline-X Agent")

	info("Bline-X agent uninstalled from Windows.")
}

func uninstallDarwin() {
	if os.Geteuid() != 0 {
		fatal("Please run as root (sudo)")
	}

	plist := "/Library/LaunchDaemons/io.blinex.agent.plist"

	// Unload and remove launchd service
	if _, err := os.Stat(plist); err == nil {
		info("Stopping blinex-agent service...")
		runSilent("launchctl", "unload", plist)
		info("Removing launchd plist...")
		os.Remove(plist)
	}

	// Remove binary
	binary := "/usr/local/bin/blinex-agent"
	if _, err := os.Stat(binary); err == nil {
		info("Removing agent binary...")
		os.Remove(binary)
	}

	// Remove config and state
	for _, dir := range []string{"/etc/blinex", "/var/lib/blinex"} {
		if _, err := os.Stat(dir); err == nil {
			info("Removing " + dir + "...")
			os.RemoveAll(dir)
		}
	}

	// Remove log file
	logFile := "/var/log/blinex-agent.log"
	if _, err := os.Stat(logFile); err == nil {
		info("Removing log file...")
		os.Remove(logFile)
	}

	info("Bline-X agent uninstalled from macOS.")
}

func uninstallLinux() {
	if os.Geteuid() != 0 {
		fatal("Please run as root (sudo)")
	}

	// Stop and disable systemd service
	if runSilent("systemctl", "is-active", "--quiet", "blinex-agent") == nil {
		info("Stopping blinex-agent service...")
		run("systemctl", "stop", "blinex-agent")
	}
	if runSilent("systemctl", "is-enabled", "--quiet", "blinex-agent") == nil {
		info("Disabling blinex-agent service...")
		run("systemctl", "disable", "blinex-agent")
	}
	unitFile := "/etc/systemd/system/blinex-agent.service"
	if _, err := os.Stat(unitFile); err == nil {
		info("Removing systemd unit file...")
		os.Remove(unitFile)
		run("systemctl", "daemon-reload")
	}

	// Remove iptables rules
	if runSilent("iptables", "-L", "BLINEX-ACL", "-n") == nil {
		info("Cleaning up iptables rules...")
		runSilent("iptables", "-D", "INPUT", "-i", "blinex0", "-j", "BLINEX-ACL")
		runSilent("iptables", "-D", "FORWARD", "-i", "blinex0", "-j", "BLINEX-ACL")
		runSilent("iptables", "-F", "BLINEX-ACL")
		runSilent("iptables", "-X", "BLINEX-ACL")
	}

	// Remove binary
	binary := "/usr/local/bin/blinex-agent"
	if _, err := os.Stat(binary); err == nil {
		info("Removing agent binary...")
		os.Remove(binary)
	}

	// Remove config and state
	for _, dir := range []string{"/etc/blinex", "/var/lib/blinex"} {
		if _, err := os.Stat(dir); err == nil {
			info("Removing " + dir + "...")
			os.RemoveAll(dir)
		}
	}

	// Remove the control socket
	os.Remove("/var/run/blinex-agent.sock")

	// Remove WireGuard interface
	if runSilent("ip", "link", "show", "blinex0") == nil {
		info("Removing blinex0 interface...")
		runSilent("ip", "link", "delete", "blinex0")
	}

	info("Bline-X agent uninstalled from Linux.")
}
