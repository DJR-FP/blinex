//go:build windows

package dnsconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// Windows never has a kernel-TUN interface (see wgmgr's createTUN — it
// always fails on non-Linux), so Apply/Revert (the per-link path) has
// nothing to attach to here. ApplyGlobal is the real implementation.
func Apply(_, _ string) {}
func Revert(_ string)   {}

// backupPath persists the original per-adapter DNS servers so a restart
// after a crash can still restore them later, mirroring the Linux netstack
// approach — only ApplyGlobal writes it, and only if it doesn't already
// exist (see ApplyGlobal for why that matters).
var backupPath = filepath.Join(os.Getenv("ProgramData"), "blinex", "dns-backup.json")

type adapterDNS struct {
	InterfaceIndex  int      `json:"InterfaceIndex"`
	InterfaceAlias  string   `json:"InterfaceAlias"`
	ServerAddresses []string `json:"ServerAddresses"`
}

var globalMu sync.Mutex
var globalRelay *relay

// ApplyGlobal is the Windows netstack path: no real interface exists to
// hang a per-link override off, so instead it starts a UDP relay on :53
// (what Set-DnsClientServerAddress-configured adapters actually query) that
// forwards to the resolver's real listener on :53535, then points every
// "Up" network adapter's DNS servers at 127.0.0.1.
//
// Crash safety is weaker than the kernel-TUN path (no OS-level interface
// teardown to lean on): if the process is killed, the adapters stay pointed
// at 127.0.0.1 with nothing listening until the agent restarts. Unlike the
// Linux services (systemd Restart=on-failure), nothing currently
// auto-restarts a crashed Windows agent — see the roadmap for proper
// service installation. The backup file is written to disk specifically so
// that whenever the agent does come back (even minutes later, started by
// hand), it restores the *real* original DNS rather than treating its own
// override as the original to preserve.
func ApplyGlobal(resolverAddr string) {
	globalMu.Lock()
	defer globalMu.Unlock()

	r := startRelay("127.0.0.1:53", resolverAddr)
	if r == nil {
		return // already logged; leave DNS untouched
	}
	globalRelay = r

	if err := os.MkdirAll(filepath.Dir(backupPath), 0755); err != nil {
		log.Warn().Err(err).Msg("dnsconfig: could not create backup directory, skipping DNS takeover")
		return
	}

	// Only back up if no backup exists yet: on a crash-triggered restart, the
	// adapters right now are already pointed at US, not the real original —
	// backing them up here would permanently lose the real original.
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		current, err := queryAdapterDNS()
		if err != nil {
			log.Warn().Err(err).Msg("dnsconfig: could not read current adapter DNS settings, skipping DNS takeover")
			return
		}
		data, err := json.Marshal(current)
		if err != nil {
			log.Warn().Err(err).Msg("dnsconfig: could not serialize DNS backup")
			return
		}
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			log.Warn().Err(err).Msg("dnsconfig: could not write DNS backup")
			return
		}
	}

	backup, err := readBackup()
	if err != nil {
		log.Warn().Err(err).Msg("dnsconfig: could not read DNS backup, skipping DNS takeover")
		return
	}
	applied := 0
	for _, a := range backup {
		if err := setAdapterDNS(a.InterfaceIndex, []string{"127.0.0.1"}); err != nil {
			log.Warn().Err(err).Str("adapter", a.InterfaceAlias).Msg("dnsconfig: failed to set adapter DNS")
			continue
		}
		applied++
	}
	log.Info().Int("adapters", applied).Str("resolver", resolverAddr).Msg("dnsconfig: system DNS now routed through the agent (global override)")
}

// RevertGlobal undoes ApplyGlobal on a clean shutdown.
func RevertGlobal() {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalRelay != nil {
		globalRelay.Close()
		globalRelay = nil
	}
	backup, err := readBackup()
	if err != nil {
		return // never applied, or already reverted
	}
	for _, a := range backup {
		if len(a.ServerAddresses) == 0 {
			exec.Command("powershell", "-NoProfile", "-Command",
				"Set-DnsClientServerAddress -InterfaceIndex "+strconv.Itoa(a.InterfaceIndex)+" -ResetServerAddresses").Run() //nolint:errcheck
			continue
		}
		if err := setAdapterDNS(a.InterfaceIndex, a.ServerAddresses); err != nil {
			log.Warn().Err(err).Str("adapter", a.InterfaceAlias).Msg("dnsconfig: failed to restore adapter DNS")
		}
	}
	_ = os.Remove(backupPath)
	log.Info().Msg("dnsconfig: restored original adapter DNS settings")
}

func readBackup() ([]adapterDNS, error) {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, err
	}
	var backup []adapterDNS
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, err
	}
	return backup, nil
}

func queryAdapterDNS() ([]adapterDNS, error) {
	script := `Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
		$dns = Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4
		[PSCustomObject]@{InterfaceIndex=$_.InterfaceIndex; InterfaceAlias=$_.Name; ServerAddresses=@($dns.ServerAddresses)}
	} | ConvertTo-Json`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		return nil, err
	}
	var adapters []adapterDNS
	// A single "Up" adapter serializes to a JSON object, not an array —
	// PowerShell's ConvertTo-Json quirk. Try array first, fall back to one.
	if err := json.Unmarshal(out, &adapters); err != nil {
		var single adapterDNS
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil, err
		}
		adapters = []adapterDNS{single}
	}
	return adapters, nil
}

func setAdapterDNS(interfaceIndex int, servers []string) error {
	script := "Set-DnsClientServerAddress -InterfaceIndex " + strconv.Itoa(interfaceIndex) + " -ServerAddresses " + psStringArray(servers)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// psStringArray renders a Go string slice as a PowerShell array literal,
// e.g. ["127.0.0.1"] -> @('127.0.0.1'). Every value here comes from our own
// relay address or from IPs PowerShell itself reported back to us (never
// free-form user input), so a plain single-quote escape is sufficient.
func psStringArray(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = "'" + strings.ReplaceAll(v, "'", "''") + "'"
	}
	return "@(" + strings.Join(quoted, ",") + ")"
}
