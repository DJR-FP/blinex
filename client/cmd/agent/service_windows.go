//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/blinex/client/internal/config"
	"github.com/blinex/client/internal/engine"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "BlinexAgent"

// serviceConfigPath is where `install` writes the agent's settings, and
// where the service (started by the SCM with no interactive environment —
// no env vars from a user's shell session) reads them back from.
var serviceConfigPath = filepath.Join(os.Getenv("ProgramData"), "blinex", "agent.json")

// serviceLogPath is where the running service's logs go. A Windows Service
// has no attached console, so the zerolog output the foreground/interactive
// path relies on (stderr) goes nowhere — without this, every log line from
// a running service is silently discarded, which is exactly what made an
// earlier live connectivity problem impossible to diagnose.
var serviceLogPath = filepath.Join(os.Getenv("ProgramData"), "blinex", "agent.log")

func isWindowsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// runAsService is the Windows Service entry point: it registers with the
// Service Control Manager and blocks until the SCM tells it to stop.
func runAsService() {
	if err := os.MkdirAll(filepath.Dir(serviceLogPath), 0755); err == nil {
		if f, err := os.OpenFile(serviceLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: f, NoColor: true, TimeFormat: "2006-01-02 15:04:05"})
		}
	}
	// If the log file couldn't be opened, fall through and run anyway with
	// zerolog's default (still-silent) writer — a service that can't log is
	// far better than one that fails to start over a logging problem.

	if err := svc.Run(serviceName, &winService{}); err != nil {
		log.Fatal().Err(err).Msg("service failed")
	}
}

type winService struct{}

// Execute implements svc.Handler. A clean Stop/Shutdown request cancels the
// engine's context and waits for its deferred cleanup (including
// dnsconfig.RevertGlobal) to finish before reporting Stopped — this is what
// makes "the user stops it manually" work correctly rather than just killing
// the process. If the engine exits on its own (a fatal error, not a
// requested stop), Execute returns a failure exit code instead, which is
// what makes Windows' service Recovery actions (configured by `install`,
// equivalent to systemd's Restart=on-failure) actually trigger — a plain
// process crash is caught by the SCM independently of this return value.
func (m *winService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	cfg, err := config.Load(serviceConfigPath)
	if err != nil {
		log.Error().Err(err).Msg("service: failed to load config")
		return true, 1
	}
	cfg.Version = version

	eng, err := engine.New(cfg)
	if err != nil {
		log.Error().Err(err).Msg("service: failed to initialise engine")
		return true, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- eng.Run(ctx) }()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-runErrCh // wait for Run's deferred cleanup (DNS revert, etc.) to finish
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case <-runErrCh:
			// The engine exited on its own without a stop request — a real
			// failure. Report a nonzero exit so the SCM's Recovery actions
			// (auto-restart) engage the same way they would for a crash.
			log.Error().Msg("service: engine exited unexpectedly")
			return true, 1
		}
	}
}

// installService registers the agent as a Windows Service that starts on
// boot and restarts automatically on failure — while a deliberate
// Stop-Service/net stop is honored immediately and does NOT trigger a
// restart, same as systemd's Restart=on-failure not firing on
// `systemctl stop`. Run once, elevated (Administrator).
func installService(setupKey, managementURL, signalURL, stunURL, turnUser, turnPass string) error {
	if err := os.MkdirAll(filepath.Dir(serviceConfigPath), 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	cfgJSON := struct {
		ManagementURL string   `json:"management_url"`
		SignalURL     string   `json:"signal_url"`
		SetupKey      string   `json:"setup_key"`
		StunURLs      []string `json:"stun_urls,omitempty"`
		TurnUser      string   `json:"turn_user,omitempty"`
		TurnPass      string   `json:"turn_pass,omitempty"`
	}{ManagementURL: managementURL, SignalURL: signalURL, SetupKey: setupKey, TurnUser: turnUser, TurnPass: turnPass}
	if stunURL != "" {
		cfgJSON.StunURLs = []string{stunURL}
	}
	data, err := json.MarshalIndent(cfgJSON, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := os.WriteFile(serviceConfigPath, data, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating own executable: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to service manager (run as Administrator?): %w", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(serviceName); err == nil {
		existing.Close()
		return fmt.Errorf("service %q already installed — run 'uninstall' first", serviceName)
	}

	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: "Bline-X Agent",
		Description: "Bline-X mesh VPN agent — WireGuard, ICE, Magic DNS",
		StartType:   mgr.StartAutomatic,
	}, "-config", serviceConfigPath)
	if err != nil {
		return fmt.Errorf("creating service: %w", err)
	}
	defer s.Close()

	// The mgr package has no direct API for failure-recovery actions, so
	// this shells out to sc.exe. A single action with no reset limit means
	// every failure restarts the service after a 3s delay, indefinitely —
	// mirroring RestartSec=3 on the Linux systemd units.
	if out, err := exec.Command("sc", "failure", serviceName, "reset=", "86400", "actions=", "restart/3000").CombinedOutput(); err != nil {
		return fmt.Errorf("configuring restart-on-failure: %w: %s", err, out)
	}
	// Recovery actions only fire for failures by default when the flag below
	// is set — without it, some Windows versions only recover from crashes
	// that also fail a separate "is this exe well-formed" style check.
	exec.Command("sc", "failureflag", serviceName, "1").Run() //nolint:errcheck

	if err := s.Start(); err != nil {
		return fmt.Errorf("starting service: %w", err)
	}
	return nil
}

// uninstallService stops and removes the service. The config file at
// serviceConfigPath is left in place (harmless, and handy if reinstalling).
func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to service manager (run as Administrator?): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed", serviceName)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop) // best-effort; Delete works either way once stopped
	return s.Delete()
}
