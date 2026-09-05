package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"

	"github.com/blinex/client/internal/config"
	"github.com/blinex/client/internal/controlapi"
	"github.com/blinex/client/internal/engine"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var version = "dev"

func main() {
	// When Windows starts this exe as a service, it does so via the Service
	// Control Manager with no arguments the switch below would recognize —
	// this check must run before any of that, and unconditionally, or the
	// SCM never gets the prompt "I'm alive" response it expects and reports
	// the service failed to start. No-op on every other OS.
	if isWindowsService() {
		runAsService()
		return
	}

	// Subcommands query a running agent over its local control socket.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "status", "peers", "routes":
			runCLI(os.Args[1], os.Args[2:])
			return
		case "install":
			runInstall(os.Args[2:])
			return
		case "uninstall":
			if err := uninstallService(); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			fmt.Println("service removed")
			return
		case "version", "-version", "--version":
			fmt.Println(version)
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}
	runDaemon()
}

func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	setupKey := fs.String("setup-key", "", "enrollment key from the Setup Keys page (required)")
	mgmtURL := fs.String("management-url", "", "management server address, host:50051 (required)")
	sigURL := fs.String("signal-url", "", "signal server address, host:10000 (required)")
	stunURL := fs.String("stun-url", "", "STUN/TURN server, e.g. stun:host:3478 — strongly recommended (see below)")
	turnUser := fs.String("turn-user", "", "TURN long-term credential username")
	turnPass := fs.String("turn-pass", "", "TURN long-term credential password")
	_ = fs.Parse(args)

	if *setupKey == "" || *mgmtURL == "" || *sigURL == "" {
		fmt.Fprintln(os.Stderr, "error: -setup-key, -management-url, and -signal-url are all required")
		fs.Usage()
		os.Exit(1)
	}
	if *stunURL == "" || *turnUser == "" || *turnPass == "" {
		fmt.Println("warning: -stun-url/-turn-user/-turn-pass not fully set — this device will fall")
		fmt.Println("back to Google's public STUN server with no TURN relay at all. Without a TURN")
		fmt.Println("candidate, ICE has nothing to fall back on if direct hole-punching fails (e.g.")
		fmt.Println("behind a symmetric NAT), and this device will be stuck on the signal-relay path")
		fmt.Println("indefinitely. Pass all three, matching your other agents' config, to fix this.")
		fmt.Println()
	}
	fmt.Println("note: this binary is not code-signed. Windows Defender's real-time")
	fmt.Println("protection may flag and remove it and the service it creates — a service")
	fmt.Println("that rewrites system DNS settings and binds port 53 looks a lot like known")
	fmt.Println("DNS-hijacking malware. If install succeeds but the service vanishes shortly")
	fmt.Println("after, check Get-MpThreatDetection. For testing, exclude this folder:")
	fmt.Println(`  Add-MpPreference -ExclusionPath "<this folder>"`)
	fmt.Println("Do not ship an unsigned build to real users for this reason.")
	fmt.Println()

	if err := installService(*setupKey, *mgmtURL, *sigURL, *stunURL, *turnUser, *turnPass); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println("service installed and started — it will now start on boot and restart automatically if it crashes")
}

func runDaemon() {
	cfgPath := flag.String("config", "", "path to agent config JSON (default: /etc/blinex/agent.json)")
	flag.Parse()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("version", version).Msg("blinex agent starting")

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}
	cfg.Version = version

	eng, err := engine.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise engine")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := eng.Run(ctx); err != nil && err != context.Canceled {
		log.Fatal().Err(err).Msg("agent error")
	}
	log.Info().Msg("agent stopped")
}

func runCLI(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	socket := fs.String("socket", controlapi.DefaultSocket, "agent control socket path")
	_ = fs.Parse(args)

	st, err := controlapi.Query(*socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	switch cmd {
	case "status":
		printStatus(st)
	case "peers":
		printPeers(st)
	case "routes":
		printRoutes(st)
	}
}

func printStatus(st controlapi.Status) {
	fmt.Printf("Bline-X agent  v%s\n", st.Version)
	fmt.Printf("  Hostname:   %s\n", st.Hostname)
	fmt.Printf("  Mesh IP:    %s\n", st.SelfIP)
	fmt.Printf("  Interface:  %s (%s mode)\n", st.Interface, st.Mode)
	direct := 0
	for _, p := range st.Peers {
		if p.Path == "direct" {
			direct++
		}
	}
	fmt.Printf("  Peers:      %d (%d direct, %d relayed)\n", len(st.Peers), direct, len(st.Peers)-direct)
	fmt.Printf("  Routes:     %d\n", len(st.Routes))
}

func printPeers(st controlapi.Status) {
	if len(st.Peers) == 0 {
		fmt.Println("No peers.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "HOSTNAME\tMESH IP\tDNS\tPATH")
	for _, p := range st.Peers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", dash(p.Hostname), p.IP, dash(p.DNSName), p.Path)
	}
	_ = w.Flush()
}

func printRoutes(st controlapi.Status) {
	if len(st.Routes) == 0 {
		fmt.Println("No routes advertised.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NETWORK\tVIA\tENABLED")
	for _, r := range st.Routes {
		enabled := "yes"
		if !r.Enabled {
			enabled = "no"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.Network, r.Via, enabled)
	}
	_ = w.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func printUsage() {
	fmt.Print(`blinex-agent — Bline-X mesh VPN agent

Usage:
  blinex-agent [-config <path>]      run the agent in the foreground
  blinex-agent status                show this device's mesh status
  blinex-agent peers                 list mesh peers and their data path
  blinex-agent routes                list advertised subnet / exit-node routes
  blinex-agent version               print the agent version

  Windows only, run as Administrator:
  blinex-agent install -setup-key <key> -management-url <host:50051> -signal-url <host:10000>
                        [-stun-url stun:<host:3478> -turn-user <user> -turn-pass <pass>]
                                      install as a Windows Service: starts on
                                      boot and restarts automatically on a
                                      crash; Stop-Service/net stop still works
                                      normally and does not trigger a restart.
                                      Pass the STUN/TURN flags to match your
                                      other agents' config — omitting them
                                      leaves this device with no TURN relay
                                      candidate for ICE, which can prevent it
                                      from ever forming a direct connection
  blinex-agent uninstall             stop and remove the service

Status/peers/routes query the running agent via its control socket
(default ` + controlapi.DefaultSocket + `, override with -socket).
`)
}
