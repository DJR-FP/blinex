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
	// Subcommands query a running agent over its local control socket.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "status", "peers", "routes":
			runCLI(os.Args[1], os.Args[2:])
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
  blinex-agent [-config <path>]      run the agent (daemon)
  blinex-agent status                show this device's mesh status
  blinex-agent peers                 list mesh peers and their data path
  blinex-agent routes                list advertised subnet / exit-node routes
  blinex-agent version               print the agent version

Subcommands query the running agent via its control socket
(default ` + controlapi.DefaultSocket + `, override with -socket).
`)
}
