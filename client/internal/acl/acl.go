package acl

import (
	"fmt"
	"os/exec"
	"strings"

	commonv1 "github.com/meshnet/gen/common/v1"
	"github.com/rs/zerolog/log"
)

const chain = "MESHNET-ACL"

// EnsureChain creates the MESHNET-ACL iptables chain and jumps to it from
// INPUT and FORWARD if not already present.
func EnsureChain(iface string) error {
	// Create chain (ignore error if it already exists)
	run("iptables", "-N", chain)

	// Jump to chain from INPUT if not already there
	if !ruleExists("-A", "INPUT", "-i", iface, "-j", chain) {
		if err := run("iptables", "-A", "INPUT", "-i", iface, "-j", chain); err != nil {
			return fmt.Errorf("jump INPUT→%s: %w", chain, err)
		}
	}
	// Jump to chain from FORWARD if not already there
	if !ruleExists("-A", "FORWARD", "-i", iface, "-j", chain) {
		if err := run("iptables", "-A", "FORWARD", "-i", iface, "-j", chain); err != nil {
			return fmt.Errorf("jump FORWARD→%s: %w", chain, err)
		}
	}
	return nil
}

// ApplyRules flushes the MESHNET-ACL chain and reinstalls rules in priority order.
// Only enabled rules are installed. If no deny rules exist the default is allow-all.
func ApplyRules(rules []*commonv1.Rule, iface string) error {
	// Flush existing rules
	if err := run("iptables", "-F", chain); err != nil {
		return fmt.Errorf("flush %s: %w", chain, err)
	}

	hasDeny := false
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if r.Action == "deny" {
			hasDeny = true
		}
		args := buildIPTablesArgs(r, iface)
		if err := run("iptables", args...); err != nil {
			log.Warn().Err(err).Strs("args", args).Msg("ACL rule install failed")
		}
	}

	// If any deny rules exist, add a default ACCEPT at the end so explicitly
	// allowed traffic passes through after deny rules are evaluated.
	if hasDeny {
		run("iptables", "-A", chain, "-j", "ACCEPT")
	}

	return nil
}

// RemoveChain tears down the MESHNET-ACL chain completely.
func RemoveChain(iface string) {
	run("iptables", "-D", "INPUT", "-i", iface, "-j", chain)
	run("iptables", "-D", "FORWARD", "-i", iface, "-j", chain)
	run("iptables", "-F", chain)
	run("iptables", "-X", chain)
}

func buildIPTablesArgs(r *commonv1.Rule, iface string) []string {
	args := []string{"-A", chain, "-i", iface}

	if r.Src != "" && r.Src != "*" {
		args = append(args, "-s", r.Src)
	}
	if r.Dst != "" && r.Dst != "*" {
		args = append(args, "-d", r.Dst)
	}

	proto := strings.ToLower(r.Protocol)
	if proto != "" && proto != "all" {
		args = append(args, "-p", proto)
		if r.Port > 0 && (proto == "tcp" || proto == "udp") {
			args = append(args, "--dport", fmt.Sprintf("%d", r.Port))
		}
	}

	target := "ACCEPT"
	if r.Action == "deny" {
		target = "DROP"
	}
	args = append(args, "-j", target)
	return args
}

func ruleExists(args ...string) bool {
	checkArgs := make([]string, 0, len(args)+1)
	// Replace -A with -C to check existence
	for _, a := range args {
		if a == "-A" {
			checkArgs = append(checkArgs, "-C")
		} else {
			checkArgs = append(checkArgs, a)
		}
	}
	return exec.Command("iptables", checkArgs...).Run() == nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}
