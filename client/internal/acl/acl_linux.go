//go:build linux

package acl

import (
	"fmt"
	"os/exec"
	"strings"

	commonv1 "github.com/blinex/gen/common/v1"
	"github.com/rs/zerolog/log"
)

const chain = "BLINEX-ACL"

// iptablesRun executes the iptables binary with the given args. It is a package
// var so tests can substitute a fake without invoking the real binary.
var iptablesRun = func(args ...string) error { return run("iptables", args...) }

// EnsureChain creates the BLINEX-ACL iptables chain and jumps to it from
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

// ApplyRules flushes the BLINEX-ACL chain and reinstalls rules in priority order.
// Only enabled rules are installed. Default is deny: traffic not matched by an
// explicit allow rule above is dropped, even when zero rules are configured at
// all — a fresh account is seeded with one rule permitting Default↔Default so
// this doesn't cut off an otherwise-unconfigured mesh (see domain.Rule).
func ApplyRules(rules []*commonv1.Rule, iface string) error {
	// Flush existing rules
	if err := iptablesRun("-F", chain); err != nil {
		return fmt.Errorf("flush %s: %w", chain, err)
	}

	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		args := buildIPTablesArgs(r, iface)
		if err := iptablesRun(args...); err != nil {
			log.Warn().Err(err).Strs("args", args).Msg("ACL rule install failed")
		}
	}

	// Terminal deny: unconditional, so traffic that matched nothing above —
	// including the zero-rules case — is dropped rather than falling through
	// to the chain's caller (INPUT/FORWARD default ACCEPT policy).
	iptablesRun("-A", chain, "-j", "DROP")

	return nil
}

// RemoveChain tears down the BLINEX-ACL chain completely.
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
