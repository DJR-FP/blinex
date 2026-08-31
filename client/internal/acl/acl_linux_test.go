//go:build linux

package acl

import (
	"strings"
	"testing"

	commonv1 "github.com/blinex/gen/common/v1"
)

// captureIptables swaps iptablesRun for a recorder and restores it on cleanup.
func captureIptables(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	orig := iptablesRun
	iptablesRun = func(args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}
	t.Cleanup(func() { iptablesRun = orig })
	return &calls
}

// Regression for the stale-ACL bug (engine.go guarded ApplyRules on
// len(rules) > 0, so deleting the last rule never flushed the chain).
// ApplyRules with an empty ruleset must still flush BLINEX-ACL, and — since
// the default policy is deny — install the terminal DROP and nothing else.
func TestApplyRulesEmptyFlushesChainAndDeniesByDefault(t *testing.T) {
	calls := captureIptables(t)

	if err := ApplyRules(nil, "blinex0"); err != nil {
		t.Fatalf("ApplyRules(nil): %v", err)
	}

	if len(*calls) == 0 || (*calls)[0][0] != "-F" || (*calls)[0][1] != chain {
		t.Fatalf("expected flush of %s first, got %v", chain, *calls)
	}
	terminal := (*calls)[len(*calls)-1]
	if strings.Join(terminal, " ") != "-A "+chain+" -j DROP" {
		t.Fatalf("expected a terminal default-deny with zero rules configured, got %v", *calls)
	}
	for _, c := range (*calls)[1 : len(*calls)-1] {
		if len(c) > 0 && c[0] == "-A" {
			t.Fatalf("empty ruleset must install no rules besides the terminal deny, but appended: %v", c)
		}
	}
}

// With an allow rule present, the chain is flushed, the ACCEPT is installed,
// and a trailing default DROP is appended so anything not explicitly allowed
// is denied.
func TestApplyRulesInstallsAllowThenDefaultDeny(t *testing.T) {
	calls := captureIptables(t)

	rules := []*commonv1.Rule{
		{Src: "100.64.0.8/32", Dst: "100.64.0.7/32", Protocol: "all", Action: "allow", Enabled: true},
	}
	if err := ApplyRules(rules, "blinex0"); err != nil {
		t.Fatalf("ApplyRules: %v", err)
	}

	if (*calls)[0][0] != "-F" {
		t.Fatalf("expected flush first, got %v", (*calls)[0])
	}
	var accepted bool
	for _, c := range *calls {
		if strings.Contains(strings.Join(c, " "), "-j ACCEPT") {
			accepted = true
		}
	}
	if !accepted {
		t.Errorf("expected the configured ACCEPT rule to be installed, calls=%v", *calls)
	}
	terminal := (*calls)[len(*calls)-1]
	if strings.Join(terminal, " ") != "-A "+chain+" -j DROP" {
		t.Errorf("expected trailing default DROP, calls=%v", *calls)
	}
}

// Disabled rules are skipped entirely — only the unconditional terminal deny
// (unrelated to this specific rule) should be present.
func TestApplyRulesSkipsDisabled(t *testing.T) {
	calls := captureIptables(t)

	rules := []*commonv1.Rule{
		{Src: "100.64.0.8/32", Dst: "100.64.0.7/32", Protocol: "all", Action: "deny", Enabled: false},
	}
	if err := ApplyRules(rules, "blinex0"); err != nil {
		t.Fatalf("ApplyRules: %v", err)
	}
	for _, c := range (*calls)[:len(*calls)-1] {
		if strings.Contains(strings.Join(c, " "), "100.64.0.8") {
			t.Fatalf("disabled rule must not be installed, calls=%v", *calls)
		}
	}
}
