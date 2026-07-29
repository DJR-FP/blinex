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
// ApplyRules with an empty ruleset must still flush BLINEX-ACL and install
// nothing — i.e. deleting all rules clears enforcement.
func TestApplyRulesEmptyFlushesChain(t *testing.T) {
	calls := captureIptables(t)

	if err := ApplyRules(nil, "blinex0"); err != nil {
		t.Fatalf("ApplyRules(nil): %v", err)
	}

	if len(*calls) == 0 || (*calls)[0][0] != "-F" || (*calls)[0][1] != chain {
		t.Fatalf("expected flush of %s first, got %v", chain, *calls)
	}
	for _, c := range (*calls)[1:] {
		if len(c) > 0 && c[0] == "-A" {
			t.Fatalf("empty ruleset must install no rules, but appended: %v", c)
		}
	}
}

// With a deny rule present, the chain is flushed, the DROP is installed, and a
// trailing default ACCEPT is appended so allow-exceptions can pass.
func TestApplyRulesInstallsDenyThenDefaultAccept(t *testing.T) {
	calls := captureIptables(t)

	rules := []*commonv1.Rule{
		{Src: "100.64.0.8/32", Dst: "100.64.0.7/32", Protocol: "all", Action: "deny", Enabled: true},
	}
	if err := ApplyRules(rules, "blinex0"); err != nil {
		t.Fatalf("ApplyRules: %v", err)
	}

	if (*calls)[0][0] != "-F" {
		t.Fatalf("expected flush first, got %v", (*calls)[0])
	}
	var dropped, accepted bool
	for _, c := range *calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "DROP") {
			dropped = true
		}
		if strings.Contains(j, "-j ACCEPT") {
			accepted = true
		}
	}
	if !dropped {
		t.Errorf("expected a DROP rule to be installed, calls=%v", *calls)
	}
	if !accepted {
		t.Errorf("expected trailing default ACCEPT, calls=%v", *calls)
	}
}

// Disabled rules are skipped entirely.
func TestApplyRulesSkipsDisabled(t *testing.T) {
	calls := captureIptables(t)

	rules := []*commonv1.Rule{
		{Src: "100.64.0.8/32", Dst: "100.64.0.7/32", Protocol: "all", Action: "deny", Enabled: false},
	}
	if err := ApplyRules(rules, "blinex0"); err != nil {
		t.Fatalf("ApplyRules: %v", err)
	}
	for _, c := range *calls {
		if strings.Contains(strings.Join(c, " "), "DROP") {
			t.Fatalf("disabled rule must not be installed, calls=%v", *calls)
		}
	}
}
