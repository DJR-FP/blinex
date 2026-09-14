//go:build windows

package dnsconfig

import "testing"

// psQuote feeds adapter aliases straight into a PowerShell command line.
// Aliases are operator-chosen ("Ethernet 2", and apostrophes are legal), so a
// naive concatenation would break the command or, worse, run the rest of the
// alias as script.
func TestPSQuote(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Ethernet", "'Ethernet'"},
		{"Ethernet 2", "'Ethernet 2'"},
		{"Bob's NIC", "'Bob''s NIC'"},
		{"'; Remove-Item C:\\ #", "'''; Remove-Item C:\\ #'"},
	} {
		if got := psQuote(tc.in); got != tc.want {
			t.Errorf("psQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
