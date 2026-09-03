package domain

import "testing"

func TestToDNSLabel(t *testing.T) {
	cases := map[string]string{
		"Laptop":        "laptop",
		"my host.local": "my-host-local",
		"--weird--":     "weird",
	}
	for in, want := range cases {
		if got := ToDNSLabel(in); got != want {
			t.Errorf("ToDNSLabel(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ToDNSLabel(""); got == "" || len(got) < 5 {
		t.Errorf("empty hostname should get a generated label, got %q", got)
	}
}
