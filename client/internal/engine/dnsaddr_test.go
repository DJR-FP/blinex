package engine

import "testing"

// meshDNSAddr feeds dnsconfig.Apply, which points the host's *only* DNS route
// at whatever comes out. The first live run of this fix got it wrong — the
// management server sends a CIDR, so the bind address came out as
// "100.64.0.9/32:53535" and the listener refused to bind — so pin the shape.
func TestMeshDNSAddr(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		wantErr        bool
	}{
		{name: "cidr as the server actually sends it", in: "100.64.0.9/32", want: "100.64.0.9:53535"},
		{name: "wider prefix", in: "100.64.0.9/10", want: "100.64.0.9:53535"},
		{name: "bare IP tolerated", in: "100.64.0.9", want: "100.64.0.9:53535"},
		{name: "empty", in: "", wantErr: true},
		{name: "garbage", in: "not-an-address", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := meshDNSAddr(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("meshDNSAddr(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
