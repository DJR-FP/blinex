package tlsconfig

import (
	"os"
	"testing"
)

func TestPersistentCertStableAcrossLoads(t *testing.T) {
	dir, _ := os.MkdirTemp("", "tlstest")
	defer os.RemoveAll(dir)

	c1, ss1, err := Load("", "", dir)
	if err != nil || !ss1 {
		t.Fatalf("load1: err=%v selfSigned=%v", err, ss1)
	}
	c2, _, err := Load("", "", dir)
	if err != nil {
		t.Fatalf("load2: %v", err)
	}
	if string(c1.Certificates[0].Certificate[0]) != string(c2.Certificates[0].Certificate[0]) {
		t.Fatal("cert changed between loads — persistence not working")
	}
	t.Log("cert stable across reloads ✓")
}

func TestEphemeralCertChangesWithoutDir(t *testing.T) {
	c1, _, _ := Load("", "", "")
	c2, _, _ := Load("", "", "")
	if string(c1.Certificates[0].Certificate[0]) == string(c2.Certificates[0].Certificate[0]) {
		t.Fatal("expected different ephemeral certs with empty dir")
	}
	t.Log("ephemeral certs differ as expected ✓")
}
