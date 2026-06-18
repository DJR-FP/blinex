package state

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type State struct {
	WGPrivateKey       string            `json:"wg_private_key"`                  // base64
	ServerFingerprints map[string]string `json:"server_fingerprints,omitempty"`   // addr → SHA-256 hex
}

// Save persists state to dir/state.json.
func (s *State) Save(dir string) error {
	path := filepath.Join(dir, "state.json")
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

// LoadOrCreate reads persisted state, or creates fresh state if the file doesn't exist.
func LoadOrCreate(dir string) (*State, wgtypes.Key, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, wgtypes.Key{}, fmt.Errorf("creating state dir: %w", err)
	}

	path := filepath.Join(dir, "state.json")
	data, err := os.ReadFile(path)
	if err == nil {
		var s State
		if err := json.Unmarshal(data, &s); err == nil {
			raw, err := base64.StdEncoding.DecodeString(s.WGPrivateKey)
			if err == nil && len(raw) == 32 {
				var key wgtypes.Key
				copy(key[:], raw)
				return &s, key, nil
			}
		}
	}

	// Generate fresh private key.
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, wgtypes.Key{}, fmt.Errorf("generating key: %w", err)
	}

	s := &State{WGPrivateKey: base64.StdEncoding.EncodeToString(privKey[:])}
	if b, err := json.Marshal(s); err == nil {
		_ = os.WriteFile(path, b, 0600)
	}

	return s, privKey, nil
}
