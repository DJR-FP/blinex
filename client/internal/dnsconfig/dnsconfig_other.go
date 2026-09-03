//go:build !linux && !windows

package dnsconfig

import (
	"runtime"

	"github.com/rs/zerolog/log"
)

// Neither Apply (kernel-TUN, Linux-only — this build never has a real
// interface anyway) nor ApplyGlobal (netstack) is implemented here yet.
// macOS support is a deliberate next step, not an oversight (see the
// roadmap). Magic DNS and domain filtering still work if the OS is pointed
// at the resolver manually.
func Apply(_, _ string) {
	log.Warn().Str("os", runtime.GOOS).Msg("dnsconfig: automatic DNS configuration not yet implemented on this OS (Magic DNS/domain filtering will only apply if you point your system DNS at the agent manually)")
}

func Revert(_ string) {}

func ApplyGlobal(_ string) {
	log.Warn().Str("os", runtime.GOOS).Msg("dnsconfig: automatic DNS configuration not yet implemented on this OS (Magic DNS/domain filtering will only apply if you point your system DNS at the agent manually)")
}

func RevertGlobal() {}
