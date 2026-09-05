//go:build windows

package wgmgr

// wintunDLL is the official prebuilt wintun.dll for this architecture,
// embedded so the agent stays a single deployable binary. Declared per-arch
// in wintun_dll_windows_amd64.go / wintun_dll_windows_arm64.go — see
// winassets/WINTUN_LICENSE.txt for its license terms (unmodified,
// redistributable alongside software that only uses its public API, which
// is all wireguard-go's tun package does).
