//go:build windows && arm64

package wgmgr

import _ "embed"

//go:embed winassets/wintun_arm64.dll
var wintunDLL []byte
