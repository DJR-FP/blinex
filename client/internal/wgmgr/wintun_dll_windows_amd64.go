//go:build windows && amd64

package wgmgr

import _ "embed"

//go:embed winassets/wintun_amd64.dll
var wintunDLL []byte
