//go:build !linux

package wgmgr

import (
	"context"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Forwarder is a no-op on non-Linux platforms.
// Traffic forwarding via iptables REDIRECT is not available.
type Forwarder struct{}

func NewForwarder(_ *netstack.Net, _ string) *Forwarder { return &Forwarder{} }
func (f *Forwarder) Start(_ context.Context) error      { return nil }
func (f *Forwarder) Stop()                              {}
