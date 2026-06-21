package wgmgr

import "golang.org/x/sys/unix"

func mknodTUN() error {
	return unix.Mknod("/dev/net/tun", unix.S_IFCHR|0666, int(unix.Mkdev(10, 200)))
}
