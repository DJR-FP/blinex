package wgmgr

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// getOriginalDst retrieves the original destination of a connection that was
// redirected via iptables REDIRECT (SO_ORIGINAL_DST).
func getOriginalDst(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return "", err
	}

	var addr syscall.RawSockaddrInet4
	var getErr error
	err = raw.Control(func(fd uintptr) {
		addrLen := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IP,
			80, // SO_ORIGINAL_DST
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			getErr = errno
		}
	})
	if err != nil {
		return "", err
	}
	if getErr != nil {
		return "", getErr
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8) | int(addr.Port&0xff)<<8
	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}
