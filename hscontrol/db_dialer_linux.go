//go:build linux

package hscontrol

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// pgsqlDialControl caps the time a TCP connection may hold unacknowledged
// data (TCP_USER_TIMEOUT). Keepalive probes only run on idle sockets; a
// write into a black-holed connection is otherwise retried by the kernel
// for ~15 minutes before failing.
func pgsqlDialControl(network, address string, conn syscall.RawConn) error {
	var sockErr error
	err := conn.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(
			int(fd),
			unix.IPPROTO_TCP,
			unix.TCP_USER_TIMEOUT,
			int(_pgsqlTCPUserTimeout.Milliseconds()),
		)
	})
	if err != nil {
		return err
	}

	return sockErr
}
