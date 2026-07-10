//go:build !linux

package hscontrol

import "syscall"

// TCP_USER_TIMEOUT is Linux-only; other platforms rely on keepalive alone.
func pgsqlDialControl(network, address string, conn syscall.RawConn) error {
	return nil
}
