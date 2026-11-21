package portscan

import (
	"errors"
	"syscall"
)

func platformState(err error) State {
	// These Winsock errors have different values from the POSIX errno constants.
	const (
		wsaNetDown     syscall.Errno = 10050
		wsaNetUnreach  syscall.Errno = 10051
		wsaTimedOut    syscall.Errno = 10060
		wsaConnRefused syscall.Errno = 10061
		wsaHostDown    syscall.Errno = 10064
		wsaHostUnreach syscall.Errno = 10065
	)
	switch {
	case errors.Is(err, wsaTimedOut):
		return StateTimeout
	case errors.Is(err, wsaConnRefused):
		return StateClosed
	case errors.Is(err, wsaNetDown), errors.Is(err, wsaNetUnreach),
		errors.Is(err, wsaHostDown), errors.Is(err, wsaHostUnreach):
		return StateUnreachable
	default:
		return StateError
	}
}
