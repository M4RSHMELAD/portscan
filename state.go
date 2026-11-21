package portscan

import (
	"context"
	"errors"
	"net"
	"syscall"
)

func classifyError(err error) State {
	var networkErr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return StateCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return StateTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return StateClosed
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETDOWN), errors.Is(err, syscall.EHOSTDOWN):
		return StateUnreachable
	case errors.As(err, &networkErr) && networkErr.Timeout():
		return StateTimeout
	default:
		return platformState(err)
	}
}
