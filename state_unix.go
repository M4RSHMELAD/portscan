//go:build unix

package portscan

func platformState(error) State {
	return StateError
}
