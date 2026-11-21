package portscan

import (
	"cmp"
	"fmt"
	"slices"
)

// PortRange is an inclusive interval of ports. Use Port or Range to create one.
type PortRange struct {
	first, last int
}

// Port selects an individual port for Scan.
func Port(number int) PortRange {
	return Range(number, number)
}

// Range selects all ports from first through last. Scan validates the bounds.
func Range(first, last int) PortRange {
	return PortRange{first, last}
}

func expandPorts(ranges []PortRange) ([]uint16, error) {
	if len(ranges) == 0 {
		return nil, &InputError{"ports", -1, "must contain at least one port or range"}
	}
	for i, span := range ranges {
		if span.first < 1 || span.last > 65535 || span.first > span.last {
			reason := fmt.Sprintf("invalid range %d–%d (expected 1 <= first <= last <= 65535)", span.first, span.last)
			return nil, &InputError{"ports", i, reason}
		}
	}

	sorted := slices.Clone(ranges)
	slices.SortFunc(sorted, func(a, b PortRange) int {
		return cmp.Compare(a.first, b.first)
	})
	var ports []uint16
	next := 1
	for _, span := range sorted {
		for port := max(next, span.first); port <= span.last; port++ {
			ports = append(ports, uint16(port))
		}
		next = max(next, span.last+1)
	}
	return ports, nil
}
