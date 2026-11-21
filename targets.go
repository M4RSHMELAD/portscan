package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

type target struct {
	host string
	ip   netip.Addr
}

func parseTargets(hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, &InputError{"hosts", -1, "must contain at least one host"}
	}
	targets := make([]target, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for i, value := range hosts {
		host := strings.TrimSpace(value)
		ip, err := netip.ParseAddr(host)
		switch {
		case err == nil:
			if strings.ContainsAny(ip.Zone(), "[]%") || strings.ContainsFunc(ip.Zone(), unicode.IsSpace) ||
				strings.ContainsFunc(ip.Zone(), unicode.IsControl) {
				return nil, &InputError{"hosts", i, fmt.Sprintf("invalid IPv6 zone in %q", value)}
			}
			ip = normalizeIP(ip)
			host = ip.String()
		case validDNSName(host):
			host = strings.ToLower(host)
		default:
			return nil, &InputError{"hosts", i, fmt.Sprintf("invalid IP address or DNS name %q", value)}
		}
		if _, exists := seen[host]; !exists {
			seen[host] = struct{}{}
			targets = append(targets, target{host: host, ip: ip})
		}
	}
	return targets, nil
}

func validDNSName(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	nonNumeric := false
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			switch {
			case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch == '-':
				nonNumeric = true
			case ch >= '0' && ch <= '9':
			default:
				return false
			}
		}
	}
	return nonNumeric
}

func normalizeIP(ip netip.Addr) netip.Addr {
	if ip.Zone() != "" {
		return ip
	}
	return ip.Unmap()
}

func (s *Scanner) resolve(ctx context.Context, target target) ([]netip.Addr, time.Duration, error) {
	if target.ip.IsValid() {
		return []netip.Addr{target.ip}, 0, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	started := time.Now()
	addresses, err := s.lookup(lookupCtx, "ip", target.host)
	duration := time.Since(started)
	if err != nil {
		return nil, duration, err
	}
	if len(addresses) == 0 {
		return nil, duration, &net.DNSError{Name: target.host, Err: "no IP addresses", IsNotFound: true}
	}

	unique := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, ip := range addresses {
		ip = normalizeIP(ip)
		if _, exists := seen[ip]; !exists {
			seen[ip] = struct{}{}
			unique = append(unique, ip)
		}
	}
	return unique, duration, nil
}
