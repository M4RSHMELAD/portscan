// Package portscan checks TCP ports by establishing and closing connections.
package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// State describes the outcome of a check.
type State string

const (
	StateOpen        State = "open"
	StateClosed      State = "closed"
	StateTimeout     State = "timeout"
	StateUnreachable State = "unreachable"
	StateCanceled    State = "canceled"
	StateError       State = "error"
	MaxResultBuffer        = 64
)

// Result describes one port check. An invalid IP indicates a DNS lookup failure.
// Duration measures the TCP dial, or the DNS lookup when IP is invalid.
type Result struct {
	Host     string
	IP       netip.Addr
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}

// Config sets the limits for a Scanner. Both fields must be positive.
type Config struct {
	// Concurrency limits simultaneous TCP connections across all scans.
	Concurrency int
	// ConnectTimeout applies separately to each TCP dial and each DNS lookup.
	ConnectTimeout time.Duration
}

// InputError identifies an invalid argument passed to New or Scan.
type InputError struct {
	Field  string
	Index  int // Index in hosts or ports, or -1 for a scalar argument.
	Reason string
}

func (e *InputError) Error() string {
	if e.Index >= 0 {
		return fmt.Sprintf("%s[%d]: %s", e.Field, e.Index, e.Reason)
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

// Scanner can be reused by concurrent callers. Construct it with New.
type Scanner struct {
	timeout time.Duration
	dials   chan struct{}
	dial    func(context.Context, string, string) (net.Conn, error)
	lookup  func(context.Context, string, string) ([]netip.Addr, error)
}

// New constructs a Scanner with the given limits.
func New(config Config) (*Scanner, error) {
	if config.Concurrency <= 0 {
		return nil, &InputError{"concurrency", -1, "must be positive"}
	}
	if config.ConnectTimeout <= 0 {
		return nil, &InputError{"connectTimeout", -1, "must be positive"}
	}
	return &Scanner{
		timeout: config.ConnectTimeout,
		dials:   make(chan struct{}, config.Concurrency),
		dial:    (&net.Dialer{}).DialContext,
		lookup:  (&net.Resolver{}).LookupNetIP,
	}, nil
}

// Scan validates its arguments and streams one result per unique target, IP
// and port. A failed DNS lookup produces a result per port with no IP.
// Result order is unspecified. Drain the channel or cancel ctx to stop the scan.
// After cancellation, results that would block delivery may be dropped.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports ...PortRange) (<-chan Result, error) {
	if s == nil || s.dials == nil {
		return nil, &InputError{"scanner", -1, "construct with New"}
	}
	if ctx == nil {
		return nil, &InputError{"context", -1, "must not be nil"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	targets, err := parseTargets(hosts)
	if err != nil {
		return nil, err
	}
	numbers, err := expandPorts(ports)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	results := make(chan Result, min(cap(s.dials), MaxResultBuffer))
	go s.run(ctx, targets, numbers, results)
	return results, nil
}

func (s *Scanner) run(ctx context.Context, targets []target, ports []uint16, results chan<- Result) {
	var pending sync.WaitGroup
	defer close(results)
	defer pending.Wait()

	// Bound the work waiting to publish in this scan independently of other scans.
	active := make(chan struct{}, cap(s.dials))
	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}

		addresses, duration, err := s.resolve(ctx, target)
		if err != nil {
			state := classifyError(err)
			for _, port := range ports {
				result := Result{Host: target.host, Port: port, State: state, Duration: duration, Err: err}
				if ctx.Err() != nil || !publish(ctx, results, result) {
					return
				}
			}
			continue
		}

		for _, ip := range addresses {
			for _, port := range ports {
				if !acquire(ctx, active) {
					return
				}
				if !acquire(ctx, s.dials) {
					<-active
					return
				}
				pending.Go(func() {
					defer func() { <-active }()
					result := s.connect(ctx, target.host, ip, port)
					<-s.dials
					publish(ctx, results, result)
				})
			}
		}
	}
}

func (s *Scanner) connect(ctx context.Context, host string, ip netip.Addr, port uint16) Result {
	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	result := Result{Host: host, IP: ip, Port: port}
	if err := dialCtx.Err(); err != nil {
		result.Err = err
		result.State = classifyError(err)
		return result
	}

	address := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	started := time.Now()
	conn, err := s.dial(dialCtx, "tcp", address)
	result.Duration = time.Since(started)
	if err != nil {
		result.Err = err
		result.State = classifyError(err)
		return result
	}
	_ = conn.Close()
	result.State = StateOpen
	return result
}

func acquire(ctx context.Context, slots chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case slots <- struct{}{}:
		if ctx.Err() == nil {
			return true
		}
		<-slots
		return false
	}
}

func publish(ctx context.Context, results chan<- Result, result Result) bool {
	// Keep the result if there's room even when cancellation has just occurred.
	select {
	case results <- result:
		return true
	default:
	}
	select {
	case results <- result:
		return true
	case <-ctx.Done():
		return false
	}
}
