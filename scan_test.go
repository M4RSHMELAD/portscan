package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func newScanner(t *testing.T, concurrency int, timeout time.Duration) *Scanner {
	t.Helper()
	scanner, err := New(Config{Concurrency: concurrency, ConnectTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return scanner
}

func scan(t *testing.T, scanner *Scanner, ctx context.Context, hosts []string, ports ...PortRange) <-chan Result {
	t.Helper()
	results, err := scanner.Scan(ctx, hosts, ports...)
	if err != nil {
		t.Fatal(err)
	}
	return results
}

func TestScanLoopback(t *testing.T) {
	for _, test := range []struct{ network, host string }{
		{"tcp4", "127.0.0.1"},
		{"tcp6", "::1"},
	} {
		t.Run(test.network, func(t *testing.T) {
			ip := netip.MustParseAddr(test.host)
			listener, err := net.ListenTCP(test.network, net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
			if err != nil && test.network == "tcp6" {
				t.Skipf("IPv6 loopback unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			port := listener.Addr().(*net.TCPAddr).AddrPort().Port()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			scanner := newScanner(t, 2, time.Second)
			for _, want := range []State{StateOpen, StateClosed} {
				results := scan(t, scanner, ctx, []string{test.host}, Port(int(port)))
				result, ok := <-results
				if !ok || result.IP != ip || result.Port != port || result.State != want ||
					(result.Err == nil) != (want == StateOpen) {
					t.Fatalf("got %+v (ok=%t), want %v on %v:%d", result, ok, want, ip, port)
				}
				if extra, ok := <-results; ok {
					t.Fatalf("unexpected result: %+v", extra)
				}

				if want == StateOpen {
					if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					conn, err := listener.AcceptTCP()
					if err != nil {
						t.Fatal(err)
					}
					if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
						conn.Close()
						t.Fatal(err)
					}
					data, err := io.ReadAll(conn)
					conn.Close()
					if err != nil || len(data) != 0 {
						t.Fatalf("expected EOF without payload, got %q, %v", data, err)
					}
					if err := listener.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestScanDNSAndDuplicates(t *testing.T) {
	v4 := netip.MustParseAddr("127.0.0.1")
	v6 := netip.MustParseAddr("::1")
	scanner := newScanner(t, 4, time.Second)
	lookedUp := []string{}
	dnsErr := &net.DNSError{Name: "123-45", Err: "NXDOMAIN", IsNotFound: true}
	scanner.lookup = func(_ context.Context, network, host string) ([]netip.Addr, error) {
		lookedUp = append(lookedUp, host)
		if network != "ip" {
			t.Errorf("unexpected DNS network %q", network)
		}
		if host == "dual.example." {
			return []netip.Addr{v4, v6, netip.MustParseAddr("::ffff:127.0.0.1"), v6}, nil
		}
		return nil, dnsErr
	}
	scanner.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || !(strings.HasPrefix(address, "127.0.0.1:") || strings.HasPrefix(address, "[::1]:")) {
			t.Errorf("unexpected dial: %s %s", network, address)
		}
		return nil, syscall.ECONNREFUSED
	}
	hosts := []string{" DUAL.Example. ", "dual.example.", "123-45", "::ffff:127.0.0.1", "127.0.0.1"}
	results := scan(t, scanner, t.Context(), hosts, Range(82, 83), Port(81), Range(80, 82))
	type key struct {
		host string
		ip   netip.Addr
		port uint16
	}
	want := make(map[key]State)
	for port := uint16(80); port <= 83; port++ {
		want[key{"dual.example.", v4, port}] = StateClosed
		want[key{"dual.example.", v6, port}] = StateClosed
		want[key{"123-45", netip.Addr{}, port}] = StateError
		want[key{"127.0.0.1", v4, port}] = StateClosed
	}
	for result := range results {
		k := key{result.Host, result.IP, result.Port}
		if want[k] != result.State || result.State == "" {
			t.Errorf("unexpected or duplicate result: %+v", result)
		}
		if !result.IP.IsValid() && !errors.Is(result.Err, dnsErr) {
			t.Errorf("expected DNS error, got %v", result.Err)
		}
		delete(want, k)
	}
	if len(want) != 0 || !slices.Equal(lookedUp, []string{"dual.example.", "123-45"}) {
		t.Fatalf("missing results: %v, lookups: %v", want, lookedUp)
	}
}

func TestScanValidation(t *testing.T) {
	scanner := newScanner(t, 1, time.Second)
	for _, test := range []struct {
		name  string
		hosts []string
		ports []PortRange
		field string
		index int
	}{
		{"no hosts", nil, []PortRange{Port(80)}, "hosts", -1},
		{"blank host", []string{" "}, []PortRange{Port(80)}, "hosts", 0},
		{"invalid v4", []string{"127.0.0.1", "127.0.0.256"}, []PortRange{Port(80)}, "hosts", 1},
		{"invalid v6", []string{"[::1]:80"}, []PortRange{Port(80)}, "hosts", 0},
		{"invalid DNS", []string{"host..example"}, []PortRange{Port(80)}, "hosts", 0},
		{"no ports", []string{"::1"}, nil, "ports", -1},
		{"port zero", []string{"::1"}, []PortRange{Port(0)}, "ports", 0},
		{"port overflow", []string{"::1"}, []PortRange{Port(65536)}, "ports", 0},
		{"reversed range", []string{"::1"}, []PortRange{Port(1), Range(1000, 1)}, "ports", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			results, err := scanner.Scan(t.Context(), test.hosts, test.ports...)
			var input *InputError
			if results != nil || !errors.As(err, &input) || input.Field != test.field || input.Index != test.index {
				t.Fatalf("got %v, %v, want input error (%s, %d)", results, err, test.field, test.index)
			}
		})
	}

	for _, config := range []Config{{0, time.Second}, {1, 0}} {
		if scanner, err := New(config); scanner != nil || err == nil {
			t.Errorf("invalid config accepted: %+v", config)
		}
	}
	if results, err := scanner.Scan(nil, []string{"::1"}, Port(80)); results != nil || err == nil {
		t.Errorf("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if results, err := scanner.Scan(ctx, []string{"::1"}, Port(80)); results != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("already canceled context: got %v, %v", results, err)
	}
}

func TestExpandAllPorts(t *testing.T) {
	ports, err := expandPorts([]PortRange{Range(2, 65533), Range(100, 110), Port(1), Range(65532, 65535)})
	if err != nil || len(ports) != 65535 {
		t.Fatalf("got %d ports, error %v", len(ports), err)
	}
	for i, port := range ports {
		if int(port) != i+1 {
			t.Fatalf("port at %d = %d", i, port)
		}
	}
}

func TestScanSharesConcurrencyLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		scanner := newScanner(t, 2, time.Second)
		var active atomic.Int32
		release := make(chan struct{})
		scanner.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
			if count := active.Add(1); count > 2 {
				t.Errorf("too many parallel dials: %d", count)
			}
			<-release
			active.Add(-1)
			return nil, syscall.ECONNREFUSED
		}

		first := scan(t, scanner, t.Context(), []string{"127.0.0.1"}, Range(1, 4))
		second := scan(t, scanner, t.Context(), []string{"::1"}, Range(1, 4))
		synctest.Wait()
		if count := active.Load(); count != 2 {
			t.Errorf("expected 2 parallel dials, got %d", count)
		}
		close(release)
		for _, results := range []<-chan Result{first, second} {
			var count int
			for range results {
				count++
			}
			if count != 4 {
				t.Errorf("got %d results, want 4", count)
			}
		}
	})
}

func TestScanSlowReaderAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		scanner := newScanner(t, 1, time.Second)
		var firstDials atomic.Int32
		scanner.dial = func(_ context.Context, _, address string) (net.Conn, error) {
			if strings.HasPrefix(address, "127.0.0.1:") {
				firstDials.Add(1)
			}
			return nil, syscall.ECONNREFUSED
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		first := scan(t, scanner, ctx, []string{"127.0.0.1"}, Range(1, 65535))
		synctest.Wait()
		if count := firstDials.Load(); count != 2 {
			t.Errorf("expected backpressure after 2 dials, got %d", count)
		}

		second := scan(t, scanner, t.Context(), []string{"::1"}, Port(80))
		var secondResults int
		for result := range second {
			if result.State != StateClosed {
				t.Errorf("unexpected second scan result: %+v", result)
			}
			secondResults++
		}
		if secondResults != 1 {
			t.Errorf("second scan returned %d results, want 1", secondResults)
		}
		cancel()
		synctest.Wait()
		if result := <-first; result.State != StateClosed {
			t.Errorf("unexpected buffered result: %+v", result)
		}
		select {
		case result, ok := <-first:
			if ok {
				t.Errorf("unexpected result after cancellation with a full buffer: %+v", result)
			}
		default:
			t.Error("result channel should close while the reader is paused")
		}
		if count := firstDials.Load(); count != 2 {
			t.Errorf("scheduled more dials after cancellation: %d", count)
		}
	})
}

func TestScanCancelsInFlightDials(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		scanner := newScanner(t, 2, time.Second)
		var started atomic.Int32
		scanner.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			started.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		results := scan(t, scanner, ctx, []string{"127.0.0.1"}, Range(1, 10))
		synctest.Wait()
		cancel()
		var canceled int
		for result := range results {
			if result.State != StateCanceled || !errors.Is(result.Err, context.Canceled) {
				t.Errorf("unexpected result: %+v", result)
			}
			canceled++
		}
		if canceled != 2 || started.Load() != 2 {
			t.Errorf("started %d dials and got %d results, want 2 each", started.Load(), canceled)
		}
	})
}

func TestScanCancelsDNSLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		scanner := newScanner(t, 2, time.Second)
		var lookups atomic.Int32
		scanner.lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			lookups.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		scanner.dial = func(_ context.Context, _, address string) (net.Conn, error) {
			t.Errorf("unexpected dial: %s", address)
			return nil, syscall.ECONNREFUSED
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		results := scan(t, scanner, ctx, []string{"slow.example", "later.example", "::1"}, Port(80))
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case result, ok := <-results:
			if ok {
				t.Errorf("unexpected port result when DNS is canceled: %+v", result)
			}
		default:
			t.Error("result channel should close after the DNS lookup is canceled")
		}
		if count := lookups.Load(); count != 1 {
			t.Errorf("started %d lookups, want 1", count)
		}
	})
}

func TestScanTimeouts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 75 * time.Millisecond
		scanner := newScanner(t, 2, timeout)
		scanner.lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		scanner.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		results := scan(t, scanner, t.Context(), []string{"slow.example", "::1"}, Range(80, 81))
		counts := make(map[string]int)
		for result := range results {
			if result.State != StateTimeout || result.Duration != timeout ||
				!errors.Is(result.Err, context.DeadlineExceeded) || result.IP.IsValid() != (result.Host == "::1") {
				t.Errorf("unexpected timeout result: %+v", result)
			}
			counts[result.Host]++
		}
		if counts["slow.example"] != 2 || counts["::1"] != 2 {
			t.Errorf("unexpected counts: %v", counts)
		}
	})
}

func TestClassifyWrappedErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want State
	}{
		{syscall.ECONNREFUSED, StateClosed},
		{syscall.EHOSTUNREACH, StateUnreachable},
		{syscall.ENETUNREACH, StateUnreachable},
		{syscall.ETIMEDOUT, StateTimeout},
		{context.Canceled, StateCanceled},
		{context.DeadlineExceeded, StateTimeout},
		{&net.DNSError{IsTimeout: true}, StateTimeout},
		{errors.New("connection refused"), StateError},
		{syscall.ECONNRESET, StateError},
	} {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", test.err)}
		if got := classifyError(err); got != test.want {
			t.Errorf("classifyError(%v) = %s, want %s", err, got, test.want)
		}
	}
}
