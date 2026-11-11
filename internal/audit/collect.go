package audit

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FirewallStatus separates "there is no firewall" from "we are not allowed to
// look". Only the first one is an alert.
type FirewallStatus struct {
	Active   bool
	Readable bool
}

// CollectFirewall detects the active backend and returns its snapshot.
// Detection prefers the most human-readable source: ufw, then nftables, then
// iptables, then firewalld. A missing backend is not an error, it is "none".
func CollectFirewall(ctx context.Context, r Runner) (*Snapshot, FirewallStatus, error) {
	if out, err := r.Run(ctx, "ufw", "status", "verbose"); err == nil {
		if strings.Contains(string(out), "Status: active") {
			s, perr := ParseUFW(out)
			if perr != nil {
				return nil, FirewallStatus{}, perr
			}
			s.Raw = string(out)
			s.At = time.Now()
			return s, FirewallStatus{Active: true, Readable: true}, nil
		}
	}

	if out, err := r.Run(ctx, "nft", "-j", "list", "ruleset"); err == nil && len(out) > 32 {
		s, perr := ParseNFT(out)
		if perr != nil {
			return nil, FirewallStatus{}, perr
		}
		s.Raw = string(out)
		s.At = time.Now()
		return s, FirewallStatus{Active: true, Readable: true}, nil
	}

	if out, err := r.Run(ctx, "iptables-save"); err == nil {
		s, perr := ParseIptables(out, "ip")
		if perr != nil {
			return nil, FirewallStatus{}, perr
		}
		if v6, err := r.Run(ctx, "ip6tables-save"); err == nil {
			s6, _ := ParseIptables(v6, "ip6")
			if s6 != nil && len(s6.Rules) > 0 {
				s.Rules = append(s.Rules, s6.Rules...)
				s.IPv6Covered = true
			}
		}
		s.Raw = string(out)
		s.At = time.Now()
		s.Finalize(s.At)
		return s, FirewallStatus{Active: len(s.Rules) > 0, Readable: true}, nil
	}

	if out, err := r.Run(ctx, "firewall-cmd", "--list-all"); err == nil && len(strings.TrimSpace(string(out))) > 0 {
		s, perr := ParseFirewalld(out)
		if perr != nil {
			return nil, FirewallStatus{}, perr
		}
		s.Raw = string(out)
		s.At = time.Now()
		return s, FirewallStatus{Active: true, Readable: true}, nil
	}

	readable := true
	if _, err := r.Run(ctx, "nft", "-j", "list", "ruleset"); err != nil && isPermissionErr(err) {
		if _, err2 := r.Run(ctx, "iptables-save"); err2 != nil && isPermissionErr(err2) {
			readable = false
		}
	}
	return &Snapshot{Backend: BackendNone, Policy: map[string]string{}, At: time.Now()}, FirewallStatus{Readable: readable}, nil
}

// isPermissionErr distinguishes "cannot look" from "nothing configured".
func isPermissionErr(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "permission") ||
		strings.Contains(s, "not permitted") ||
		strings.Contains(s, "must be root") ||
		strings.Contains(s, "operation not permitted")
}

// CollectPorts returns listening sockets.
func CollectPorts(ctx context.Context, r Runner) ([]Listen, error) {
	out, err := r.Run(ctx, "ss", "-Htulpen")
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	return ParseSS(out), nil
}

// ParseProbeAddr validates "ip:port" style targets.
func ParseProbeAddr(s string) (string, int, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	return host, p, nil
}

// ProbePorts checks whether each public listener is reachable from outside by
// dialing publicIP:port. Failures are reported as unreachable; callers must
// treat a nil map as "unknown" rather than "closed".
func ProbePorts(ctx context.Context, publicIP string, listens []Listen, timeout time.Duration) map[string]bool {
	if publicIP == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	reach := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for _, l := range listens {
		if !l.Public() {
			continue
		}
		key := l.Proto + "/" + strconv.Itoa(l.Port)
		mu.Lock()
		_, done := reach[key]
		mu.Unlock()
		if done {
			continue
		}

		wg.Add(1)
		go func(l Listen, key string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			dctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			network := "tcp"
			if l.Proto == "udp" {
				// A UDP connect only proves routability, not that anyone listens.
				return
			}
			conn, err := (&net.Dialer{}).DialContext(dctx, network, net.JoinHostPort(publicIP, strconv.Itoa(l.Port)))
			ok := err == nil
			if ok {
				conn.Close()
			}
			mu.Lock()
			reach[key] = ok
			mu.Unlock()
		}(l, key)
	}
	wg.Wait()
	return reach
}
