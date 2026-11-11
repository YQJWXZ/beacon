package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"
)

// StepResult is one layer of the connectivity check.
type StepResult struct {
	Name     string
	OK       bool
	Duration time.Duration
	Err      error
}

// Probe checks the transport layer by layer: endpoint, DNS, TCP, TLS, write.
// It stops at the first failure so the output points at the real cause.
func Probe(ctx context.Context, cfg Config, payload []byte) []StepResult {
	var out []StepResult
	add := func(name string, start time.Time, err error) bool {
		out = append(out, StepResult{Name: name, OK: err == nil, Duration: time.Since(start), Err: err})
		return err == nil
	}

	start := time.Now()
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme == "" {
		add("endpoint", start, fmt.Errorf("invalid endpoint %q", cfg.Endpoint))
		return out
	}
	add("endpoint", start, nil)

	if u.Scheme == "unix" {
		d, derr := newDialer(cfg, u)
		if derr != nil {
			add("dial", time.Now(), derr)
			return out
		}
		start = time.Now()
		conn, derr := d.DialContext(ctx, "unix", u.Path)
		if !add("dial", start, derr) {
			return out
		}
		conn.Close()
	} else {
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}

		if net.ParseIP(host) == nil {
			start = time.Now()
			_, derr := net.DefaultResolver.LookupHost(ctx, host)
			if !add("resolve", start, derr) {
				return out
			}
		}

		d, derr := newDialer(cfg, u)
		if derr != nil {
			add("dial", time.Now(), derr)
			return out
		}
		start = time.Now()
		conn, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if !add("dial", start, derr) {
			return out
		}
		defer conn.Close()

		if u.Scheme == "https" {
			start = time.Now()
			tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
			terr := tc.HandshakeContext(ctx)
			if !add("tls", start, terr) {
				return out
			}
		}
	}

	start = time.Now()
	tr, err := New(cfg)
	if err != nil {
		add("write", start, err)
		return out
	}
	defer tr.Close()
	add("write", start, tr.Send(ctx, payload))
	return out
}
