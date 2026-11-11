// Package transport hides how a payload reaches the center. The agent only
// depends on Transport; switching between direct, Tailscale, proxy or a unix
// socket is a configuration change (see ADR-004).
package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yqjwxz/beacon/internal/version"
)

// Transport delivers one compressed write request.
type Transport interface {
	Name() string
	Send(ctx context.Context, payload []byte) error
	Close() error
}

// Config is the resolved transport configuration.
type Config struct {
	Endpoint string
	Token    string
	Dial     string
	ProxyURL string
	Timeout  time.Duration
}

// HTTPError carries the status so callers can decide whether to retry.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("remote write rejected: status %d: %s", e.Status, strings.TrimSpace(e.Body))
}

// Retryable reports whether retrying later could succeed. 4xx (except 429) is
// a permanent configuration problem.
func (e *HTTPError) Retryable() bool {
	if e.Status == http.StatusTooManyRequests {
		return true
	}
	return e.Status >= 500
}

// Retryable reports whether err is worth retrying.
func Retryable(err error) bool {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Retryable()
	}
	// Network errors are retryable by default.
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	return !errors.Is(err, context.Canceled)
}

type httpTransport struct {
	cfg    Config
	client *http.Client
	url    string
}

func New(cfg Config) (Transport, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Dial == "" {
		cfg.Dial = "direct"
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("invalid endpoint %q: missing scheme", cfg.Endpoint)
	}
	if u.Scheme == "unix" {
		cfg.Dial = "unix"
	}

	dialer, err := newDialer(cfg, u)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          4,
		ForceAttemptHTTP2:     true,
	}
	if u.Scheme == "unix" {
		tr.ForceAttemptHTTP2 = false
	}
	if cfg.ProxyURL != "" {
		pu, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}

	return &httpTransport{
		cfg:    cfg,
		url:    endpointURL(u),
		client: &http.Client{Transport: tr, Timeout: cfg.Timeout},
	}, nil
}

// endpointURL converts unix:///path into an HTTP URL the dialer understands.
func endpointURL(u *url.URL) string {
	if u.Scheme == "unix" {
		return "http://unix" + u.Path
	}
	return u.String()
}

func (t *httpTransport) Name() string { return "http/" + t.cfg.Dial }

func (t *httpTransport) Send(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	req.Header.Set("User-Agent", "beacon/"+version.Version)
	if t.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.cfg.Token)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Status: resp.StatusCode, Body: string(body)}
	}
	return nil
}

func (t *httpTransport) Close() error {
	t.client.CloseIdleConnections()
	return nil
}

// dialer is net.Dialer compatible so http.Transport can use it directly.
type dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

func newDialer(cfg Config, u *url.URL) (dialer, error) {
	base := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
	switch cfg.Dial {
	case "direct", "system":
		// "system" intentionally behaves like direct: Tailscale is transparent
		// once the host is in a tailnet, because the OS handles routing.
		return base, nil
	case "proxy":
		if cfg.ProxyURL == "" {
			return nil, fmt.Errorf("dial=proxy requires transport.proxy_url")
		}
		return base, nil
	case "unix":
		if u.Path == "" {
			return nil, fmt.Errorf("unix endpoint requires a path")
		}
		return &unixDialer{base: base, path: u.Path}, nil
	case "tsnet":
		return nil, fmt.Errorf("dial=tsnet is not implemented yet (planned for M6)")
	default:
		return nil, fmt.Errorf("unsupported dial %q", cfg.Dial)
	}
}

// unixDialer dials a unix socket regardless of the HTTP host.
type unixDialer struct {
	base *net.Dialer
	path string
}

func (d *unixDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return d.base.DialContext(ctx, "unix", d.path)
}
