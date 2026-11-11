package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"

	"github.com/yqjwxz/beacon/internal/capability"
	"github.com/yqjwxz/beacon/internal/collector"
	"github.com/yqjwxz/beacon/internal/config"
	"github.com/yqjwxz/beacon/internal/procfs"
	"github.com/yqjwxz/beacon/internal/promwrite"
	"github.com/yqjwxz/beacon/internal/shipper"
	"github.com/yqjwxz/beacon/internal/transport"
	"github.com/yqjwxz/beacon/internal/version"
)

type Agent struct {
	cfg  *config.Config
	log  *slog.Logger
	src  *procfs.Source
	caps *capability.Set
	self *Self
	reg  *prometheus.Registry
	cols []collector.Collector

	tr   transport.Transport
	ship *shipper.Shipper

	mu       sync.Mutex
	streak   map[string]int
	lastBeat time.Time
}

func New(cfg *config.Config, log *slog.Logger) (*Agent, error) {
	src := procfs.New(cfg.Agent.ProcFS, cfg.Agent.SysFS)
	a := &Agent{
		cfg:    cfg,
		log:    log,
		src:    src,
		caps:   capability.NewSet(cfg.Agent.Host),
		self:   NewSelf(cfg.Agent.Host, version.Version, version.Commit),
		reg:    prometheus.NewRegistry(),
		streak: map[string]int{},
	}
	a.cols = []collector.Collector{
		collector.NewCPU(src, cfg.Agent.Host, cfg.Agent.Intervals.Fast.D()),
		collector.NewMem(src, cfg.Agent.Host, cfg.Agent.Intervals.Fast.D()),
		collector.NewNet(src, cfg.Agent.Host, cfg.Agent.Intervals.Fast.D()),
		collector.NewDisk(src, cfg.Agent.Host, cfg.Agent.Intervals.Normal.D(), mustRegexp(cfg.Agent.DiskMountExclude)),
	}
	for _, c := range a.cols {
		a.reg.MustRegister(c)
	}
	a.reg.MustRegister(a.self)
	a.reg.MustRegister(capability.NewExporter(a.caps))

	if cfg.Transport.Endpoint != "" {
		// A credential from enrollment wins over a static config token.
		if cfg.Transport.Token == "" {
			if c, err := LoadCredentials(cfg.Agent.StateDir); err == nil && c.Token != "" {
				cfg.Transport.Token = c.Token
				if cfg.Agent.Host == "" {
					cfg.Agent.Host = c.Host
				}
			}
		}
		tr, err := transport.New(transport.Config{
			Endpoint: cfg.Transport.Endpoint,
			Token:    cfg.Transport.Token,
			Dial:     cfg.Transport.Dial,
			ProxyURL: cfg.Transport.ProxyURL,
			Timeout:  cfg.Transport.Timeout.D(),
		})
		if err != nil {
			return nil, fmt.Errorf("transport: %w", err)
		}
		sh, err := shipper.New(shipper.Options{
			Dir:      filepath.Join(cfg.Agent.StateDir, "wal"),
			MaxBytes: cfg.Agent.WAL.MaxBytes,
			SegSize:  cfg.Agent.WAL.SegmentBytes,
			Batch:    200,
		}, tr, log)
		if err != nil {
			return nil, fmt.Errorf("shipper: %w", err)
		}
		a.tr = tr
		a.ship = sh
	}
	return a, nil
}

func (a *Agent) Capabilities() *capability.Set { return a.caps }

// Probe performs one-shot capability detection with a bounded metadata request.
func (a *Agent) Probe(ctx context.Context) {
	timeout := 300 * time.Millisecond
	if !a.cfg.Agent.MetadataProbe {
		timeout = 0
	}
	a.caps.Probe(ctx, a.src, timeout)
}

func (a *Agent) Run(ctx context.Context) error {
	a.Probe(ctx)

	for _, w := range a.cfg.Warnings() {
		a.log.Warn("config", "warning", w)
	}
	a.log.Info("agent starting",
		"host", a.cfg.Agent.Host,
		"version", version.Version,
		"commit", version.Commit,
		"collectors", len(a.cols),
	)

	var wg sync.WaitGroup
	for _, c := range a.cols {
		wg.Add(1)
		go func(c collector.Collector) {
			defer wg.Done()
			a.schedule(ctx, c)
		}(c)
	}

	if a.ship != nil {
		a.log.Info("shipping enabled",
			"endpoint", a.cfg.Transport.Endpoint,
			"dial", a.cfg.Transport.Dial,
			"wal", filepath.Join(a.cfg.Agent.StateDir, "wal"),
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.ship.Run(ctx)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.shipLoop(ctx)
		}()
	}

	var srv *http.Server
	if a.cfg.Agent.Metrics.Enabled {
		ln, err := net.Listen("tcp", a.cfg.Agent.Metrics.Listen)
		if err != nil {
			return fmt.Errorf("listen %s: %w", a.cfg.Agent.Metrics.Listen, err)
		}
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(a.reg, promhttp.HandlerOpts{}))
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok\n"))
		})
		srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		a.log.Info("metrics endpoint listening", "addr", ln.Addr().String())
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				a.log.Error("metrics server", "err", err)
			}
		}()
	}

	<-ctx.Done()
	a.log.Info("shutting down")
	if srv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}
	wg.Wait()
	if a.ship != nil {
		if err := a.ship.Close(); err != nil {
			a.log.Warn("close wal", "err", err)
		}
	}
	if a.tr != nil {
		_ = a.tr.Close()
	}
	return nil
}

// shipLoop snapshots the registry, encodes it and appends to the WAL. The
// shipper drains the WAL independently, so a network outage never blocks
// collection.
func (a *Agent) shipLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.Agent.Intervals.Fast.D())
	defer t.Stop()
	a.shipOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.shipOnce(ctx)
		}
	}
}

func (a *Agent) shipOnce(ctx context.Context) {
	if a.ship == nil {
		return
	}
	mfs, err := a.reg.Gather()
	if err != nil {
		a.log.Warn("gather for shipping", "err", err)
		return
	}
	ts := time.Now().UnixMilli()
	series := promwrite.FromFamilies(mfs, ts)

	a.mu.Lock()
	beat := time.Since(a.lastBeat) >= a.cfg.Agent.Heartbeat.D()
	if beat {
		a.lastBeat = time.Now()
	}
	a.mu.Unlock()
	if beat {
		series = append(series, promwrite.Gauge("beacon_agent_heartbeat",
			map[string]string{"host": a.cfg.Agent.Host}, float64(ts)/1000, ts))
	}

	payload, err := promwrite.Marshal(series)
	if err != nil {
		a.log.Warn("encode batch", "err", err)
		return
	}
	if err := a.ship.Append(payload); err != nil {
		a.log.Warn("append to wal", "err", err)
	}
	a.self.SetBufferBytes(float64(a.ship.BufferBytes()))
}

func (a *Agent) schedule(ctx context.Context, c collector.Collector) {
	a.refresh(ctx, c)
	t := time.NewTicker(c.Interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.refresh(ctx, c)
		}
	}
}

func (a *Agent) refresh(ctx context.Context, c collector.Collector) {
	start := time.Now()
	err := c.Refresh(ctx)
	d := time.Since(start)
	a.self.Observe(c.Name(), d, err)

	if err != nil {
		a.mu.Lock()
		a.streak[c.Name()]++
		n := a.streak[c.Name()]
		a.mu.Unlock()
		if n == 1 || n%20 == 0 {
			a.log.Warn("collect failed", "collector", c.Name(), "err", err, "consecutive", n)
		}
		return
	}

	a.mu.Lock()
	if a.streak[c.Name()] > 0 {
		delete(a.streak, c.Name())
	}
	a.mu.Unlock()

	if d > c.Interval() {
		a.log.Warn("collect slower than interval",
			"collector", c.Name(), "took", d.String(), "interval", c.Interval().String())
	}
}

// WriteMetrics refreshes every collector, optionally waits for a second sample
// so rate-based metrics are populated, then writes the text exposition format.
func (a *Agent) WriteMetrics(ctx context.Context, w io.Writer, settle time.Duration) error {
	for _, c := range a.cols {
		a.refresh(ctx, c)
	}
	if settle > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(settle):
		}
		for _, c := range a.cols {
			a.refresh(ctx, c)
		}
	}
	mfs, err := a.reg.Gather()
	if err != nil {
		return err
	}
	enc := expfmt.NewEncoder(w, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return err
		}
	}
	return nil
}

func mustRegexp(expr string) *regexp.Regexp {
	if expr == "" {
		return nil
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil
	}
	return re
}
