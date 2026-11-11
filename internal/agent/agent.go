package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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

	mu     sync.Mutex
	streak map[string]int
}

func New(cfg *config.Config, log *slog.Logger) *Agent {
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
	return a
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
	return nil
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
