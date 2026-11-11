package collector

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yqjwxz/beacon/internal/procfs"
)

type netCounters struct {
	RxBytes, RxPackets, RxErrs, RxDrop uint64
	TxBytes, TxPackets, TxErrs, TxDrop uint64
}

// parseNetDev parses /proc/net/dev.
func parseNetDev(b []byte) map[string]netCounters {
	out := map[string]netCounters{}
	for _, line := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if name == "" || len(f) < 16 {
			continue
		}
		u := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		out[name] = netCounters{
			RxBytes: u(0), RxPackets: u(1), RxErrs: u(2), RxDrop: u(3),
			TxBytes: u(8), TxPackets: u(9), TxErrs: u(10), TxDrop: u(11),
		}
	}
	return out
}

var tcpStateNames = map[string]string{
	"01": "established", "02": "syn_sent", "03": "syn_recv",
	"04": "fin_wait1", "05": "fin_wait2", "06": "time_wait",
	"07": "close", "08": "close_wait", "09": "last_ack",
	"0A": "listen", "0B": "closing", "0C": "new_syn_recv",
}

// parseTCPStates counts sockets per state from /proc/net/tcp{,6}.
func parseTCPStates(b []byte) map[string]uint64 {
	out := map[string]uint64{}
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		if i == 0 { // header
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		state := strings.ToUpper(f[3])
		name, ok := tcpStateNames[state]
		if !ok {
			name = "unknown"
		}
		out[name]++
	}
	return out
}

// parseSNMP extracts the Tcp columns of /proc/net/snmp into a name->value map.
func parseSNMP(b []byte) map[string]float64 {
	out := map[string]float64{}
	var header []string
	for _, line := range strings.Split(string(b), "\n") {
		proto, rest, ok := strings.Cut(line, ":")
		if !ok || proto != "Tcp" {
			continue
		}
		f := strings.Fields(rest)
		if header == nil {
			header = f
			continue
		}
		for i, name := range header {
			if i >= len(f) {
				break
			}
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				continue
			}
			out[name] = v
		}
		break
	}
	return out
}

func parseUintFile(b []byte) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v, err == nil
}

type netSnapshot struct {
	ifaces       map[string]netCounters
	up           map[string]bool
	tcpStates    map[string]uint64
	conntrack    float64
	hasConntrack bool
	retrans      float64
	hasRetrans   bool
}

type Net struct {
	base
	src      *procfs.Source
	interval time.Duration

	mu       sync.RWMutex
	snap     *netSnapshot
	prevSNMP map[string]float64

	dRxBytes, dTxBytes   *prometheus.Desc
	dRxPkts, dTxPkts     *prometheus.Desc
	dRxErr, dTxErr       *prometheus.Desc
	dRxDrop, dTxDrop     *prometheus.Desc
	dUp, dTCP            *prometheus.Desc
	dConntrack, dRetrans *prometheus.Desc
}

func NewNet(src *procfs.Source, host string, interval time.Duration) *Net {
	b := base{host: host}
	return &Net{
		base: b, src: src, interval: interval,
		dRxBytes:   b.desc("beacon_net_rx_bytes_total", "Bytes received per interface.", "iface"),
		dTxBytes:   b.desc("beacon_net_tx_bytes_total", "Bytes transmitted per interface.", "iface"),
		dRxPkts:    b.desc("beacon_net_rx_packets_total", "Packets received per interface.", "iface"),
		dTxPkts:    b.desc("beacon_net_tx_packets_total", "Packets transmitted per interface.", "iface"),
		dRxErr:     b.desc("beacon_net_rx_errors_total", "Receive errors per interface.", "iface"),
		dTxErr:     b.desc("beacon_net_tx_errors_total", "Transmit errors per interface.", "iface"),
		dRxDrop:    b.desc("beacon_net_rx_dropped_total", "Receive drops per interface.", "iface"),
		dTxDrop:    b.desc("beacon_net_tx_dropped_total", "Transmit drops per interface.", "iface"),
		dUp:        b.desc("beacon_net_up", "Interface operational state (1=up).", "iface"),
		dTCP:       b.desc("beacon_tcp_conns", "TCP sockets per state.", "state"),
		dConntrack: b.desc("beacon_conntrack_used_ratio", "conntrack table usage as a fraction of maximum."),
		dRetrans:   b.desc("beacon_tcp_retrans_ratio", "Retransmitted segments as a fraction of sent segments."),
	}
}

func (n *Net) Name() string            { return "net" }
func (n *Net) Interval() time.Duration { return n.interval }

func (n *Net) Refresh(ctx context.Context) error {
	raw, err := n.src.ReadProc("net", "dev")
	if err != nil {
		return err
	}
	s := &netSnapshot{
		ifaces: parseNetDev(raw),
		up:     map[string]bool{},
	}

	for name := range s.ifaces {
		up := false
		if b, err := n.src.ReadSys("class", "net", name, "operstate"); err == nil {
			up = strings.TrimSpace(string(b)) == "up"
		}
		s.up[name] = up
	}

	states := map[string]uint64{}
	for _, f := range []string{"tcp", "tcp6"} {
		if b, err := n.src.ReadProc("net", f); err == nil {
			for k, v := range parseTCPStates(b) {
				states[k] += v
			}
		}
	}
	s.tcpStates = states

	if cnt, ok := parseUintFile(mustRead(n.src, "sys", "net", "netfilter", "nf_conntrack_count")); ok {
		if mx, ok := parseUintFile(mustRead(n.src, "sys", "net", "netfilter", "nf_conntrack_max")); ok && mx > 0 {
			s.conntrack = float64(cnt) / float64(mx)
			s.hasConntrack = true
		}
	}

	if b, err := n.src.ReadProc("net", "snmp"); err == nil {
		cur := parseSNMP(b)
		if n.prevSNMP != nil {
			out := deltaF(cur["OutSegs"], n.prevSNMP["OutSegs"])
			if out > 0 {
				s.retrans = deltaF(cur["RetransSegs"], n.prevSNMP["RetransSegs"]) / out
				s.hasRetrans = true
			}
		}
		n.prevSNMP = cur
	}

	n.mu.Lock()
	n.snap = s
	n.mu.Unlock()
	return nil
}

func deltaF(cur, prev float64) float64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func mustRead(src *procfs.Source, parts ...string) []byte {
	b, err := src.ReadProc(parts...)
	if err != nil {
		return nil
	}
	return b
}

func (n *Net) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		n.dRxBytes, n.dTxBytes, n.dRxPkts, n.dTxPkts,
		n.dRxErr, n.dTxErr, n.dRxDrop, n.dTxDrop,
		n.dUp, n.dTCP, n.dConntrack, n.dRetrans,
	} {
		ch <- d
	}
}

func (n *Net) Collect(ch chan<- prometheus.Metric) {
	n.mu.RLock()
	s := n.snap
	n.mu.RUnlock()
	if s == nil {
		return
	}
	for name, c := range s.ifaces {
		ch <- prometheus.MustNewConstMetric(n.dRxBytes, prometheus.CounterValue, float64(c.RxBytes), name)
		ch <- prometheus.MustNewConstMetric(n.dTxBytes, prometheus.CounterValue, float64(c.TxBytes), name)
		ch <- prometheus.MustNewConstMetric(n.dRxPkts, prometheus.CounterValue, float64(c.RxPackets), name)
		ch <- prometheus.MustNewConstMetric(n.dTxPkts, prometheus.CounterValue, float64(c.TxPackets), name)
		ch <- prometheus.MustNewConstMetric(n.dRxErr, prometheus.CounterValue, float64(c.RxErrs), name)
		ch <- prometheus.MustNewConstMetric(n.dTxErr, prometheus.CounterValue, float64(c.TxErrs), name)
		ch <- prometheus.MustNewConstMetric(n.dRxDrop, prometheus.CounterValue, float64(c.RxDrop), name)
		ch <- prometheus.MustNewConstMetric(n.dTxDrop, prometheus.CounterValue, float64(c.TxDrop), name)
		up := 0.0
		if s.up[name] {
			up = 1
		}
		ch <- prometheus.MustNewConstMetric(n.dUp, prometheus.GaugeValue, up, name)
	}
	for state, v := range s.tcpStates {
		ch <- prometheus.MustNewConstMetric(n.dTCP, prometheus.GaugeValue, float64(v), state)
	}
	if s.hasConntrack {
		ch <- prometheus.MustNewConstMetric(n.dConntrack, prometheus.GaugeValue, s.conntrack)
	}
	if s.hasRetrans {
		ch <- prometheus.MustNewConstMetric(n.dRetrans, prometheus.GaugeValue, s.retrans)
	}
}
