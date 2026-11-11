// Package flow turns the kernel connection table into bounded traffic
// aggregates and a handful of explainable anomaly signals. It deliberately
// does not capture packets: on a 1C1G cloud instance, conntrack sampling is the
// only affordable option.
package flow

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Entry is one row of /proc/net/nf_conntrack, normalized.
type Entry struct {
	Family    string // ipv4 | ipv6
	Proto     string // tcp | udp | icmp | ...
	State     string // ESTABLISHED, TIME_WAIT, ...
	Unreplied bool   // no reply seen yet: the strong signal for scans
	Src       string
	Dst       string
	SPort     int
	DPort     int
	// BytesOut/BytesIn are only populated when nf_conntrack_acct=1.
	BytesOut float64
	BytesIn  float64
	HasBytes bool
}

// ParseConntrack parses one line of nf_conntrack output.
//
//	ipv4 2 tcp 6 431999 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=1234 dport=443
//	     src=5.6.7.8 dst=1.2.3.4 sport=443 dport=1234 [ASSURED] mark=0 use=1
func ParseConntrack(line string) (Entry, error) {
	f := strings.Fields(line)
	if len(f) < 6 {
		return Entry{}, errors.New("short conntrack line")
	}
	e := Entry{Family: f[0], Proto: f[2], State: f[5]}

	var bytes []float64
	direction := 0
	sawDst := false

	for _, tok := range f[6:] {
		switch {
		case tok == "[UNREPLIED]":
			e.Unreplied = true
			continue
		case strings.HasPrefix(tok, "["):
			continue
		}
		key, val, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		switch key {
		case "src":
			if sawDst {
				direction = 1
			}
			if direction == 0 {
				e.Src = val
			}
		case "dst":
			sawDst = true
			if direction == 0 {
				e.Dst = val
			}
		case "sport":
			if direction == 0 {
				e.SPort = atoi(val)
			}
		case "dport":
			if direction == 0 {
				e.DPort = atoi(val)
			}
		case "bytes":
			v, _ := strconv.ParseFloat(val, 64)
			bytes = append(bytes, v)
		}
	}

	if len(bytes) >= 1 {
		e.BytesOut = bytes[0]
		e.HasBytes = true
	}
	if len(bytes) >= 2 {
		e.BytesIn = bytes[1]
	}
	return e, nil
}

// ReadConntrack reads up to max entries. The table can be large, so it stops
// early instead of loading everything into memory.
func ReadConntrack(r io.Reader, max int) ([]Entry, int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	entries := make([]Entry, 0, max)
	total := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		total++
		if len(entries) >= max {
			continue
		}
		e, err := ParseConntrack(line)
		if err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return entries, total, fmt.Errorf("scan conntrack: %w", err)
	}
	return entries, total, nil
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

// LocalAddresses returns every address assigned to this host. Connections
// whose both ends are local are excluded from aggregates: container-to-container
// traffic would otherwise be misclassified as inbound or outbound.
func LocalAddresses() map[string]bool {
	set := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return set
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				set[ipnet.IP.String()] = true
			}
		}
	}
	return set
}
