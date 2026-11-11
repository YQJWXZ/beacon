package audit

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Listen is one listening socket.
type Listen struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  int    `json:"port"`
	PID   int    `json:"pid,omitempty"`
	Comm  string `json:"comm,omitempty"`
	UID   int    `json:"uid,omitempty"`
}

// Key identifies a service across restarts: the PID changes, the role does not.
func (l Listen) Key() string {
	name := l.Comm
	if name == "" {
		name = strconv.Itoa(l.PID)
	}
	return l.Proto + "|" + strconv.Itoa(l.Port) + "|" + name
}

// AddrPort renders the socket address for humans.
func (l Listen) AddrPort() string { return l.Addr + ":" + strconv.Itoa(l.Port) }

// Public reports whether the socket is bound to all interfaces.
func (l Listen) Public() bool {
	return l.Addr == "0.0.0.0" || l.Addr == "::" || l.Addr == "*"
}

// Loopback reports whether the socket only accepts local connections.
func (l Listen) Loopback() bool {
	return strings.HasPrefix(l.Addr, "127.") || l.Addr == "::1" || l.Addr == "localhost"
}

var (
	ssUsers = regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)
	ssUID   = regexp.MustCompile(`uid:(\d+)`)
)

// ParseSS parses `ss -Htulpen` output.
func ParseSS(raw []byte) []Listen {
	var out []Listen
	seen := map[string]bool{}

	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := strings.ToLower(f[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		addr, port, ok := splitAddrPort(f[4])
		if !ok {
			continue
		}
		l := Listen{Proto: proto, Addr: addr, Port: port}

		rest := strings.Join(f[6:], " ")
		if m := ssUsers.FindStringSubmatch(rest); m != nil {
			l.Comm = strings.TrimSuffix(m[1], "-")
			l.PID, _ = strconv.Atoi(m[2])
		}
		if m := ssUID.FindStringSubmatch(rest); m != nil {
			l.UID, _ = strconv.Atoi(m[1])
		}

		key := l.Proto + "|" + l.Addr + "|" + strconv.Itoa(l.Port) + "|" + strconv.Itoa(l.PID)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, l)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

func splitAddrPort(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false
	}
	addr := s[:i]
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	// Drop the interface zone before brackets: "[fe80::1]%eth0".
	if zone := strings.Index(addr, "%"); zone >= 0 {
		addr = addr[:zone]
	}
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	switch addr {
	case "*", "":
		addr = "0.0.0.0"
	}
	return addr, port, true
}

// PortDiff describes how the listening set changed.
type PortDiff struct {
	Added   []Listen `json:"added"`
	Removed []Listen `json:"removed"`
	Widened []Widen  `json:"widened"`
}

// Widen is the same service moving to a broader bind address.
type Widen struct {
	Before Listen `json:"before"`
	After  Listen `json:"after"`
}

// Empty reports whether nothing changed.
func (d PortDiff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Widened) == 0
}

// DiffListens compares two snapshots by service identity.
func DiffListens(before, after []Listen) PortDiff {
	var d PortDiff
	prev := map[string]Listen{}
	for _, l := range before {
		prev[l.Key()] = l
	}
	cur := map[string]Listen{}
	for _, l := range after {
		cur[l.Key()] = l
	}

	for k, l := range cur {
		old, ok := prev[k]
		if !ok {
			d.Added = append(d.Added, l)
			continue
		}
		if old.Addr != l.Addr {
			d.Widened = append(d.Widened, Widen{Before: old, After: l})
		}
	}
	for k, l := range prev {
		if _, ok := cur[k]; !ok {
			d.Removed = append(d.Removed, l)
		}
	}

	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Port < d.Added[j].Port })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Port < d.Removed[j].Port })
	sort.Slice(d.Widened, func(i, j int) bool { return d.Widened[i].After.Port < d.Widened[j].After.Port })
	return d
}

// Matcher decides whether a listening socket is expected.
type Matcher struct {
	ports map[int]bool
	cond  []string
}

// NewMatcher parses entries like "22", "tcp/443", "0.0.0.0:9100".
func NewMatcher(entries []string) Matcher {
	m := Matcher{ports: map[int]bool{}}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, ":") {
			_, port, ok := splitAddrPort(e)
			if ok {
				m.ports[port] = true
				continue
			}
		}
		if _, port, ok := strings.Cut(e, "/"); ok {
			if p, err := strconv.Atoi(port); err == nil {
				m.ports[p] = true
				continue
			}
		}
		if p, err := strconv.Atoi(e); err == nil {
			m.ports[p] = true
			continue
		}
		m.cond = append(m.cond, e)
	}
	return m
}

// Allowed reports whether the socket matches the allow list.
func (m Matcher) Allowed(l Listen) bool { return m.ports[l.Port] }

// Empty reports whether the matcher has no rules.
func (m Matcher) Empty() bool { return len(m.ports) == 0 && len(m.cond) == 0 }

// Ephemeral ports are reserved by the kernel for outgoing connections. A UDP
// socket bound to one of them is a client, not a service, and treating it as a
// listener turns browser chatter into an event storm.
var (
	ephemeralLow  = 32768
	ephemeralHigh = 60999
)

// SetEphemeralRange overrides the range, normally from
// /proc/sys/net/ipv4/ip_local_port_range.
func SetEphemeralRange(lo, hi int) {
	if lo > 0 && hi >= lo {
		ephemeralLow, ephemeralHigh = lo, hi
	}
}

// IsEphemeral reports whether a port belongs to the ephemeral range.
func IsEphemeral(port int) bool { return port >= ephemeralLow && port <= ephemeralHigh }

// SplitEphemeral removes client-side sockets and reports how many were dropped.
func SplitEphemeral(in []Listen) ([]Listen, int) {
	out := make([]Listen, 0, len(in))
	skipped := 0
	for _, l := range in {
		if IsEphemeral(l.Port) {
			skipped++
			continue
		}
		out = append(out, l)
	}
	return out, skipped
}
