package audit

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ParseIptables parses `iptables-save` / `ip6tables-save` output.
func ParseIptables(raw []byte, family string) (*Snapshot, error) {
	s := &Snapshot{Backend: BackendIptables, Policy: map[string]string{}}
	table := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "*"):
			table = strings.TrimPrefix(line, "*")
		case strings.HasPrefix(line, ":"):
			fields := strings.Fields(line[1:])
			if len(fields) >= 2 {
				s.Policy[family+"/"+table+"/"+fields[0]] = strings.ToLower(fields[1])
			}
		case strings.HasPrefix(line, "-A "):
			s.Rules = append(s.Rules, parseIptablesRule(line, family, table))
		}
	}

	// iptables only covers IPv4; coverage of IPv6 is decided by the caller
	// after it also parses ip6tables-save.
	if family == "ip6" && len(s.Rules) > 0 {
		s.IPv6Covered = true
	}
	sort.Slice(s.Rules, func(i, j int) bool { return s.Rules[i].Key() < s.Rules[j].Key() })
	s.Hash = s.computeHash()
	return s, nil
}

func parseIptablesRule(line, family, table string) Rule {
	fields := strings.Fields(line)
	r := Rule{Family: family, Table: table, Text: strings.Join(fields[2:], " ")}
	if len(fields) > 1 {
		r.Chain = fields[1]
	}
	for i := 2; i < len(fields); i++ {
		switch fields[i] {
		case "-p", "--protocol":
			if i+1 < len(fields) {
				r.Proto = fields[i+1]
			}
		case "--dport", "--dports", "--destination-port":
			if i+1 < len(fields) {
				r.DPort = fields[i+1]
			}
		case "-s", "--source":
			if i+1 < len(fields) {
				r.SAddr = fields[i+1]
			}
		case "-d", "--destination":
			if i+1 < len(fields) {
				r.DAddr = fields[i+1]
			}
		case "-j", "--jump", "-g", "--goto":
			if i+1 < len(fields) {
				r.Action = strings.ToLower(fields[i+1])
			}
		}
	}
	return r
}

var ufwColumns = regexp.MustCompile(`\s{2,}`)

// ParseUFW parses `ufw status verbose`.
func ParseUFW(raw []byte) (*Snapshot, error) {
	s := &Snapshot{Backend: BackendUFW, Policy: map[string]string{}}
	lines := strings.Split(string(raw), "\n")
	inRules := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Status:"):
			if strings.Contains(trimmed, "inactive") {
				return s, nil
			}
		case strings.HasPrefix(trimmed, "Default:"):
			// e.g. "Default: deny (incoming), allow (outgoing), disabled (routed)"
			parts := strings.Split(strings.TrimPrefix(trimmed, "Default:"), ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.Contains(p, "incoming") {
					s.Policy["ufw/input"] = strings.Fields(p)[0]
				}
				if strings.Contains(p, "outgoing") {
					s.Policy["ufw/output"] = strings.Fields(p)[0]
				}
			}
		case strings.HasPrefix(trimmed, "--"):
			inRules = true
		case inRules && trimmed != "":
			if r, ok := parseUFWRule(trimmed); ok {
				s.Rules = append(s.Rules, r)
			}
		}
	}
	s.IPv6Covered = hasUFWv6(s.Rules)
	sort.Slice(s.Rules, func(i, j int) bool { return s.Rules[i].Key() < s.Rules[j].Key() })
	s.Hash = s.computeHash()
	return s, nil
}

func hasUFWv6(rules []Rule) bool {
	for _, r := range rules {
		if r.Family == "ip6" {
			return true
		}
	}
	return false
}

func parseUFWRule(line string) (Rule, bool) {
	cols := ufwColumns.Split(line, -1)
	if len(cols) < 2 {
		return Rule{}, false
	}
	to := strings.TrimSpace(cols[0])
	actionCol := strings.TrimSpace(cols[1])
	from := ""
	if len(cols) > 2 {
		from = strings.TrimSpace(cols[2])
	}

	family := "ip"
	if strings.Contains(to, "(v6)") || strings.Contains(from, "(v6)") {
		family = "ip6"
	}
	to = strings.ReplaceAll(to, "(v6)", "")
	from = strings.ReplaceAll(from, "(v6)", "")
	to = strings.TrimSpace(to)
	from = strings.TrimSpace(from)

	action := strings.ToLower(strings.Fields(actionCol)[0])
	r := Rule{Family: family, Table: "ufw", Chain: "input", SAddr: from}
	r.Action = mapUFWAction(action)

	if to != "Anywhere" && to != "" {
		if port, proto, ok := strings.Cut(to, "/"); ok {
			r.DPort = strings.TrimSpace(port)
			r.Proto = strings.TrimSpace(proto)
		} else if isAllDigits(to) {
			r.DPort = to
		} else {
			// Application profile such as "Nginx Full": keep the name so the
			// diff still detects changes.
			r.DPort = to
		}
	}
	if from == "Anywhere" {
		r.SAddr = ""
	}
	r.Text = strings.TrimSpace(strings.Join([]string{
		"to=" + to, "action=" + action, "from=" + from,
	}, " "))
	return r, true
}

func mapUFWAction(a string) string {
	switch {
	case strings.HasPrefix(a, "allow"):
		return "accept"
	case strings.HasPrefix(a, "deny"):
		return "drop"
	case strings.HasPrefix(a, "reject"):
		return "reject"
	case strings.HasPrefix(a, "limit"):
		return "limit"
	default:
		return a
	}
}

func isAllDigits(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// firewalldServicePorts maps the common service names to ports so rules can be
// evaluated for exposure. Unknown services stay opaque instead of guessing.
var firewalldServicePorts = map[string]struct {
	Port  string
	Proto string
}{
	"ssh":           {"22", "tcp"},
	"http":          {"80", "tcp"},
	"https":         {"443", "tcp"},
	"cockpit":       {"9090", "tcp"},
	"mysql":         {"3306", "tcp"},
	"redis":         {"6379", "tcp"},
	"dhcpv6-client": {"546", "udp"},
	"mdns":          {"5353", "udp"},
	"samba-client":  {"137", "udp"},
	"postgresql":    {"5432", "tcp"},
	"mongodb":       {"27017", "tcp"},
}

// ParseFirewalld parses `firewall-cmd --list-all` output.
func ParseFirewalld(raw []byte) (*Snapshot, error) {
	s := &Snapshot{Backend: BackendFirewalld, Policy: map[string]string{}}
	lines := strings.Split(string(raw), "\n")
	zone := "public"
	target := "default"

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, "(active)") || strings.HasSuffix(trimmed, "(inactive)") {
			zone = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(trimmed, "(active)"), "(inactive)"))
			continue
		}
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "target":
			target = val
			s.Policy["firewalld/"+zone] = val
		case "services":
			for _, svc := range strings.Fields(val) {
				r := Rule{Family: "ip", Table: "firewalld", Chain: zone, Action: "accept", DPort: svc, Text: "service " + svc + " accept"}
				if p, ok := firewalldServicePorts[svc]; ok {
					r.DPort = p.Port
					r.Proto = p.Proto
					r.Text = "service " + svc + " (dport " + p.Port + ") accept"
				}
				s.Rules = append(s.Rules, r)
			}
		case "ports":
			for _, p := range strings.Fields(val) {
				port, proto, ok := strings.Cut(p, "/")
				if !ok {
					continue
				}
				s.Rules = append(s.Rules, Rule{
					Family: "ip", Table: "firewalld", Chain: zone, Action: "accept",
					Proto: proto, DPort: port, Text: "dport " + port + " " + proto + " accept",
				})
			}
		}
	}
	// firewalld applies to both families when IPv6 is enabled; assume covered.
	s.IPv6Covered = true
	if target != "default" {
		s.Policy["firewalld/input"] = target
	}
	sort.Slice(s.Rules, func(i, j int) bool { return s.Rules[i].Key() < s.Rules[j].Key() })
	s.Hash = s.computeHash()
	return s, nil
}
