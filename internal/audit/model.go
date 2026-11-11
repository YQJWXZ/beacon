// Package audit turns host firewall and socket state into comparable snapshots
// and explains what changed. Parsing is separate from execution so every
// backend can be tested against fixtures without root.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// Backend identifies where the ruleset came from.
type Backend string

const (
	BackendNFT       Backend = "nftables"
	BackendIptables  Backend = "iptables"
	BackendUFW       Backend = "ufw"
	BackendFirewalld Backend = "firewalld"
	BackendNone      Backend = "none"
)

// Rule is one normalized firewall rule.
type Rule struct {
	Family string `json:"family,omitempty"`
	Table  string `json:"table,omitempty"`
	Chain  string `json:"chain"`
	Handle int    `json:"handle,omitempty"`
	Action string `json:"action,omitempty"`
	Proto  string `json:"proto,omitempty"`
	DPort  string `json:"dport,omitempty"`
	SAddr  string `json:"saddr,omitempty"`
	DAddr  string `json:"daddr,omitempty"`
	// Text is the canonical rendering used for identity and diffing.
	Text string `json:"text"`
}

// ChainKey identifies a chain within a table.
func (r Rule) ChainKey() string { return r.Family + "/" + r.Table + "/" + r.Chain }

// Key is the identity of a rule independent of its handle: handles change when
// rules are re-added, but the rule itself is the same.
func (r Rule) Key() string {
	return r.ChainKey() + "|" + r.Text
}

// Snapshot is a full firewall state at a point in time.
type Snapshot struct {
	Backend     Backend           `json:"backend"`
	Rules       []Rule            `json:"rules"`
	Policy      map[string]string `json:"policy"`
	IPv6Covered bool              `json:"ipv6_covered"`
	Raw         string            `json:"-"`
	Hash        string            `json:"hash"`
	At          time.Time         `json:"at"`
}

// Finalize sorts rules, computes the hash and fills the timestamp.
func (s *Snapshot) Finalize(at time.Time) {
	sort.Slice(s.Rules, func(i, j int) bool { return s.Rules[i].Key() < s.Rules[j].Key() })
	s.At = at
	s.Hash = s.computeHash()
}

func (s *Snapshot) computeHash() string {
	h := sha256.New()
	keys := make([]string, 0, len(s.Policy))
	for k := range s.Policy {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte("p|" + k + "=" + s.Policy[k] + "\n"))
	}
	for _, r := range s.Rules {
		h.Write([]byte("r|" + r.Key() + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// CountByTable returns rule counts per table.
func (s *Snapshot) CountByTable() map[string]int {
	out := map[string]int{}
	for _, r := range s.Rules {
		out[r.Table]++
	}
	return out
}

// MarshalText renders a rule deterministically for logs and events.
func (r Rule) MarshalText() string { return r.Text }

// jsonText is a helper for canonicalizing nft expression trees.
func jsonText(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
