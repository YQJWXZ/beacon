package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type nftEntry map[string]json.RawMessage

// ParseNFT parses the output of `nft -j list ruleset`.
func ParseNFT(raw []byte) (*Snapshot, error) {
	var doc struct {
		Nftables []nftEntry `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}

	s := &Snapshot{Backend: BackendNFT, Policy: map[string]string{}}
	families := map[string]bool{}
	hooked := map[string]bool{}

	for _, entry := range doc.Nftables {
		if b, ok := entry["table"]; ok {
			var t struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			}
			if err := json.Unmarshal(b, &t); err == nil {
				families[t.Family] = true
			}
			continue
		}
		if b, ok := entry["chain"]; ok {
			var c struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Hook   string `json:"hook"`
				Policy string `json:"policy"`
			}
			if err := json.Unmarshal(b, &c); err != nil {
				continue
			}
			if c.Hook != "" {
				hooked[c.Family] = true
			}
			if c.Policy != "" {
				s.Policy[c.Family+"/"+c.Table+"/"+c.Name] = c.Policy
			}
			continue
		}
		if b, ok := entry["rule"]; ok {
			var r struct {
				Family string           `json:"family"`
				Table  string           `json:"table"`
				Chain  string           `json:"chain"`
				Handle int              `json:"handle"`
				Expr   []map[string]any `json:"expr"`
			}
			if err := json.Unmarshal(b, &r); err != nil {
				continue
			}
			s.Rules = append(s.Rules, buildNFTRule(r.Family, r.Table, r.Chain, r.Handle, r.Expr))
			continue
		}
	}

	s.IPv6Covered = families["ip6"] || hooked["inet"]

	sort.Slice(s.Rules, func(i, j int) bool { return s.Rules[i].Key() < s.Rules[j].Key() })
	s.Hash = s.computeHash()
	return s, nil
}

func buildNFTRule(family, table, chain string, handle int, expr []map[string]any) Rule {
	r := Rule{Family: family, Table: table, Chain: chain, Handle: handle}
	var readable []string

	for _, e := range expr {
		for k, v := range e {
			switch k {
			case "match":
				m, ok := v.(map[string]any)
				if !ok {
					continue
				}
				applyNFTMatch(&r, m)
			case "counter", "comment", "log", "metainfo", "payload", "notrack":
				continue
			case "jump", "goto":
				r.Action = k
				if target, ok := v.(string); ok {
					readable = append(readable, k+" "+target)
				}
			default:
				if r.Action == "" {
					r.Action = k
				}
			}
		}
	}

	if r.Proto != "" {
		readable = append(readable, r.Proto)
	}
	if r.SAddr != "" {
		readable = append(readable, "saddr "+r.SAddr)
	}
	if r.DAddr != "" {
		readable = append(readable, "daddr "+r.DAddr)
	}
	if r.DPort != "" {
		readable = append(readable, "dport "+r.DPort)
	}
	if r.Action != "" {
		readable = append(readable, r.Action)
	}
	// The readable form is for humans; the digest keeps identity exact when
	// rules differ in matches this summary does not model.
	canon := jsonText(expr)
	sum := sha256.Sum256([]byte(canon))
	r.Text = strings.Join(readable, " ") + " #" + hex.EncodeToString(sum[:4])
	return r
}

func applyNFTMatch(r *Rule, m map[string]any) {
	left, _ := m["left"].(map[string]any)
	right := m["right"]
	if left == nil {
		return
	}
	if payload, ok := left["payload"].(map[string]any); ok {
		if p, ok := payload["protocol"].(string); ok && p != "" {
			r.Proto = p
		}
		field, _ := payload["field"].(string)
		switch field {
		case "dport", "sport":
			if field == "dport" {
				r.DPort = valueText(right)
			}
		case "saddr":
			r.SAddr = valueText(right)
		case "daddr":
			r.DAddr = valueText(right)
		}
	}
	if meta, ok := left["meta"].(map[string]any); ok {
		if key, _ := meta["key"].(string); key == "l4proto" {
			if p, ok := right.(string); ok && p != "ip" && p != "ip6" {
				r.Proto = p
			}
		}
	}
}

// valueText flattens the different shapes nft uses for match values.
func valueText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "1"
		}
		return "0"
	case map[string]any:
		if r, ok := x["range"].([]any); ok && len(r) == 2 {
			return valueText(r[0]) + "-" + valueText(r[1])
		}
		if p, ok := x["prefix"].(map[string]any); ok {
			addr := valueText(p["addr"])
			plen := valueText(p["prefix_len"])
			return addr + "/" + plen
		}
		return jsonText(x)
	default:
		return fmt.Sprint(x)
	}
}
