package audit

import "sort"

// PolicyChange records a default-policy mutation.
type PolicyChange struct {
	Chain  string `json:"chain"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Diff is the change set between two firewall snapshots.
type Diff struct {
	Added         []Rule         `json:"added,omitempty"`
	Removed       []Rule         `json:"removed,omitempty"`
	PolicyChanges []PolicyChange `json:"policy_changes,omitempty"`
	BeforeHash    string         `json:"before_hash"`
	AfterHash     string         `json:"after_hash"`
	Flushed       bool           `json:"flushed"`
}

// Empty reports whether nothing changed.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.PolicyChanges) == 0
}

// DiffSnapshots compares two rule sets by rule identity, not handle.
func DiffSnapshots(before, after *Snapshot) Diff {
	d := Diff{BeforeHash: before.Hash, AfterHash: after.Hash}
	if before.Hash == after.Hash {
		return d
	}

	prev := map[string]Rule{}
	for _, r := range before.Rules {
		prev[r.Key()] = r
	}
	cur := map[string]Rule{}
	for _, r := range after.Rules {
		cur[r.Key()] = r
	}
	for k, r := range cur {
		if _, ok := prev[k]; !ok {
			d.Added = append(d.Added, r)
		}
	}
	for k, r := range prev {
		if _, ok := cur[k]; !ok {
			d.Removed = append(d.Removed, r)
		}
	}

	keys := map[string]bool{}
	for k := range before.Policy {
		keys[k] = true
	}
	for k := range after.Policy {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	for _, k := range ordered {
		b, a := before.Policy[k], after.Policy[k]
		if b != a {
			d.PolicyChanges = append(d.PolicyChanges, PolicyChange{Chain: k, Before: b, After: a})
		}
	}

	if len(before.Rules) > 0 && len(after.Rules) == 0 {
		d.Flushed = true
	}
	if len(before.Rules) >= 10 && len(after.Rules)*2 < len(before.Rules) {
		d.Flushed = true
	}

	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Key() < d.Added[j].Key() })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Key() < d.Removed[j].Key() })
	return d
}
