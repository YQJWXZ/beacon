package flow

import (
	"sort"
	"strconv"
	"time"
)

// commonPorts are kept as their own bucket; everything else collapses into
// "other" so the label set stays bounded no matter what scans arrive.
var commonPorts = map[int]bool{
	22: true, 25: true, 53: true, 80: true, 123: true, 443: true,
	465: true, 587: true, 993: true, 3306: true, 3389: true, 5432: true,
	6379: true, 8080: true, 8443: true, 9200: true, 11211: true, 27017: true,
}

// Bucket maps a destination port to a bounded label value.
func Bucket(port int) string {
	if commonPorts[port] {
		return strconv.Itoa(port)
	}
	return "other"
}

// Side is the aggregate for one direction.
type Side struct {
	Conns     int     `json:"conns"`
	Unreplied int     `json:"unreplied"`
	Bytes     float64 `json:"bytes"`
}

// PortAgg is the aggregate for one direction+bucket pair.
type PortAgg struct {
	Conns     int     `json:"conns"`
	Unreplied int     `json:"unreplied"`
	Bytes     float64 `json:"bytes"`
}

// Sample is one snapshot of the connection table, already reduced to bounded
// dimensions. Unique sets are only used for detection, never as labels.
type Sample struct {
	At            time.Time          `json:"at"`
	Total         int                `json:"total"`
	Unreplied     int                `json:"unreplied"`
	LocalSkipped  int                `json:"local_skipped"`
	In            Side               `json:"in"`
	Out           Side               `json:"out"`
	Ports         map[string]PortAgg `json:"ports"` // key: "in|22", "out|other"
	DstOut        map[string]int     `json:"dst_out"`
	SuspiciousOut map[int]int        `json:"suspicious_out"`

	UniqueDstPortsIn  map[int]struct{}    `json:"-"`
	UniqueSrcsIn      map[string]struct{} `json:"-"`
	UniqueDstPortsOut map[int]struct{}    `json:"-"`
	Truncated         bool                `json:"truncated"`
}

const uniqueCap = 8192

func NewSample() *Sample {
	return &Sample{
		Ports:             map[string]PortAgg{},
		DstOut:            map[string]int{},
		SuspiciousOut:     map[int]int{},
		UniqueDstPortsIn:  map[int]struct{}{},
		UniqueSrcsIn:      map[string]struct{}{},
		UniqueDstPortsOut: map[int]struct{}{},
	}
}

// Classify decides the direction of an entry relative to the host.
func Classify(e Entry, local map[string]bool) string {
	srcLocal, dstLocal := local[e.Src], local[e.Dst]
	switch {
	case srcLocal && !dstLocal:
		return "out"
	case dstLocal && !srcLocal:
		return "in"
	default:
		// Loopback, container-to-container, or a spoofed pair: not traffic we
		// can reason about, so it is excluded rather than mislabelled.
		return ""
	}
}

// Aggregate reduces raw entries into a bounded sample.
func Aggregate(entries []Entry, local map[string]bool, at time.Time) *Sample {
	s := NewSample()
	s.At = at

	for _, e := range entries {
		s.Total++
		if e.Unreplied {
			s.Unreplied++
		}
		dir := Classify(e, local)
		if dir == "" {
			s.LocalSkipped++
			continue
		}

		side := &s.In
		if dir == "out" {
			side = &s.Out
		}
		side.Conns++
		if e.Unreplied {
			side.Unreplied++
		}
		if e.HasBytes {
			side.Bytes += e.BytesOut + e.BytesIn
		}

		key := dir + "|" + Bucket(e.DPort)
		agg := s.Ports[key]
		agg.Conns++
		if e.Unreplied {
			agg.Unreplied++
		}
		if e.HasBytes {
			agg.Bytes += e.BytesOut + e.BytesIn
		}
		s.Ports[key] = agg

		if dir == "in" {
			addInt(s.UniqueDstPortsIn, e.DPort)
			if len(s.UniqueSrcsIn) < uniqueCap {
				s.UniqueSrcsIn[e.Src] = struct{}{}
			} else {
				s.Truncated = true
			}
		} else {
			addInt(s.UniqueDstPortsOut, e.DPort)
			if suspiciousDsts[e.DPort] != "" {
				s.SuspiciousOut[e.DPort]++
			}
			dst := e.Dst + ":" + strconv.Itoa(e.DPort)
			if len(s.DstOut) < uniqueCap {
				s.DstOut[dst]++
			} else {
				s.Truncated = true
			}
		}
	}
	return s
}

func addInt(m map[int]struct{}, v int) {
	if len(m) < uniqueCap {
		m[v] = struct{}{}
	}
}

// DestinationCount is one row of the top-K table.
type DestinationCount struct {
	Dst   string
	Conns int
}

// PortCount is one row of the top port table.
type PortCount struct {
	Key   string
	Conns int
}

// TopDestinations returns the busiest outbound destinations.
func (s *Sample) TopDestinations(k int) []DestinationCount {
	all := make([]DestinationCount, 0, len(s.DstOut))
	for dst, n := range s.DstOut {
		all = append(all, DestinationCount{dst, n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Conns != all[j].Conns {
			return all[i].Conns > all[j].Conns
		}
		return all[i].Dst < all[j].Dst
	})
	if len(all) > k {
		all = all[:k]
	}
	return all
}

// TopPorts returns the busiest direction+bucket pairs.
func (s *Sample) TopPorts(k int) []PortCount {
	all := make([]PortCount, 0, len(s.Ports))
	for key, agg := range s.Ports {
		all = append(all, PortCount{key, agg.Conns})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Conns != all[j].Conns {
			return all[i].Conns > all[j].Conns
		}
		return all[i].Key < all[j].Key
	})
	if len(all) > k {
		all = all[:k]
	}
	return all
}
