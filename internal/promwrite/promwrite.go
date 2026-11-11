// Package promwrite converts Prometheus exposition data into remote-write
// protobuf payloads. Keeping the encoding here means the agent never depends on
// collector internals and the format stays portable across backends.
package promwrite

import (
	"fmt"
	"sort"

	"github.com/golang/snappy"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prometheus/prompb"
)

// FromFamilies flattens gathered metric families into time series with a common
// timestamp. The __name__ label is always first and the rest are sorted, as
// required by most remote-write receivers.
func FromFamilies(mfs []*dto.MetricFamily, tsMillis int64) []prompb.TimeSeries {
	var out []prompb.TimeSeries
	for _, mf := range mfs {
		name := mf.GetName()
		for _, m := range mf.GetMetric() {
			var v float64
			switch {
			case m.Gauge != nil:
				v = m.Gauge.GetValue()
			case m.Counter != nil:
				v = m.Counter.GetValue()
			case m.Untyped != nil:
				v = m.Untyped.GetValue()
			case m.Summary != nil:
				continue // summaries need per-quantile expansion; not used by this agent
			case m.Histogram != nil:
				continue // buckets are expanded by the collector, not here
			default:
				continue
			}
			labels := make([]prompb.Label, 0, len(m.Label)+1)
			labels = append(labels, prompb.Label{Name: "__name__", Value: name})
			rest := make([]prompb.Label, 0, len(m.Label))
			for _, l := range m.Label {
				rest = append(rest, prompb.Label{Name: l.GetName(), Value: l.GetValue()})
			}
			sort.Slice(rest, func(i, j int) bool { return rest[i].Name < rest[j].Name })
			labels = append(labels, rest...)
			out = append(out, prompb.TimeSeries{
				Labels:  labels,
				Samples: []prompb.Sample{{Value: v, Timestamp: tsMillis}},
			})
		}
	}
	return out
}

// Gauge builds a single series, used for heartbeat and synthetic signals.
func Gauge(name string, labels map[string]string, value float64, tsMillis int64) prompb.TimeSeries {
	ls := make([]prompb.Label, 0, len(labels)+1)
	ls = append(ls, prompb.Label{Name: "__name__", Value: name})
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ls = append(ls, prompb.Label{Name: k, Value: labels[k]})
	}
	return prompb.TimeSeries{Labels: ls, Samples: []prompb.Sample{{Value: value, Timestamp: tsMillis}}}
}

// Marshal encodes a write request and compresses it with snappy, which is what
// the remote-write protocol mandates.
func Marshal(series []prompb.TimeSeries) ([]byte, error) {
	if len(series) == 0 {
		return nil, fmt.Errorf("empty write request")
	}
	raw, err := (&prompb.WriteRequest{Timeseries: series}).Marshal()
	if err != nil {
		return nil, err
	}
	return snappy.Encode(nil, raw), nil
}

// Merge concatenates already-marshaled write requests into one payload.
func Merge(payloads [][]byte) ([]byte, error) {
	if len(payloads) == 1 {
		return payloads[0], nil
	}
	var all []prompb.TimeSeries
	for _, p := range payloads {
		raw, err := snappy.Decode(nil, p)
		if err != nil {
			return nil, fmt.Errorf("snappy decode: %w", err)
		}
		var req prompb.WriteRequest
		if err := req.Unmarshal(raw); err != nil {
			return nil, fmt.Errorf("protobuf decode: %w", err)
		}
		all = append(all, req.Timeseries...)
	}
	raw, err := (&prompb.WriteRequest{Timeseries: all}).Marshal()
	if err != nil {
		return nil, err
	}
	return snappy.Encode(nil, raw), nil
}

// Decode is used by tests and by the gateway to inspect payloads.
func Decode(payload []byte) (*prompb.WriteRequest, error) {
	raw, err := snappy.Decode(nil, payload)
	if err != nil {
		return nil, err
	}
	var req prompb.WriteRequest
	if err := req.Unmarshal(raw); err != nil {
		return nil, err
	}
	return &req, nil
}
