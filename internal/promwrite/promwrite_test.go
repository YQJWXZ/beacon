package promwrite

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prometheus/prompb"
)

func TestFromFamiliesOrdersLabels(t *testing.T) {
	name := "beacon_test_metric"
	help := "test"
	typ := dto.MetricType_GAUGE
	val := 1.5
	mf := &dto.MetricFamily{
		Name: &name,
		Help: &help,
		Type: &typ,
		Metric: []*dto.Metric{{
			Label: []*dto.LabelPair{
				{Name: strPtr("zone"), Value: strPtr("b")},
				{Name: strPtr("host"), Value: strPtr("a")},
			},
			Gauge: &dto.Gauge{Value: &val},
		}},
	}

	ts := FromFamilies([]*dto.MetricFamily{mf}, 1700000000000)
	if len(ts) != 1 {
		t.Fatalf("got %d series", len(ts))
	}
	labels := ts[0].Labels
	if labels[0].Name != "__name__" || labels[0].Value != name {
		t.Fatalf("first label = %+v", labels[0])
	}
	if labels[1].Name != "host" || labels[2].Name != "zone" {
		t.Fatalf("labels not sorted: %+v", labels)
	}
	if ts[0].Samples[0].Value != 1.5 || ts[0].Samples[0].Timestamp != 1700000000000 {
		t.Fatalf("sample = %+v", ts[0].Samples[0])
	}
}

func TestMarshalDecodeMerge(t *testing.T) {
	a, err := Marshal([]prompb.TimeSeries{Gauge("m", map[string]string{"host": "h"}, 1, 1000)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal([]prompb.TimeSeries{Gauge("m", map[string]string{"host": "h"}, 2, 2000)})
	if err != nil {
		t.Fatal(err)
	}

	merged, err := Merge([][]byte{a, b})
	if err != nil {
		t.Fatal(err)
	}
	req, err := Decode(merged)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Timeseries) != 2 {
		t.Fatalf("merged series = %d", len(req.Timeseries))
	}
	if req.Timeseries[1].Samples[0].Value != 2 {
		t.Fatalf("second sample lost: %+v", req.Timeseries[1])
	}
}

func TestMarshalRejectsEmpty(t *testing.T) {
	if _, err := Marshal(nil); err == nil {
		t.Fatal("expected error for empty request")
	}
}

func strPtr(s string) *string { return &s }
