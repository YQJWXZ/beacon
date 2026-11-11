package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yqjwxz/beacon/internal/notify"
)

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func alertPayload(status string) notify.AlertmanagerPayload {
	return notify.AlertmanagerPayload{
		Version:  "4",
		GroupKey: `{}/{host="h1",alertname="BeaconDiskFull"}`,
		Status:   status,
		CommonLabels: map[string]string{
			"host": "h1", "alertname": "BeaconDiskFull", "severity": "P0",
		},
		Alerts: []notify.AMAlert{{
			Status:      status,
			Labels:      map[string]string{"host": "h1", "alertname": "BeaconDiskFull"},
			Annotations: map[string]string{"summary": "disk full"},
			StartsAt:    time.Now(),
		}},
	}
}

func TestAlertHandlerDelivers(t *testing.T) {
	var received bool
	fs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received = true
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer fs.Close()

	n := notify.NewNotifier(fs.URL, "", "", "", nil)
	srv := NewServer(nil, nil, ServerOptions{Notifier: n}, testLog())
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	body, _ := json.Marshal(alertPayload("firing"))
	resp, err := http.Post(ts.URL+"/hooks/alert", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !received {
		t.Fatal("feishu did not receive the card")
	}
}

func TestAlertHandlerWithoutWebhook(t *testing.T) {
	srv := NewServer(nil, nil, ServerOptions{}, testLog())
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	body, _ := json.Marshal(alertPayload("firing"))
	resp, err := http.Post(ts.URL+"/hooks/alert", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestSnoozeRejectsBadSignature(t *testing.T) {
	srv := NewServer(nil, nil, ServerOptions{AMURL: "http://127.0.0.1:1", SnoozeKey: []byte("k")}, testLog())
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/snooze?host=h1&alert=X&exp=9999999999&sig=deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestSnoozeCreatesSilence(t *testing.T) {
	var silence map[string]any
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&silence)
		_, _ = w.Write([]byte(`{"silenceID":"abc"}`))
	}))
	defer am.Close()

	key := []byte("snooze-key")
	srv := NewServer(nil, nil, ServerOptions{AMURL: am.URL, SnoozeKey: key}, testLog())
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	link := notify.SnoozeURL(ts.URL, key, "h1", "BeaconDiskFull", time.Now().Add(24*time.Hour))
	u, _ := url.Parse(link)
	resp, err := http.Get(ts.URL + u.RequestURI())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if silence == nil {
		t.Fatal("alertmanager was not called")
	}
}
