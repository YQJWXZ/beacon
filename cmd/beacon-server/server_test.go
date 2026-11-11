package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/prometheus/prompb"

	"github.com/yqjwxz/beacon/internal/audit"
	"github.com/yqjwxz/beacon/internal/promwrite"
)

func testServer(t *testing.T) (*httptest.Server, *httptest.Server, *atomic.Int64) {
	t.Helper()
	var vmCalls atomic.Int64
	var lastBody atomic.Value
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		lastBody.Store(string(b))
		vmCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(vm.Close)

	store, err := OpenStore(filepath.Join(t.TempDir(), "hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	events, err := OpenEvents(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { events.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewServer(store, events, vm.URL, "enroll-secret", log).Routes())
	t.Cleanup(srv.Close)
	return srv, vm, &vmCalls
}

func payloadFor(t *testing.T, host string) []byte {
	t.Helper()
	b, err := promwrite.Marshal([]prompb.TimeSeries{promwrite.Gauge("probe", map[string]string{"host": host}, 1, time.Now().UnixMilli())})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func postRaw(t *testing.T, url string, body []byte, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func postJSON(t *testing.T, url string, body any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func TestEnrollThenWrite(t *testing.T) {
	srv, _, vmCalls := testServer(t)

	// Wrong enrollment token is rejected.
	resp, _ := postJSON(t, srv.URL+"/api/v1/enroll", enrollRequest{Token: "nope", Host: "h1"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d", resp.StatusCode)
	}

	resp, body := postJSON(t, srv.URL+"/api/v1/enroll", enrollRequest{Token: "enroll-secret", Host: "h1"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d body=%s", resp.StatusCode, body)
	}
	var er enrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatal(err)
	}
	if er.Token == "" || er.ID == "" {
		t.Fatalf("enroll response = %+v", er)
	}

	// Write with the issued token reaches the upstream.
	resp, _ = postRaw(t, srv.URL+"/api/v1/write", payloadFor(t, er.Host), map[string]string{
		"Authorization":    "Bearer " + er.Token,
		"Content-Encoding": "snappy",
		"Content-Type":     "application/x-protobuf",
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("write status = %d", resp.StatusCode)
	}
	if vmCalls.Load() != 1 {
		t.Fatalf("upstream calls = %d", vmCalls.Load())
	}

	// A bogus token is rejected before reaching upstream.
	resp, _ = postRaw(t, srv.URL+"/api/v1/write", payloadFor(t, er.Host), map[string]string{
		"Authorization": "Bearer bogus",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bogus token status = %d", resp.StatusCode)
	}
	if vmCalls.Load() != 1 {
		t.Fatalf("upstream should not be called for bogus token")
	}
}

func TestUpstreamFailurePropagates(t *testing.T) {
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer vm.Close()

	store, _ := OpenStore(filepath.Join(t.TempDir(), "hosts.json"))
	token, _, err := store.Enroll("h1")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(store, mustEvents(t), vm.URL, "s", slog.New(slog.NewTextHandler(io.Discard, nil))).Routes())
	defer srv.Close()

	resp, _ := postRaw(t, srv.URL+"/api/v1/write", payloadFor(t, "h1"), map[string]string{
		"Authorization": "Bearer " + token,
	})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 so the agent retries", resp.StatusCode)
	}
}

func TestEnrollmentDisabledWithoutToken(t *testing.T) {
	store, _ := OpenStore(filepath.Join(t.TempDir(), "hosts.json"))
	srv := httptest.NewServer(NewServer(store, mustEvents(t), "http://127.0.0.1:1", "", slog.New(slog.NewTextHandler(io.Discard, nil))).Routes())
	defer srv.Close()

	resp, _ := postJSON(t, srv.URL+"/api/v1/enroll", enrollRequest{Token: "", Host: "h"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestWriteRejectsForeignHostLabel(t *testing.T) {
	srv, _, vmCalls := testServer(t)

	_, body := postJSON(t, srv.URL+"/api/v1/enroll", enrollRequest{Token: "enroll-secret", Host: "h1"}, nil)
	var er enrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatal(err)
	}

	resp, _ := postRaw(t, srv.URL+"/api/v1/write", payloadFor(t, "someone-else"), map[string]string{
		"Authorization": "Bearer " + er.Token,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if vmCalls.Load() != 0 {
		t.Fatal("foreign payload reached the upstream")
	}
}

func mustEvents(t *testing.T) *EventStore {
	t.Helper()
	ev, err := OpenEvents(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ev.Close() })
	return ev
}

func TestEventsRoundTrip(t *testing.T) {
	srv, _, _ := testServer(t)

	_, body := postJSON(t, srv.URL+"/api/v1/enroll", enrollRequest{Token: "enroll-secret", Host: "h1"}, nil)
	var er enrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatal(err)
	}

	payload := eventsPayload{
		Host: er.Host,
		Events: []audit.Event{{
			Time: time.Now(), Host: er.Host, Type: "port_added", Severity: "P0",
			Data: map[string]any{"port": 6379},
		}},
	}
	resp, _ := postJSON(t, srv.URL+"/api/v1/events", payload, map[string]string{
		"Authorization": "Bearer " + er.Token,
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("post events status = %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/events?host="+er.Host, nil)
	req.Header.Set("Authorization", "Bearer enroll-secret")
	gresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer gresp.Body.Close()
	var out struct {
		Count  int        `json:"count"`
		Events []EventRow `json:"events"`
	}
	if err := json.NewDecoder(gresp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || out.Events[0].Type != "port_added" {
		t.Fatalf("events = %+v", out)
	}
	if string(out.Events[0].Data) == "" {
		t.Fatal("event payload lost")
	}
}

func TestEventsRejectForeignHost(t *testing.T) {
	srv, _, _ := testServer(t)
	_, body := postJSON(t, srv.URL+"/api/v1/enroll", enrollRequest{Token: "enroll-secret", Host: "h1"}, nil)
	var er enrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatal(err)
	}

	payload := eventsPayload{Host: "someone-else", Events: []audit.Event{{Type: "fw_change"}}}
	resp, _ := postJSON(t, srv.URL+"/api/v1/events", payload, map[string]string{
		"Authorization": "Bearer " + er.Token,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestEventQueryRequiresAdmin(t *testing.T) {
	srv, _, _ := testServer(t)
	_, body := postJSON(t, srv.URL+"/api/v1/enroll", enrollRequest{Token: "enroll-secret", Host: "h1"}, nil)
	var er enrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+er.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
