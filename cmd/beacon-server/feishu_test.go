package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func samplePayload(status string) AlertmanagerPayload {
	return AlertmanagerPayload{
		Version:  "4",
		GroupKey: `{}/{host="h1",alertname="BeaconDiskFull"}`,
		Status:   status,
		CommonLabels: map[string]string{
			"host": "h1", "alertname": "BeaconDiskFull", "severity": "P0", "kind": "disk_full",
		},
		CommonAnnotations: map[string]string{
			"summary": "/data is 96% full",
		},
		Alerts: []AMAlert{{
			Status:      status,
			Labels:      map[string]string{"host": "h1", "alertname": "BeaconDiskFull", "severity": "P0"},
			Annotations: map[string]string{"description": "filesystem /data", "evidence": `{"used_ratio":0.96}`},
			StartsAt:    time.Now().Add(-5 * time.Minute),
		}},
	}
}

func TestFeishuSignIsDeterministicAndSecretBound(t *testing.T) {
	a := feishuSign("secret", "1700000000")
	b := feishuSign("secret", "1700000000")
	c := feishuSign("other", "1700000000")
	if a != b {
		t.Fatal("signature must be deterministic")
	}
	if a == c {
		t.Fatal("signature must depend on the secret")
	}
	raw, err := base64.StdEncoding.DecodeString(a)
	if err != nil || len(raw) != 32 {
		t.Fatalf("signature must be base64 of a 32-byte HMAC, got %q", a)
	}
}

func TestSendRendersCard(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"code":0,"msg":"ok"}`))
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, "shh", "http://vm:8428/vmui", "http://center:8080", []byte("k"))
	suppressed, err := n.Send(context.Background(), samplePayload("firing"))
	if err != nil {
		t.Fatal(err)
	}
	if suppressed {
		t.Fatal("first delivery must not be suppressed")
	}
	if got["msg_type"] != "interactive" {
		t.Fatalf("msg_type = %v", got["msg_type"])
	}
	if got["sign"] == "" || got["timestamp"] == "" {
		t.Fatal("signed bot must include timestamp and sign")
	}
	card, _ := got["card"].(map[string]any)
	header, _ := card["header"].(map[string]any)
	title, _ := header["title"].(map[string]any)
	if !strings.Contains(title["content"].(string), "h1") {
		t.Fatalf("title missing host: %v", title)
	}
	if header["template"] != "red" {
		t.Fatalf("P0 must be red, got %v", header["template"])
	}
}

func TestSendSuppressesDuplicates(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, "", "", "", nil)
	for i := 0; i < 3; i++ {
		suppressed, err := n.Send(context.Background(), samplePayload("firing"))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && suppressed {
			t.Fatal("first delivery suppressed")
		}
		if i > 0 && !suppressed {
			t.Fatal("duplicate delivery was not suppressed")
		}
	}
	if calls != 1 {
		t.Fatalf("feishu calls = %d, want 1", calls)
	}
}

func TestResolvedCardIsGreen(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, "", "", "", nil)
	if _, err := n.Send(context.Background(), samplePayload("resolved")); err != nil {
		t.Fatal(err)
	}
	card := got["card"].(map[string]any)
	header := card["header"].(map[string]any)
	if header["template"] != "green" {
		t.Fatalf("resolved card template = %v", header["template"])
	}
}

func TestSnoozeLinkRoundTrip(t *testing.T) {
	var silence map[string]any
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&silence)
		_, _ = w.Write([]byte(`{"silenceID":"abc"}`))
	}))
	defer am.Close()

	key := []byte("snooze-key")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(nil, nil, ServerOptions{AMURL: am.URL, SnoozeKey: key}, log)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	link := snoozeURL(ts.URL, key, "h1", "BeaconDiskFull", time.Now().Add(time.Hour))
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	// snoozeURL prepends the base, so reuse only the path and query.
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
	matchers := silence["matchers"].([]any)
	if len(matchers) != 2 {
		t.Fatalf("matchers = %v", matchers)
	}
}

func TestSnoozeRejectsBadSignature(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(nil, nil, ServerOptions{AMURL: "http://127.0.0.1:1", SnoozeKey: []byte("k")}, log)
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

func TestAlertHandlerDelivers(t *testing.T) {
	var received bool
	fs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer fs.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := NewNotifier(fs.URL, "", "", "", nil)
	srv := NewServer(nil, nil, ServerOptions{Notifier: n}, log)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	body, _ := json.Marshal(samplePayload("firing"))
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(nil, nil, ServerOptions{}, log)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	body, _ := json.Marshal(samplePayload("firing"))
	resp, err := http.Post(ts.URL+"/hooks/alert", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}
