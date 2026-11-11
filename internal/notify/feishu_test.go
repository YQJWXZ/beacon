package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

	n := NewNotifier(srv.URL, "shh", "http://vm:8428", "http://center:8080", []byte("k"))
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

func TestCreateSilence(t *testing.T) {
	var silence map[string]any
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&silence)
		_, _ = w.Write([]byte(`{"silenceID":"abc"}`))
	}))
	defer am.Close()

	if err := CreateSilence(context.Background(), am.Client(), am.URL, "h1", "BeaconDiskFull", time.Hour); err != nil {
		t.Fatal(err)
	}
	matchers := silence["matchers"].([]any)
	if len(matchers) != 2 {
		t.Fatalf("matchers = %v", matchers)
	}
}

func TestSnoozeURLRoundTrip(t *testing.T) {
	key := []byte("k")
	exp := time.Now().Add(time.Hour).Unix()
	link := SnoozeURL("http://center:8080", key, "h1", "BeaconDiskFull", time.Unix(exp, 0))
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if !VerifySnooze(key, q.Get("host"), q.Get("alert"), exp, q.Get("sig")) {
		t.Fatal("valid link rejected")
	}
	if VerifySnooze([]byte("other"), "h1", "BeaconDiskFull", exp, q.Get("sig")) {
		t.Fatal("wrong key accepted")
	}
	if VerifySnooze(key, "h2", "BeaconDiskFull", exp, q.Get("sig")) {
		t.Fatal("tampered host accepted")
	}
}

func TestSnoozeExpires(t *testing.T) {
	key := []byte("k")
	exp := time.Now().Add(-time.Minute).Unix()
	sig := snoozeSignature(key, "h1", "X", exp)
	if VerifySnooze(key, "h1", "X", exp, sig) {
		t.Fatal("expired link accepted")
	}
}
