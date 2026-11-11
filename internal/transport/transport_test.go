package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendSetsRemoteWriteHeaders(t *testing.T) {
	var got http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	tr, err := New(Config{Endpoint: srv.URL + "/api/v1/write", Token: "abc", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	payload := []byte("compressed")
	if err := tr.Send(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	if got.Get("Content-Encoding") != "snappy" {
		t.Errorf("content-encoding = %q", got.Get("Content-Encoding"))
	}
	if got.Get("Authorization") != "Bearer abc" {
		t.Errorf("authorization = %q", got.Get("Authorization"))
	}
	if got.Get("X-Prometheus-Remote-Write-Version") != "0.1.0" {
		t.Errorf("version header = %q", got.Get("X-Prometheus-Remote-Write-Version"))
	}
	if string(body) != "compressed" {
		t.Errorf("body = %q", body)
	}
}

func TestSendClassifiesErrors(t *testing.T) {
	cases := []struct {
		status    int
		retryable bool
	}{
		{http.StatusInternalServerError, true},
		{http.StatusTooManyRequests, true},
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		}))
		tr, err := New(Config{Endpoint: srv.URL, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		err = tr.Send(context.Background(), []byte("x"))
		tr.Close()
		srv.Close()

		var he *HTTPError
		if !errors.As(err, &he) {
			t.Fatalf("status %d: want HTTPError, got %v", tc.status, err)
		}
		if Retryable(err) != tc.retryable {
			t.Errorf("status %d: retryable = %v, want %v", tc.status, Retryable(err), tc.retryable)
		}
	}
}

func TestProbeReportsFailureLayer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	url := srv.URL
	srv.Close() // nothing is listening now

	steps := Probe(context.Background(), Config{Endpoint: url + "/api/v1/write", Timeout: 500 * time.Millisecond}, []byte("x"))
	if len(steps) < 2 {
		t.Fatalf("expected multiple steps, got %+v", steps)
	}
	last := steps[len(steps)-1]
	if last.OK {
		t.Fatalf("expected failure on closed server, got %+v", steps)
	}
}

func TestUnixEndpointValidation(t *testing.T) {
	if _, err := New(Config{Endpoint: "unix://"}); err == nil {
		t.Fatal("expected error for unix endpoint without path")
	}
}
