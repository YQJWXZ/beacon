package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Snooze links are self-contained: host, alert and expiry are signed with a
// server-side key, so the card button works without a login and cannot be
// replayed after expiry.
func snoozeSignature(key []byte, host, alert string, exp int64) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s|%s|%d", host, alert, exp)
	return hex.EncodeToString(mac.Sum(nil))
}

func snoozeURL(base string, key []byte, host, alert string, exp time.Time) string {
	e := exp.Unix()
	q := url.Values{}
	q.Set("host", host)
	q.Set("alert", alert)
	q.Set("exp", strconv.FormatInt(e, 10))
	q.Set("sig", snoozeSignature(key, host, alert, e))
	return fmt.Sprintf("%s/snooze?%s", base, q.Encode())
}

func verifySnooze(key []byte, host, alert string, exp int64, sig string) bool {
	if time.Now().Unix() > exp {
		return false
	}
	want := snoozeSignature(key, host, alert, exp)
	return hmac.Equal([]byte(want), []byte(sig))
}

// handleSnooze creates an Alertmanager silence for one host+alert pair.
func (s *Server) handleSnooze(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host, alert := q.Get("host"), q.Get("alert")
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil || host == "" || alert == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !verifySnooze(s.snoozeKey, host, alert, exp, q.Get("sig")) {
		http.Error(w, "invalid or expired link", http.StatusForbidden)
		return
	}
	if s.amURL == "" {
		http.Error(w, "alertmanager not configured", http.StatusNotImplemented)
		return
	}

	d := time.Duration(exp-time.Now().Unix()) * time.Second
	if d > time.Hour {
		d = time.Hour
	}
	body := map[string]any{
		"matchers": []map[string]any{
			{"name": "host", "value": host, "isRegex": false},
			{"name": "alertname", "value": alert, "isRegex": false},
		},
		"startsAt":  time.Now().UTC().Format(time.RFC3339),
		"endsAt":    time.Now().Add(d).UTC().Format(time.RFC3339),
		"createdBy": "beacon-feishu",
		"comment":   "snoozed from a Feishu alert card",
	}
	payload, _ := json.Marshal(body)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.amURL+"/api/v2/silences", bytes.NewReader(payload))
	if err != nil {
		http.Error(w, "build request failed", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("create silence", "err", err)
		http.Error(w, "alertmanager unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		s.log.Warn("silence rejected", "status", resp.StatusCode, "body", string(respBody))
		http.Error(w, "alertmanager rejected the silence", http.StatusBadGateway)
		return
	}
	s.log.Info("silence created", "host", host, "alert", alert, "duration", d.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body style=\"font-family:sans-serif;padding:24px\"><h3>已静默 %s 的 %s</h3><p>时长 %s，到期自动恢复。</p></body></html>",
		host, alert, d.Round(time.Minute))
}
