package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/yqjwxz/beacon/internal/notify"
)

// handleSnooze creates an Alertmanager silence for one host+alert pair. The
// link is signed by the notifier and expires on its own.
func (s *Server) handleSnooze(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host, alert := q.Get("host"), q.Get("alert")
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil || host == "" || alert == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !notify.VerifySnooze(s.snoozeKey, host, alert, exp, q.Get("sig")) {
		http.Error(w, "invalid or expired link", http.StatusForbidden)
		return
	}

	d := time.Duration(exp-time.Now().Unix()) * time.Second
	if d > time.Hour {
		d = time.Hour
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := notify.CreateSilence(ctx, s.client, s.amURL, host, alert, d); err != nil {
		s.log.Warn("create silence", "err", err)
		http.Error(w, "alertmanager unavailable", http.StatusBadGateway)
		return
	}
	s.log.Info("silence created", "host", host, "alert", alert, "duration", d.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body style=\"font-family:sans-serif;padding:24px\"><h3>已静默 %s 的 %s</h3><p>时长 %s，到期自动恢复。</p></body></html>",
		host, alert, d.Round(time.Minute))
}
