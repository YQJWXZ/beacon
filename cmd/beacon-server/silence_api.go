package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/yqjwxz/beacon/internal/notify"
)

type silencePayload struct {
	Host     string `json:"host"`
	Alert    string `json:"alert"`
	Duration string `json:"duration"`
}

// handleSilenceCreate lets the console silence one alert without going through
// Feishu. Duration defaults to one hour and is capped at 24 hours.
func (s *Server) handleSilenceCreate(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if s.amURL == "" {
		writeError(w, http.StatusServiceUnavailable, "alertmanager not configured")
		return
	}
	var p silencePayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if p.Host == "" || p.Alert == "" {
		writeError(w, http.StatusBadRequest, "host and alert are required")
		return
	}

	d := time.Hour
	if p.Duration != "" {
		parsed, err := time.ParseDuration(p.Duration)
		if err != nil || parsed < 5*time.Minute || parsed > 24*time.Hour {
			writeError(w, http.StatusBadRequest, "duration must be between 5m and 24h")
			return
		}
		d = parsed
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := notify.CreateSilence(ctx, s.client, s.amURL, p.Host, p.Alert, d); err != nil {
		s.log.Warn("create silence", "host", p.Host, "alert", p.Alert, "err", err)
		writeError(w, http.StatusBadGateway, "alertmanager rejected the silence")
		return
	}
	s.log.Info("silence created", "host", p.Host, "alert", p.Alert, "duration", d.String())
	w.WriteHeader(http.StatusNoContent)
}
