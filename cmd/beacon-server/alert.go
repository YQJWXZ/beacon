package main

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/yqjwxz/beacon/internal/notify"
)

// handleAlert receives Alertmanager webhook deliveries and forwards them to
// Feishu. It is unauthenticated by design: Alertmanager runs inside the same
// compose network, and the endpoint only renders notifications.
func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	var p notify.AlertmanagerPayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	if s.notifier == nil || !s.notifier.Enabled() {
		http.Error(w, "feishu webhook not configured", http.StatusServiceUnavailable)
		return
	}
	if len(p.Alerts) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	suppressed, err := s.notifier.Send(r.Context(), p)
	if err != nil {
		s.log.Warn("feishu send failed", "group", p.GroupKey, "err", err)
		http.Error(w, "delivery failed", http.StatusBadGateway)
		return
	}
	if suppressed {
		s.log.Debug("alert suppressed", "group", p.GroupKey)
	}
	w.WriteHeader(http.StatusNoContent)
}
