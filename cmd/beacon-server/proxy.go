package main

import (
	"io"
	"net/http"
	"strings"
)

// The dashboard talks to VictoriaMetrics and Alertmanager through the center,
// so the browser never needs credentials for those services and they can stay
// bound to loopback.

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if s.vmBase == "" {
		writeError(w, http.StatusServiceUnavailable, "metrics backend not configured")
		return
	}
	s.proxyGET(w, r, s.vmBase+"/api/v1/query?"+r.URL.RawQuery)
}

func (s *Server) handleQueryRange(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if s.vmBase == "" {
		writeError(w, http.StatusServiceUnavailable, "metrics backend not configured")
		return
	}
	s.proxyGET(w, r, s.vmBase+"/api/v1/query_range?"+r.URL.RawQuery)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if s.amURL == "" {
		writeError(w, http.StatusServiceUnavailable, "alertmanager not configured")
		return
	}
	s.proxyGET(w, r, strings.TrimRight(s.amURL, "/")+"/api/v2/alerts")
}

func (s *Server) proxyGET(w http.ResponseWriter, r *http.Request, upstream string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build upstream request failed")
		return
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("upstream query failed", "url", upstream, "err", err)
		writeError(w, http.StatusBadGateway, "upstream unavailable")
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 32<<20))
}
