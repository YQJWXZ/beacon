package notify

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
// server-side key, so a card button works without a login and cannot be
// replayed after expiry.
func snoozeSignature(key []byte, host, alert string, exp int64) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s|%s|%d", host, alert, exp)
	return hex.EncodeToString(mac.Sum(nil))
}

// SnoozeURL builds the signed link embedded in a Feishu card.
func SnoozeURL(base string, key []byte, host, alert string, exp time.Time) string {
	e := exp.Unix()
	q := url.Values{}
	q.Set("host", host)
	q.Set("alert", alert)
	q.Set("exp", strconv.FormatInt(e, 10))
	q.Set("sig", snoozeSignature(key, host, alert, e))
	return fmt.Sprintf("%s/snooze?%s", base, q.Encode())
}

// VerifySnooze checks the signature and expiry.
func VerifySnooze(key []byte, host, alert string, exp int64, sig string) bool {
	if time.Now().Unix() > exp {
		return false
	}
	want := snoozeSignature(key, host, alert, exp)
	return hmac.Equal([]byte(want), []byte(sig))
}

// CreateSilence asks Alertmanager to silence one host+alert pair.
func CreateSilence(ctx context.Context, client *http.Client, amURL, host, alert string, d time.Duration) error {
	if amURL == "" {
		return fmt.Errorf("alertmanager URL not configured")
	}
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, amURL+"/api/v2/silences", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("alertmanager rejected the silence: %d %s", resp.StatusCode, string(respBody))
	}
	return nil
}
