package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Feishu custom-bot webhook. Signature algorithm (from the docs):
//
//	stringToSign = timestamp + "\n" + secret
//	sign         = base64(HMAC-SHA256(key=stringToSign, data=""))
func feishuSign(secret, timestamp string) string {
	mac := hmac.New(sha256.New, []byte(timestamp+"\n"+secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// AlertmanagerPayload is the subset of the webhook body we use.
type AlertmanagerPayload struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []AMAlert         `json:"alerts"`
}

type AMAlert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// Notifier renders Alertmanager groups into Feishu cards.
type Notifier struct {
	webhook   string
	secret    string
	vmuiURL   string
	publicURL string
	snoozeKey []byte
	client    *http.Client
	dedupe    *deduper
}

func NewNotifier(webhook, secret, vmuiURL, publicURL string, snoozeKey []byte) *Notifier {
	return &Notifier{
		webhook:   webhook,
		secret:    secret,
		vmuiURL:   vmuiURL,
		publicURL: publicURL,
		snoozeKey: snoozeKey,
		client:    &http.Client{Timeout: 10 * time.Second},
		dedupe:    newDeduper(10*time.Minute, 20),
	}
}

// Enabled reports whether a webhook is configured.
func (n *Notifier) Enabled() bool { return n.webhook != "" }

// Send delivers the alert group. Deduplicated groups return suppressed=true.
func (n *Notifier) Send(ctx context.Context, p AlertmanagerPayload) (suppressed bool, err error) {
	if !n.Enabled() {
		return false, fmt.Errorf("feishu webhook not configured")
	}
	if p.Status == "firing" && n.dedupe.seen(p.GroupKey) {
		return true, nil
	}

	msg, err := n.buildMessage(p)
	if err != nil {
		return false, err
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return false, err
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		err := n.post(ctx, body)
		if err == nil {
			return false, nil
		}
		lastErr = err
		// 4xx means a bad request or bad signature: retrying will not help.
		var statusErr *statusError
		if ok := asStatusError(err, &statusErr); ok && statusErr.code >= 400 && statusErr.code < 500 {
			break
		}
	}
	return false, lastErr
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string { return fmt.Sprintf("feishu status %d: %s", e.code, e.body) }

func asStatusError(err error, target **statusError) bool {
	se, ok := err.(*statusError)
	if ok {
		*target = se
	}
	return ok
}

func (n *Notifier) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return &statusError{code: resp.StatusCode, body: string(respBody)}
	}
	// Feishu returns 200 with a non-zero "code" on logical failures.
	var ack struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if json.Unmarshal(respBody, &ack) == nil && ack.Code != 0 {
		return &statusError{code: http.StatusBadRequest, body: ack.Msg}
	}
	return nil
}

func (n *Notifier) buildMessage(p AlertmanagerPayload) (map[string]any, error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	card := n.buildCard(p)
	msg := map[string]any{
		"msg_type": "interactive",
		"card":     card,
	}
	if n.secret != "" {
		msg["timestamp"] = ts
		msg["sign"] = feishuSign(n.secret, ts)
	}
	return msg, nil
}

func (n *Notifier) buildCard(p AlertmanagerPayload) map[string]any {
	severity := p.CommonLabels["severity"]
	if severity == "" && len(p.Alerts) > 0 {
		severity = p.Alerts[0].Labels["severity"]
	}
	host := p.CommonLabels["host"]
	alertName := p.CommonLabels["alertname"]
	if alertName == "" && len(p.Alerts) > 0 {
		alertName = p.Alerts[0].Labels["alertname"]
	}

	title := fmt.Sprintf("[%s] %s · %s", severity, host, alertName)
	if p.Status == "resolved" {
		title = fmt.Sprintf("[已恢复] %s · %s", host, alertName)
	}

	color := "blue"
	switch severity {
	case "P0":
		color = "red"
	case "P1":
		color = "orange"
	case "P2":
		color = "grey"
	}
	if p.Status == "resolved" {
		color = "green"
	}

	elements := []any{}
	summary := p.CommonAnnotations["summary"]
	if summary == "" && len(p.Alerts) > 0 {
		summary = p.Alerts[0].Annotations["summary"]
	}
	if summary != "" {
		elements = append(elements, map[string]any{
			"tag":  "div",
			"text": map[string]string{"tag": "lark_md", "content": "**" + summary + "**"},
		})
	}

	for i, a := range p.Alerts {
		if i >= 5 {
			elements = append(elements, map[string]any{
				"tag":  "div",
				"text": map[string]string{"tag": "lark_md", "content": fmt.Sprintf("… 另有 %d 条告警", len(p.Alerts)-5)},
			})
			break
		}
		content := alertBody(a, p.Status)
		if content != "" {
			elements = append(elements, map[string]any{
				"tag":  "div",
				"text": map[string]string{"tag": "lark_md", "content": content},
			})
		}
	}

	fields := []any{
		field("级别", severity),
		field("主机", host),
	}
	if len(p.Alerts) > 0 {
		fields = append(fields, field("开始", p.Alerts[0].StartsAt.Local().Format("01-02 15:04:05")))
		if p.Status == "resolved" && !p.Alerts[0].EndsAt.IsZero() {
			fields = append(fields, field("恢复", p.Alerts[0].EndsAt.Local().Format("01-02 15:04:05")))
		}
	}
	elements = append(elements, map[string]any{"tag": "div", "fields": fields})

	actions := []any{}
	if q := metricsQuery(p); q != "" {
		actions = append(actions, map[string]any{
			"tag":  "button",
			"text": map[string]string{"tag": "plain_text", "content": "查看曲线"},
			"type": "primary",
			"url":  n.vmuiLink(q),
		})
	}
	if link := n.snoozeLink(p); link != "" {
		actions = append(actions, map[string]any{
			"tag":  "button",
			"text": map[string]string{"tag": "plain_text", "content": "静默 1 小时"},
			"type": "default",
			"url":  link,
		})
	}
	if len(actions) > 0 {
		elements = append(elements, map[string]any{"tag": "action", "actions": actions})
	}

	return map[string]any{
		"config": map[string]any{"wide_screen_mode": true},
		"header": map[string]any{
			"template": color,
			"title":    map[string]string{"tag": "plain_text", "content": title},
		},
		"elements": elements,
	}
}

func field(label, value string) map[string]any {
	if value == "" {
		value = "-"
	}
	return map[string]any{
		"is_short": true,
		"text":     map[string]string{"tag": "lark_md", "content": "**" + label + "**\n" + value},
	}
}

func alertBody(a AMAlert, groupStatus string) string {
	parts := []string{}
	if d := a.Annotations["description"]; d != "" {
		parts = append(parts, d)
	}
	// Surface evidence verbatim: an alert without evidence is noise.
	if ev := a.Annotations["evidence"]; ev != "" {
		if len(ev) > 400 {
			ev = ev[:400] + "…"
		}
		parts = append(parts, "```\n"+ev+"\n```")
	}
	if a.Status == "resolved" && groupStatus != "resolved" {
		parts = append(parts, "_该条已恢复_")
	}
	return strings.Join(parts, "\n")
}

// metricsQuery picks the most useful ad-hoc query for the "view" button.
func metricsQuery(p AlertmanagerPayload) string {
	host := p.CommonLabels["host"]
	if host == "" {
		return ""
	}
	switch p.CommonLabels["kind"] {
	case "disk_full":
		return fmt.Sprintf(`beacon_disk_used_ratio{host="%s"}`, host)
	case "agent_down":
		return fmt.Sprintf(`beacon_agent_heartbeat{host="%s"}`, host)
	case "port_added", "port_exposure":
		return fmt.Sprintf(`beacon_port_listen_info{host="%s"}`, host)
	case "fw_change":
		return fmt.Sprintf(`changes(beacon_fw_change_total{host="%s"}[1h])`, host)
	default:
		return fmt.Sprintf(`{host="%s"}`, host)
	}
}

func (n *Notifier) vmuiLink(query string) string {
	return strings.TrimRight(n.vmuiURL, "/") + "/vmui?g0.expr=" + url.QueryEscape(query)
}

// snoozeLink returns a signed URL that creates an Alertmanager silence. Only
// single-alert groups get a button; grouped alerts are too coarse to silence.
func (n *Notifier) snoozeLink(p AlertmanagerPayload) string {
	if len(p.Alerts) != 1 || len(n.snoozeKey) == 0 || n.publicURL == "" {
		return ""
	}
	host := p.Alerts[0].Labels["host"]
	alertName := p.Alerts[0].Labels["alertname"]
	if host == "" || alertName == "" {
		return ""
	}
	return snoozeURL(n.publicURL, n.snoozeKey, host, alertName, time.Now().Add(24*time.Hour))
}
