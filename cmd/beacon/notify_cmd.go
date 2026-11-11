package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/yqjwxz/beacon/internal/notify"
)

func cmdNotify(args []string) error {
	if len(args) < 2 || args[0] != "test" {
		return fmt.Errorf("usage: beacon notify test feishu [-webhook url] [-secret secret]")
	}
	switch args[1] {
	case "feishu":
		return cmdNotifyTestFeishu(args[2:])
	default:
		return fmt.Errorf("unknown notify target %q", args[1])
	}
}

// cmdNotifyTestFeishu sends one real card. It exists because signature and card
// schema are the only things a local mock cannot verify.
func cmdNotifyTestFeishu(args []string) error {
	fs := flag.NewFlagSet("notify test feishu", flag.ContinueOnError)
	webhook := fs.String("webhook", os.Getenv("BEACON_FEISHU_WEBHOOK"), "Feishu bot webhook (or BEACON_FEISHU_WEBHOOK)")
	secret := fs.String("secret", os.Getenv("BEACON_FEISHU_SECRET"), "Feishu signing secret (or BEACON_FEISHU_SECRET)")
	vmui := fs.String("vmui-url", os.Getenv("BEACON_VMUI_URL"), "vmui base URL for the curve button")
	publicURL := fs.String("public-url", os.Getenv("BEACON_PUBLIC_URL"), "beacon-server URL for the snooze button")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *webhook == "" {
		return fmt.Errorf("no webhook: pass -webhook or set BEACON_FEISHU_WEBHOOK")
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "beacon-test"
	}
	labels := map[string]string{
		"host": host, "alertname": "BeaconNotifyTest", "severity": "P0", "kind": "test",
	}
	payload := notify.AlertmanagerPayload{
		Version:      "4",
		GroupKey:     "beacon-notify-test",
		Status:       "firing",
		CommonLabels: labels,
		CommonAnnotations: map[string]string{
			"summary": "beacon 通知链路自检",
		},
		Alerts: []notify.AMAlert{{
			Status: "firing",
			Labels: labels,
			Annotations: map[string]string{
				"description": "看到这张卡片说明 webhook、签名和卡片渲染都正常。",
				"evidence":    `{"source":"beacon notify test","signed":true}`,
			},
			StartsAt: time.Now(),
		}},
	}

	n := notify.NewNotifier(*webhook, *secret, *vmui, *publicURL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := time.Now()
	suppressed, err := n.Send(ctx, payload)
	if err != nil {
		return fmt.Errorf("send failed: %w", err)
	}
	if suppressed {
		return fmt.Errorf("delivery was suppressed by the rate limiter")
	}
	fmt.Printf("ok: card delivered in %s (signed=%v, host=%s)\n",
		time.Since(start).Round(time.Millisecond), *secret != "", host)
	return nil
}
