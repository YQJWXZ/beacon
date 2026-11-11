package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Credentials are the long-term token issued by the center at enrollment.
type Credentials struct {
	Host  string `json:"host"`
	ID    string `json:"id"`
	Token string `json:"token"`
}

func credPath(stateDir string) string { return filepath.Join(stateDir, "cred.json") }

// LoadCredentials returns stored credentials, if any.
func LoadCredentials(stateDir string) (*Credentials, error) {
	b, err := os.ReadFile(credPath(stateDir))
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	return &c, nil
}

// SaveCredentials writes the token with owner-only permissions.
func SaveCredentials(stateDir string, c *Credentials) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := credPath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, credPath(stateDir))
}

type enrollRequest struct {
	Token    string `json:"token"`
	Host     string `json:"host"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

type enrollResponse struct {
	ID    string `json:"id"`
	Host  string `json:"host"`
	Token string `json:"token"`
}

// Enroll exchanges a one-time token for a long-term credential.
func Enroll(ctx context.Context, serverURL, enrollToken, host, version string) (*Credentials, error) {
	body, err := json.Marshal(enrollRequest{
		Token:    enrollToken,
		Host:     host,
		Hostname: hostname(),
		Version:  version,
	})
	if err != nil {
		return nil, err
	}
	u := bytes.TrimRight([]byte(serverURL), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		string(u)+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll rejected: status %d: %s", resp.StatusCode, string(respBody))
	}
	var out enrollResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode enroll response: %w", err)
	}
	if out.Token == "" {
		return nil, fmt.Errorf("enroll response missing token")
	}
	return &Credentials{Host: out.Host, ID: out.ID, Token: out.Token}, nil
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
