package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// LoadSnapshotFile reads a persisted snapshot; a missing or broken file is not
// an error, it just means "no baseline".
func LoadSnapshotFile(path string) *Snapshot {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil
	}
	return &s
}

// SaveSnapshotFile writes the snapshot atomically.
func SaveSnapshotFile(path string, s *Snapshot) error {
	if path == "" {
		return nil
	}
	return writeJSONAtomic(path, s)
}

// LoadListensFile reads the last known listening set.
func LoadListensFile(path string) []Listen {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []Listen
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// SaveListensFile writes the listening set atomically.
func SaveListensFile(path string, l []Listen) error {
	if path == "" {
		return nil
	}
	return writeJSONAtomic(path, l)
}

func writeJSONAtomic(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
