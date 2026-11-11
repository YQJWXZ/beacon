package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Host is a registered agent. Only the token hash is stored on disk.
type Host struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}

type Store struct {
	path   string
	mu     sync.Mutex
	hosts  map[string]*Host
	byHash map[string]string
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, hosts: map[string]*Host{}, byHash: map[string]string{}}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var list []*Host
		if err := json.Unmarshal(b, &list); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, h := range list {
			s.hosts[h.ID] = h
			s.byHash[h.TokenHash] = h.ID
		}
	case os.IsNotExist(err):
	default:
		return nil, err
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	list := make([]*Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		list = append(list, h)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Enroll creates a host and returns the plaintext token exactly once.
func (s *Store) Enroll(name string) (string, *Host, error) {
	token, err := randomToken()
	if err != nil {
		return "", nil, err
	}
	id, err := randomID()
	if err != nil {
		return "", nil, err
	}
	h := &Host{
		ID:        id,
		Name:      name,
		TokenHash: hashToken(token),
		CreatedAt: time.Now().UTC(),
	}
	s.mu.Lock()
	s.hosts[h.ID] = h
	s.byHash[h.TokenHash] = h.ID
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		return "", nil, err
	}
	return token, h, nil
}

// Verify maps a bearer token to a host.
func (s *Store) Verify(token string) (*Host, bool) {
	if token == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byHash[hashToken(token)]
	if !ok {
		return nil, false
	}
	h, ok := s.hosts[id]
	if !ok {
		return nil, false
	}
	cp := *h
	return &cp, true
}

// Touch records liveness without writing to disk on every request.
func (s *Store) Touch(id string) {
	s.mu.Lock()
	if h, ok := s.hosts[id]; ok {
		h.LastSeen = time.Now().UTC()
	}
	s.mu.Unlock()
}

// Flush persists last-seen updates; called periodically by the server.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) List() []Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
