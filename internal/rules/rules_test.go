package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidateOK(t *testing.T) {
	p := write(t, `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        labels: {severity: P0, kind: x}
        annotations: {summary: s}
`)
	errs, warns, err := Validate(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 0 {
		t.Fatalf("errors = %v", errs)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings = %v", warns)
	}
}

func TestValidateCatchesErrors(t *testing.T) {
	p := write(t, `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
      - alert: A
        expr: ""
`)
	errs, warns, err := Validate(p)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(errs, ";")
	if !strings.Contains(joined, "duplicate alert name") {
		t.Errorf("errors = %v", errs)
	}
	if !strings.Contains(joined, "missing expr") {
		t.Errorf("errors = %v", errs)
	}
	if len(warns) == 0 {
		t.Error("expected warnings for missing labels")
	}
}

func TestValidateRejectsEmptyFile(t *testing.T) {
	p := write(t, "groups: []\n")
	if _, _, err := Validate(p); err == nil {
		t.Fatal("expected error for empty rule file")
	}
}
