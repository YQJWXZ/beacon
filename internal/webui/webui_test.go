package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func build(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>app</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestServesIndexAndAssets(t *testing.T) {
	h := Handler(build(t))

	if rec := get(h, "/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "app") {
		t.Fatalf("/ => %d %q", rec.Code, rec.Body.String())
	}
	rec := get(h, "/assets/app.js")
	if rec.Code != 200 || rec.Body.String() != "console.log(1)" {
		t.Fatalf("asset => %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("cache-control = %q", got)
	}
}

func TestSPAFallback(t *testing.T) {
	h := Handler(build(t))
	rec := get(h, "/host/abc")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "app") {
		t.Fatalf("fallback => %d %q", rec.Code, rec.Body.String())
	}
}

func TestMissingBuildServesPlaceholder(t *testing.T) {
	h := Handler(filepath.Join(t.TempDir(), "does-not-exist"))
	rec := get(h, "/")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "make ui") {
		t.Fatalf("placeholder missing instructions: %q", rec.Body.String())
	}
}

func TestRejectsTraversal(t *testing.T) {
	dir := build(t)
	secret := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(secret, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := Handler(dir)
	rec := get(h, "/../secret.txt")
	if strings.Contains(rec.Body.String(), "nope") {
		t.Fatal("path traversal leaked a file")
	}
}
