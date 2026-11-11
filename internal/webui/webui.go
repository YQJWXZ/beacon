// Package webui serves the built dashboard. Assets are read from disk so the
// server binary does not need to be rebuilt when the UI changes; when the
// directory is missing a self-explanatory placeholder is served instead.
package webui

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const fallbackHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>BEACON · UI 未构建</title>
<style>
  body{background:#0a0a0a;color:#fff;font-family:Inter,"Arial Black",sans-serif;
       display:grid;place-items:center;height:100vh;margin:0}
  main{max-width:520px;padding:32px;border:1px solid rgba(255,0,110,.35);
       border-radius:4px;box-shadow:0 0 20px rgba(255,0,110,.25)}
  h1{font-size:28px;letter-spacing:.18em;text-transform:uppercase;margin:0 0 12px}
  code{color:#00d4ff}
  p{color:rgba(255,255,255,.75);line-height:1.6}
</style></head>
<body><main>
  <h1>UI 未构建</h1>
  <p>前端资源不存在。在仓库根目录执行：</p>
  <p><code>make ui</code></p>
  <p>然后刷新此页面。API 不受影响，<code>/api/v1/*</code> 仍然可用。</p>
</main></body></html>`

// Handler serves dir, falling back to index.html for client-side routes.
func Handler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		rel := strings.TrimPrefix(clean, "/")
		if rel == "" {
			rel = "index.html"
		}

		full := filepath.Join(dir, filepath.FromSlash(rel))
		if !within(dir, full) {
			http.NotFound(w, r)
			return
		}
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			if strings.HasPrefix(clean, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFile(w, r, full)
			return
		}

		index := filepath.Join(dir, "index.html")
		if _, err := os.Stat(index); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(fallbackHTML))
			return
		}
		// Unknown path with a built SPA: let the client router handle it.
		http.ServeFile(w, r, index)
	})
}

func within(dir, full string) bool {
	absDir, err1 := filepath.Abs(dir)
	absFull, err2 := filepath.Abs(full)
	if err1 != nil || err2 != nil {
		return false
	}
	return absFull == absDir || strings.HasPrefix(absFull, absDir+string(os.PathSeparator))
}
