package httpserver

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// spaHandler serves the embedded UI: real files as-is (hashed assets immutable),
// everything else falls back to index.html with no-store.
func spaHandler(static fs.FS) http.Handler {
	fileServer := http.FileServerFS(static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		clean := path.Clean("/" + r.URL.Path)
		name := strings.TrimPrefix(clean, "/")
		if name != "" && name != "index.html" {
			if st, err := fs.Stat(static, name); err == nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-store")
				}
				r.URL.Path = clean
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		b, err := fs.ReadFile(static, "index.html")
		if err != nil {
			http.Error(w, "ui not built", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
}
