package httpserver

import "net/http"

// notImplemented backs handler stubs until their task lands; removed in Task 7.
func notImplemented(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented, "not_implemented", "not implemented", nil)
}
