package httpserver

import "net/http"

func notImplemented(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented, "not_implemented", "not implemented", nil)
}

func (h *handlers) login(w http.ResponseWriter, r *http.Request)        { notImplemented(w, r) }
func (h *handlers) logout(w http.ResponseWriter, r *http.Request)       { notImplemented(w, r) }
func (h *handlers) me(w http.ResponseWriter, r *http.Request)           { notImplemented(w, r) }
func (h *handlers) oidcStart(w http.ResponseWriter, r *http.Request)    { notImplemented(w, r) }
func (h *handlers) oidcCallback(w http.ResponseWriter, r *http.Request) { notImplemented(w, r) }
