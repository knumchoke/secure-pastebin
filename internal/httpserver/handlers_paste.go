package httpserver

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/paste"
	"github.com/knumchoke/secure-pastebin/internal/ratelimit"
)

var hexSHA = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func pasteJSON(baseURL string, m paste.PasteMeta, status paste.Status, hashVisible bool, content []byte, includeOwner bool) map[string]any {
	out := map[string]any{
		"id": m.ID.String(), "url": paste.PasteURL(baseURL, m.ID), "status": string(status),
		"created_at": m.CreatedAt.UTC().Format(time.RFC3339), "expires_at": m.ExpiresAt.UTC().Format(time.RFC3339),
		"ttl_seconds": m.TTLSeconds, "size_bytes": m.SizeBytes, "password_protected": m.PasswordProtected,
		"hash_algo": m.HashAlgo, "view_count": m.ViewCount,
	}
	if m.DeletedAt != nil {
		out["deleted_at"] = m.DeletedAt.UTC().Format(time.RFC3339)
	}
	if hashVisible {
		out["sha256"] = m.ContentHash
	}
	if content != nil {
		out["content"] = string(content)
	}
	if includeOwner {
		out["owner_id"] = m.OwnerID.String()
	}
	return out
}

func pathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "id must be a uuid", nil)
		return uuid.Nil, false
	}
	return id, true
}

func statusErr(s paste.Status) error {
	switch s {
	case paste.StatusExpired:
		return paste.ErrExpired
	case paste.StatusDeleted:
		return paste.ErrDeleted
	case paste.StatusUnavailable:
		return paste.ErrUnavailable
	}
	return nil
}

func (h *handlers) createPaste(w http.ResponseWriter, r *http.Request) {
	si, _ := sessionFrom(r.Context())
	var in struct {
		Content        string `json:"content"`
		Password       string `json:"password"`
		TTLSeconds     int    `json:"ttl_seconds"`
		ChallengeToken string `json:"challenge_token"`
	}
	if err := decodeJSON(r, &in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body too large", map[string]any{"limit_bytes": mbe.Limit})
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", "invalid json body", nil)
		return
	}
	if !h.limit(w, r, ratelimit.ScopePasteCreate, si.User.ID.String()) {
		return
	}
	if h.chal != nil {
		if err := h.chal.Consume(r.Context(), si.User.ID, in.ChallengeToken); err != nil {
			h.fail(w, r, paste.ErrChallengeRequired)
			return
		}
	}
	res, err := h.pastes.Create(r.Context(), si.User.Principal(), paste.CreateInput{Content: in.Content, Password: in.Password, TTLSeconds: in.TTLSeconds})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.metrics.Inc(MetricPastesCreated)
	writeJSON(w, http.StatusCreated, pasteJSON(h.cfg.AppBaseURL, res.Meta, paste.StatusActive, true, nil, false))
}

func (h *handlers) getPaste(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	res, err := h.pastes.Read(r.Context(), principalFrom(r.Context()), id, "")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pasteJSON(h.cfg.AppBaseURL, res.Meta, res.Status, res.HashVisible, res.Content, false))
}

func writeRaw(w http.ResponseWriter, id uuid.UUID, content []byte) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.txt"`, id))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (h *handlers) unlockPaste(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ip := ipFrom(r.Context())
	if !h.limit(w, r, ratelimit.ScopeUnlockIP, ip) || !h.limit(w, r, ratelimit.ScopeUnlock, id.String()+":"+ip) {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &in); err != nil || in.Password == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "password required", nil)
		return
	}
	res, err := h.pastes.Read(r.Context(), principalFrom(r.Context()), id, in.Password)
	if err != nil {
		if errors.Is(err, paste.ErrWrongPassword) {
			h.metrics.Inc(MetricUnlockFailures)
		}
		h.fail(w, r, err)
		return
	}
	if e := statusErr(res.Status); e != nil {
		h.fail(w, r, e)
		return
	}
	if strings.HasPrefix(r.Header.Get("Accept"), "text/plain") {
		writeRaw(w, id, res.Content)
		return
	}
	writeJSON(w, http.StatusOK, pasteJSON(h.cfg.AppBaseURL, res.Meta, res.Status, true, res.Content, false))
}

func (h *handlers) rawPaste(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	res, err := h.pastes.Read(r.Context(), principalFrom(r.Context()), id, "")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if e := statusErr(res.Status); e != nil {
		h.fail(w, r, e)
		return
	}
	if res.Meta.PasswordProtected {
		h.fail(w, r, paste.ErrPasswordRequired)
		return
	}
	writeRaw(w, id, res.Content)
}

func (h *handlers) verifyPaste(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !h.limit(w, r, ratelimit.ScopeVerifyGlobal, "global") || !h.limit(w, r, ratelimit.ScopeVerify, ipFrom(r.Context())) {
		return
	}
	var in struct {
		SHA256 string `json:"sha256"`
	}
	if err := decodeJSON(r, &in); err != nil || !hexSHA.MatchString(in.SHA256) {
		writeError(w, http.StatusBadRequest, "bad_request", "sha256 must be 64 hex characters", nil)
		return
	}
	v, err := h.pastes.Verify(r.Context(), id, in.SHA256)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"match": v.Match, "status": string(v.Status),
		"created_at": v.Meta.CreatedAt.UTC().Format(time.RFC3339), "expires_at": v.Meta.ExpiresAt.UTC().Format(time.RFC3339),
		"size_bytes": v.Meta.SizeBytes,
	})
}

func (h *handlers) deletePaste(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	si, _ := sessionFrom(r.Context())
	if !h.limit(w, r, ratelimit.ScopeDelete, si.User.ID.String()) {
		return
	}
	if err := h.pastes.Delete(r.Context(), si.User.Principal(), id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func pageFrom(r *http.Request) paste.Page {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return paste.Page{Limit: limit, Offset: offset}
}

func (h *handlers) writeList(w http.ResponseWriter, items []paste.PasteMeta) {
	out := make([]map[string]any, 0, len(items))
	now := h.now()
	for _, m := range items {
		out = append(out, pasteJSON(h.cfg.AppBaseURL, m, m.Status(now), !m.PasswordProtected, nil, true))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *handlers) listMine(w http.ResponseWriter, r *http.Request) {
	si, _ := sessionFrom(r.Context())
	items, err := h.pastes.ListMine(r.Context(), si.User.Principal(), pageFrom(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeList(w, items)
}

func (h *handlers) adminList(w http.ResponseWriter, r *http.Request) {
	si, _ := sessionFrom(r.Context())
	var owner *uuid.UUID
	if o := r.URL.Query().Get("owner"); o != "" {
		id, err := uuid.Parse(o)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "owner must be a uuid", nil)
			return
		}
		owner = &id
	}
	items, err := h.pastes.ListAll(r.Context(), si.User.Principal(), owner, pageFrom(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeList(w, items)
}
