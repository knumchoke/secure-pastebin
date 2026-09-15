package httpserver

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/knumchoke/secure-pastebin/internal/challenge"
	"github.com/knumchoke/secure-pastebin/internal/ratelimit"
)

func (h *handlers) issueChallenge(w http.ResponseWriter, r *http.Request) {
	if h.chal == nil {
		writeError(w, http.StatusNotFound, "not_found", "challenge disabled", nil)
		return
	}
	si, _ := sessionFrom(r.Context())
	if !h.limit(w, r, ratelimit.ScopeChallengeIssue, si.User.ID.String()) {
		return
	}
	iss, err := h.chal.Issue(r.Context(), si.User.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"challenge_id":       iss.ID,
		"background_png_b64": base64.StdEncoding.EncodeToString(iss.BackgroundPNG),
		"piece_png_b64":      base64.StdEncoding.EncodeToString(iss.PiecePNG),
		"piece_y":            iss.PieceY,
		"width":              iss.Width,
		"height":             iss.Height,
		"expires_in":         int(iss.ExpiresIn.Seconds()),
	})
}

func (h *handlers) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	if h.chal == nil {
		writeError(w, http.StatusNotFound, "not_found", "challenge disabled", nil)
		return
	}
	si, _ := sessionFrom(r.Context())
	var in struct {
		X int `json:"x"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "x required", nil)
		return
	}
	tok, err := h.chal.Verify(r.Context(), si.User.ID, r.PathValue("id"), in.X)
	if err != nil {
		if errors.Is(err, challenge.ErrChallengeFailed) {
			h.metrics.Inc(MetricChallengeFailed)
		}
		h.fail(w, r, err)
		return
	}
	h.metrics.Inc(MetricChallengePassed)
	writeJSON(w, http.StatusOK, map[string]any{"challenge_token": tok, "expires_in": int(h.cfg.Challenge.TTL.Seconds())})
}
