package httpserver

import "net/http"

type publicConfig struct {
	AuthModes         []string `json:"auth_modes"`
	ChallengeEnabled  bool     `json:"challenge_enabled"`
	PasteMaxSizeBytes int64    `json:"paste_max_size_bytes"`
	TTLDefault        int      `json:"ttl_default"`
	TTLMin            int      `json:"ttl_min"`
	TTLMax            int      `json:"ttl_max"`
	ViewRequiresAuth  bool     `json:"view_requires_auth"`
	NoticeText        string   `json:"notice_text"`
}

func (h *handlers) getConfig(w http.ResponseWriter, r *http.Request) {
	modes := []string{}
	if h.cfg.LocalEnabled() && h.local != nil {
		modes = append(modes, "local")
	}
	if h.cfg.OIDCEnabled() && h.oidc != nil {
		modes = append(modes, "oidc")
	}
	writeJSON(w, http.StatusOK, publicConfig{
		AuthModes: modes, ChallengeEnabled: h.chal != nil, PasteMaxSizeBytes: h.cfg.PasteMaxSize,
		TTLDefault: h.cfg.PasteTTLDefault, TTLMin: h.cfg.PasteTTLMin, TTLMax: h.cfg.PasteTTLMax,
		ViewRequiresAuth: h.cfg.ViewRequiresAuth, NoticeText: h.cfg.NoticeText,
	})
}
