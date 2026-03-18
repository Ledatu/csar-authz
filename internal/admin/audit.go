package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/audit"
)

func (h *Handler) handleListAudit(w http.ResponseWriter, r *http.Request) {
	subject := extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	if apiErr := h.requirePermission(r, subject, "admin.audit.read", "platform", ""); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	if h.auditStore == nil {
		apierror.New("not_configured", http.StatusServiceUnavailable, "audit store not configured").Write(w)
		return
	}

	q := r.URL.Query()
	filter := audit.ListFilter{
		ScopeType:  q.Get("scope_type"),
		ScopeID:    q.Get("scope_id"),
		Actor:      q.Get("actor"),
		Action:     q.Get("action"),
		TargetType: q.Get("target_type"),
		Cursor:     q.Get("cursor"),
	}

	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Limit = n
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = &t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = &t
		}
	}

	result, err := h.auditStore.List(r.Context(), &filter)
	if err != nil {
		h.logger.Error("failed to list audit events", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list audit events").Write(w)
		return
	}

	writeJSON(w, http.StatusOK, result)
}
