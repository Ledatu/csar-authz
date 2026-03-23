package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ledatu/csar-core/apierror"
)

// extractServiceSubject returns the gateway subject if it is a trusted service identity.
func extractServiceSubject(r *http.Request) (string, *apierror.Response) {
	subject := extractSubject(r)
	if subject == "" {
		return "", apierror.New("unauthorized", http.StatusUnauthorized, "not authenticated")
	}
	if !strings.HasPrefix(subject, "svc:") {
		return "", apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "service identity required")
	}
	return subject, nil
}

func (h *Handler) RegisterServiceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /svc/tenants/{tenantId}/members/{subject}/roles", h.handleSvcAssignRole)
	mux.HandleFunc("GET /svc/subjects/{subject}/scopes", h.handleSvcListSubjectScopes)
	mux.HandleFunc("GET /svc/tenants/{tenantId}/assignments", h.handleSvcListScopeAssignments)
}

type svcAssignRoleRequest struct {
	Role string `json:"role"`
}

func (h *Handler) handleSvcAssignRole(w http.ResponseWriter, r *http.Request) {
	actor, apiErr := extractServiceSubject(r)
	if apiErr != nil {
		writeError(w, apiErr)
		return
	}

	tenantID := r.PathValue("tenantId")
	targetSubject := r.PathValue("subject")
	if tenantID == "" || targetSubject == "" {
		apierror.New("bad_request", http.StatusBadRequest, "tenant ID and subject are required").Write(w)
		return
	}

	var body svcAssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Role == "" {
		apierror.New("bad_request", http.StatusBadRequest, "request body must contain role").Write(w)
		return
	}

	if err := h.engine.AssignRole(r.Context(), targetSubject, body.Role, "tenant", tenantID); err != nil {
		h.logger.Error("svc assign role failed", "target", targetSubject, "role", body.Role, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to assign role").Write(w)
		return
	}

	if err := h.recordAudit(r, actor, "role.assign", "assignment", targetSubject+"/"+body.Role, "tenant", tenantID, nil); err != nil {
		apierror.New("audit_error", http.StatusInternalServerError, "mutation succeeded but audit write failed").Write(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type svcScopesResponse struct {
	Scopes []scopeDTO `json:"scopes"`
}

type scopeDTO struct {
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id"`
}

func (h *Handler) handleSvcListSubjectScopes(w http.ResponseWriter, r *http.Request) {
	if _, apiErr := extractServiceSubject(r); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	subject := r.PathValue("subject")
	if subject == "" {
		apierror.New("bad_request", http.StatusBadRequest, "subject is required").Write(w)
		return
	}

	scopes, err := h.engine.ListSubjectScopes(r.Context(), subject)
	if err != nil {
		h.logger.Error("svc list subject scopes failed", "subject", subject, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list scopes").Write(w)
		return
	}

	out := make([]scopeDTO, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, scopeDTO{ScopeType: s.ScopeType, ScopeID: s.ScopeID})
	}
	writeJSON(w, http.StatusOK, svcScopesResponse{Scopes: out})
}

type svcAssignmentsResponse struct {
	Assignments []assignmentDTO `json:"assignments"`
}

type assignmentDTO struct {
	Subject string `json:"subject"`
	Role    string `json:"role"`
}

func (h *Handler) handleSvcListScopeAssignments(w http.ResponseWriter, r *http.Request) {
	if _, apiErr := extractServiceSubject(r); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	tenantID := r.PathValue("tenantId")
	if tenantID == "" {
		apierror.New("bad_request", http.StatusBadRequest, "tenant ID is required").Write(w)
		return
	}

	assignments, err := h.engine.ListScopeAssignments(r.Context(), "tenant", tenantID)
	if err != nil {
		h.logger.Error("svc list scope assignments failed", "tenant", tenantID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list assignments").Write(w)
		return
	}

	out := make([]assignmentDTO, 0, len(assignments))
	for _, a := range assignments {
		out = append(out, assignmentDTO{Subject: a.Subject, Role: a.Role})
	}
	writeJSON(w, http.StatusOK, svcAssignmentsResponse{Assignments: out})
}
