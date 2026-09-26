package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
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

// requireServiceAssignable rejects roles outside admin.service_assignable_roles.
// A service caller is trusted only by its gateway subject, so the allowlist is
// what keeps a compromised service from granting admin or platform roles.
func (h *Handler) requireServiceAssignable(actor, tenantID, role string) *apierror.Response {
	if slices.Contains(h.cfg.Load().ServiceAssignableRoles, role) {
		return nil
	}
	h.logger.Warn("svc role write rejected: role not service-assignable",
		"actor", actor, "tenant", tenantID, "role", role)
	return apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "role is not assignable by services")
}

func (h *Handler) RegisterServiceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /svc/tenants/{tenantId}/members/{subject}/roles", h.handleSvcAssignRole)
	mux.HandleFunc("DELETE /svc/tenants/{tenantId}/members/{subject}/roles/{role}", h.handleSvcRevokeRole)
	mux.HandleFunc("GET /svc/subjects/{subject}/scopes", h.handleSvcListSubjectScopes)
	mux.HandleFunc("GET /svc/tenants/{tenantId}/assignments", h.handleSvcListScopeAssignments)
	mux.HandleFunc("POST /svc/assignments/query", h.handleSvcQueryAssignments)
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
	if apiErr := h.requireServiceAssignable(actor, tenantID, body.Role); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	if err := h.engine.AssignRole(r.Context(), targetSubject, body.Role, "tenant", tenantID); err != nil {
		h.logger.Error("svc assign role failed", "target", targetSubject, "role", body.Role, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to assign role").Write(w)
		return
	}

	if err := h.recordAudit(r, actor, "role.assign", "assignment", targetSubject+"/"+body.Role, "tenant", tenantID, nil); err != nil {
		// Role grant already succeeded; do not fail the HTTP response so callers
		// (e.g. campaigns) do not compensate against a live authz mutation.
		h.logger.Error("svc assign role: audit write failed after successful role assignment",
			"target", targetSubject, "role", body.Role, "tenant", tenantID, "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleSvcRevokeRole(w http.ResponseWriter, r *http.Request) {
	actor, apiErr := extractServiceSubject(r)
	if apiErr != nil {
		writeError(w, apiErr)
		return
	}

	tenantID := r.PathValue("tenantId")
	targetSubject := r.PathValue("subject")
	role := r.PathValue("role")
	if tenantID == "" || targetSubject == "" || role == "" {
		apierror.New("bad_request", http.StatusBadRequest, "tenant ID, subject, and role are required").Write(w)
		return
	}
	if apiErr := h.requireServiceAssignable(actor, tenantID, role); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	if err := h.engine.RevokeRole(r.Context(), targetSubject, role, "tenant", tenantID); err != nil {
		h.logger.Error("svc revoke role failed", "target", targetSubject, "role", role, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to revoke role").Write(w)
		return
	}

	if err := h.recordAudit(r, actor, "role.revoke", "assignment", targetSubject+"/"+role, "tenant", tenantID, nil); err != nil {
		// Role revoke already succeeded; do not fail the HTTP response so callers
		// (e.g. campaigns) do not attempt to compensate against a live authz mutation.
		h.logger.Error("svc revoke role: audit write failed after successful role revoke",
			"target", targetSubject, "role", role, "tenant", tenantID, "error", err)
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

const (
	maxSvcAssignmentQueryTenants   = 1000
	maxSvcAssignmentQueryBodyBytes = 1 << 20
)

type svcAssignmentQueryRequest struct {
	TenantIDs []string `json:"tenant_ids"`
}

type tenantAssignmentDTO struct {
	TenantID string `json:"tenant_id"`
	Subject  string `json:"subject"`
	Role     string `json:"role"`
}

type svcAssignmentQueryResponse struct {
	Assignments []tenantAssignmentDTO `json:"assignments"`
}

func (h *Handler) handleSvcQueryAssignments(w http.ResponseWriter, r *http.Request) {
	if _, apiErr := extractServiceSubject(r); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	var req svcAssignmentQueryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSvcAssignmentQueryBodyBytes)).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "request body must contain tenant_ids").Write(w)
		return
	}
	if len(req.TenantIDs) == 0 || len(req.TenantIDs) > maxSvcAssignmentQueryTenants {
		apierror.New("bad_request", http.StatusBadRequest,
			fmt.Sprintf("tenant_ids must contain 1 to %d entries", maxSvcAssignmentQueryTenants)).Write(w)
		return
	}
	if slices.Contains(req.TenantIDs, "") {
		apierror.New("bad_request", http.StatusBadRequest, "tenant_ids must not contain empty values").Write(w)
		return
	}

	assignments, err := h.engine.ListAssignmentsForScopes(r.Context(), "tenant", req.TenantIDs)
	if err != nil {
		h.logger.Error("svc query assignments failed", "tenants", len(req.TenantIDs), "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list assignments").Write(w)
		return
	}

	out := make([]tenantAssignmentDTO, 0, len(assignments))
	for _, a := range assignments {
		out = append(out, tenantAssignmentDTO{TenantID: a.ScopeID, Subject: a.Subject, Role: a.Role})
	}
	writeJSON(w, http.StatusOK, svcAssignmentQueryResponse{Assignments: out})
}
