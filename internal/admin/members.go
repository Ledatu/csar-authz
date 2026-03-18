package admin

import (
	"cmp"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/ledatu/csar-core/apierror"
)

type memberEntry struct {
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
}

type listMembersResponse struct {
	TenantID string        `json:"tenant_id"`
	Members  []memberEntry `json:"members"`
}

func (h *Handler) handleListMembers(w http.ResponseWriter, r *http.Request) {
	subject := extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	tenantID := r.PathValue("tenantId")
	if tenantID == "" {
		apierror.New("bad_request", http.StatusBadRequest, "tenant ID is required").Write(w)
		return
	}

	if apiErr := h.requirePermission(r, subject, "tenant.members.read", "tenant", tenantID); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	assignments, err := h.engine.ListScopeAssignments(r.Context(), "tenant", tenantID)
	if err != nil {
		h.logger.Error("failed to list scope assignments", "tenant", tenantID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list members").Write(w)
		return
	}

	memberMap := make(map[string][]string)
	for _, a := range assignments {
		memberMap[a.Subject] = append(memberMap[a.Subject], a.Role)
	}

	members := make([]memberEntry, 0, len(memberMap))
	for subj, roles := range memberMap {
		slices.Sort(roles)
		members = append(members, memberEntry{Subject: subj, Roles: roles})
	}
	slices.SortFunc(members, func(a, b memberEntry) int {
		return cmp.Compare(a.Subject, b.Subject)
	})

	writeJSON(w, http.StatusOK, listMembersResponse{TenantID: tenantID, Members: members})
}

type assignRoleRequest struct {
	Role string `json:"role"`
}

func (h *Handler) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	actor := extractSubject(r)
	if actor == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	tenantID := r.PathValue("tenantId")
	targetSubject := r.PathValue("subject")
	if tenantID == "" || targetSubject == "" {
		apierror.New("bad_request", http.StatusBadRequest, "tenant ID and subject are required").Write(w)
		return
	}

	var body assignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Role == "" {
		apierror.New("bad_request", http.StatusBadRequest, "request body must contain role").Write(w)
		return
	}

	if apiErr := h.requirePermission(r, actor, "tenant.members.assign_role", "tenant", tenantID); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	if apiErr := h.enforceDelegation(r, actor, body.Role, tenantID); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	if err := h.engine.AssignRole(r.Context(), targetSubject, body.Role, "tenant", tenantID); err != nil {
		h.logger.Error("failed to assign role", "target", targetSubject, "role", body.Role, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to assign role").Write(w)
		return
	}

	if err := h.recordAudit(r, actor, "role.assign", "assignment", targetSubject+"/"+body.Role, "tenant", tenantID, nil); err != nil {
		apierror.New("audit_error", http.StatusInternalServerError, "mutation succeeded but audit write failed").Write(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleRevokeRole(w http.ResponseWriter, r *http.Request) {
	actor := extractSubject(r)
	if actor == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	tenantID := r.PathValue("tenantId")
	targetSubject := r.PathValue("subject")
	role := r.PathValue("role")
	if tenantID == "" || targetSubject == "" || role == "" {
		apierror.New("bad_request", http.StatusBadRequest, "tenant ID, subject, and role are required").Write(w)
		return
	}

	if apiErr := h.requirePermission(r, actor, "tenant.members.revoke_role", "tenant", tenantID); apiErr != nil {
		writeError(w, apiErr)
		return
	}

	if err := h.engine.RevokeRole(r.Context(), targetSubject, role, "tenant", tenantID); err != nil {
		h.logger.Error("failed to revoke role", "target", targetSubject, "role", role, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to revoke role").Write(w)
		return
	}

	if err := h.recordAudit(r, actor, "role.revoke", "assignment", targetSubject+"/"+role, "tenant", tenantID, nil); err != nil {
		apierror.New("audit_error", http.StatusInternalServerError, "mutation succeeded but audit write failed").Write(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// enforceDelegation checks delegation rules for tenant-scoped role assignment.
func (h *Handler) enforceDelegation(r *http.Request, actor, role, tenantID string) *apierror.Response {
	cfg := h.cfg.Load()

	// Platform admins bypass delegation checks.
	result, err := h.engine.CheckAccess(r.Context(), actor, "platform", "", "admin", "platform.roles.assign")
	if err == nil && result.Allowed {
		return nil
	}

	if len(cfg.DelegatableRoles) > 0 {
		allowed := false
		for _, dr := range cfg.DelegatableRoles {
			if dr == role {
				allowed = true
				break
			}
		}
		if !allowed {
			return apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "role is not delegatable by tenant admins")
		}
	}

	return nil
}
