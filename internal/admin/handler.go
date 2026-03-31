// Package admin provides the HTTP admin API for authorization management.
//
// These handlers run inside the csar-authz process and call the engine
// directly -- no gRPC hop, no serialization overhead.
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/gatewayctx"
)

// Handler holds dependencies for admin HTTP endpoints.
type Handler struct {
	engine        *engine.Engine
	auditRecorder audit.Recorder // nil when audit emission is not configured
	auditStore    audit.Store    // nil when audit querying is not configured
	logger        *slog.Logger
	cfg           atomic.Pointer[authzconfig.AdminConfig]
}

// New creates a Handler with all dependencies.
func New(eng *engine.Engine, auditRecorder audit.Recorder, auditStore audit.Store, logger *slog.Logger, cfg *authzconfig.AdminConfig) *Handler {
	h := &Handler{
		engine:        eng,
		auditRecorder: auditRecorder,
		auditStore:    auditStore,
		logger:        logger,
	}
	h.cfg.Store(cfg)
	return h
}

// SetConfig atomically replaces the admin configuration.
func (h *Handler) SetConfig(cfg *authzconfig.AdminConfig) {
	h.cfg.Store(cfg)
}

// RegisterRoutes sets up all admin HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/me/capabilities", h.handleCapabilities)
	mux.HandleFunc("GET /admin/me/tenants", h.handleMyTenants)

	mux.HandleFunc("GET /admin/platform/members", h.handleListPlatformMembers)
	mux.HandleFunc("POST /admin/platform/members/{subject}/roles", h.handleAssignPlatformRole)
	mux.HandleFunc("DELETE /admin/platform/members/{subject}/roles/{role}", h.handleRevokePlatformRole)

	mux.HandleFunc("GET /admin/tenants/{tenantId}/members", h.handleListMembers)
	mux.HandleFunc("POST /admin/tenants/{tenantId}/members/{subject}/roles", h.handleAssignRole)
	mux.HandleFunc("DELETE /admin/tenants/{tenantId}/members/{subject}/roles/{role}", h.handleRevokeRole)

	mux.HandleFunc("GET /admin/roles", h.handleListRoles)
	mux.HandleFunc("POST /admin/roles", h.handleCreateRole)
	mux.HandleFunc("GET /admin/roles/{role}", h.handleGetRole)
	mux.HandleFunc("DELETE /admin/roles/{role}", h.handleDeleteRole)

	mux.HandleFunc("GET /admin/roles/{role}/permissions", h.handleListRolePermissions)
	mux.HandleFunc("POST /admin/roles/{role}/permissions", h.handleAddPermission)
	mux.HandleFunc("DELETE /admin/roles/{role}/permissions/{permId}", h.handleRemovePermission)

	mux.HandleFunc("GET /admin/audit", h.handleListAudit)

	h.RegisterServiceRoutes(mux)
}

// extractSubject reads the acting user's subject from the trusted gateway
// context. TrustedMiddleware must have already verified the request source
// and parsed headers into context before this is called.
func extractSubject(r *http.Request) string {
	id, ok := gatewayctx.FromContext(r.Context())
	if !ok {
		return ""
	}
	return id.Subject
}

// requirePermission calls the engine's CheckAccess to verify the subject
// has the given admin permission. Returns nil on success.
func (h *Handler) requirePermission(r *http.Request, subject, permission, scopeType, scopeID string) *apierror.Response {
	result, err := h.engine.CheckAccess(r.Context(), subject, scopeType, scopeID, "admin", permission)
	if err != nil {
		h.logger.Error("authz check failed", "subject", subject, "permission", permission, "error", err)
		return apierror.New("authz_error", http.StatusBadGateway, "authorization check failed")
	}
	if !result.Allowed {
		return apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "insufficient permissions")
	}
	return nil
}

// recordAudit writes an audit event. When admin.audit_required is true,
// a write failure is returned to the caller so the mutation can be failed.
// Otherwise the failure is logged and swallowed (best-effort).
func (h *Handler) recordAudit(r *http.Request, actor, action, targetType, targetID, scopeType, scopeID string, afterState json.RawMessage) error {
	if h.auditRecorder == nil {
		return nil
	}
	event := &audit.Event{
		Actor:      actor,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		ScopeType:  scopeType,
		ScopeID:    scopeID,
		AfterState: afterState,
	}
	if err := h.auditRecorder.Record(r.Context(), event); err != nil {
		if h.cfg.Load().AuditRequired {
			h.logger.Error("required audit write failed", "action", action, "error", err)
			return err
		}
		h.logger.Warn("failed to record audit event", "action", action, "error", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err *apierror.Response) {
	err.Write(w)
}
