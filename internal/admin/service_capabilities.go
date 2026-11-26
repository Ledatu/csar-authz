package admin

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
)

// Service capability policies are owned at startup. Omitted/disabled policies
// preserve old wire behavior until consumer migration; an enabled policy never
// falls back to the broad legacy service-prefix authorization.
func (h *Handler) authorizeServiceOperation(r *http.Request, operation, subject string, tenants []string, role string) (string, *apierror.Response) {
	actor, apiErr := extractServiceSubject(r)
	if apiErr != nil {
		return "", apiErr
	}
	d := h.servicePolicies
	if d == nil {
		return actor, nil
	}
	deny := func() (string, *apierror.Response) {
		return "", apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "service capability denied")
	}
	id, ok := d.verifiedService(r)
	if !ok {
		return deny()
	}
	op := d.operation(actor, operation)
	if op == nil {
		return deny()
	}
	if subject != "" && !caller.ValidReference(subject) {
		return deny()
	}
	if operation == "list_subject_scopes" {
		bound := slices.Contains(op.SubjectModes, "request_bound") && decisionSubjectBound(&id, &serviceDecisionRequest{Subject: subject, SubjectMode: "request_bound"})
		if !bound && !slices.Contains(op.SubjectModes, "background") {
			return deny()
		}
	}
	if role != "" && (!slices.Contains(op.Roles, role) || !slices.Contains(d.roleCeiling, role)) {
		return deny()
	}
	for _, tenant := range tenants {
		if !d.operationScope(op, "tenant", tenant) {
			return deny()
		}
	}
	return actor, nil
}

func (d *serviceDecisionHandler) operation(service, operation string) *authzconfig.ServiceOperation {
	if d == nil || d.policies == nil || !d.policies.Enabled {
		return nil
	}
	for i := range d.policies.Services {
		entry := &d.policies.Services[i]
		if entry.Subject != service {
			continue
		}
		for j := range entry.Operations {
			if entry.Operations[j].Operation == operation {
				return &entry.Operations[j]
			}
		}
	}
	return nil
}

func (d *serviceDecisionHandler) operationScope(op *authzconfig.ServiceOperation, scopeType, scopeID string) bool {
	if (authntokens.ScopeRef{Type: scopeType, ID: scopeID}).Validate() != nil {
		return false
	}
	for _, profile := range d.policies.DecisionProfiles {
		if !slices.Contains(op.Profiles, profile.ID) {
			continue
		}
		for _, binding := range profile.Bindings {
			if binding.ScopeType != scopeType {
				continue
			}
			if scopeType == "platform" {
				return scopeID == ""
			}
			if strings.HasPrefix(scopeID, binding.ScopeIDPrefix) && (authntokens.ResourceRef{Namespace: binding.Namespace, ID: strings.TrimPrefix(scopeID, binding.ScopeIDPrefix)}).Validate() == nil {
				return true
			}
		}
	}
	return false
}

func (h *Handler) serviceScopeVisible(r *http.Request, scopeType, scopeID string) bool {
	if h.servicePolicies == nil {
		return true
	}
	op := h.servicePolicies.operation(extractSubject(r), "list_subject_scopes")
	return op != nil && h.servicePolicies.operationScope(op, scopeType, scopeID)
}

func (d *serviceDecisionHandler) verifiedService(r *http.Request) (gatewayctx.Identity, bool) {
	id, ok := gatewayctx.FromContext(r.Context())
	return id, ok && d.trustedGateway(r) && id.Caller != nil && id.Caller.ValidateBinding(id.Subject, id.CredentialID) == nil && id.Caller.CallerKind == caller.Service && id.Caller.CredentialKind == caller.STS && id.Caller.CallerID == id.Subject
}

func (h *Handler) boundServiceOperation(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.servicePolicies == nil {
			fn(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		fn(w, r.WithContext(ctx))
	}
}
