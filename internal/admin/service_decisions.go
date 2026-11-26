package admin

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/ledatu/csar-authz/internal/config"
	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"
)

type decisionEngine interface {
	CheckAccess(context.Context, string, string, string, string, string) (*engine.Result, error)
}

type serviceDecisionHandler struct {
	engine      decisionEngine
	policies    *authzconfig.ServicePolicyConfig
	gatewayCN   string
	roleCeiling []string
}

// This HTTP contract conveys current permission only. Credential validity,
// persisted consent and live owner data scope remain separate mandatory gates.
type serviceDecisionRequest struct {
	Version     int                       `json:"version"`
	Profile     string                    `json:"profile"`
	Audience    string                    `json:"audience"`
	Subject     string                    `json:"subject"`
	SubjectMode string                    `json:"subject_mode"`
	Resources   []authntokens.ResourceRef `json:"resources"`
}

type resourceDecision struct {
	Resource authntokens.ResourceRef `json:"resource"`
	Allowed  bool                    `json:"allowed"`
	Scope    *authntokens.ScopeRef   `json:"scope,omitempty"`
}

type serviceDecisionResponse struct {
	Version  int                `json:"version"`
	Profile  string             `json:"profile"`
	Audience string             `json:"audience"`
	Subject  string             `json:"subject"`
	Results  []resourceDecision `json:"results"`
}

func (h *Handler) RegisterServiceDecisions(mux *http.ServeMux, cfg *config.Config) error {
	if cfg.ServicePolicies == nil || !cfg.ServicePolicies.Enabled {
		return nil
	}
	if err := config.ValidateDecisionIngress(cfg); err != nil {
		return err
	}
	// Own the startup policy. A caller mutating its parsed config cannot broaden
	// a running handler or race a request; supported reloads never replace it.
	policy := *cfg.ServicePolicies
	policy.DecisionProfiles = slices.Clone(policy.DecisionProfiles)
	for i := range policy.DecisionProfiles {
		policy.DecisionProfiles[i].Bindings = slices.Clone(policy.DecisionProfiles[i].Bindings)
	}
	policy.Services = slices.Clone(policy.Services)
	for i := range policy.Services {
		policy.Services[i].Operations = slices.Clone(policy.Services[i].Operations)
		for j := range policy.Services[i].Operations {
			op := &policy.Services[i].Operations[j]
			op.Profiles, op.SubjectModes, op.Roles = slices.Clone(op.Profiles), slices.Clone(op.SubjectModes), slices.Clone(op.Roles)
		}
	}
	d := &serviceDecisionHandler{engine: h.engine, policies: &policy, gatewayCN: cfg.Admin.AllowedClientCN, roleCeiling: slices.Clone(cfg.Admin.ServiceAssignableRoles)}
	h.servicePolicies = d
	mux.HandleFunc("POST /svc/decisions/check", d.check)
	return nil
}

func (d *serviceDecisionHandler) check(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, ok := d.verifiedService(r)
	if !ok {
		decisionError(w, 403, "verified service ingress required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, authntokens.MaxCandidateRequestBytes)
	var in serviceDecisionRequest
	if httpx.ReadStrictJSON(r, &in) != nil || in.Version != 1 || !authntokens.ValidProfileID(in.Profile) || !authntokens.ValidAudience(in.Audience) || in.Subject == "" || !caller.ValidReference(in.Subject) || authntokens.ValidateResources(in.Resources, authntokens.MaxDecisionResources) != nil {
		decisionError(w, 400, "invalid decision request")
		return
	}
	profile := d.permittedProfile(id.Subject, in.Profile, in.Audience, in.SubjectMode)
	if profile == nil || !decisionSubjectBound(&id, &in) {
		decisionError(w, 403, "decision capability denied")
		return
	}
	// Validate the entire candidate set before consulting the engine. No caller
	// supplies a policy, scope prefix, arbitrary permission or mixed subject.
	for _, ref := range in.Resources {
		if !slices.ContainsFunc(profile.Bindings, func(b authzconfig.ServiceScopeBinding) bool { return b.Namespace == ref.Namespace }) {
			decisionError(w, 403, "resource namespace denied")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out := serviceDecisionResponse{Version: 1, Profile: in.Profile, Audience: in.Audience, Subject: in.Subject, Results: make([]resourceDecision, 0, len(in.Resources))}
	for _, ref := range in.Resources {
		result, err := d.evaluate(ctx, profile, in.Subject, ref)
		if err != nil {
			decisionError(w, 503, "authorization unavailable")
			return
		}
		out.Results = append(out.Results, result)
	}
	if ctx.Err() != nil || in.SubjectMode == "request_bound" && !decisionSubjectBound(&id, &in) {
		decisionError(w, 503, "authorization unavailable")
		return
	}
	httpx.WriteJSON(w, 200, out)
}

func (d *serviceDecisionHandler) trustedGateway(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	peer := r.TLS.PeerCertificates[0]
	if peer.Subject.CommonName != d.gatewayCN {
		return false
	}
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) >= 2 && chain[0].Equal(peer) {
			return true
		}
	}
	return false
}

func (d *serviceDecisionHandler) permittedProfile(service, profile, audience, mode string) *authzconfig.ServiceDecisionProfile {
	if d.policies == nil || !d.policies.Enabled {
		return nil
	}
	for _, capability := range d.policies.Services {
		if capability.Subject != service {
			continue
		}
		for _, op := range capability.Operations {
			if op.Operation != "decide" || !slices.Contains(op.Profiles, profile) || !slices.Contains(op.SubjectModes, mode) {
				continue
			}
			for i := range d.policies.DecisionProfiles {
				p := &d.policies.DecisionProfiles[i]
				if p.ID == profile && p.Audience == audience {
					return p
				}
			}
		}
	}
	return nil
}

func decisionSubjectBound(id *gatewayctx.Identity, in *serviceDecisionRequest) bool {
	if in.SubjectMode == "background" {
		return true
	}
	if in.SubjectMode != "request_bound" || id.Origin == nil || !time.Now().Before(id.Origin.ExpiresAt) {
		return false
	}
	original := id.Origin.Caller
	if original == nil || original.Validate() != nil || original.OwnerSubject != in.Subject || original.EffectiveSubject != in.Subject {
		return false
	}
	return (original.CallerKind == caller.Human || original.CallerKind == caller.Agent || original.CallerKind == caller.Application) && original.CredentialKind != caller.STS
}

func (d *serviceDecisionHandler) evaluate(ctx context.Context, profile *authzconfig.ServiceDecisionProfile, subject string, ref authntokens.ResourceRef) (resourceDecision, error) {
	out := resourceDecision{Resource: ref}
	for _, binding := range profile.Bindings {
		if binding.Namespace != ref.Namespace {
			continue
		}
		scope := authntokens.ScopeRef{Type: binding.ScopeType}
		if scope.Type == "tenant" {
			scope.ID = binding.ScopeIDPrefix + ref.ID
		}
		if scope.Validate() != nil {
			return out, fmt.Errorf("invalid configured decision scope")
		}
		result, err := d.engine.CheckAccess(ctx, subject, scope.Type, scope.ID, profile.Resource, profile.Action)
		if err != nil || result == nil {
			return out, fmt.Errorf("decision engine unavailable")
		}
		if result.Allowed {
			out.Allowed = true
			out.Scope = &scope
			break
		}
	}
	return out, nil
}

func decisionError(w http.ResponseWriter, status int, message string) {
	apierror.New("decision_failed", status, message).Write(w)
}
