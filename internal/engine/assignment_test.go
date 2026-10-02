package engine

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-authz/internal/store/memory"
	"github.com/ledatu/csar-core/authzconfig"
)

func TestAssignRole_AdminScopes(t *testing.T) {
	cases := []struct {
		name, role, scope, id string
		allowed               bool
	}{
		{"tenant seller", "tenant_admin", "tenant", "wildberries:32709d54-a113-46f0-ac1c-fc418ab7d1ae", true},
		{"ozon seller", "tenant_admin", "tenant", "ozon:123", true},
		{"tenant in platform", "tenant_admin", "platform", "", false},
		{"tenant without account", "tenant_admin", "tenant", "wildberries:", false},
		{"tenant without marketplace", "tenant_admin", "tenant", "seller-1", false},
		{"tenant wildcard", "tenant_admin", "tenant", "wildberries:*", false},
		{"tenant extra separator", "tenant_admin", "tenant", "wildberries:a:b", false},
		{"tenant path", "tenant_admin", "tenant", "wildberries:a/b", false},
		{"tenant spaces", "tenant_admin", "tenant", "wildberries:a b", false},
		{"platform", "platform_admin", "platform", "", true},
		{"platform with tenant", "platform_admin", "tenant", "wildberries:seller", false},
		{"platform with id", "platform_admin", "platform", "seller", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := memory.New()
			if err := s.CreateRole(ctx, &store.Role{Name: tc.role}); err != nil {
				t.Fatal(err)
			}
			err := New(s).AssignRole(ctx, "user", tc.role, tc.scope, tc.id)
			if tc.allowed && err != nil {
				t.Fatal(err)
			}
			if !tc.allowed && !errors.Is(err, ErrInvalidAssignment) {
				t.Fatalf("expected validation error, got %v", err)
			}
			grants, err := s.ListSubjectAssignments(ctx, "user")
			if err != nil {
				t.Fatal(err)
			}
			if (len(grants) == 1) != tc.allowed {
				t.Fatalf("unexpected persisted grants: %v", grants)
			}
		})
	}
}

func TestAdminPolicy_SellerIsolationAndPlatformInheritance(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	roles := []*store.Role{{Name: "tenant_admin"}, {Name: "platform_admin", Parents: []string{"tenant_admin"}}, {Name: "massAdvert_viewer"}}
	perms := []*store.Permission{
		{Role: "tenant_admin", Resource: "campaign", Action: "*"},
		{Role: "tenant_admin", Resource: "campaign_module", Action: "*"},
		{Role: "tenant_admin", Resource: "arts", Action: "*"},
		{Role: "tenant_admin", Resource: "admin", Action: "tenant.members.assign_role"},
		{Role: "platform_admin", Resource: "**", Action: "*"},
		{Role: "massAdvert_viewer", Resource: "campaign_module", Action: "massAdvert.read"},
	}
	// Release verification can exercise this same matrix against the actual
	// deployment policy instead of the small unit-test fixture.
	if path := os.Getenv("CSAR_AUTHZ_POLICY_TEST_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := authzconfig.LoadFromBytes(data)
		if err != nil {
			t.Fatal(err)
		}
		roles, perms = nil, nil
		for _, rc := range cfg.Policy.Roles {
			roles = append(roles, &store.Role{Name: rc.Name, Parents: rc.Parents})
			for _, pc := range rc.Permissions {
				perms = append(perms, &store.Permission{Role: rc.Name, Resource: pc.Resource, Action: pc.Action})
			}
		}
	}
	if err := s.SyncPolicy(ctx, roles, perms); err != nil {
		t.Fatal(err)
	}
	e := New(s)
	for _, a := range []store.ScopedAssignment{
		{Subject: "tenant", Role: "tenant_admin", ScopeType: "tenant", ScopeID: "wildberries:a"},
		{Subject: "platform", Role: "platform_admin", ScopeType: "platform"},
		{Subject: "viewer", Role: "massAdvert_viewer", ScopeType: "tenant", ScopeID: "wildberries:a"},
	} {
		if err := e.AssignRole(ctx, a.Subject, a.Role, a.ScopeType, a.ScopeID); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		subject, scope, id, resource, action string
		allowed                              bool
	}{
		{"tenant", "tenant", "wildberries:a", "campaign_module", "massAdvert.read", true},
		{"tenant", "tenant", "wildberries:a", "campaign_module", "massAdvert.write", true},
		{"tenant", "tenant", "wildberries:a", "campaign_module", "prices.write", true},
		{"tenant", "tenant", "wildberries:a", "campaign", "archive", true},
		{"tenant", "tenant", "wildberries:a", "arts", "write", true},
		{"tenant", "tenant", "wildberries:a", "admin", "tenant.members.assign_role", true},
		{"tenant", "tenant", "wildberries:b", "campaign_module", "massAdvert.read", false},
		{"tenant", "tenant", "ozon:a", "campaign_module", "massAdvert.read", false},
		{"tenant", "platform", "", "admin", "platform.roles.assign", false},
		{"tenant", "tenant", "wildberries:a", "admin", "platform.roles.assign", false},
		{"platform", "tenant", "wildberries:a", "campaign_module", "massAdvert.read", true},
		{"platform", "tenant", "wildberries:b", "campaign_module", "massAdvert.write", true},
		{"platform", "platform", "", "admin", "platform.roles.assign", true},
		{"viewer", "tenant", "wildberries:a", "campaign_module", "massAdvert.read", true},
		{"viewer", "tenant", "wildberries:a", "campaign_module", "massAdvert.write", false},
		{"viewer", "tenant", "wildberries:b", "campaign_module", "massAdvert.read", false},
	}
	for _, tc := range cases {
		result, err := e.CheckAccess(ctx, tc.subject, tc.scope, tc.id, tc.resource, tc.action)
		if err != nil {
			t.Fatal(err)
		}
		if result.Allowed != tc.allowed {
			t.Errorf("%+v: allowed = %v", tc, result.Allowed)
		}
	}
}
