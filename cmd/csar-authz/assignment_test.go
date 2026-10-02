package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/ledatu/csar-authz/internal/config"
	"github.com/ledatu/csar-authz/internal/store/memory"
)

func TestBootstrap_InvalidAdminGrantIsRejectedBeforeAnyMutation(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	cfg := &config.Config{Policy: config.PolicyConfig{Roles: []config.RoleConfig{
		{Name: "platform_admin", Permissions: []config.PermissionConfig{{Resource: "**", Action: "*"}}},
	}}}
	if err := syncPolicy(ctx, s, cfg, slog.Default()); err != nil {
		t.Fatal(err)
	}
	cfg.BootstrapAssignments = []config.BootstrapAssignment{
		{Subject: "valid", Role: "platform_admin", ScopeType: "platform"},
		{Subject: "invalid", Role: "platform_admin", ScopeType: "tenant", ScopeID: "wildberries:seller"},
	}
	if err := applyBootstrapAssignments(ctx, s, cfg, slog.Default()); err == nil {
		t.Fatal("expected invalid bootstrap rejection")
	}
	grants, err := s.ListSubjectAssignments(ctx, "valid")
	if err != nil || len(grants) != 0 {
		t.Fatalf("partial bootstrap: %v, %v", grants, err)
	}
	if err := syncPolicy(ctx, s, cfg, slog.Default()); err == nil {
		t.Fatal("expected invalid reload rejection")
	}
}
