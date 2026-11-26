package config

import (
	"strings"
	"testing"

	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/configutil"
)

func TestDecisionIngressAndReloadFailClosed(t *testing.T) {
	base := Config{Admin: authzconfig.AdminConfig{Enabled: true, AllowedClientCN: "gateway", TLS: configutil.TLSSection{CertFile: "server.pem", KeyFile: "key.pem", ClientCAFile: "router-ca.pem"}}, ServicePolicies: &authzconfig.ServicePolicyConfig{Version: 1, Enabled: true}}
	if err := ValidateDecisionIngress(&base); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Admin.Enabled = false }, func(c *Config) { c.Admin.AllowedClientCN = "" }, func(c *Config) { c.Admin.AllowedClientCN = "*" }, func(c *Config) { c.Admin.TLS.ClientCAFile = "" }, func(c *Config) { c.Admin.TLS.KeyFile = "" },
	} {
		changed := base
		mutate(&changed)
		if ValidateDecisionIngress(&changed) == nil {
			t.Fatal("unverified listener accepted")
		}
		if ValidateReload(&base, &changed) == nil {
			t.Fatal("ingress change accepted on reload")
		}
	}
	changed := base
	changed.Admin.ServiceAssignableRoles = []string{"new-role"}
	if ValidateReload(&base, &changed) == nil {
		t.Fatal("service role ceiling changed on reload")
	}
	changed = base
	changed.ServicePolicies = nil
	if err := ValidateReload(&base, &changed); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatal("policy removal accepted on reload")
	}
	if err := ValidateReload(&base, &base); err != nil {
		t.Fatal("unchanged config rejected", err)
	}
}

func TestBootstrapAcceptsGenericLiteralTenantAndPreservesGuards(t *testing.T) {
	for _, id := range []string{"north-branch", "workspace:north-branch", "organization:workspace:north"} {
		cfg := Config{BootstrapAssignments: []authzconfig.BootstrapAssignment{{Subject: "owner", Role: "tenant_admin", ScopeType: "tenant", ScopeID: id}}}
		if err := ValidateAdminAssignments(&cfg); err != nil {
			t.Fatal("generic tenant rejected", err)
		}
		cfg.BootstrapAssignments[0].Role = "platform_admin"
		if ValidateAdminAssignments(&cfg) == nil {
			t.Fatal("platform role allowed in tenant scope")
		}
	}
	for _, id := range []string{"", "workspace:", "workspace:*", "workspace::north", "workspace:bad/id", strings.Repeat("x", 257)} {
		cfg := Config{BootstrapAssignments: []authzconfig.BootstrapAssignment{{Subject: "owner", Role: "tenant_admin", ScopeType: "tenant", ScopeID: id}}}
		if ValidateAdminAssignments(&cfg) == nil {
			t.Fatal("invalid bootstrap scope accepted")
		}
	}
}
