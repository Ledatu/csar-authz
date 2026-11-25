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
	changed.ServicePolicies = nil
	if err := ValidateReload(&base, &changed); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatal("policy removal accepted on reload")
	}
	if err := ValidateReload(&base, &base); err != nil {
		t.Fatal("unchanged config rejected", err)
	}
}
