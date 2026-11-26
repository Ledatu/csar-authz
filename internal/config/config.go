// Package config re-exports the csar-authz configuration schema from
// csar-core/authzconfig. The canonical definitions live in csar-core so
// that csar-helper can validate authz configs without importing this repo.
package config

import (
	"fmt"
	"reflect"

	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-core/authzconfig"
)

type (
	Config              = authzconfig.Config
	StoreConfig         = authzconfig.StoreConfig
	GRPCConfig          = authzconfig.GRPCConfig
	AuthnConfig         = authzconfig.AuthnConfig
	PolicyConfig        = authzconfig.PolicyConfig
	RoleConfig          = authzconfig.RoleConfig
	PermissionConfig    = authzconfig.PermissionConfig
	AssignmentConfig    = authzconfig.AssignmentConfig
	BootstrapAssignment = authzconfig.BootstrapAssignment
	AdminConfig         = authzconfig.AdminConfig
	Duration            = authzconfig.Duration
)

// LoadFromBytes validates the shared schema and service-owned admin grants.
func LoadFromBytes(data []byte) (*Config, error) {
	cfg, err := authzconfig.LoadFromBytesWithServiceCapabilities(data)
	if err != nil {
		return nil, err
	}
	if err := ValidateAdminAssignments(cfg); err != nil {
		return nil, err
	}
	if err := ValidateDecisionIngress(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ValidateDecisionIngress prevents enabled decisions on an unpinned or plaintext
// admin listener. The service still verifies the live client chain per request.
func ValidateDecisionIngress(cfg *Config) error {
	return authzconfig.ValidateServicePolicyIngress(cfg)
}

// ValidateReload runs before policy sync or any config mutation. Service
// capabilities and their trusted ingress are immutable until process restart.
func ValidateReload(current, next *Config) error {
	if !reflect.DeepEqual(current.ServicePolicies, next.ServicePolicies) {
		return fmt.Errorf("service_policies changes require restart")
	}
	if current.ServicePolicies != nil && current.ServicePolicies.Enabled &&
		(current.Admin.Enabled != next.Admin.Enabled || current.Admin.Addr != next.Admin.Addr || current.Admin.TLS != next.Admin.TLS || current.Admin.AllowedClientCN != next.Admin.AllowedClientCN || !reflect.DeepEqual(current.Admin.ServiceAssignableRoles, next.Admin.ServiceAssignableRoles)) {
		return fmt.Errorf("service decision ingress changes require restart")
	}
	return nil
}

// ValidateAdminAssignments checks all configured grants before any policy or
// bootstrap mutation, including legacy policy.assignments configurations.
func ValidateAdminAssignments(cfg *Config) error {
	for _, a := range cfg.Policy.Assignments {
		for _, role := range a.Roles {
			if err := engine.ValidateRoleAssignment(role, a.ScopeType, a.ScopeID); err != nil {
				return fmt.Errorf("policy.assignments: %w", err)
			}
		}
	}
	for _, a := range cfg.BootstrapAssignments {
		if err := engine.ValidateRoleAssignment(a.Role, a.ScopeType, a.ScopeID); err != nil {
			return fmt.Errorf("bootstrap_assignments: %w", err)
		}
	}
	return nil
}
