// Package config handles loading and validating csar-authz configuration.
package config

import (
	"fmt"
	"time"

	"github.com/ledatu/csar-core/configutil"
	"gopkg.in/yaml.v3"
)

// Duration is a type alias for the shared configutil.Duration.
type Duration = configutil.Duration

// Config is the top-level csar-authz configuration.
type Config struct {
	ListenAddr string       `yaml:"listen_addr"`
	TLS        TLSConfig    `yaml:"tls"`
	GRPC       GRPCConfig   `yaml:"grpc"`
	Authn      AuthnConfig  `yaml:"authn"`
	Store      StoreConfig  `yaml:"store"`
	Policy     PolicyConfig `yaml:"policy"`
}

// StoreConfig configures the persistence backend.
type StoreConfig struct {
	Backend string `yaml:"backend"` // "memory" (default) or "postgres"
	DSN     string `yaml:"dsn"`     // PostgreSQL connection string (required for postgres backend)
}

// TLSConfig configures TLS for the gRPC server.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// GRPCConfig configures gRPC server options.
type GRPCConfig struct {
	Reflection bool `yaml:"reflection"`
}

// AuthnConfig configures optional JWT/JWKS validation on inbound gRPC calls.
type AuthnConfig struct {
	Enabled       bool     `yaml:"enabled"`
	JWKSURL       string   `yaml:"jwks_url"`
	PublicKeyFile string   `yaml:"public_key_file"`
	Issuer        string   `yaml:"issuer"`
	Audience      string   `yaml:"audience"`
	ClockSkew     Duration `yaml:"clock_skew"`
	SubjectClaim  string   `yaml:"subject_claim"`
	CacheTTL      Duration `yaml:"cache_ttl"`
}

// PolicyConfig defines the declarative RBAC policy.
type PolicyConfig struct {
	Roles       []RoleConfig       `yaml:"roles"`
	Assignments []AssignmentConfig `yaml:"assignments"`
}

// RoleConfig defines a role with optional parents and permissions.
type RoleConfig struct {
	Name        string             `yaml:"name"`
	Description string             `yaml:"description"`
	Parents     []string           `yaml:"parents"`
	Permissions []PermissionConfig `yaml:"permissions"`
}

// PermissionConfig defines an allowed action on a resource pattern.
type PermissionConfig struct {
	Resource string `yaml:"resource"`
	Action   string `yaml:"action"`
}

// AssignmentConfig maps a subject to one or more roles within a scope.
type AssignmentConfig struct {
	Subject   string   `yaml:"subject"`
	Roles     []string `yaml:"roles"`
	ScopeType string   `yaml:"scope_type"` // "platform" (default) or "tenant"
	ScopeID   string   `yaml:"scope_id"`   // "" for platform, tenant identifier for tenant
}

// LoadFromBytes parses raw YAML bytes into a Config, expanding environment
// variables, applying defaults, and validating.
func LoadFromBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	expandEnvInConfig(&cfg)
	applyDefaults(&cfg)

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":9090"
	}
	if cfg.Store.Backend == "" {
		cfg.Store.Backend = "memory"
	}
	if cfg.Authn.SubjectClaim == "" {
		cfg.Authn.SubjectClaim = "sub"
	}
	if cfg.Authn.Enabled && cfg.Authn.ClockSkew.Duration == 0 {
		cfg.Authn.ClockSkew = Duration{Duration: 30 * time.Second}
	}
	if cfg.Authn.Enabled && cfg.Authn.CacheTTL.Duration == 0 {
		cfg.Authn.CacheTTL = Duration{Duration: 5 * time.Minute}
	}
}

func (c *Config) validate() error {
	// Validate roles.
	roleNames := make(map[string]struct{})
	for i, r := range c.Policy.Roles {
		if r.Name == "" {
			return fmt.Errorf("policy.roles[%d].name is required", i)
		}
		if _, dup := roleNames[r.Name]; dup {
			return fmt.Errorf("policy.roles[%d]: duplicate role name %q", i, r.Name)
		}
		roleNames[r.Name] = struct{}{}

		for _, parent := range r.Parents {
			if _, ok := roleNames[parent]; !ok {
				return fmt.Errorf("policy.roles[%d] (%q): parent %q not defined (must appear earlier in the list)", i, r.Name, parent)
			}
		}

		for j, p := range r.Permissions {
			if p.Resource == "" {
				return fmt.Errorf("policy.roles[%d].permissions[%d].resource is required", i, j)
			}
			if p.Action == "" {
				return fmt.Errorf("policy.roles[%d].permissions[%d].action is required", i, j)
			}
		}
	}

	// Validate assignments.
	for i, a := range c.Policy.Assignments {
		if a.Subject == "" {
			return fmt.Errorf("policy.assignments[%d].subject is required", i)
		}
		if len(a.Roles) == 0 {
			return fmt.Errorf("policy.assignments[%d].roles must not be empty", i)
		}
		for _, role := range a.Roles {
			if _, ok := roleNames[role]; !ok {
				return fmt.Errorf("policy.assignments[%d] (%q): role %q not defined", i, a.Subject, role)
			}
		}
	}

	// Validate store.
	switch c.Store.Backend {
	case "memory", "postgres":
	default:
		return fmt.Errorf("store.backend: must be \"memory\" or \"postgres\", got %q", c.Store.Backend)
	}
	if c.Store.Backend == "postgres" && c.Store.DSN == "" {
		return fmt.Errorf("store.dsn is required when store.backend is \"postgres\"")
	}

	// Validate authn.
	if c.Authn.Enabled {
		hasJWKS := c.Authn.JWKSURL != ""
		hasKey := c.Authn.PublicKeyFile != ""
		if !hasJWKS && !hasKey {
			return fmt.Errorf("authn: one of jwks_url or public_key_file is required when enabled")
		}
		if hasJWKS && hasKey {
			return fmt.Errorf("authn: specify only one of jwks_url or public_key_file")
		}
	}

	return nil
}

func expandEnv(s string) string {
	return configutil.SafeExpandEnv(s)
}

func expandEnvInConfig(cfg *Config) {
	cfg.ListenAddr = expandEnv(cfg.ListenAddr)
	cfg.TLS.CertFile = expandEnv(cfg.TLS.CertFile)
	cfg.TLS.KeyFile = expandEnv(cfg.TLS.KeyFile)
	cfg.Authn.JWKSURL = expandEnv(cfg.Authn.JWKSURL)
	cfg.Authn.PublicKeyFile = expandEnv(cfg.Authn.PublicKeyFile)
	cfg.Authn.Issuer = expandEnv(cfg.Authn.Issuer)
	cfg.Authn.Audience = expandEnv(cfg.Authn.Audience)
	cfg.Store.DSN = expandEnv(cfg.Store.DSN)
}
