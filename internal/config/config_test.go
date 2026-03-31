package config

import (
	"testing"
)

func TestLoadFromBytes_MinimalValid(t *testing.T) {
	yaml := `
policy:
  roles:
    - name: admin
      permissions:
        - resource: "/**"
          action: "*"
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Fatalf("default listen_addr = %q, want :9090", cfg.ListenAddr)
	}
	if len(cfg.Policy.Roles) != 1 {
		t.Fatalf("roles = %d, want 1", len(cfg.Policy.Roles))
	}
	if cfg.Policy.Roles[0].Name != "admin" {
		t.Fatalf("role name = %q, want admin", cfg.Policy.Roles[0].Name)
	}
}

func TestLoadFromBytes_EmptyPolicy(t *testing.T) {
	yaml := `
listen_addr: ":8080"
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Policy.Roles) != 0 {
		t.Fatal("expected no roles")
	}
}

func TestLoadFromBytes_Defaults(t *testing.T) {
	cfg, err := LoadFromBytes([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Fatalf("default listen_addr = %q", cfg.ListenAddr)
	}
	if cfg.Authn.SubjectClaim != "sub" {
		t.Fatalf("default subject_claim = %q", cfg.Authn.SubjectClaim)
	}
}

func TestLoadFromBytes_RoleParentOrder(t *testing.T) {
	yaml := `
policy:
  roles:
    - name: child
      parents: [parent]
      permissions:
        - resource: "/**"
          action: "*"
    - name: parent
      permissions:
        - resource: "/**"
          action: "*"
`
	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error: child references parent before parent is defined")
	}
}

func TestLoadFromBytes_DuplicateRole(t *testing.T) {
	yaml := `
policy:
  roles:
    - name: admin
      permissions:
        - resource: "/**"
          action: "*"
    - name: admin
      permissions:
        - resource: "/api/**"
          action: "GET"
`
	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error: duplicate role name")
	}
}

func TestLoadFromBytes_NonEmptyAssignmentsRejected(t *testing.T) {
	yaml := `
policy:
  roles:
    - name: viewer
      permissions:
        - resource: "/**"
          action: "GET"
  assignments:
    - subject: "bob"
      roles: [viewer]
`
	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error: non-empty policy.assignments should be rejected")
	}
}

func TestLoadFromBytes_MissingRoleName(t *testing.T) {
	yaml := `
policy:
  roles:
    - permissions:
        - resource: "/**"
          action: "*"
`
	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error: missing role name")
	}
}

func TestLoadFromBytes_MissingPermissionResource(t *testing.T) {
	yaml := `
policy:
  roles:
    - name: admin
      permissions:
        - action: "GET"
`
	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error: missing resource")
	}
}

func TestLoadFromBytes_AuthnValidation(t *testing.T) {
	// Enabled without key source.
	yaml := `
authn:
  enabled: true
`
	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error: authn enabled without jwks_url or public_key_file")
	}

	// Both set.
	yaml = `
authn:
  enabled: true
  jwks_url: "https://example.com/jwks"
  public_key_file: "/tmp/pub.pem"
`
	_, err = LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error: both jwks_url and public_key_file set")
	}
}

func TestLoadFromBytes_AuthnDefaults(t *testing.T) {
	yaml := `
authn:
  enabled: true
  jwks_url: "https://example.com/jwks"
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authn.ClockSkew.Duration == 0 {
		t.Fatal("expected default clock_skew")
	}
	if cfg.Authn.CacheTTL.Duration == 0 {
		t.Fatal("expected default cache_ttl")
	}
}

func TestLoadFromBytes_WithParents(t *testing.T) {
	yaml := `
policy:
  roles:
    - name: viewer
      permissions:
        - resource: "/api/**"
          action: "GET"
    - name: editor
      parents: [viewer]
      permissions:
        - resource: "/api/**"
          action: "PUT"
    - name: admin
      parents: [editor]
      permissions:
        - resource: "/**"
          action: "*"
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Policy.Roles) != 3 {
		t.Fatalf("roles = %d, want 3", len(cfg.Policy.Roles))
	}
	if len(cfg.Policy.Roles[2].Parents) != 1 || cfg.Policy.Roles[2].Parents[0] != "editor" {
		t.Fatal("admin should have editor as parent")
	}
}

func TestLoadFromBytes_EnvExpansion(t *testing.T) {
	t.Setenv("TEST_LISTEN", ":7777")
	yaml := `
listen_addr: "${TEST_LISTEN}"
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":7777" {
		t.Fatalf("listen_addr = %q, want :7777", cfg.ListenAddr)
	}
}

func TestLoadFromBytes_AuditValidation(t *testing.T) {
	yaml := `
audit:
  router_base_url: "https://csar:8443/svc/audit"
`

	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for partially configured audit block")
	}
}
