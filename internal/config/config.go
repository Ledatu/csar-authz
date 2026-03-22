// Package config re-exports the csar-authz configuration schema from
// csar-core/authzconfig. The canonical definitions live in csar-core so
// that csar-helper can validate authz configs without importing this repo.
package config

import (
	"github.com/ledatu/csar-core/authzconfig"
)

type (
	Config           = authzconfig.Config
	StoreConfig      = authzconfig.StoreConfig
	GRPCConfig       = authzconfig.GRPCConfig
	AuthnConfig      = authzconfig.AuthnConfig
	PolicyConfig     = authzconfig.PolicyConfig
	RoleConfig       = authzconfig.RoleConfig
	PermissionConfig = authzconfig.PermissionConfig
	AssignmentConfig    = authzconfig.AssignmentConfig
	BootstrapAssignment = authzconfig.BootstrapAssignment
	AdminConfig         = authzconfig.AdminConfig
	Duration         = authzconfig.Duration
)

var LoadFromBytes = authzconfig.LoadFromBytes
