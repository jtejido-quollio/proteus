package rbac

import (
	"testing"

	"proteus/internal/domain"
)

func TestAuthorizer_TenantMismatch(t *testing.T) {
	authz := NewAuthorizer()
	principal := domain.Principal{
		Subject:  "user",
		TenantID: "tenant-a",
		Scopes:   []string{"logs:read"},
	}
	err := authz.Require(principal, "tenant-b", "logs:read")
	authzErr, ok := IsAuthzError(err)
	if !ok {
		t.Fatalf("expected authz error, got %v", err)
	}
	if authzErr.Code != "TENANT_MISMATCH" {
		t.Fatalf("expected TENANT_MISMATCH, got %s", authzErr.Code)
	}
}

func TestAuthorizer_MissingScope(t *testing.T) {
	authz := NewAuthorizer()
	principal := domain.Principal{
		Subject:  "user",
		TenantID: "tenant-a",
		Scopes:   []string{"logs:read"},
	}
	err := authz.Require(principal, "tenant-a", "manifests:record")
	authzErr, ok := IsAuthzError(err)
	if !ok {
		t.Fatalf("expected authz error, got %v", err)
	}
	if authzErr.Code != "MISSING_SCOPE" {
		t.Fatalf("expected MISSING_SCOPE, got %s", authzErr.Code)
	}
}

func TestAuthorizer_AdminBypasses(t *testing.T) {
	authz := NewAuthorizer()
	principal := domain.Principal{
		Subject: "admin",
		Roles:   []string{DefaultAdminRole},
	}
	if err := authz.Require(principal, "tenant-b", "admin:tenants:create"); err != nil {
		t.Fatalf("expected admin allow, got %v", err)
	}
	if err := authz.Require(principal, "tenant-b", "logs:read"); err != nil {
		t.Fatalf("expected admin allow, got %v", err)
	}
}

func TestAuthorizer_AdminPermissionRequiresRole(t *testing.T) {
	authz := NewAuthorizer()
	principal := domain.Principal{
		Subject:  "user",
		TenantID: "tenant-a",
		Scopes:   []string{"logs:read"},
	}
	err := authz.Require(principal, "", "admin:tenants:create")
	authzErr, ok := IsAuthzError(err)
	if !ok {
		t.Fatalf("expected authz error, got %v", err)
	}
	if authzErr.Code != "MISSING_ROLE" {
		t.Fatalf("expected MISSING_ROLE, got %s", authzErr.Code)
	}
}
