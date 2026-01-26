package auth

import (
	"errors"
	"strings"

	"proteus/case-service/internal/domain/cases"
)

const (
	DefaultAdminRole  = "proteus_admin"
	DefaultAdminScope = "admin:*"
)

type AuthzError struct {
	Code string
	Err  error
}

func (e *AuthzError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

func (e *AuthzError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type Authorizer struct {
	adminRole  string
	adminScope string
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{adminRole: DefaultAdminRole, adminScope: DefaultAdminScope}
}

func (a *Authorizer) Require(principal cases.Principal, tenantID string, permission string) error {
	if principal.Subject == "" {
		return cases.ErrUnauthorized
	}
	if permission == "" {
		return nil
	}
	if a.hasAdmin(principal) {
		return nil
	}
	if strings.HasPrefix(permission, "admin:") {
		return &AuthzError{Code: "MISSING_ROLE", Err: cases.ErrForbidden}
	}
	if tenantID != "" {
		if principal.TenantID == "" || tenantID != principal.TenantID {
			return &AuthzError{Code: "TENANT_MISMATCH", Err: cases.ErrForbidden}
		}
	}
	if !hasScope(principal, permission) {
		return &AuthzError{Code: "MISSING_SCOPE", Err: cases.ErrForbidden}
	}
	return nil
}

func (a *Authorizer) hasAdmin(principal cases.Principal) bool {
	if hasRole(principal, a.adminRole) {
		return true
	}
	return hasScope(principal, a.adminScope)
}

func hasRole(principal cases.Principal, role string) bool {
	for _, r := range principal.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func hasScope(principal cases.Principal, scope string) bool {
	if scope == "" {
		return false
	}
	for _, s := range principal.Scopes {
		if s == scope || s == DefaultAdminScope {
			return true
		}
	}
	return false
}

func IsAuthzError(err error) (*AuthzError, bool) {
	var authz *AuthzError
	if errors.As(err, &authz) {
		return authz, true
	}
	return nil, false
}
