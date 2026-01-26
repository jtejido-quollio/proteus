package domain

import "context"

type Principal struct {
	Subject   string
	TenantID  string
	Roles     []string
	Scopes    []string
	RawClaims map[string]any
}

type Authenticator interface {
	Authenticate(ctx context.Context, bearerToken string) (Principal, error)
}

type Authorizer interface {
	Require(principal Principal, tenantID string, permission string) error
}
