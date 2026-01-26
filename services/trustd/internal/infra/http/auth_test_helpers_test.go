package http

import (
	"context"
	"net/http"
	"strings"

	"proteus/internal/domain"
)

const testAuthTokenPrefix = "tenant:"

type staticAuthenticator struct {
	roles  []string
	scopes []string
}

func (a *staticAuthenticator) Authenticate(ctx context.Context, bearerToken string) (domain.Principal, error) {
	token := strings.TrimSpace(bearerToken)
	if token == "" {
		return domain.Principal{}, domain.ErrUnauthorized
	}
	tenantID := token
	if strings.HasPrefix(token, testAuthTokenPrefix) {
		tenantID = strings.TrimPrefix(token, testAuthTokenPrefix)
	}
	return domain.Principal{
		Subject:  "test-subject",
		TenantID: tenantID,
		Roles:    a.roles,
		Scopes:   a.scopes,
	}, nil
}

type allowAuthorizer struct{}

func (a *allowAuthorizer) Require(principal domain.Principal, tenantID string, permission string) error {
	return nil
}

func authTokenForTenant(tenantID string) string {
	return testAuthTokenPrefix + tenantID
}

func addAuthHeader(req *http.Request, tenantID string) {
	req.Header.Set("Authorization", "Bearer "+authTokenForTenant(tenantID))
}
