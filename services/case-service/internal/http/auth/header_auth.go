package auth

import (
	"strings"

	"proteus/case-service/internal/domain/cases"

	"github.com/gin-gonic/gin"
)

type HeaderAuthenticator struct{}

func NewHeaderAuthenticator() *HeaderAuthenticator {
	return &HeaderAuthenticator{}
}

func (h *HeaderAuthenticator) Authenticate(c *gin.Context) (cases.Principal, error) {
	principal := cases.Principal{
		Subject:  strings.TrimSpace(c.GetHeader("X-Principal-Subject")),
		TenantID: strings.TrimSpace(c.GetHeader("X-Principal-Tenant")),
	}
	if scopes := strings.TrimSpace(c.GetHeader("X-Principal-Scopes")); scopes != "" {
		principal.Scopes = splitCSV(scopes)
	}
	if roles := strings.TrimSpace(c.GetHeader("X-Principal-Roles")); roles != "" {
		principal.Roles = splitCSV(roles)
	}
	return principal, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
