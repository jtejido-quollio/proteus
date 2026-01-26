package http

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"proteus/internal/domain"
	"proteus/internal/infra/auth/rbac"

	"github.com/gin-gonic/gin"
)

const principalContextKey = "principal"

func (s *Server) requireAuth(c *gin.Context, permission string, tenantID string, allowAdminKey bool) (domain.Principal, bool) {
	if s.cfg.AuthMode == "none" {
		if allowAdminKey {
			if key := strings.TrimSpace(c.GetHeader("X-Admin-Key")); key != "" && subtle.ConstantTimeCompare([]byte(key), []byte(s.adminAPIKey)) == 1 {
				principal := domain.Principal{
					Subject: "admin-key",
					Roles:   []string{rbac.DefaultAdminRole},
					Scopes:  []string{rbac.DefaultAdminScope},
				}
				c.Set(principalContextKey, principal)
				return principal, true
			}
			writeErrorCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "admin key required")
			return domain.Principal{}, false
		}
		return domain.Principal{}, true
	}
	if s.authInitErr != nil || s.authenticator == nil {
		writeErrorCode(c, http.StatusInternalServerError, "AUTH_CONFIG_ERROR", "auth configuration error")
		return domain.Principal{}, false
	}
	if allowAdminKey && s.adminAPIKey != "" {
		if key := strings.TrimSpace(c.GetHeader("X-Admin-Key")); key != "" {
			if subtle.ConstantTimeCompare([]byte(key), []byte(s.adminAPIKey)) == 1 {
				principal := domain.Principal{
					Subject: "admin-key",
					Roles:   []string{rbac.DefaultAdminRole},
					Scopes:  []string{rbac.DefaultAdminScope},
				}
				if s.authorizer != nil {
					if err := s.authorizer.Require(principal, tenantID, permission); err != nil {
						writeAuthzError(c, err)
						return domain.Principal{}, false
					}
				}
				c.Set(principalContextKey, principal)
				return principal, true
			}
		}
	}

	token := strings.TrimSpace(extractBearerToken(c.GetHeader("Authorization")))
	if token == "" {
		writeErrorCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing bearer token")
		return domain.Principal{}, false
	}
	principal, err := s.authenticator.Authenticate(c.Request.Context(), token)
	if err != nil {
		writeErrorCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid bearer token")
		return domain.Principal{}, false
	}
	if s.authorizer != nil {
		if err := s.authorizer.Require(principal, tenantID, permission); err != nil {
			writeAuthzError(c, err)
			return domain.Principal{}, false
		}
	}
	c.Set(principalContextKey, principal)
	return principal, true
}

func extractBearerToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return ""
	}
	return strings.TrimSpace(value[len("bearer "):])
}

func getPrincipal(c *gin.Context) (domain.Principal, bool) {
	raw, ok := c.Get(principalContextKey)
	if !ok {
		return domain.Principal{}, false
	}
	principal, ok := raw.(domain.Principal)
	return principal, ok
}

func writeAuthzError(c *gin.Context, err error) {
	if authz, ok := rbac.IsAuthzError(err); ok {
		writeErrorCode(c, http.StatusForbidden, authz.Code, "forbidden")
		return
	}
	if err == domain.ErrUnauthorized {
		writeErrorCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return
	}
	writeErrorCode(c, http.StatusForbidden, "FORBIDDEN", "forbidden")
}
