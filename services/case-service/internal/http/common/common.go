package common

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"proteus/case-service/internal/domain/cases"
	"proteus/case-service/internal/http/auth"
	"proteus/case-service/internal/usecase"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	principalKey = "principal"
	requestIDKey = "request_id"
)

type ErrorResponse struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

type CaseResponse struct {
	ID            string  `json:"id"`
	TenantID      string  `json:"tenant_id"`
	SourceType    string  `json:"source_type,omitempty"`
	SourceRefType string  `json:"source_ref_type,omitempty"`
	SourceRefHash string  `json:"source_ref_hash,omitempty"`
	SourceRefRaw  string  `json:"source_ref_raw,omitempty"`
	CreatedAt     string  `json:"created_at"`
	Status        string  `json:"status"`
	Severity      string  `json:"severity,omitempty"`
	QueueID       string  `json:"queue_id,omitempty"`
	OwnerID       string  `json:"owner_id,omitempty"`
	SLAState      string  `json:"sla_state,omitempty"`
	SLADueAt      *string `json:"sla_due_at,omitempty"`
}

type Authenticator interface {
	Authenticate(*gin.Context) (cases.Principal, error)
}

func AuthMiddleware(authenticator Authenticator, authorizer cases.Authorizer, permission string, requireRequestID bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if authenticator == nil || authorizer == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse{Code: "INTERNAL", Message: "auth misconfigured"})
			return
		}
		principal, err := authenticator.Authenticate(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Code: "UNAUTHORIZED", Message: "authentication failed"})
			return
		}
		if principal.TenantID == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{Code: "MISSING_TENANT_CLAIM", Message: "tenant_id claim required"})
			return
		}
		if err := authorizer.Require(principal, principal.TenantID, permission); err != nil {
			if authz, ok := auth.IsAuthzError(err); ok {
				c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{Code: authz.Code, Message: "forbidden"})
				return
			}
			WriteError(c, err)
			c.Abort()
			return
		}
		c.Set(principalKey, principal)
		requestID := strings.TrimSpace(c.GetHeader("X-Request-ID"))
		if requestID != "" {
			c.Set(requestIDKey, requestID)
		}
		if requireRequestID && requestID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Code: "MISSING_REQUEST_ID", Message: "X-Request-ID required"})
			return
		}
		c.Next()
	}
}

func RequireAuth(c *gin.Context, authenticator Authenticator, authorizer cases.Authorizer, permission string, tenantID string) (cases.Principal, bool) {
	if authenticator == nil || authorizer == nil {
		WriteErrorCode(c, http.StatusInternalServerError, "INTERNAL", "auth misconfigured")
		return cases.Principal{}, false
	}
	principal, err := authenticator.Authenticate(c)
	if err != nil {
		WriteErrorCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication failed")
		return cases.Principal{}, false
	}
	if principal.TenantID == "" {
		WriteErrorCode(c, http.StatusForbidden, "MISSING_TENANT_CLAIM", "tenant_id claim required")
		return cases.Principal{}, false
	}
	if tenantID == "" {
		tenantID = principal.TenantID
	}
	if err := authorizer.Require(principal, tenantID, permission); err != nil {
		if authz, ok := auth.IsAuthzError(err); ok {
			WriteErrorCode(c, http.StatusForbidden, authz.Code, "forbidden")
			return cases.Principal{}, false
		}
		WriteError(c, err)
		return cases.Principal{}, false
	}
	return principal, true
}

func PrincipalFromContext(c *gin.Context) (cases.Principal, bool) {
	value, ok := c.Get(principalKey)
	if !ok {
		WriteErrorCode(c, http.StatusInternalServerError, "INTERNAL", "principal missing")
		return cases.Principal{}, false
	}
	principal, ok := value.(cases.Principal)
	if !ok {
		WriteErrorCode(c, http.StatusInternalServerError, "INTERNAL", "principal invalid")
		return cases.Principal{}, false
	}
	return principal, true
}

func RequestID(c *gin.Context) string {
	if value, ok := c.Get(requestIDKey); ok {
		if requestID, ok := value.(string); ok {
			return strings.TrimSpace(requestID)
		}
	}
	return strings.TrimSpace(c.GetHeader("X-Request-ID"))
}

func ParseUUIDParam(c *gin.Context, name string) (string, bool) {
	value := strings.TrimSpace(c.Param(name))
	if value == "" {
		WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", name+" is required")
		return "", false
	}
	if _, err := uuid.Parse(value); err != nil {
		WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", name+" must be a UUID")
		return "", false
	}
	return value, true
}

func ToCaseResponse(view usecase.CaseView) CaseResponse {
	resp := CaseResponse{
		ID:            view.Header.ID,
		TenantID:      view.Header.TenantID,
		SourceType:    view.Header.SourceType,
		SourceRefType: string(view.Header.SourceRefType),
		SourceRefHash: view.Header.SourceRefHash,
		SourceRefRaw:  view.Header.SourceRefRaw,
		CreatedAt:     view.Header.CreatedAt.UTC().Format(time.RFC3339Nano),
		Status:        string(view.Status),
		Severity:      view.Severity,
		QueueID:       view.QueueID,
		OwnerID:       view.OwnerID,
		SLAState:      view.SLAState,
	}
	if view.SLADueAt != nil {
		formatted := view.SLADueAt.UTC().Format(time.RFC3339Nano)
		resp.SLADueAt = &formatted
	}
	return resp
}

func ToCaseListResponse(item usecase.CaseListItem) CaseResponse {
	resp := CaseResponse{
		ID:        item.CaseID,
		TenantID:  item.TenantID,
		Status:    string(item.Status),
		Severity:  item.Severity,
		QueueID:   item.QueueID,
		OwnerID:   item.OwnerID,
		SLAState:  item.SLAState,
		CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if item.SLADueAt != nil {
		formatted := item.SLADueAt.UTC().Format(time.RFC3339Nano)
		resp.SLADueAt = &formatted
	}
	return resp
}

func ToQueueListResponse(item usecase.QueueCaseItem) CaseResponse {
	resp := CaseResponse{
		ID:        item.CaseID,
		TenantID:  item.TenantID,
		Status:    string(item.Status),
		Severity:  item.Severity,
		QueueID:   item.QueueID,
		OwnerID:   item.OwnerID,
		SLAState:  item.SLAState,
		CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if item.SLADueAt != nil {
		formatted := item.SLADueAt.UTC().Format(time.RFC3339Nano)
		resp.SLADueAt = &formatted
	}
	return resp
}

func WriteError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, cases.ErrUnauthorized):
		WriteErrorCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
	case errors.Is(err, cases.ErrForbidden):
		WriteErrorCode(c, http.StatusForbidden, "FORBIDDEN", "forbidden")
	case errors.Is(err, cases.ErrNotFound):
		WriteErrorCode(c, http.StatusNotFound, "NOT_FOUND", "not found")
	case errors.Is(err, cases.ErrConflict):
		WriteErrorCode(c, http.StatusConflict, "CONFLICT", "conflict")
	case errors.Is(err, cases.ErrInvalidArgument):
		WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "invalid argument")
	default:
		WriteErrorCode(c, http.StatusInternalServerError, "INTERNAL", "internal error")
	}
}

func WriteErrorCode(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, ErrorResponse{Code: code, Message: message})
}
