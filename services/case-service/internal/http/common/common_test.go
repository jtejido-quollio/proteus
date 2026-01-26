package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"proteus/case-service/internal/domain/cases"
	"proteus/case-service/internal/http/auth"

	"github.com/gin-gonic/gin"
)

type stubAuthenticator struct {
	principal cases.Principal
	err       error
}

func (s stubAuthenticator) Authenticate(*gin.Context) (cases.Principal, error) {
	return s.principal, s.err
}

func TestWriteErrorUsesErrorsIs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)

	WriteError(c, fmt.Errorf("wrap: %w", cases.ErrNotFound))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestWriteErrorCodeAborts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)

	WriteErrorCode(c, http.StatusBadRequest, "BAD", "bad")

	if !c.IsAborted() {
		t.Fatalf("expected context aborted")
	}
}

func TestAuthMiddlewareRequiresTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authn := stubAuthenticator{
		principal: cases.Principal{Subject: "user-1"},
	}
	router := gin.New()
	router.GET("/test", AuthMiddleware(authn, auth.NewAuthorizer(), cases.PermCaseRead, false), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAuthMiddlewareRequiresRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authn := stubAuthenticator{
		principal: cases.Principal{Subject: "user-1", TenantID: "tenant-1", Scopes: []string{cases.PermCaseWrite}},
	}
	router := gin.New()
	router.POST("/test", AuthMiddleware(authn, auth.NewAuthorizer(), cases.PermCaseWrite, true), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAuthMiddlewareAllowsWithScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authn := stubAuthenticator{
		principal: cases.Principal{Subject: "user-1", TenantID: "tenant-1", Scopes: []string{cases.PermCaseRead}},
	}
	router := gin.New()
	router.GET("/test", AuthMiddleware(authn, auth.NewAuthorizer(), cases.PermCaseRead, false), func(c *gin.Context) {
		principal, ok := PrincipalFromContext(c)
		if !ok {
			return
		}
		c.JSON(http.StatusOK, gin.H{"subject": principal.Subject})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["subject"] != "user-1" {
		t.Fatalf("expected subject user-1, got %q", payload["subject"])
	}
}

func TestAuthMiddlewareRejectsMissingScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authn := stubAuthenticator{
		principal: cases.Principal{Subject: "user-1", TenantID: "tenant-1"},
	}
	router := gin.New()
	router.GET("/test", AuthMiddleware(authn, auth.NewAuthorizer(), cases.PermCaseRead, false), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}
