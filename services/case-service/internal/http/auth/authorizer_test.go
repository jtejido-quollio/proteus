package auth

import (
	"errors"
	"testing"

	"proteus/case-service/internal/domain/cases"
)

func TestAuthzErrorUnwrap(t *testing.T) {
	err := &AuthzError{Code: "MISSING_SCOPE", Err: cases.ErrForbidden}
	if !errors.Is(err, cases.ErrForbidden) {
		t.Fatalf("expected ErrForbidden to be unwrapped")
	}
}

func TestIsAuthzError(t *testing.T) {
	err := &AuthzError{Code: "MISSING_SCOPE", Err: cases.ErrForbidden}
	if _, ok := IsAuthzError(err); !ok {
		t.Fatalf("expected IsAuthzError to match")
	}
}
