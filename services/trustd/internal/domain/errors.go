package domain

import "errors"

var (
	ErrUnauthorized         = errors.New("unauthorized")
	ErrForbidden            = errors.New("forbidden")
	ErrInvalidManifest      = errors.New("invalid manifest")
	ErrSignatureInvalid     = errors.New("signature invalid")
	ErrKeyRevoked           = errors.New("key revoked")
	ErrKeyUnknown           = errors.New("key unknown")
	ErrNotFound             = errors.New("not found")
	ErrArtifactHashMismatch = errors.New("artifact hash mismatch")
	ErrProofRequired        = errors.New("proof required")
	ErrLogProofInvalid      = errors.New("log proof invalid")
	ErrSTHInvalid           = errors.New("sth invalid")
)
