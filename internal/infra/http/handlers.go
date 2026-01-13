package http

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/db"
	"proteus/internal/usecase"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type TenantStore interface {
	Create(ctx context.Context, tenant domain.Tenant) error
}

type KeyStore interface {
	Create(ctx context.Context, key domain.SigningKey) error
	ListByTenant(ctx context.Context, tenantID string) ([]domain.SigningKey, error)
}

type RevocationStore interface {
	Revoke(ctx context.Context, rev domain.Revocation) error
}

type errorResponse struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

type recordResponse struct {
	ManifestID     string            `json:"manifest_id"`
	LeafHash       string            `json:"leaf_hash"`
	LeafIndex      int64             `json:"leaf_index"`
	STH            sthResponse       `json:"sth"`
	InclusionProof inclusionResponse `json:"inclusion_proof"`
}

type verificationResponse struct {
	SignatureValid      bool                 `json:"signature_valid"`
	KeyStatus           string               `json:"key_status"`
	RevocationCheckedAt string               `json:"revocation_checked_at"`
	LogIncluded         bool                 `json:"log_included"`
	SubjectHash         domain.Hash          `json:"subject_hash"`
	ManifestID          string               `json:"manifest_id"`
	TenantID            string               `json:"tenant_id"`
	STH                 *sthResponse         `json:"sth,omitempty"`
	InclusionProof      *inclusionResponse   `json:"inclusion_proof,omitempty"`
	ConsistencyProof    *consistencyResponse `json:"consistency_proof,omitempty"`
}

type verifyResponse struct {
	verificationResponse
	Derivation   domain.DerivationReceipt `json:"derivation,omitempty"`
	Policy       domain.PolicyReceipt     `json:"policy,omitempty"`
	Decision     domain.DecisionReceipt   `json:"decision,omitempty"`
	Replay       domain.ReplayReceipt     `json:"replay,omitempty"`
}

type sthResponse struct {
	TenantID  string `json:"tenant_id,omitempty"`
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
}

type inclusionResponse struct {
	TenantID    string   `json:"tenant_id,omitempty"`
	LeafIndex   int64    `json:"leaf_index"`
	Path        []string `json:"path"`
	STHTreeSize int64    `json:"sth_tree_size"`
	STHRootHash string   `json:"sth_root_hash"`
}

type consistencyResponse struct {
	TenantID string   `json:"tenant_id,omitempty"`
	FromSize int64    `json:"from_size"`
	ToSize   int64    `json:"to_size"`
	Path     []string `json:"path"`
}

type logInclusionResponse struct {
	LeafIndex      int64             `json:"leaf_index"`
	STH            sthResponse       `json:"sth"`
	InclusionProof inclusionResponse `json:"inclusion_proof"`
}

type verifyRequest struct {
	Envelope domain.SignedManifestEnvelope `json:"envelope"`
	Artifact *artifactInput                `json:"artifact,omitempty"`
	Proof    *proofInput                   `json:"proof,omitempty"`
	Options  *verifyOptions                `json:"options,omitempty"`
}

type artifactInput struct {
	MediaType   string `json:"media_type"`
	BytesBase64 string `json:"bytes_base64,omitempty"`
	URI         string `json:"uri,omitempty"`
}

type proofInput struct {
	STH       sthInput       `json:"sth"`
	Inclusion inclusionInput `json:"inclusion_proof"`
}

type sthInput struct {
	TenantID  string `json:"tenant_id,omitempty"`
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
}

type inclusionInput struct {
	TenantID    string   `json:"tenant_id,omitempty"`
	LeafIndex   int64    `json:"leaf_index"`
	Path        []string `json:"path"`
	STHTreeSize int64    `json:"sth_tree_size"`
	STHRootHash string   `json:"sth_root_hash"`
}

type verifyOptions struct {
	RequireProof bool `json:"require_proof"`
}

type adminTenantRequest struct {
	Name     string `json:"name"`
	TenantID string `json:"tenant_id,omitempty"`
}

type adminKeyRequest struct {
	KID       string `json:"kid"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	Status    string `json:"status,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

type adminRevokeRequest struct {
	Reason    string `json:"reason,omitempty"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

type keyResponse struct {
	KID       string `json:"kid"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	Status    string `json:"status"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

func (s *Server) handleRecord(c *gin.Context) {
	if s.recordUC == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	var env domain.SignedManifestEnvelope
	if err := c.ShouldBindJSON(&env); err != nil {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid json")
		return
	}
	resp, err := s.recordUC.Execute(c.Request.Context(), usecase.RecordSignedManifestRequest{Envelope: env})
	if err != nil {
		writeError(c, err)
		return
	}
	if resp.STH == nil || resp.Inclusion == nil {
		writeErrorCode(c, http.StatusInternalServerError, "INTERNAL", "missing log proof")
		return
	}
	out := recordResponse{
		ManifestID:     resp.ManifestID,
		LeafHash:       hex.EncodeToString(resp.LeafHash),
		LeafIndex:      resp.LeafIndex,
		STH:            buildSTHResponse(*resp.STH),
		InclusionProof: buildInclusionResponse(*resp.Inclusion),
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) handleVerify(c *gin.Context) {
	if s.verifyUC == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	var req verifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid json")
		return
	}
	var artifact []byte
	mediaType := ""
	if req.Artifact != nil {
		mediaType = req.Artifact.MediaType
		if req.Artifact.BytesBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(req.Artifact.BytesBase64)
			if err != nil {
				writeErrorCode(c, http.StatusBadRequest, "INVALID_ARTIFACT_ENCODING", "invalid artifact encoding")
				return
			}
			artifact = decoded
		}
	}

	var bundle *usecase.ProofBundle
	if req.Proof != nil {
		sth, err := parseSTHInput(req.Proof.STH)
		if err != nil {
			writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "invalid proof")
			return
		}
		inclusion, err := parseInclusionInput(req.Proof.Inclusion)
		if err != nil {
			writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "invalid proof")
			return
		}
		bundle = &usecase.ProofBundle{
			STH:          sth,
			STHSignature: req.Proof.STH.Signature,
			Inclusion:    inclusion,
		}
	}

	ucReq := usecase.VerifySignedManifestRequest{
		Envelope:          req.Envelope,
		Artifact:          artifact,
		ArtifactMediaType: mediaType,
		ProofBundle:       bundle,
	}
	if req.Options != nil {
		ucReq.RequireProof = req.Options.RequireProof
	}

	receipt, err := s.verifyUC.Execute(c.Request.Context(), ucReq)
	if err != nil {
		writeError(c, err)
		return
	}
	verOut := buildVerificationResponse(receipt)
	if verOut.STH != nil && verOut.STH.Signature == "" && req.Proof != nil {
		verOut.STH.Signature = req.Proof.STH.Signature
	}
	out := verifyResponse{
		verificationResponse: verOut,
		Derivation:           receipt.Derivation,
		Policy:               receipt.Policy,
		Decision:             receipt.Decision,
		Replay:               receipt.Replay,
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) handleNoRoute(c *gin.Context) {
	if c.Request.Method == http.MethodPost {
		switch c.Request.URL.Path {
		case "/v1/manifests:record":
			s.handleRecord(c)
			return
		case "/v1/manifests:verify":
			s.handleVerify(c)
			return
		}
	}
	writeErrorCode(c, http.StatusNotFound, "NOT_FOUND", "route not found")
}

func (s *Server) handleListSigningKeys(c *gin.Context) {
	if s.signingKey == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	tenantID := c.Param("tenant_id")
	keys, err := s.signingKey.ListByTenant(c.Request.Context(), tenantID)
	if err != nil {
		writeError(c, err)
		return
	}
	out := make([]keyResponse, 0, len(keys))
	for _, key := range keys {
		out = append(out, buildKeyResponse(key))
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) handleListLogKeys(c *gin.Context) {
	if s.logKey == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	tenantID := c.Param("tenant_id")
	keys, err := s.logKey.ListByTenant(c.Request.Context(), tenantID)
	if err != nil {
		writeError(c, err)
		return
	}
	out := make([]keyResponse, 0, len(keys))
	for _, key := range keys {
		out = append(out, buildKeyResponse(key))
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) handleLatestSTH(c *gin.Context) {
	if s.log == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	tenantID := c.Param("tenant_id")
	sth, err := s.log.GetLatestSTH(c.Request.Context(), tenantID)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, buildSTHResponse(sth))
}

func (s *Server) handleInclusionProof(c *gin.Context) {
	if s.log == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	tenantID := c.Param("tenant_id")
	leafHex := c.Param("leaf_hash")
	leafHash, err := hex.DecodeString(leafHex)
	if err != nil {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "invalid leaf hash")
		return
	}
	leafIndex, sth, inclusion, err := s.log.GetInclusionProof(c.Request.Context(), tenantID, leafHash)
	if err != nil {
		writeError(c, err)
		return
	}
	resp := logInclusionResponse{
		LeafIndex:      leafIndex,
		STH:            buildSTHResponse(sth),
		InclusionProof: buildInclusionResponse(inclusion),
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) handleConsistencyProof(c *gin.Context) {
	if s.log == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	tenantID := c.Param("tenant_id")
	fromStr := c.Query("from")
	toStr := c.Query("to")
	fromSize, err := strconv.ParseInt(fromStr, 10, 64)
	if err != nil {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "invalid from size")
		return
	}
	toSize, err := strconv.ParseInt(toStr, 10, 64)
	if err != nil {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "invalid to size")
		return
	}
	proof, err := s.log.GetConsistencyProof(c.Request.Context(), tenantID, fromSize, toSize)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, buildConsistencyResponse(proof))
}

func (s *Server) handleAdminCreateTenant(c *gin.Context) {
	if !s.requireAdmin(c) {
		return
	}
	if s.tenants == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	var req adminTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid json")
		return
	}
	if req.Name == "" {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "name is required")
		return
	}
	tenantID := req.TenantID
	if tenantID == "" {
		id, err := db.NewUUID()
		if err != nil {
			writeError(c, err)
			return
		}
		tenantID = id
	}
	tenant := domain.Tenant{
		ID:        tenantID,
		Name:      req.Name,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.tenants.Create(c.Request.Context(), tenant); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			writeErrorCode(c, http.StatusConflict, "ALREADY_EXISTS", "tenant already exists")
			return
		}
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"tenant_id": tenantID,
	})
}

func (s *Server) handleAdminRegisterSigningKey(c *gin.Context) {
	s.handleAdminRegisterKey(c, s.signingKey)
}

func (s *Server) handleAdminRegisterLogKey(c *gin.Context) {
	s.handleAdminRegisterKey(c, s.logKey)
}

func (s *Server) handleAdminRegisterKey(c *gin.Context, store KeyStore) {
	if !s.requireAdmin(c) {
		return
	}
	if store == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	tenantID := c.Param("tenant_id")
	var req adminKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid json")
		return
	}
	if req.KID == "" || req.Alg == "" || req.PublicKey == "" {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "kid, alg, and public_key are required")
		return
	}
	if req.Alg != "ed25519" {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "unsupported alg")
		return
	}
	pubKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "invalid public key")
		return
	}
	var notBefore *time.Time
	if req.NotBefore != "" {
		parsed, err := time.Parse(time.RFC3339, req.NotBefore)
		if err != nil {
			writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "invalid not_before")
			return
		}
		parsed = parsed.UTC()
		notBefore = &parsed
	}
	var notAfter *time.Time
	if req.NotAfter != "" {
		parsed, err := time.Parse(time.RFC3339, req.NotAfter)
		if err != nil {
			writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "invalid not_after")
			return
		}
		parsed = parsed.UTC()
		notAfter = &parsed
	}
	key := domain.SigningKey{
		TenantID:  tenantID,
		KID:       req.KID,
		Alg:       req.Alg,
		PublicKey: pubKey,
		Status:    domain.KeyStatus(req.Status),
		NotBefore: notBefore,
		NotAfter:  notAfter,
		CreatedAt: time.Now().UTC(),
	}
	if err := store.Create(c.Request.Context(), key); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			writeErrorCode(c, http.StatusConflict, "ALREADY_EXISTS", "key already exists")
			return
		}
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleAdminRevokeKey(c *gin.Context) {
	if !s.requireAdmin(c) {
		return
	}
	if s.revocations == nil {
		writeError(c, domain.ErrNotFound)
		return
	}
	tenantID := c.Param("tenant_id")
	kid := c.Param("kid")
	if kid == "" {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "kid is required")
		return
	}
	var req adminRevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid json")
		return
	}
	revokedAt := time.Now().UTC()
	if req.RevokedAt != "" {
		parsed, err := time.Parse(time.RFC3339, req.RevokedAt)
		if err != nil {
			writeErrorCode(c, http.StatusBadRequest, "INVALID_MANIFEST", "invalid revoked_at")
			return
		}
		revokedAt = parsed.UTC()
	}
	rev := domain.Revocation{
		TenantID:  tenantID,
		KID:       kid,
		RevokedAt: revokedAt,
		Reason:    req.Reason,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.revocations.Revoke(c.Request.Context(), rev); err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleAdminKeyAction(c *gin.Context) {
	segment := c.Param("kid_action")
	if segment == "" {
		writeErrorCode(c, http.StatusNotFound, "NOT_FOUND", "unknown action")
		return
	}
	parts := strings.SplitN(segment, ":", 2)
	if len(parts) != 2 {
		writeErrorCode(c, http.StatusNotFound, "NOT_FOUND", "unknown action")
		return
	}
	c.Params = append(c.Params, gin.Param{Key: "kid", Value: parts[0]})
	switch parts[1] {
	case "revoke":
		s.handleAdminRevokeKey(c)
	default:
		writeErrorCode(c, http.StatusNotFound, "NOT_FOUND", "unknown action")
	}
}

func (s *Server) requireAdmin(c *gin.Context) bool {
	if s.adminAPIKey == "" {
		writeErrorCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "admin key required")
		return false
	}
	key := c.GetHeader("X-Admin-Key")
	if key == "" || subtle.ConstantTimeCompare([]byte(key), []byte(s.adminAPIKey)) != 1 {
		writeErrorCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid admin key")
		return false
	}
	return true
}

func buildVerificationResponse(receipt *usecase.VerifyReceipt) verificationResponse {
	if receipt == nil {
		return verificationResponse{}
	}

	out := verificationResponse{
		SignatureValid:      receipt.SignatureValid,
		KeyStatus:           receipt.KeyStatus,
		RevocationCheckedAt: receipt.RevocationCheckedAt,
		LogIncluded:         receipt.LogIncluded,
		SubjectHash:         receipt.SubjectHash,
		ManifestID:          receipt.ManifestID,
		TenantID:            receipt.TenantID,
	}
	if receipt.STH != nil {
		sthOut := buildSTHResponse(*receipt.STH)
		out.STH = &sthOut
	}
	if receipt.InclusionProof != nil {
		inclusionOut := buildInclusionResponse(*receipt.InclusionProof)
		out.InclusionProof = &inclusionOut
	}
	if receipt.Consistency != nil {
		consOut := buildConsistencyResponse(*receipt.Consistency)
		out.ConsistencyProof = &consOut
	}
	return out
}

func buildSTHResponse(sth domain.STH) sthResponse {
	sig := ""
	if len(sth.Signature) > 0 {
		sig = base64.StdEncoding.EncodeToString(sth.Signature)
	}
	return sthResponse{
		TenantID:  sth.TenantID,
		TreeSize:  sth.TreeSize,
		RootHash:  hex.EncodeToString(sth.RootHash),
		IssuedAt:  sth.IssuedAt.UTC().Format(time.RFC3339),
		Signature: sig,
	}
}

func buildInclusionResponse(inclusion domain.InclusionProof) inclusionResponse {
	path := make([]string, 0, len(inclusion.Path))
	for _, node := range inclusion.Path {
		path = append(path, hex.EncodeToString(node))
	}
	return inclusionResponse{
		TenantID:    inclusion.TenantID,
		LeafIndex:   inclusion.LeafIndex,
		Path:        path,
		STHTreeSize: inclusion.STHTreeSize,
		STHRootHash: hex.EncodeToString(inclusion.STHRootHash),
	}
}

func buildConsistencyResponse(consistency domain.ConsistencyProof) consistencyResponse {
	path := make([]string, 0, len(consistency.Path))
	for _, node := range consistency.Path {
		path = append(path, hex.EncodeToString(node))
	}
	return consistencyResponse{
		TenantID: consistency.TenantID,
		FromSize: consistency.FromSize,
		ToSize:   consistency.ToSize,
		Path:     path,
	}
}

func buildKeyResponse(key domain.SigningKey) keyResponse {
	resp := keyResponse{
		KID:       key.KID,
		Alg:       key.Alg,
		PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey),
		Status:    string(key.Status),
	}
	if key.NotBefore != nil {
		resp.NotBefore = key.NotBefore.UTC().Format(time.RFC3339)
	}
	if key.NotAfter != nil {
		resp.NotAfter = key.NotAfter.UTC().Format(time.RFC3339)
	}
	return resp
}

func parseSTHInput(input sthInput) (domain.STH, error) {
	root, err := hex.DecodeString(input.RootHash)
	if err != nil {
		return domain.STH{}, err
	}
	issuedAt, err := time.Parse(time.RFC3339, input.IssuedAt)
	if err != nil {
		return domain.STH{}, err
	}
	return domain.STH{
		TenantID: input.TenantID,
		TreeSize: input.TreeSize,
		RootHash: root,
		IssuedAt: issuedAt.UTC(),
	}, nil
}

func parseInclusionInput(input inclusionInput) (domain.InclusionProof, error) {
	path := make([][]byte, 0, len(input.Path))
	for _, node := range input.Path {
		hash, err := hex.DecodeString(node)
		if err != nil {
			return domain.InclusionProof{}, err
		}
		path = append(path, hash)
	}
	root, err := hex.DecodeString(input.STHRootHash)
	if err != nil {
		return domain.InclusionProof{}, err
	}
	return domain.InclusionProof{
		TenantID:    input.TenantID,
		LeafIndex:   input.LeafIndex,
		Path:        path,
		STHTreeSize: input.STHTreeSize,
		STHRootHash: root,
	}, nil
}

func writeError(c *gin.Context, err error) {
	status, code := http.StatusInternalServerError, "INTERNAL"
	switch {
	case errors.Is(err, domain.ErrInvalidManifest):
		status, code = http.StatusBadRequest, "INVALID_MANIFEST"
	case errors.Is(err, domain.ErrSignatureInvalid):
		status, code = http.StatusBadRequest, "SIGNATURE_INVALID"
	case errors.Is(err, domain.ErrKeyUnknown):
		status, code = http.StatusBadRequest, "KEY_UNKNOWN"
	case errors.Is(err, domain.ErrKeyRevoked):
		status, code = http.StatusBadRequest, "KEY_REVOKED"
	case errors.Is(err, domain.ErrLogProofInvalid):
		status, code = http.StatusBadRequest, "LOG_PROOF_INVALID"
	case errors.Is(err, domain.ErrSTHInvalid):
		status, code = http.StatusBadRequest, "STH_INVALID"
	case errors.Is(err, domain.ErrArtifactHashMismatch):
		status, code = http.StatusBadRequest, "ARTIFACT_HASH_MISMATCH"
	case errors.Is(err, domain.ErrProofRequired):
		status, code = http.StatusBadRequest, "PROOF_REQUIRED"
	case errors.Is(err, domain.ErrNotFound):
		status, code = http.StatusNotFound, "NOT_FOUND"
	case errors.Is(err, domain.ErrUnauthorized):
		status, code = http.StatusUnauthorized, "UNAUTHORIZED"
	}
	writeErrorCode(c, status, code, err.Error())
}

func writeErrorCode(c *gin.Context, status int, code, message string) {
	c.JSON(status, errorResponse{
		Code:    code,
		Message: message,
	})
}
