package cases

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"proteus/case-service/internal/domain/cases"
	"proteus/case-service/internal/http/common"
	"proteus/case-service/internal/usecase"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	Service *usecase.CaseService
}

type listResponse struct {
	Items      []common.CaseResponse `json:"items"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

func NewHandler(service *usecase.CaseService) *Handler {
	return &Handler{Service: service}
}

func (h *Handler) HandleCreateCase(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	var req struct {
		SourceType    string `json:"source_type"`
		SourceRefType string `json:"source_ref_type"`
		SourceRefRaw  string `json:"source_ref_raw"`
		Severity      string `json:"severity"`
		QueueID       string `json:"queue_id,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	reqID := common.RequestID(c)
	if req.SourceType == "" || req.SourceRefType == "" || req.SourceRefRaw == "" {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "source_type, source_ref_type, source_ref_raw are required")
		return
	}
	view, created, err := h.Service.CreateCase(c.Request.Context(), usecase.CreateCaseInput{
		TenantID:      principal.TenantID,
		SourceType:    req.SourceType,
		SourceRefType: cases.SourceRefType(req.SourceRefType),
		SourceRefRaw:  req.SourceRefRaw,
		Severity:      req.Severity,
		QueueID:       req.QueueID,
		RequestID:     reqID,
		Actor:         usecase.Actor{Type: "user", ID: principal.Subject},
	})
	if err != nil {
		common.WriteError(c, err)
		return
	}
	payload := gin.H{
		"case":    common.ToCaseResponse(view),
		"created": created,
	}
	c.JSON(http.StatusOK, payload)
}

func (h *Handler) HandleGetCase(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	view, err := h.Service.GetCase(c.Request.Context(), principal.TenantID, caseID)
	if err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"case": common.ToCaseResponse(view)})
}

func (h *Handler) HandleListCases(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	filter := usecase.CaseListFilter{TenantID: principal.TenantID}
	filter.Status = strings.TrimSpace(c.Query("status"))
	filter.QueueID = strings.TrimSpace(c.Query("queue_id"))
	filter.OwnerID = strings.TrimSpace(c.Query("owner"))
	filter.Severity = strings.TrimSpace(c.Query("severity"))
	filter.SLAState = strings.TrimSpace(c.Query("sla_state"))
	filter.Cursor = strings.TrimSpace(c.Query("cursor"))
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if limit, err := strconv.Atoi(raw); err == nil {
			filter.Limit = limit
		}
	}
	if raw := strings.TrimSpace(c.Query("created_after")); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			filter.CreatedAfter = &parsed
		}
	}
	if raw := strings.TrimSpace(c.Query("created_before")); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			filter.CreatedBefore = &parsed
		}
	}
	items, next, err := h.Service.ListCases(c.Request.Context(), filter)
	if err != nil {
		common.WriteError(c, err)
		return
	}
	resp := make([]common.CaseResponse, 0, len(items))
	for _, item := range items {
		resp = append(resp, common.ToCaseListResponse(item))
	}
	c.JSON(http.StatusOK, listResponse{Items: resp, NextCursor: next})
}

func (h *Handler) HandleListEvents(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	events, err := h.Service.ListEvents(c.Request.Context(), principal.TenantID, caseID)
	if err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}

func (h *Handler) HandleAddEvidence(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		EvidenceType string         `json:"evidence_type"`
		EvidenceRef  string         `json:"evidence_ref"`
		EvidenceHash string         `json:"evidence_hash,omitempty"`
		Metadata     map[string]any `json:"metadata,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	reqID := common.RequestID(c)
	if req.EvidenceType == "" || req.EvidenceRef == "" {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "evidence_type and evidence_ref are required")
		return
	}
	err := h.Service.AddEvidence(c.Request.Context(), usecase.EvidenceInput{
		TenantID:     principal.TenantID,
		CaseID:       caseID,
		EvidenceType: req.EvidenceType,
		EvidenceRef:  req.EvidenceRef,
		EvidenceHash: req.EvidenceHash,
		Metadata:     req.Metadata,
		RequestID:    reqID,
		Actor:        usecase.Actor{Type: "user", ID: principal.Subject},
	})
	if err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleAddComment(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	reqID := common.RequestID(c)
	if strings.TrimSpace(req.Body) == "" {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "body is required")
		return
	}
	err := h.Service.AddComment(c.Request.Context(), usecase.CommentInput{
		TenantID:  principal.TenantID,
		CaseID:    caseID,
		Body:      req.Body,
		RequestID: reqID,
		Actor:     usecase.Actor{Type: "user", ID: principal.Subject},
	})
	if err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleAssign(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		AssigneeType string `json:"assignee_type"`
		AssigneeID   string `json:"assignee_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	reqID := common.RequestID(c)
	if req.AssigneeType == "" || req.AssigneeID == "" {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "assignee_type and assignee_id are required")
		return
	}
	err := h.Service.Assign(c.Request.Context(), usecase.AssignInput{
		TenantID:     principal.TenantID,
		CaseID:       caseID,
		AssigneeType: req.AssigneeType,
		AssigneeID:   req.AssigneeID,
		RequestID:    reqID,
		Actor:        usecase.Actor{Type: "user", ID: principal.Subject},
	})
	if err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleUnassign(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	reqID := common.RequestID(c)
	if err := h.Service.Unassign(c.Request.Context(), principal.TenantID, caseID, reqID, usecase.Actor{Type: "user", ID: principal.Subject}); err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleHold(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		Reason   string `json:"reason"`
		HoldType string `json:"hold_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	reqID := common.RequestID(c)
	if req.Reason == "" || req.HoldType == "" {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "reason and hold_type are required")
		return
	}
	if err := h.Service.Hold(c.Request.Context(), usecase.HoldInput{
		TenantID:  principal.TenantID,
		CaseID:    caseID,
		Reason:    req.Reason,
		HoldType:  req.HoldType,
		RequestID: reqID,
		Actor:     usecase.Actor{Type: "user", ID: principal.Subject},
	}); err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleUnhold(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	reqID := common.RequestID(c)
	if err := h.Service.Unhold(c.Request.Context(), principal.TenantID, caseID, reqID, usecase.Actor{Type: "user", ID: principal.Subject}); err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleEscalate(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		FromQueueID string `json:"from_queue_id"`
		ToQueueID   string `json:"to_queue_id"`
		Reason      string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	reqID := common.RequestID(c)
	if req.ToQueueID == "" || req.Reason == "" {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "to_queue_id and reason are required")
		return
	}
	if err := h.Service.Escalate(c.Request.Context(), usecase.EscalateInput{
		TenantID:  principal.TenantID,
		CaseID:    caseID,
		FromQueue: req.FromQueueID,
		ToQueue:   req.ToQueueID,
		Reason:    req.Reason,
		RequestID: reqID,
		Actor:     usecase.Actor{Type: "user", ID: principal.Subject},
	}); err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleDeescalate(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	reqID := common.RequestID(c)
	if err := h.Service.Deescalate(c.Request.Context(), principal.TenantID, caseID, reqID, usecase.Actor{Type: "user", ID: principal.Subject}); err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleDecide(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		Decision         string `json:"decision"`
		PolicySnapshotID string `json:"policy_snapshot_id"`
		BundleHash       string `json:"bundle_hash"`
		EvaluatorVersion string `json:"evaluator_version"`
		Rationale        string `json:"rationale"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	reqID := common.RequestID(c)
	if req.Decision == "" || req.PolicySnapshotID == "" {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "decision and policy_snapshot_id are required")
		return
	}
	if err := h.Service.Decide(c.Request.Context(), usecase.DecideInput{
		TenantID:         principal.TenantID,
		CaseID:           caseID,
		Decision:         req.Decision,
		PolicySnapshotID: req.PolicySnapshotID,
		BundleHash:       req.BundleHash,
		EvaluatorVersion: req.EvaluatorVersion,
		Rationale:        req.Rationale,
		RequestID:        reqID,
		Actor:            usecase.Actor{Type: "user", ID: principal.Subject},
	}); err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleReopen(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	reqID := common.RequestID(c)
	if req.Reason == "" {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "reason is required")
		return
	}
	if err := h.Service.Reopen(c.Request.Context(), usecase.ReopenInput{
		TenantID:  principal.TenantID,
		CaseID:    caseID,
		Reason:    req.Reason,
		RequestID: reqID,
		Actor:     usecase.Actor{Type: "user", ID: principal.Subject},
	}); err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) HandleExport(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	caseID, ok := common.ParseUUIDParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		Format string `json:"format"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	reqID := common.RequestID(c)
	if req.Format == "" {
		common.WriteErrorCode(c, http.StatusBadRequest, "INVALID_ARGUMENT", "format is required")
		return
	}
	if err := h.Service.Export(c.Request.Context(), usecase.ExportInput{
		TenantID:  principal.TenantID,
		CaseID:    caseID,
		Format:    req.Format,
		RequestID: reqID,
		Actor:     usecase.Actor{Type: "user", ID: principal.Subject},
	}); err != nil {
		common.WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
