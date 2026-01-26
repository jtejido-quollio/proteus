package queues

import (
	"net/http"
	"strconv"
	"strings"

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

func (h *Handler) HandleQueueCases(c *gin.Context) {
	principal, ok := common.PrincipalFromContext(c)
	if !ok {
		return
	}
	queueID, ok := common.ParseUUIDParam(c, "queue_id")
	if !ok {
		return
	}
	filter := usecase.QueueListFilter{
		TenantID: principal.TenantID,
		QueueID:  queueID,
	}
	filter.Status = strings.TrimSpace(c.Query("status"))
	filter.OwnerID = strings.TrimSpace(c.Query("owner"))
	filter.Severity = strings.TrimSpace(c.Query("severity"))
	filter.SLAState = strings.TrimSpace(c.Query("sla_state"))
	filter.Cursor = strings.TrimSpace(c.Query("cursor"))
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if limit, err := strconv.Atoi(raw); err == nil {
			filter.Limit = limit
		}
	}
	items, next, err := h.Service.ListQueueCases(c.Request.Context(), filter)
	if err != nil {
		common.WriteError(c, err)
		return
	}
	resp := make([]common.CaseResponse, 0, len(items))
	for _, item := range items {
		resp = append(resp, common.ToQueueListResponse(item))
	}
	c.JSON(http.StatusOK, listResponse{Items: resp, NextCursor: next})
}
