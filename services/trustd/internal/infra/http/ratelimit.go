package http

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"proteus/internal/domain"

	"github.com/gin-gonic/gin"
)

var subjectLimitedRoutes = map[string]bool{
	routeManifestsRecord: true,
	routeManifestsVerify: true,
}

const (
	routeManifestsRecord = "manifests:record"
	routeManifestsVerify = "manifests:verify"
	routeLogsRead        = "logs:read"
	routeKeysRead        = "keys:read"
	routeLineageRead     = "lineage:read"
	routeDerivationRead  = "derivation:read"
)

func (s *Server) enforceRateLimit(c *gin.Context, routeID, tenantID string, principal domain.Principal) bool {
	if s.rateLimiter == nil || s.rateLimitRequests <= 0 {
		return true
	}
	key := fmt.Sprintf("tenant:%s:endpoint:%s", tenantID, routeID)
	if s.rateLimitWithSubject && subjectLimitedRoutes[routeID] && principal.Subject != "" {
		if s.rateLimitSubjectMax <= 0 || len(principal.Subject) <= s.rateLimitSubjectMax {
			subject := principal.Subject
			if s.rateLimitSubjectHash {
				sum := sha256.Sum256([]byte(subject))
				subject = hex.EncodeToString(sum[:])
				key = key + ":subject_hash:" + subject
			} else {
				key = key + ":subject:" + subject
			}
		}
	}

	decision, err := s.rateLimiter.Allow(c.Request.Context(), key, s.rateLimitRequests, s.rateLimitWindow)
	if err != nil {
		if s.rateLimitFailClosed {
			writeErrorCode(c, http.StatusTooManyRequests, "RATE_LIMIT_UNAVAILABLE", "rate limiter unavailable")
			return false
		}
		return true
	}
	writeRateLimitHeaders(c, decision)
	if !decision.Allowed {
		writeErrorCode(c, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded")
		return false
	}
	return true
}

func writeRateLimitHeaders(c *gin.Context, decision domain.RateLimitDecision) {
	if decision.Limit > 0 {
		c.Header("RateLimit-Limit", strconv.Itoa(decision.Limit))
	}
	if decision.Remaining >= 0 {
		c.Header("RateLimit-Remaining", strconv.Itoa(decision.Remaining))
	}
	if !decision.ResetAt.IsZero() {
		resetUnix := decision.ResetAt.Unix()
		c.Header("RateLimit-Reset", strconv.FormatInt(resetUnix, 10))
		if !decision.Allowed {
			retryAfter := int64(time.Until(decision.ResetAt).Seconds())
			if retryAfter < 0 {
				retryAfter = 0
			}
			c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
		}
	}
}
