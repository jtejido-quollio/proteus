package http

import (
	"log"

	"proteus/case-service/internal/config"
	"proteus/case-service/internal/domain/cases"
	"proteus/case-service/internal/http/auth"
	casehttp "proteus/case-service/internal/http/cases"
	"proteus/case-service/internal/http/common"
	queuehttp "proteus/case-service/internal/http/queues"
	"proteus/case-service/internal/repo/postgres"
	"proteus/case-service/internal/usecase"

	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg           config.Config
	r             *gin.Engine
	service       *usecase.CaseService
	authenticator common.Authenticator
	authorizer    cases.Authorizer
}

type ServerDeps struct {
	Service       *usecase.CaseService
	Authenticator common.Authenticator
	Authorizer    cases.Authorizer
}

func NewServer(cfg config.Config, store *postgres.Store) *Server {
	caseRepo := postgres.NewCaseRepo(store.Pool)
	eventRepo := postgres.NewEventRepo(store.Pool)
	evidenceRepo := postgres.NewEvidenceRepo(store.Pool)
	projectionRepo := postgres.NewProjectionRepo(store.Pool)
	policyRepo := postgres.NewPolicySnapshotRepo(store.Pool)

	service := usecase.NewCaseService(caseRepo, eventRepo, evidenceRepo, projectionRepo, policyRepo)
	return NewServerWithDeps(cfg, ServerDeps{
		Service:       service,
		Authenticator: auth.NewHeaderAuthenticator(),
		Authorizer:    auth.NewAuthorizer(),
	})
}

func NewServerWithDeps(cfg config.Config, deps ServerDeps) *Server {
	r := gin.New()
	r.Use(gin.Recovery())

	s := &Server{
		cfg:           cfg,
		r:             r,
		service:       deps.Service,
		authenticator: deps.Authenticator,
		authorizer:    deps.Authorizer,
	}
	if s.authenticator == nil {
		s.authenticator = auth.NewHeaderAuthenticator()
	}
	if s.authorizer == nil {
		s.authorizer = auth.NewAuthorizer()
	}
	s.routes()
	return s
}

func (s *Server) Run() error {
	addr := s.cfg.HTTPAddr
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("case-service listening on %s", addr)
	return s.r.Run(addr)
}

func (s *Server) routes() {
	s.r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	caseHandler := casehttp.NewHandler(s.service)
	queueHandler := queuehttp.NewHandler(s.service)

	v1 := s.r.Group("/v1")
	{
		auth := func(permission string, requireRequestID bool) gin.HandlerFunc {
			return common.AuthMiddleware(s.authenticator, s.authorizer, permission, requireRequestID)
		}

		v1.POST("/cases", auth(cases.PermCaseWrite, true), caseHandler.HandleCreateCase)
		v1.GET("/cases", auth(cases.PermCaseRead, false), caseHandler.HandleListCases)
		v1.GET("/cases/:id", auth(cases.PermCaseRead, false), caseHandler.HandleGetCase)
		v1.GET("/cases/:id/events", auth(cases.PermCaseRead, false), caseHandler.HandleListEvents)
		v1.POST("/cases/:id/evidence", auth(cases.PermCaseEvent, true), caseHandler.HandleAddEvidence)
		v1.POST("/cases/:id/comments", auth(cases.PermCaseComment, true), caseHandler.HandleAddComment)
		v1.POST("/cases/:id/assign", auth(cases.PermCaseAssign, true), caseHandler.HandleAssign)
		v1.POST("/cases/:id/unassign", auth(cases.PermCaseAssign, true), caseHandler.HandleUnassign)
		v1.POST("/cases/:id/hold", auth(cases.PermCaseHold, true), caseHandler.HandleHold)
		v1.POST("/cases/:id/unhold", auth(cases.PermCaseHold, true), caseHandler.HandleUnhold)
		v1.POST("/cases/:id/escalate", auth(cases.PermCaseEscalate, true), caseHandler.HandleEscalate)
		v1.POST("/cases/:id/deescalate", auth(cases.PermCaseEscalate, true), caseHandler.HandleDeescalate)
		v1.POST("/cases/:id/decide", auth(cases.PermCaseDecide, true), caseHandler.HandleDecide)
		v1.POST("/cases/:id/reopen", auth(cases.PermCaseDecide, true), caseHandler.HandleReopen)
		v1.POST("/cases/:id/exports", auth(cases.PermCaseExport, true), caseHandler.HandleExport)

		v1.GET("/queues/:queue_id/cases", auth(cases.PermQueueRead, false), queueHandler.HandleQueueCases)
	}
}
