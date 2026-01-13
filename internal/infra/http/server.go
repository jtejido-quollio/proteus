package http

import (
	"net/http"
	"os"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/db"
	"proteus/internal/infra/logdb"
	"proteus/internal/infra/logmem"
	"proteus/internal/infra/merkle"
	"proteus/internal/usecase"

	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg   config.Config
	store *db.Store
	r     *gin.Engine

	recordUC *usecase.RecordSignedManifest
	verifyUC *usecase.VerifySignedManifest
	log      usecase.TenantLog

	tenants     TenantStore
	signingKey  KeyStore
	logKey      KeyStore
	revocations RevocationStore

	adminAPIKey string
}

func NewServer(cfg config.Config, store *db.Store) *Server {
	r := gin.New()
	r.Use(gin.Recovery())

	s := &Server{cfg: cfg, store: store, r: r}
	s.initDeps()
	s.routes()
	return s
}

type ServerDeps struct {
	Record      *usecase.RecordSignedManifest
	Verify      *usecase.VerifySignedManifest
	Log         usecase.TenantLog
	Tenants     TenantStore
	SigningKeys KeyStore
	LogKeys     KeyStore
	Revocations RevocationStore
	AdminAPIKey string
}

func NewServerWithDeps(cfg config.Config, deps ServerDeps) *Server {
	r := gin.New()
	r.Use(gin.Recovery())

	s := &Server{
		cfg:         cfg,
		r:           r,
		recordUC:    deps.Record,
		verifyUC:    deps.Verify,
		log:         deps.Log,
		tenants:     deps.Tenants,
		signingKey:  deps.SigningKeys,
		logKey:      deps.LogKeys,
		revocations: deps.Revocations,
		adminAPIKey: deps.AdminAPIKey,
	}
	if s.log == nil {
		if s.recordUC != nil {
			s.log = s.recordUC.Log
		} else if s.verifyUC != nil {
			s.log = s.verifyUC.Log
		}
	}
	s.routes()
	return s
}

func (s *Server) initDeps() {
	s.adminAPIKey = os.Getenv("ADMIN_API_KEY")

	cryptoSvc := &crypto.Service{}
	merkleSvc := &merkle.Service{}

	var signer func(domain.STH) ([]byte, error)
	if signFunc := loadLogSignerFromEnv(cryptoSvc); signFunc != nil {
		signer = signFunc
	}
	var log usecase.TenantLog

	var (
		signingRepo  *db.SigningKeyRepository
		logKeyRepo   *db.LogKeyRepository
		revRepo      *db.RevocationRepository
		tenantRepo   *db.TenantRepository
		manifestRepo *db.ManifestRepository
	)
	if s.store != nil {
		signingRepo = db.NewSigningKeyRepository(s.store.DB)
		logKeyRepo = db.NewLogKeyRepository(s.store.DB)
		revRepo = db.NewRevocationRepository(s.store.DB)
		tenantRepo = db.NewTenantRepository(s.store.DB)
		manifestRepo = db.NewManifestRepository(s.store.DB)
		if s.store.DB != nil {
			logRepo := db.NewTransparencyLogRepository(s.store.DB)
			log = logdb.NewWithSignerAndClock(logRepo, signer, nil)
		}
	}
	if log == nil {
		log = logmem.NewWithSignerAndClock(signer, nil)
	}

	keyRepo := db.NewKeyRepository(signingRepo, revRepo)
	s.recordUC = &usecase.RecordSignedManifest{
		Tenants: tenantRepo,
		Keys:    keyRepo,
		Manif:   manifestRepo,
		Log:     log,
		Crypto:  cryptoSvc,
	}
	s.verifyUC = &usecase.VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Log:     log,
		Crypto:  cryptoSvc,
		Merkle:  merkleSvc,
	}
	s.log = log
	s.tenants = tenantRepo
	s.signingKey = signingRepo
	s.logKey = logKeyRepo
	s.revocations = revRepo
}

func (s *Server) routes() {
	s.r.GET("/healthz", func(c *gin.Context) {
		status := "ok"
		dbMode := "no-db"
		if s.store != nil && s.store.DB != nil {
			dbMode = "db"
		}
		c.JSON(http.StatusOK, gin.H{"status": status, "mode": dbMode})
	})

	v1 := s.r.Group("/v1")
	{
		v1.GET("/tenants/:tenant_id/keys/signing", s.handleListSigningKeys)
		v1.GET("/tenants/:tenant_id/keys/log", s.handleListLogKeys)
		v1.GET("/logs/:tenant_id/sth/latest", s.handleLatestSTH)
		v1.GET("/logs/:tenant_id/inclusion/:leaf_hash", s.handleInclusionProof)
		v1.GET("/logs/:tenant_id/consistency", s.handleConsistencyProof)

		v1.POST("/tenants", s.handleAdminCreateTenant)
		v1.POST("/tenants/:tenant_id/keys/signing", s.handleAdminRegisterSigningKey)
		v1.POST("/tenants/:tenant_id/keys/log", s.handleAdminRegisterLogKey)
		v1.POST("/tenants/:tenant_id/keys/:kid_action", s.handleAdminKeyAction)
	}

	s.r.NoRoute(s.handleNoRoute)
}

func notImplemented(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"code":    "NOT_IMPLEMENTED",
		"message": "Phase 0 scaffold. Implement in Phase 1.",
	})
}

func (s *Server) Run() error {
	return s.r.Run(s.cfg.HTTPAddr)
}
