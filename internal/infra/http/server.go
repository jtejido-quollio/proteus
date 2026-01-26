package http

import (
	"errors"
	"net/http"
	"time"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/auth/oidc"
	"proteus/internal/infra/auth/rbac"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/db"
	"proteus/internal/infra/keys/awskms"
	"proteus/internal/infra/keys/gcpkms"
	"proteus/internal/infra/keys/soft"
	"proteus/internal/infra/keys/vault"
	"proteus/internal/infra/logdb"
	"proteus/internal/infra/logmem"
	"proteus/internal/infra/merkle"
	"proteus/internal/infra/ratelimit"
	"proteus/internal/usecase"

	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg   config.Config
	store *db.Store
	r     *gin.Engine

	recordUC      *usecase.RecordSignedManifest
	verifyUC      *usecase.VerifySignedManifest
	log           usecase.TenantLog
	rotation      *usecase.KeyRotationService
	audit         *usecase.AuditEmitter
	revocationSvc *usecase.RevocationService
	provenance    *usecase.ProvenanceQuery

	tenants     TenantStore
	signingKey  KeyStore
	logKey      KeyStore
	revocations RevocationStore

	adminAPIKey string

	authenticator domain.Authenticator
	authorizer    domain.Authorizer
	authInitErr   error

	rateLimiter          domain.RateLimiter
	rateLimitRequests    int
	rateLimitWindow      time.Duration
	rateLimitWithSubject bool
	rateLimitFailClosed  bool
	rateLimitSubjectMax  int
	rateLimitSubjectHash bool
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
	Record           *usecase.RecordSignedManifest
	Verify           *usecase.VerifySignedManifest
	Log              usecase.TenantLog
	Rotation         *usecase.KeyRotationService
	Audit            *usecase.AuditEmitter
	RevocationSvc    *usecase.RevocationService
	Provenance       *usecase.ProvenanceQuery
	Tenants          TenantStore
	SigningKeys      KeyStore
	LogKeys          KeyStore
	Revocations      RevocationStore
	RevocationEpochs usecase.RevocationEpochRepository
	AdminAPIKey      string
	Authenticator    domain.Authenticator
	Authorizer       domain.Authorizer
	RateLimiter      domain.RateLimiter
}

func NewServerWithDeps(cfg config.Config, deps ServerDeps) *Server {
	r := gin.New()
	r.Use(gin.Recovery())

	s := &Server{
		cfg:           cfg,
		r:             r,
		recordUC:      deps.Record,
		verifyUC:      deps.Verify,
		log:           deps.Log,
		rotation:      deps.Rotation,
		audit:         deps.Audit,
		revocationSvc: deps.RevocationSvc,
		provenance:    deps.Provenance,
		tenants:       deps.Tenants,
		signingKey:    deps.SigningKeys,
		logKey:        deps.LogKeys,
		revocations:   deps.Revocations,
		adminAPIKey:   deps.AdminAPIKey,
		authenticator: deps.Authenticator,
		authorizer:    deps.Authorizer,
	}
	if s.log == nil {
		if s.recordUC != nil {
			s.log = s.recordUC.Log
		} else if s.verifyUC != nil {
			s.log = s.verifyUC.Log
		}
	}
	if s.revocationSvc == nil && deps.Revocations != nil && deps.RevocationEpochs != nil {
		if revRepo, ok := deps.Revocations.(usecase.RevocationRepository); ok {
			s.revocationSvc = usecase.NewRevocationService(revRepo, deps.RevocationEpochs)
		}
	}
	s.initRateLimit(deps.RateLimiter)
	s.initAuth()
	s.routes()
	return s
}

func (s *Server) initDeps() {
	s.adminAPIKey = s.cfg.AdminAPIKey

	cryptoSvc := &crypto.Service{}
	merkleSvc := &merkle.Service{}

	softManager := soft.NewManagerFromConfig(s.cfg)
	keyManager := domain.KeyManager(softManager)
	keyMaterial := usecase.KeyMaterialStore(soft.NewStore(softManager))
	if vaultManager, err := vault.NewManagerFromConfig(s.cfg); err == nil {
		if vaultStore, err := vault.NewStoreFromConfig(s.cfg); err == nil {
			keyManager = vaultManager
			keyMaterial = vaultStore
		}
	} else if awsManager, err := awskms.NewManagerFromConfig(s.cfg); err == nil {
		if awsStore, err := awskms.NewStoreFromConfig(s.cfg); err == nil {
			keyManager = awsManager
			keyMaterial = awsStore
		}
	} else if gcpManager, err := gcpkms.NewManagerFromConfig(s.cfg); err == nil {
		if gcpStore, err := gcpkms.NewStoreFromConfig(s.cfg); err == nil {
			keyManager = gcpManager
			keyMaterial = gcpStore
		}
	}

	var (
		signingRepo  *db.SigningKeyRepository
		logKeyRepo   *db.LogKeyRepository
		revRepo      *db.RevocationRepository
		epochRepo    *db.RevocationEpochRepository
		tenantRepo   *db.TenantRepository
		manifestRepo *db.ManifestRepository
		provRepo     *db.ProvenanceRepository
		logRepo      *db.TransparencyLogRepository
		auditRepo    *db.AuditEventRepository
	)
	if s.store != nil {
		signingRepo = db.NewSigningKeyRepository(s.store.DB)
		logKeyRepo = db.NewLogKeyRepository(s.store.DB)
		revRepo = db.NewRevocationRepository(s.store.DB)
		epochRepo = db.NewRevocationEpochRepository(s.store.DB)
		tenantRepo = db.NewTenantRepository(s.store.DB)
		manifestRepo = db.NewManifestRepository(s.store.DB)
		provRepo = db.NewProvenanceRepository(s.store.DB)
		if s.store.DB != nil {
			logRepo = db.NewTransparencyLogRepository(s.store.DB)
			auditRepo = db.NewAuditEventRepository(s.store.DB)
		}
	}

	var logKeyStore KeyStore
	var logKeySource usecase.LogKeyRepository
	if logKeyRepo != nil {
		logKeyStore = logKeyRepo
		logKeySource = logKeyRepo
	}

	signer := buildLogSigner(s.cfg, cryptoSvc, keyManager, logKeySource)
	var log usecase.TenantLog
	if logRepo != nil {
		log = logdb.NewWithSignerAndClock(logRepo, signer, nil)
	}
	if log == nil {
		log = logmem.NewWithSignerAndClock(signer, nil)
	}

	var rotationSvc *usecase.KeyRotationService
	if signingRepo != nil && logKeyRepo != nil {
		rotationSvc = usecase.NewKeyRotationServiceWithInterval(signingRepo, logKeyRepo, keyMaterial, nil, s.cfg.KeyRotationInterval())
	}
	if auditRepo != nil {
		s.audit = usecase.NewAuditEmitter(auditRepo, nil)
	}
	if revRepo != nil && epochRepo != nil {
		s.revocationSvc = usecase.NewRevocationService(revRepo, epochRepo)
	}
	keyRepo := db.NewKeyRepository(signingRepo, revRepo)
	s.recordUC = &usecase.RecordSignedManifest{
		Tenants:    tenantRepo,
		Keys:       keyRepo,
		Manif:      manifestRepo,
		Log:        log,
		Crypto:     cryptoSvc,
		KeyManager: keyManager,
		Provenance: provRepo,
	}
	s.verifyUC = &usecase.VerifySignedManifest{
		Keys:             keyRepo,
		LogKeys:          logKeySource,
		Log:              log,
		Crypto:           cryptoSvc,
		Merkle:           merkleSvc,
		KeyManager:       keyManager,
		RevocationEpochs: epochRepo,
	}
	if manifestRepo != nil && provRepo != nil && signingRepo != nil && revRepo != nil {
		s.verifyUC.Derivation = &usecase.DerivationVerifier{
			Manifests:  manifestRepo,
			Provenance: provRepo,
			Keys:       keyRepo,
		}
	}
	if manifestRepo != nil && provRepo != nil {
		s.provenance = &usecase.ProvenanceQuery{
			Manifests:  manifestRepo,
			Provenance: provRepo,
		}
	}
	s.rotation = rotationSvc
	s.log = log
	s.tenants = tenantRepo
	s.signingKey = signingRepo
	s.logKey = logKeyStore
	s.revocations = revRepo

	s.initRateLimit(nil)
	s.initAuth()
}

func (s *Server) initAuth() {
	if s.cfg.AuthMode == "" {
		s.authInitErr = errors.New("AUTH_MODE is required")
		return
	}
	switch s.cfg.AuthMode {
	case "none":
		return
	case "oidc":
		if s.authenticator != nil && s.authorizer != nil {
			return
		}
		if s.authenticator == nil {
			authenticator, err := oidc.NewAuthenticator(s.cfg)
			if err != nil {
				s.authInitErr = err
				return
			}
			s.authenticator = authenticator
		}
		if s.authorizer == nil {
			s.authorizer = rbac.NewAuthorizer()
		}
	default:
		s.authInitErr = errors.New("unsupported auth mode")
	}
}

func (s *Server) initRateLimit(override domain.RateLimiter) {
	if override != nil {
		s.rateLimiter = override
	}
	if s.rateLimiter == nil && s.cfg.RateLimitRequests > 0 {
		if s.cfg.RedisAddr != "" {
			if limiter, err := ratelimit.NewRedisLimiter(s.cfg.RedisAddr, s.cfg.RedisPassword, s.cfg.RedisDB, nil); err == nil {
				s.rateLimiter = limiter
			}
		}
		if s.rateLimiter == nil {
			s.rateLimiter = ratelimit.NewMemoryLimiter(ratelimit.MemoryLimiterConfig{
				MaxKeys: s.cfg.RateLimitMaxKeys,
			})
		}
	}
	s.rateLimitRequests = s.cfg.RateLimitRequests
	if s.cfg.RateLimitWindowSeconds > 0 {
		s.rateLimitWindow = time.Duration(s.cfg.RateLimitWindowSeconds) * time.Second
	}
	s.rateLimitWithSubject = s.cfg.RateLimitIncludeSubject
	s.rateLimitFailClosed = s.cfg.RateLimitFailClosed
	s.rateLimitSubjectMax = s.cfg.RateLimitSubjectMaxLen
	s.rateLimitSubjectHash = s.cfg.RateLimitSubjectHash
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
		v1.GET("/lineage/:artifact_hash", s.handleLineage)
		v1.GET("/derivation/:manifest_id", s.handleDerivation)

		v1.POST("/tenants", s.handleAdminCreateTenant)
		v1.POST("/tenants/:tenant_id/keys/signing", s.handleAdminRegisterSigningKey)
		v1.POST("/tenants/:tenant_id/keys/log", s.handleAdminRegisterLogKey)
		v1.POST("/tenants/:tenant_id/keys/:kid_action", s.handleAdminKeyAction)
	}

	s.r.NoRoute(s.handleNoRoute)
}

func (s *Server) Run() error {
	if s.authInitErr != nil {
		return s.authInitErr
	}
	return s.r.Run(s.cfg.HTTPAddr)
}
