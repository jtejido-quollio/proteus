package db

import (
	"context"
	"errors"
	"time"

	"proteus/internal/domain"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ProvenanceRepository struct {
	db *gorm.DB
}

func NewProvenanceRepository(db *gorm.DB) *ProvenanceRepository {
	return &ProvenanceRepository{db: db}
}

func (r *ProvenanceRepository) UpsertArtifact(ctx context.Context, tenantID string, artifact domain.Artifact) (string, error) {
	if r.db == nil {
		return "", errDBUnavailable
	}
	if tenantID == "" {
		return "", errors.New("tenant_id is required")
	}
	if artifact.Hash.Alg == "" || artifact.Hash.Value == "" {
		return "", errors.New("artifact hash is required")
	}
	if artifact.MediaType == "" {
		return "", errors.New("artifact media_type is required")
	}

	var existing ArtifactModel
	err := r.db.WithContext(ctx).
		Select("id").
		Where("tenant_id = ? AND hash_alg = ? AND hash_value = ?", tenantID, artifact.Hash.Alg, artifact.Hash.Value).
		First(&existing).Error
	if err == nil {
		return existing.ID, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}

	artifactID, err := newUUID()
	if err != nil {
		return "", err
	}
	createdAt := artifact.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	model := ArtifactModel{
		ID:        artifactID,
		TenantID:  tenantID,
		HashAlg:   artifact.Hash.Alg,
		HashValue: artifact.Hash.Value,
		MediaType: artifact.MediaType,
		URI:       nil,
		CreatedAt: createdAt,
	}
	if artifact.URI != "" {
		model.URI = &artifact.URI
	}

	result := r.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&model)
	if result.Error != nil {
		return "", result.Error
	}
	if result.RowsAffected > 0 {
		return artifactID, nil
	}

	err = r.db.WithContext(ctx).
		Select("id").
		Where("tenant_id = ? AND hash_alg = ? AND hash_value = ?", tenantID, artifact.Hash.Alg, artifact.Hash.Value).
		First(&existing).Error
	if err != nil {
		return "", err
	}
	return existing.ID, nil
}

func (r *ProvenanceRepository) AddEdge(ctx context.Context, edge domain.ProvenanceEdge) error {
	if r.db == nil {
		return errDBUnavailable
	}
	if edge.TenantID == "" || edge.ManifestID == "" {
		return errors.New("tenant_id and manifest_id are required")
	}
	if edge.Type == "" {
		return errors.New("edge type is required")
	}
	if edge.Type == domain.ProvenanceEdgeSignedBy && edge.KID == "" {
		return errors.New("signing kid is required")
	}
	if edge.Type != domain.ProvenanceEdgeSignedBy && edge.ArtifactID == "" {
		return errors.New("artifact_id is required")
	}

	var artifactID *string
	if edge.ArtifactID != "" {
		artifactID = &edge.ArtifactID
	}
	var kid *string
	if edge.KID != "" {
		kid = &edge.KID
	}
	createdAt := edge.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	model := ProvenanceEdgeModel{
		TenantID:   edge.TenantID,
		ManifestID: edge.ManifestID,
		EdgeType:   string(edge.Type),
		ArtifactID: artifactID,
		KID:        kid,
		CreatedAt:  createdAt,
	}
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&model).Error
}

func (r *ProvenanceRepository) ListGeneratedManifestIDs(ctx context.Context, tenantID string, hash domain.Hash) ([]string, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	if hash.Alg == "" || hash.Value == "" {
		return nil, errors.New("hash is required")
	}

	var manifestIDs []string
	err := r.db.WithContext(ctx).
		Table("provenance_edges").
		Select("DISTINCT provenance_edges.manifest_id").
		Joins("JOIN artifacts ON artifacts.id = provenance_edges.artifact_id").
		Where("provenance_edges.tenant_id = ?", tenantID).
		Where("provenance_edges.edge_type = ?", string(domain.ProvenanceEdgeGenerated)).
		Where("artifacts.tenant_id = ? AND artifacts.hash_alg = ? AND artifacts.hash_value = ?", tenantID, hash.Alg, hash.Value).
		Order("provenance_edges.manifest_id ASC").
		Scan(&manifestIDs).Error
	if err != nil {
		return nil, err
	}
	return manifestIDs, nil
}

func (r *ProvenanceRepository) GetArtifactByHash(ctx context.Context, tenantID string, hash domain.Hash) (*domain.Artifact, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	if hash.Alg == "" || hash.Value == "" {
		return nil, errors.New("hash is required")
	}

	var model ArtifactModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND hash_alg = ? AND hash_value = ?", tenantID, hash.Alg, hash.Value).
		First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	artifact := domain.Artifact{
		TenantID:  model.TenantID,
		Hash:      domain.Hash{Alg: model.HashAlg, Value: model.HashValue},
		MediaType: model.MediaType,
		CreatedAt: model.CreatedAt,
	}
	if model.URI != nil {
		artifact.URI = *model.URI
	}
	return &artifact, nil
}
