package capture

import (
	"errors"

	"proteus/internal/domain"
)

const DefaultManifestSchema = "trust.manifest.v0"

type ManifestInput struct {
	Schema     string
	ManifestID string
	TenantID   string
	Subject    domain.Subject
	Actor      domain.Actor
	Tool       domain.Tool
	Time       domain.ManifestTime
	Inputs     []domain.InputArtifact
	Claims     map[string]any
}

func BuildManifest(input ManifestInput) (domain.Manifest, error) {
	schema := input.Schema
	if schema == "" {
		schema = DefaultManifestSchema
	}
	inputs := input.Inputs
	if inputs == nil {
		inputs = []domain.InputArtifact{}
	}
	manifest := domain.Manifest{
		Schema:     schema,
		ManifestID: input.ManifestID,
		TenantID:   input.TenantID,
		Subject:    input.Subject,
		Actor:      input.Actor,
		Tool:       input.Tool,
		Time:       input.Time,
		Inputs:     inputs,
		Claims:     input.Claims,
	}
	if err := ValidateManifest(manifest); err != nil {
		return domain.Manifest{}, err
	}
	return manifest, nil
}

func ValidateManifest(manifest domain.Manifest) error {
	if manifest.Schema == "" {
		return errors.New("manifest schema is required")
	}
	if manifest.ManifestID == "" || manifest.TenantID == "" {
		return errors.New("manifest_id and tenant_id are required")
	}
	if manifest.Subject.Type == "" || manifest.Subject.MediaType == "" {
		return errors.New("subject type and media_type are required")
	}
	if manifest.Subject.Hash.Alg != "sha256" || manifest.Subject.Hash.Value == "" {
		return errors.New("subject hash is required")
	}
	if manifest.Actor.Type == "" || manifest.Actor.ID == "" {
		return errors.New("actor type and id are required")
	}
	if manifest.Tool.Name == "" || manifest.Tool.Version == "" {
		return errors.New("tool name and version are required")
	}
	if manifest.Time.CreatedAt.IsZero() || manifest.Time.SubmittedAt.IsZero() {
		return errors.New("created_at and submitted_at are required")
	}
	return nil
}
