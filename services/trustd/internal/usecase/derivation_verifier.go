package usecase

import (
	"context"
	"errors"
	"sort"
	"time"

	"proteus/internal/domain"
)

type DerivationVerifier struct {
	Manifests  ManifestReader
	Provenance ProvenanceRepository
	Keys       KeyRepository
}

func (v *DerivationVerifier) Verify(ctx context.Context, tenantID, manifestID string) (domain.DerivationSummary, error) {
	if v == nil || v.Manifests == nil || v.Provenance == nil || v.Keys == nil {
		return domain.DerivationSummary{}, errors.New("derivation verifier requires manifest reader, provenance repository, and key repository")
	}
	state := derivationState{
		failures:   make([]domain.DerivationFailure, 0),
		failureSet: map[string]struct{}{},
	}
	stack := map[string]bool{}
	cache := map[string]derivationCacheEntry{}
	depth, err := v.walk(ctx, tenantID, manifestID, nil, stack, cache, &state)
	if err != nil {
		return domain.DerivationSummary{}, err
	}
	state.sortFailures()
	summary := domain.DerivationSummary{
		Complete: len(state.failures) == 0,
		Depth:    depth,
		Failures: state.failures,
		Severity: domain.DerivationSeverityError,
	}
	if summary.Complete {
		summary.Severity = domain.DerivationSeverityNone
	}
	return summary, nil
}

func (v *DerivationVerifier) walk(ctx context.Context, tenantID, manifestID string, parentCreatedAt *time.Time, stack map[string]bool, cache map[string]derivationCacheEntry, state *derivationState) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if entry, ok := cache[manifestID]; ok {
		if parentCreatedAt != nil && entry.createdAt.After(*parentCreatedAt) {
			state.addFailure(domain.DerivationFailureTimeParadox, manifestID, nil)
		}
		return entry.depth, nil
	}
	if stack[manifestID] {
		state.addFailure(domain.DerivationFailureCycleDetected, manifestID, nil)
		return 0, nil
	}

	stack[manifestID] = true
	defer delete(stack, manifestID)

	env, err := v.Manifests.GetEnvelopeByManifestID(ctx, tenantID, manifestID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			state.addFailure(domain.DerivationFailureManifestNotFound, manifestID, nil)
			return 0, nil
		}
		return 0, err
	}

	if env.Manifest.Tool.Name == "" || env.Manifest.Tool.Version == "" {
		state.addFailure(domain.DerivationFailureToolMetadataMissing, manifestID, nil)
	}
	if env.Manifest.Time.CreatedAt.After(env.Manifest.Time.SubmittedAt) {
		state.addFailure(domain.DerivationFailureTimeParadox, manifestID, nil)
	}
	if parentCreatedAt != nil && env.Manifest.Time.CreatedAt.After(*parentCreatedAt) {
		state.addFailure(domain.DerivationFailureTimeParadox, manifestID, nil)
	}
	if env.Signature.KID != "" {
		revoked, err := v.Keys.IsRevoked(ctx, tenantID, env.Signature.KID)
		if err != nil {
			return 0, err
		}
		if revoked {
			state.addFailure(domain.DerivationFailureSignerRevoked, manifestID, nil)
		}
	}
	if env.Manifest.Subject.Hash.Alg != "" && env.Manifest.Subject.Hash.Value != "" {
		if _, err := v.Provenance.GetArtifactByHash(ctx, tenantID, env.Manifest.Subject.Hash); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				state.addFailure(domain.DerivationFailureArtifactMissing, manifestID, &env.Manifest.Subject.Hash)
			} else {
				return 0, err
			}
		}
	}

	inputs := sortedInputs(env.Manifest.Inputs)
	maxDepth := 0
	for _, input := range inputs {
		if input.Hash.Alg == "" || input.Hash.Value == "" {
			state.addFailure(domain.DerivationFailureInputInvalid, manifestID, nil)
			continue
		}
		hash := input.Hash
		if _, err := v.Provenance.GetArtifactByHash(ctx, tenantID, hash); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				state.addFailure(domain.DerivationFailureArtifactMissing, manifestID, &hash)
			} else {
				return 0, err
			}
		}
		generators, err := v.Provenance.ListGeneratedManifestIDs(ctx, tenantID, hash)
		if err != nil {
			return 0, err
		}
		sort.Strings(generators)
		if len(generators) == 0 {
			state.addFailure(domain.DerivationFailureInputMissing, manifestID, &hash)
			continue
		}
		if len(generators) > 1 {
			state.addFailure(domain.DerivationFailureMultipleGenerators, manifestID, &hash)
			continue
		}
		childDepth, err := v.walk(ctx, tenantID, generators[0], &env.Manifest.Time.CreatedAt, stack, cache, state)
		if err != nil {
			return 0, err
		}
		if childDepth+1 > maxDepth {
			maxDepth = childDepth + 1
		}
	}
	cache[manifestID] = derivationCacheEntry{depth: maxDepth, createdAt: env.Manifest.Time.CreatedAt}
	return maxDepth, nil
}

func sortedInputs(inputs []domain.InputArtifact) []domain.InputArtifact {
	if len(inputs) == 0 {
		return nil
	}
	out := make([]domain.InputArtifact, len(inputs))
	copy(out, inputs)
	sort.Slice(out, func(i, j int) bool {
		return inputKey(out[i]) < inputKey(out[j])
	})
	return out
}

func inputKey(input domain.InputArtifact) string {
	return input.Hash.Alg + ":" + input.Hash.Value + ":" + input.MediaType + ":" + input.URI
}

type derivationState struct {
	failures   []domain.DerivationFailure
	failureSet map[string]struct{}
}

type derivationCacheEntry struct {
	depth     int
	createdAt time.Time
}

func (s *derivationState) addFailure(code string, manifestID string, hash *domain.Hash) {
	key := code + "|" + manifestID
	if hash != nil {
		key += "|" + hash.Alg + ":" + hash.Value
	}
	if _, ok := s.failureSet[key]; ok {
		return
	}
	s.failureSet[key] = struct{}{}
	s.failures = append(s.failures, domain.DerivationFailure{
		Code:         code,
		ManifestID:   manifestID,
		ArtifactHash: hash,
	})
}

func (s *derivationState) sortFailures() {
	sort.Slice(s.failures, func(i, j int) bool {
		if s.failures[i].Code == s.failures[j].Code {
			if s.failures[i].ManifestID == s.failures[j].ManifestID {
				return hashKey(s.failures[i].ArtifactHash) < hashKey(s.failures[j].ArtifactHash)
			}
			return s.failures[i].ManifestID < s.failures[j].ManifestID
		}
		return s.failures[i].Code < s.failures[j].Code
	})
}

func hashKey(hash *domain.Hash) string {
	if hash == nil {
		return ""
	}
	return hash.Alg + ":" + hash.Value
}
