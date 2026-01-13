package usecase

import (
	"context"
	"errors"
	"sort"

	"proteus/internal/domain"
)

type DerivationVerifier struct {
	Manifests  ManifestReader
	Provenance ProvenanceRepository
}

func (v *DerivationVerifier) Verify(ctx context.Context, tenantID, manifestID string) (domain.DerivationSummary, error) {
	if v == nil || v.Manifests == nil || v.Provenance == nil {
		return domain.DerivationSummary{}, errors.New("derivation verifier requires manifest reader and provenance repository")
	}
	state := derivationState{
		failures:   make([]domain.DerivationFailure, 0),
		failureSet: map[string]struct{}{},
	}
	stack := map[string]bool{}
	cache := map[string]int{}
	depth, err := v.walk(ctx, tenantID, manifestID, stack, cache, &state)
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

func (v *DerivationVerifier) walk(ctx context.Context, tenantID, manifestID string, stack map[string]bool, cache map[string]int, state *derivationState) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if depth, ok := cache[manifestID]; ok {
		return depth, nil
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

	inputs := sortedInputs(env.Manifest.Inputs)
	maxDepth := 0
	for _, input := range inputs {
		if input.Hash.Alg == "" || input.Hash.Value == "" {
			state.addFailure(domain.DerivationFailureInputInvalid, manifestID, nil)
			continue
		}
		hash := input.Hash
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
		childDepth, err := v.walk(ctx, tenantID, generators[0], stack, cache, state)
		if err != nil {
			return 0, err
		}
		if childDepth+1 > maxDepth {
			maxDepth = childDepth + 1
		}
	}
	cache[manifestID] = maxDepth
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
