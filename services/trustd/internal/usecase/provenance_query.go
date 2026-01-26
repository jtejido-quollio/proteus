package usecase

import (
	"context"
	"errors"
	"sort"
	"strings"

	"proteus/internal/domain"
)

type ProvenanceQuery struct {
	Manifests  ManifestReader
	Provenance ProvenanceRepository
}

type LineageResult struct {
	TenantID            string            `json:"tenant_id"`
	ArtifactHash        domain.Hash       `json:"artifact_hash"`
	Depth               int               `json:"depth"`
	Complete            bool              `json:"complete"`
	Truncated           bool              `json:"truncated"`
	Limits              LineageLimits     `json:"limits"`
	GeneratingManifests []LineageManifest `json:"generating_manifests,omitempty"`
	MissingArtifacts    []domain.Hash     `json:"missing_artifacts,omitempty"`
	MissingManifests    []string          `json:"missing_manifests,omitempty"`
}

type LineageOptions struct {
	MaxDepth int
	MaxNodes int
}

type LineageLimits struct {
	MaxDepth int      `json:"max_depth"`
	MaxNodes int      `json:"max_nodes"`
	Hit      []string `json:"hit,omitempty"`
}

type LineageManifest struct {
	ManifestID  string         `json:"manifest_id"`
	SubjectHash domain.Hash    `json:"subject_hash"`
	Inputs      []LineageInput `json:"inputs,omitempty"`
}

type LineageInput struct {
	Hash       domain.Hash       `json:"hash"`
	Generators []LineageManifest `json:"generators,omitempty"`
}

type DerivationView struct {
	ManifestID string              `json:"manifest_id"`
	TenantID   string              `json:"tenant_id"`
	Schema     string              `json:"schema"`
	Tool       domain.Tool         `json:"tool"`
	Actor      domain.Actor        `json:"actor"`
	Time       domain.ManifestTime `json:"time"`
	SignerKID  string              `json:"signer_kid,omitempty"`
	Inputs     []domain.Hash       `json:"inputs,omitempty"`
	Outputs    []domain.Hash       `json:"outputs,omitempty"`
	Truncated  bool                `json:"truncated"`
	Limits     LineageLimits       `json:"limits"`
}

func (q *ProvenanceQuery) Lineage(ctx context.Context, tenantID string, hash domain.Hash, opts LineageOptions) (LineageResult, error) {
	if q == nil || q.Manifests == nil || q.Provenance == nil {
		return LineageResult{}, errors.New("provenance query requires manifest reader and provenance repository")
	}
	if tenantID == "" || hash.Alg == "" || hash.Value == "" {
		return LineageResult{}, errors.New("tenant_id and hash are required")
	}
	if opts.MaxDepth < 0 || opts.MaxNodes < 0 {
		return LineageResult{}, errors.New("invalid lineage limits")
	}

	state := lineageState{
		complete:         true,
		missingArtifacts: map[string]domain.Hash{},
		missingManifests: map[string]struct{}{},
		maxDepth:         opts.MaxDepth,
		maxNodes:         opts.MaxNodes,
		hit:              map[string]struct{}{},
	}

	if _, err := q.Provenance.GetArtifactByHash(ctx, tenantID, hash); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			state.addMissingArtifact(hash)
		} else {
			return LineageResult{}, err
		}
	}

	generatorIDs, err := q.Provenance.ListGeneratedManifestIDs(ctx, tenantID, hash)
	if err != nil {
		return LineageResult{}, err
	}
	sort.Strings(generatorIDs)

	manifests := make([]LineageManifest, 0, len(generatorIDs))
	maxDepth := 0
	for _, manifestID := range generatorIDs {
		node, depth, err := q.buildLineage(ctx, tenantID, manifestID, 0, map[string]bool{}, &state)
		if err != nil {
			return LineageResult{}, err
		}
		if node != nil {
			manifests = append(manifests, *node)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
	}
	if len(generatorIDs) == 0 {
		state.complete = false
	}

	return LineageResult{
		TenantID:     tenantID,
		ArtifactHash: hash,
		Depth:        maxDepth,
		Complete:     state.complete,
		Truncated:    state.truncated,
		Limits: LineageLimits{
			MaxDepth: opts.MaxDepth,
			MaxNodes: opts.MaxNodes,
			Hit:      state.hitList(),
		},
		GeneratingManifests: manifests,
		MissingArtifacts:    state.missingArtifactsList(),
		MissingManifests:    state.missingManifestsList(),
	}, nil
}

func (q *ProvenanceQuery) buildLineage(ctx context.Context, tenantID, manifestID string, depth int, stack map[string]bool, state *lineageState) (*LineageManifest, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if stack[manifestID] {
		state.complete = false
		return nil, 0, nil
	}
	if state.maxNodes > 0 && state.nodesVisited >= state.maxNodes {
		state.truncate("max_nodes")
		return nil, 0, nil
	}

	stack[manifestID] = true
	defer delete(stack, manifestID)

	env, err := q.Manifests.GetEnvelopeByManifestID(ctx, tenantID, manifestID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			state.addMissingManifest(manifestID)
			return nil, 0, nil
		}
		return nil, 0, err
	}

	inputs := sortedInputs(env.Manifest.Inputs)
	lineageInputs := make([]LineageInput, 0, len(inputs))
	maxDepth := 0
	state.nodesVisited++
	noTraversal := state.maxDepth == 0
	depthLimitReached := state.maxDepth > 0 && depth >= state.maxDepth
	for _, input := range inputs {
		if input.Hash.Alg == "" || input.Hash.Value == "" {
			state.complete = false
			continue
		}
		if _, err := q.Provenance.GetArtifactByHash(ctx, tenantID, input.Hash); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				state.addMissingArtifact(input.Hash)
			} else {
				return nil, 0, err
			}
		}

		generatorIDs, err := q.Provenance.ListGeneratedManifestIDs(ctx, tenantID, input.Hash)
		if err != nil {
			return nil, 0, err
		}
		sort.Strings(generatorIDs)
		if len(generatorIDs) == 0 {
			state.complete = false
		}

		generators := make([]LineageManifest, 0, len(generatorIDs))
		childDepth := 0
		if noTraversal {
			if len(generatorIDs) > 0 {
				state.truncate("max_depth")
			}
		} else if depthLimitReached {
			if len(generatorIDs) > 0 {
				state.truncate("max_depth")
			}
		} else {
			for _, genID := range generatorIDs {
				child, depth, err := q.buildLineage(ctx, tenantID, genID, depth+1, stack, state)
				if err != nil {
					return nil, 0, err
				}
				if child != nil {
					generators = append(generators, *child)
					if depth > childDepth {
						childDepth = depth
					}
				}
			}
		}
		if len(generators) > 1 {
			state.complete = false
		}
		if len(generators) > 0 {
			if childDepth+1 > maxDepth {
				maxDepth = childDepth + 1
			}
		}

		lineageInputs = append(lineageInputs, LineageInput{
			Hash:       input.Hash,
			Generators: generators,
		})
	}

	node := &LineageManifest{
		ManifestID:  manifestID,
		SubjectHash: env.Manifest.Subject.Hash,
		Inputs:      lineageInputs,
	}
	return node, maxDepth, nil
}

func (q *ProvenanceQuery) Derivation(ctx context.Context, tenantID, manifestID string, opts LineageOptions) (DerivationView, error) {
	if q == nil || q.Manifests == nil {
		return DerivationView{}, errors.New("provenance query requires manifest reader")
	}
	if tenantID == "" || manifestID == "" {
		return DerivationView{}, errors.New("tenant_id and manifest_id are required")
	}
	if opts.MaxDepth < 0 || opts.MaxNodes < 0 {
		return DerivationView{}, errors.New("invalid derivation limits")
	}

	env, err := q.Manifests.GetEnvelopeByManifestID(ctx, tenantID, manifestID)
	if err != nil {
		return DerivationView{}, err
	}

	inputs := make([]domain.Hash, 0, len(env.Manifest.Inputs))
	for _, input := range sortedInputs(env.Manifest.Inputs) {
		if input.Hash.Alg == "" || input.Hash.Value == "" {
			continue
		}
		inputs = append(inputs, input.Hash)
	}
	sort.Slice(inputs, func(i, j int) bool {
		return hashKey(&inputs[i]) < hashKey(&inputs[j])
	})

	outputs := []domain.Hash{env.Manifest.Subject.Hash}
	truncated := false
	hit := map[string]struct{}{}

	if opts.MaxDepth == 0 && len(inputs) > 0 {
		truncated = true
		hit["max_depth"] = struct{}{}
		inputs = nil
	}

	if opts.MaxNodes > 0 {
		capacity := opts.MaxNodes - len(outputs)
		if capacity < 0 {
			capacity = 0
		}
		if len(inputs) > capacity {
			truncated = true
			hit["max_nodes"] = struct{}{}
			inputs = inputs[:capacity]
		}
	}

	return DerivationView{
		ManifestID: env.Manifest.ManifestID,
		TenantID:   env.Manifest.TenantID,
		Schema:     env.Manifest.Schema,
		Tool:       env.Manifest.Tool,
		Actor:      env.Manifest.Actor,
		Time:       env.Manifest.Time,
		SignerKID:  strings.TrimSpace(env.Signature.KID),
		Inputs:     inputs,
		Outputs:    outputs,
		Truncated:  truncated,
		Limits: LineageLimits{
			MaxDepth: opts.MaxDepth,
			MaxNodes: opts.MaxNodes,
			Hit:      hitList(hit),
		},
	}, nil
}

type lineageState struct {
	complete         bool
	missingArtifacts map[string]domain.Hash
	missingManifests map[string]struct{}
	hit              map[string]struct{}
	nodesVisited     int
	maxDepth         int
	maxNodes         int
	truncated        bool
}

func (s *lineageState) addMissingArtifact(hash domain.Hash) {
	if s.missingArtifacts == nil {
		s.missingArtifacts = map[string]domain.Hash{}
	}
	s.complete = false
	s.missingArtifacts[hashKey(&hash)] = hash
}

func (s *lineageState) addMissingManifest(manifestID string) {
	if s.missingManifests == nil {
		s.missingManifests = map[string]struct{}{}
	}
	s.complete = false
	s.missingManifests[manifestID] = struct{}{}
}

func (s *lineageState) truncate(reason string) {
	s.truncated = true
	s.complete = false
	if s.hit == nil {
		s.hit = map[string]struct{}{}
	}
	s.hit[reason] = struct{}{}
}

func (s *lineageState) missingArtifactsList() []domain.Hash {
	if len(s.missingArtifacts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(s.missingArtifacts))
	for key := range s.missingArtifacts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]domain.Hash, 0, len(keys))
	for _, key := range keys {
		out = append(out, s.missingArtifacts[key])
	}
	return out
}

func (s *lineageState) missingManifestsList() []string {
	if len(s.missingManifests) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.missingManifests))
	for id := range s.missingManifests {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (s *lineageState) hitList() []string {
	return hitList(s.hit)
}

func hitList(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
