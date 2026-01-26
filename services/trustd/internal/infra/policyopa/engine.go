package policyopa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"proteus/internal/domain"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

const defaultQuery = "data.proteus.policy.result"

type Engine struct {
	query      rego.PreparedEvalQuery
	bundleHash string
	bundleID   string
}

func NewEngineFromBundlePath(ctx context.Context, bundlePath string, bundleID string) (*Engine, error) {
	bundleHash, err := ComputeBundleHashFromPath(bundlePath)
	if err != nil {
		return nil, err
	}

	capabilities := ast.CapabilitiesForThisVersion()
	capabilities.Builtins = filterBuiltins(capabilities.Builtins)
	compiler := ast.NewCompiler().WithCapabilities(capabilities)

	r := rego.New(
		rego.Query(defaultQuery),
		rego.Compiler(compiler),
		rego.StrictBuiltinErrors(true),
		rego.Load([]string{bundlePath}, nil),
	)
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	if err := assertNoForbiddenBuiltins(compiler); err != nil {
		return nil, err
	}

	return &Engine{
		query:      prepared,
		bundleHash: bundleHash,
		bundleID:   bundleID,
	}, nil
}

func (e *Engine) BundleHash() string {
	return e.bundleHash
}

func (e *Engine) Evaluate(ctx context.Context, input domain.PolicyInput) (domain.PolicyEvaluation, error) {
	if e == nil {
		return domain.PolicyEvaluation{}, errors.New("policy engine is nil")
	}
	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return domain.PolicyEvaluation{}, err
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return domain.PolicyEvaluation{}, errors.New("empty policy result")
	}
	raw := results[0].Expressions[0].Value
	result, err := decodePolicyResult(raw)
	if err != nil {
		return domain.PolicyEvaluation{}, err
	}
	normalizePolicyResult(&result)
	return domain.PolicyEvaluation{
		BundleID:   e.bundleID,
		BundleHash: e.bundleHash,
		Result:     result,
	}, nil
}

func decodePolicyResult(value any) (domain.PolicyResult, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return domain.PolicyResult{}, err
	}
	var result domain.PolicyResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return domain.PolicyResult{}, err
	}
	return result, nil
}

func normalizePolicyResult(result *domain.PolicyResult) {
	if result == nil {
		return
	}
	sort.Slice(result.Deny, func(i, j int) bool {
		if result.Deny[i].Code == result.Deny[j].Code {
			return result.Deny[i].Message < result.Deny[j].Message
		}
		return result.Deny[i].Code < result.Deny[j].Code
	})
}

func assertNoForbiddenBuiltins(compiler *ast.Compiler) error {
	if compiler == nil {
		return errors.New("policy compiler is nil")
	}
	forbidden := make(map[string]struct{})
	for _, module := range compiler.Modules {
		ast.WalkTerms(module, func(term *ast.Term) bool {
			call, ok := term.Value.(ast.Call)
			if !ok || len(call) == 0 || call[0] == nil {
				return false
			}
			name := call[0].Value.String()
			if _, ok := ast.BuiltinMap[name]; !ok {
				return false
			}
			if _, ok := allowedBuiltins[name]; ok {
				return false
			}
			forbidden[name] = struct{}{}
			return false
		})
	}
	if len(forbidden) == 0 {
		return nil
	}
	names := make([]string, 0, len(forbidden))
	for name := range forbidden {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Errorf("forbidden builtins: %s", strings.Join(names, ", "))
}
