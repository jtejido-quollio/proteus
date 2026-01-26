package policyopa

import "github.com/open-policy-agent/opa/ast"

var allowedBuiltins = map[string]struct{}{
	"abs":             {},
	"ceil":            {},
	"concat":          {},
	"contains":        {},
	"count":           {},
	"eq":              {},
	"equal":           {},
	"endswith":        {},
	"floor":           {},
	"format_int":      {},
	"format_number":   {},
	"json.marshal":    {},
	"json.unmarshal":  {},
	"lower":           {},
	"max":             {},
	"min":             {},
	"neq":             {},
	"object.get":      {},
	"object.remove":   {},
	"object.union":    {},
	"pow":             {},
	"replace":         {},
	"round":           {},
	"sort":            {},
	"split":           {},
	"sprintf":         {},
	"startswith":      {},
	"substring":       {},
	"sum":             {},
	"trim":            {},
	"trim_left":       {},
	"trim_right":      {},
	"upper":           {},
	"urlquery.decode": {},
	"urlquery.encode": {},
}

func filterBuiltins(builtins []*ast.Builtin) []*ast.Builtin {
	allowed := make([]*ast.Builtin, 0, len(builtins))
	for _, builtin := range builtins {
		if _, ok := allowedBuiltins[builtin.Name]; !ok {
			continue
		}
		allowed = append(allowed, builtin)
	}
	return allowed
}
