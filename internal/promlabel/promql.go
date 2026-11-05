package promlabel

import (
	"fmt"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/promql/parser"
)

// promqlEnforcer applies an injectproxy.PromQLEnforcer to every selector of a
// query. PromQLEnforcer.Enforce isn't used because its walk skips aggregation
// parameters, which leaves the inner selector of topk(scalar(x), y) unenforced.
// parser.Inspect reaches every node, and panics on a type it doesn't know
// rather than passing over it.
type promqlEnforcer struct {
	matchers *injectproxy.PromQLEnforcer
	parser   parser.Parser
}

func newPromQLEnforcer(s Scope) (*promqlEnforcer, error) {
	matchers, err := s.matchers()
	if err != nil {
		return nil, err
	}
	return &promqlEnforcer{
		matchers: injectproxy.NewPromQLEnforcer(true, matchers...),
		// Every language option is on: this parse only has to find the
		// selectors, and the backend decides what it actually accepts.
		parser: parser.NewParser(parser.Options{
			EnableExperimentalFunctions:  true,
			ExperimentalDurationExpr:     true,
			EnableExtendedRangeSelectors: true,
			EnableBinopFillModifiers:     true,
		}),
	}, nil
}

func (e *promqlEnforcer) enforce(query string) (string, error) {
	expr, err := e.parser.ParseExpr(query)
	if err != nil {
		return "", fmt.Errorf("%w: %w", injectproxy.ErrQueryParse, err)
	}
	var failed error
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		if vs, ok := node.(*parser.VectorSelector); ok {
			vs.LabelMatchers, failed = e.matchers.EnforceMatchers(vs.LabelMatchers)
		}
		return failed
	})
	if failed != nil {
		return "", failed
	}
	return expr.String(), nil
}
