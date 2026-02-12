// Package payloads provides attack payload generation
package payloads

import (
	"context"
	"net/http"
	"sync"

	"github.com/su1ph3r/indago/pkg/types"
)

// PassiveChecker runs endpoint-level checks that don't fit the per-parameter
// AttackGenerator model. Each checker sends real HTTP requests and produces
// findings directly.
type PassiveChecker interface {
	// Check runs the passive check against the endpoint and returns findings.
	Check(ctx context.Context, endpoint types.Endpoint, client *http.Client) []types.Finding
	// Type returns the checker identifier.
	Type() string
}

// PassiveCheckRunner coordinates multiple PassiveCheckers across endpoints.
type PassiveCheckRunner struct {
	checkers []PassiveChecker
}

// NewPassiveCheckRunner creates a new runner with no checkers registered.
func NewPassiveCheckRunner() *PassiveCheckRunner {
	return &PassiveCheckRunner{}
}

// Register adds a passive checker.
func (r *PassiveCheckRunner) Register(checker PassiveChecker) {
	r.checkers = append(r.checkers, checker)
}

// RunAll runs every registered checker against every endpoint, limiting
// concurrency to 5 endpoint checks at a time.
func (r *PassiveCheckRunner) RunAll(ctx context.Context, endpoints []types.Endpoint, client *http.Client) []types.Finding {
	var (
		mu       sync.Mutex
		findings []types.Finding
		wg       sync.WaitGroup
		sem      = make(chan struct{}, 5)
	)

	for _, ep := range endpoints {
		wg.Add(1)
		go func(endpoint types.Endpoint) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			for _, checker := range r.checkers {
				if ctx.Err() != nil {
					return
				}
				results := checker.Check(ctx, endpoint, client)
				if len(results) > 0 {
					mu.Lock()
					findings = append(findings, results...)
					mu.Unlock()
				}
			}
		}(ep)
	}

	wg.Wait()
	return findings
}
