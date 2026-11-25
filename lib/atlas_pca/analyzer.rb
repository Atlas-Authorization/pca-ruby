# frozen_string_literal: true

# Static analyzability of authority (port of the TypeScript reference, @atlasauth/pca-analyzer): what can this whole delegated authority
# EVER do? The bounded decision engine, relational queries, quantitative exposure, residual policies, data filters, narrowing, coverage,
# minimal-flip counterfactuals, schema validation and the policy test runner. Policies and results are plain JSON trees.
#
# `Analyzer.admits_concrete(policy, action)` is the exact admission check the AuthZEN PDP takes as its injected `admits_concrete`
# callable; `Analyzer.decide_action(Analyzer.to_model(policy), action)` yields the ternary decision ('allow' | 'escalate' | 'deny').
require_relative 'analyzer_js'
require_relative 'analyzer_core'
require_relative 'analyzer_exposure'
require_relative 'analyzer_coverage'
require_relative 'analyzer_residual'
require_relative 'analyzer_narrowing'
require_relative 'analyzer_validate'
