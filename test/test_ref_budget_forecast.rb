# frozen_string_literal: true

# Replays the TS-reference oracle of the budget forecaster (test-data/ref-budget-forecast.json.gz, 326 cases): forecast over a
# policy compiled from {permissions, limits?, budgetModel?, riskPolicy?, now} (start null = not given; a catalog is given as
# define_action specs, null = the built-in one), recommendPolicy (kappa null = not given) and autonomyBoundOf. Every fn has a
# handler and the total is asserted. {"$num": ...} is a non-finite number.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefBudgetForecast < Minitest::Test
  A = AtlasPca
  F = AtlasPca::BudgetForecast
  C = AtlasPca::Catalog
  BY_FN = Ref.load('budget-forecast')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.compile(sp)
    A.compile_policy(sp['permissions'], sp['limits'], budget_model: sp['budgetModel'], risk_policy: sp['riskPolicy'], now: sp['now'])
  end

  HANDLERS = {
    'forecast' => lambda { |spec, plan, start, actions|
      F.forecast(compile(spec), plan, start: start, catalog: actions.nil? ? nil : C.build_catalog(actions.map { |a| C.define_action(a) }))
    },
    'recommendPolicy' => ->(n, r, kappa) { F.recommend_policy(n, r, kappa: kappa) },
    'autonomyBoundOf' => ->(p) { F.autonomy_bound_of(p) }
  }.freeze

  def test_every_fn_of_the_corpus_has_a_handler
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal 326, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| self.class.dnum(a) }) })
    end
  end
end
