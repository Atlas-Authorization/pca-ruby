# frozen_string_literal: true

# Rules 20 and 21 end to end through authorize(), against the TypeScript reference's signed cases
# (packages/pca/conformance/model-rules-vectors.json): the decision, status, failing checks, reasons (in pipeline order),
# the units / tighten check statuses and the degraded legacy-polarity note.
#   ruby -Ilib test/test_model_rules.rb
require_relative '../lib/atlas_pca'
require_relative 'support/prov_harness'
require 'minitest/autorun'

class TestModelRules < Minitest::Test
  FILE = File.expand_path('../conformance/model-rules-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def run_case(c)
    ctx_env = c['context']
    AtlasPca.authorize(c['pcactn'], operation: c['operation'], audience: DOC['audience'], resolve_grant: ->(_r) { c['grant'] },
                                    state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: DOC['now'],
                                    plan: 'single-step', context: ctx_env.nil? ? nil : ->(_p) { ctx_env },
                                    intent_v2: c.key?('intent_v2') ? c['intent_v2'] : nil,
                                    provenance: ProvHarness::OPTION) # the reference harness's principal-direct bundle (gate on)
  end

  def test_the_corpus_is_complete
    assert_equal 32, DOC['cases'].length
  end

  def test_every_case
    bad = []
    DOC['cases'].each do |c|
      r = run_case(c)
      e = c['expect']
      got = { 'allow' => r.allow, 'decision' => r.decision, 'status' => r.status, 'failed' => r.failed_checks, 'reasons' => r.reasons }
      want = e.reject { |k, _| %w[units tighten degraded].include?(k) }
      %w[units tighten].each { |k| (want[k] = e[k]; got[k] = r.checks[k]) if e.key?(k) }
      (want['degraded'] = e['degraded']; got['degraded'] = r.degraded) if e.key?('degraded')
      got['tighten'] = r.checks['tighten'] if e.key?('tighten')
      bad << "#{c['name']}: got #{got.inspect} want #{want.inspect}" if got != want
      bad << "#{c['name']}: unexpected tighten/units check #{r.checks.inspect}" if !e.key?('tighten') && r.checks.key?('tighten')
      bad << "#{c['name']}: unexpected units check" if !e.key?('units') && r.checks.key?('units')
    end
    assert_equal [], bad.first(15)
  end
end
