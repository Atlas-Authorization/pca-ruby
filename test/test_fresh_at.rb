# frozen_string_literal: true

# The `fresh_at` PCActn member (consistency token) against the shared vectors (packages/pca/conformance/fresh-at-vectors.json):
# allow, the core checks, the `fresh_at` status, the decision and (outside wire failures, whose text the core verifier does
# not carry) the `fresh_at` reason.
#   ruby -Ilib test/test_fresh_at.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestFreshAt < Minitest::Test
  FILE = File.expand_path('../conformance/fresh-at-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_the_corpus_is_complete
    assert_equal 28, DOC['vectors'].length
  end

  def run_vector(c)
    ctx = c['context']
    AtlasPca.verify_pcactn(c['pcactn'], c['grant'], now: ctx['now'], audience: ctx['aud'], fresh_at: ctx['fresh_at'])
  end

  def test_every_vector
    bad = []
    DOC['vectors'].each do |c|
      v = run_vector(c)
      e = c['expect']
      status = v.checks.key?('fresh_at') ? (v.checks['fresh_at'] ? 'pass' : 'fail') : 'absent'
      core = v.checks.reject { |k, _| k == 'fresh_at' }
      decision = AtlasPca.decision_of({ 'allow' => v.allow, 'reasons' => v.reasons,
                                        'checks' => v.checks.transform_values { |ok| ok ? 'pass' : 'fail' } })
      got = { 'allow' => v.allow, 'checks' => core, 'fresh_at' => status, 'decision' => decision }
      want = e.reject { |k, _| k == 'reason' }
      bad << "#{c['name']}: got #{got.inspect} want #{want.inspect}" if got != want
      next unless e['reason']&.start_with?('fresh_at:')

      bad << "#{c['name']}: reason #{v.reason.inspect} want #{e['reason'].inspect}" if v.reason != e['reason']
    end
    assert_equal [], bad
  end

  def test_every_check_name_is_in_the_documented_order
    names = DOC['vectors'].flat_map { |c| run_vector(c).checks.keys }.uniq
    assert_equal DOC['check_order'].sort, names.sort
  end
end
