# frozen_string_literal: true

# Replays the TS-reference oracle of the testing kit (test-data/ref-testing.json.gz): acceptance constants and route mapping, the fake
# verifier, tamper and the in-memory state store.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/testing'
require 'minitest/autorun'

class TestRefTesting < Minitest::Test
  T = AtlasPca::Testing
  BY_FN = Ref.load('testing')

  def self.apply(rec, m)
    return if m['op'] == 'none'

    cur = rec
    m['path'][0...-1].each { |k| cur = cur[k] }
    if m['op'] == 'set'
      cur[m['path'].last] = m['value']
    else
      cur.delete(m['path'].last)
    end
  end

  def self.session(ops)
    s = T.memory_state_store
    out = []
    ops.each do |op, key, st|
      if op == 'put'
        s.put(key, st)
      else
        out << s.get(key)
      end
    end
    out
  end

  def self.opts(o) = o.to_h { |k, v| [k.to_sym, v] }

  MAP = {
    'consts' => -> { { 'aud' => T::ADAPTER_ACCEPTANCE_AUDIENCE, 'expected' => T::ADAPTER_ACCEPTANCE_EXPECTED } },
    'acceptanceOperation' => ->(r) { T.acceptance_operation(r) },
    'fakeVerifyAllow' => ->(p, o) { T.fake_verify(p, **opts(o)).allow },
    'expectVerifies' => ->(p, o) { T.expect_verifies(p, **opts(o)).allow },
    'expectDenied' => ->(p, o) { T.expect_denied(p, **opts(o)).allow },
    'tamper' => ->(e, m) { T.tamper(e) { |rec| apply(rec, m) } },
    'memorySession' => ->(ops) { session(ops) }
  }.freeze

  def test_corpus_is_the_full_oracle
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_matches_the_reference_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2594, BY_FN.values.sum(&:length), 'testing'
  end

end
