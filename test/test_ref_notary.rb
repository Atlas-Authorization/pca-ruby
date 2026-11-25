# frozen_string_literal: true

# Replays the TS-reference oracle of the notary attestation module (test-data/ref-notary.json.gz): body commitment, selective
# disclosure, PCActn binding, the attested_fact caveat and notary key rings.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/notary'
require 'minitest/autorun'
require 'digest'

class TestRefNotary < Minitest::Test
  N = AtlasPca::Notary
  BY_FN = Ref.load('notary')

  # a caught runtime error's text after "(fail closed): " is the language's own message: compare up to the marker
  def self.fail_closed(v)
    case v
    when String then (i = v.index('(fail closed): ')) ? v[0, i + 15] : v
    when Hash then v.transform_values { |x| fail_closed(x) }
    when Array then v.map { |x| fail_closed(x) }
    else v
    end
  end

  COMPARE = ->(got, out, _case) { Ref.canon(fail_closed(got)) == Ref.canon(fail_closed(out)) }

  def self.bytes(v) = v.is_a?(String) && v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v

  # the reference replaces randomBytes with sha256("notary-oracle-salt/" + i)[0, k], restarting at 0 on every call
  def self.notarize(inp, opts)
    n = 0
    rb = lambda do |k|
      d = Digest::SHA256.digest("notary-oracle-salt/#{n}")[0, k]
      n += 1
      d
    end
    N.notarize_response(inp['request'], inp['response'], opts['notaryKey'],
                        { 'observed_at' => opts['observedAt'], 'text_chunk_size' => opts['textChunkSize'], 'random_bytes' => rb })
  end

  def self.require_fact(o)
    opts = {}
    opts['url'] = o['url'] if o.key?('url')
    opts['bind_to_pc_actn'] = o['bindToPcActn'] if o.key?('bindToPcActn')
    N.require_attested_fact(o['notary'], o['path'], o['equals'], opts)
  end

  MAP = {
    'constants' => -> { { 'BODY_COMMIT_ALG' => N::BODY_COMMIT_ALG, 'ATTESTED_FACT_CAVEAT' => N::ATTESTED_FACT_CAVEAT } },
    'notaryMessage' => ->(s) { bytes(N.notary_message(s)) },
    'notarizeResponse' => ->(inp, opts) { notarize(inp, opts) },
    'discloseField' => N.method(:disclose_field),
    'verifyNotaryAttestation' => N.method(:verify_notary_attestation),
    'verifyDisclosedField' => N.method(:verify_disclosed_field),
    'factRef' => N.method(:fact_ref),
    'bindFactToPcActn' => N.method(:bind_fact_to_pc_actn),
    'factMatchesPcActn' => N.method(:fact_matches_pc_actn),
    'requireAttestedFact' => ->(o) { require_fact(o) },
    'isAttestedFactCaveat' => N.method(:attested_fact_caveat?),
    'notaryKeyUsable' => N.method(:notary_key_usable),
    'evaluateAttestedFactCaveat' => ->(c, e, *policy) { N.evaluate_attested_fact_caveat(c, e, *policy) }
  }.freeze

  def test_corpus_is_the_full_oracle
    assert_equal 1752, BY_FN.values.sum(&:length)
    assert_equal [], BY_FN.keys.sort - MAP.keys.sort
    assert_equal [], MAP.keys.sort - BY_FN.keys.sort
  end

  MAP.each do |fn, call|
    define_method("test_matches_the_reference_#{fn}") { Ref.run(self, BY_FN[fn], call, compare: COMPARE) }
  end
end
