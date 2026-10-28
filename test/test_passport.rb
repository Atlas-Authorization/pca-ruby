# frozen_string_literal: true

# Replays packages/pca/conformance/passport-vectors.json (signed agent passport) against the native verifier: every signature
# suite available in this runtime (an unavailable one must answer `unsupported_suite`), and the hardware branch through a stub
# vendor verifier that answers what the vector says.
#   ruby -Ilib test/test_passport.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'json'

class TestPassport < Minitest::Test
  FILE = File.expand_path('../conformance/passport-vectors.json', __dir__)

  def test_vectors
    vs = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)['passport_vectors']
    assert_operator vs.length, :>=, 74
    supported = AtlasPca.supported_suites
    docs = {}
    bad = []
    pq_seen = 0
    vs.each do |v|
      signed = v.key?('signed_ref') ? docs[v['signed_ref']] : v['signed']
      docs[v['name']] = signed
      revoked = v['revoked']
      seen = []
      attest = nil
      if v.key?('hardware')
        h = v['hardware']
        attest = lambda do |_doc, expected|
          seen << expected
          raise 'verifier down' if h['throws']

          { 'ok' => h['ok'], 'bound' => h['bound'], 'measured' => h['measured'] }
        end
      end
      got = AtlasPca.verify_passport(signed, v['trustedIssuers'], v['now'], clock_skew_ms: v['clockSkewMs'],
                                     max_evidence_age_ms: v['maxEvidenceAgeMs'], subject: v['subject'],
                                     revoked: ->(i, _a, _b) { revoked.include?(i) }, pq_pins: v['pqPins'], attest: attest)
      want = v['expect']['ok'] ? nil : v['expect']['reason']
      alg = signed.is_a?(Hash) ? signed['alg'] : nil
      unless alg.nil?
        if supported.include?(alg)
          pq_seen += 1
        else
          want = 'unsupported_suite'
        end
      end
      bad << "#{v['name']}: got #{got.inspect} want #{want.inspect}" if got != want
      next unless v.key?('expectBinding')

      eb = v['expectBinding']
      want_b = { 'holder_pub' => eb['holderPub'], 'grant_ref' => eb['grantRef'], 'epoch' => eb['epoch'], 'nonce' => eb['nonce'] }
      bad << "#{v['name']}: verifier was handed #{seen.inspect} want #{want_b.inspect}" if seen != [want_b]
    end
    # a runtime that only adds suites no vector signs with (e.g. LESS) replays none of them
    covered = vs.filter_map { |v| v['signed']['alg'] if v['signed'].is_a?(Hash) }
    assert_operator pq_seen, :>=, 1 if (supported & covered).any? { |s| s != 'ed25519' }
    assert_equal [], bad
  end

  def test_total_on_garbage
    [nil, 5, 'x', [], {}, { 'typ' => 'atlas-pca/passport' }].each do |g|
      assert_equal 'malformed', AtlasPca.verify_passport(g, ['i'], 1, revoked: ->(*) { false })
    end
  end
end
