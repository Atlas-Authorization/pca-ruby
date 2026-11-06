# frozen_string_literal: true

# Provenance by default: replays packages/pca/conformance/arg-provenance-vectors.json (tokens, leaves, read_only, decisions; a
# missing file fails) and checks the recorder byte for byte against the generator's principal-direct bundle.
#   ruby -Ilib test/test_arg_provenance_vectors.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'digest'

class TestArgProvenanceVectors < Minitest::Test
  FILE = File.expand_path('../conformance/arg-provenance-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  NOW = 1_793_188_800_000 # Date.UTC(2026, 9, 28, 12, 0, 0), the generator's clock

  def seed(label) = Digest::SHA256.digest("atlas-pca-conformance/arg-provenance/#{label}")

  def test_format_and_sizes
    assert_equal 'pca-arg-provenance-vectors/1', DOC['format']
    assert_equal [18, 11, 7, 38], %w[tokens leaves read_only decisions].map { |k| DOC[k].length }
  end

  def test_tokens
    DOC['tokens'].each { |t| assert_equal t['expect'], AtlasPca.occurs_as_token(t['text'], t['needle']), t.inspect }
  end

  def test_leaves
    DOC['leaves'].each { |l| assert_equal l['expect'], AtlasPca.prov_leaves(l['value']), l['name'] }
  end

  def test_read_only
    DOC['read_only'].each { |r| assert_equal r['expect'], AtlasPca.read_only_action?(r['action']), r['name'] }
  end

  DOC['decisions'].each do |d|
    define_method("test_decision_#{d['name'].tr('-', '_')}") do
      got = AtlasPca.decide_arg_provenance(d['input'])
      e = d['expect']
      if e['outcome'] == 'deny'
        # a deny is compared by code; its reason text is free but never empty
        assert_equal e.reject { |k, _| k == 'reason' }, got.reject { |k, _| k == 'reason' }, d['name']
        assert_kind_of String, got['reason']
        refute_empty got['reason'], d['name']
      else
        assert_equal e, got, d['name'] # escalate (with its exact reason) and pass compare the whole object
      end
    end
  end

  def test_recorder_reproduces_the_principal_direct_bundle
    rec = AtlasPca::ProvenanceRecorder.new(mediator: 'assistant-harness', kid: 'k1', key: AtlasPca::KeyPair.new(seed('key/harness')),
                                           session: AtlasPca.b64e(seed('session/harness')), now: -> { NOW })
    assert_equal DOC['pin'], rec.pin
    op = { verb: 'payments.send', resource: 'bank', params: { iban: 'DE89370400440532013000', amount: 120 } }
    want = DOC['decisions'].find { |x| x['name'] == 'principal-direct' } || flunk('principal-direct vector missing')
    assert_equal AtlasPca.canon_bytes(want['input']['bundle']), AtlasPca.canon_bytes(AtlasPca.principal_direct_provenance(rec, op))
  end
end
