# frozen_string_literal: true

# Replays the ceremony and provenance fns of the TS-reference zk oracle (test-data/ref-zk.json.gz): vkId, circuitProvenance,
# checkCircuitProvenance, transcriptSha256, checkTranscript (with its structural sweep of a valid transcript) and ceremonyOf.
# Only these fns are replayed here (the corpus also carries the verifier's); a member an argument object does not have is an
# option not given. A reference throw must be a native raise.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefZkCeremony < Minitest::Test
  C = AtlasPca::ZkCeremony
  BY_FN = Ref.load('zk')

  def self.kw(h, map) = map.each_with_object({}) { |(k, s), out| out[s] = h[k] if h.is_a?(Hash) && h.key?(k) }

  PROV = { 'circuit' => :circuit, 'sourceSha256' => :source_sha256, 'r1csSha256' => :r1cs_sha256, 'vkey' => :vkey }.freeze
  OPTS = { 'minContributions' => :min_contributions, 'r1csSha256' => :r1cs_sha256, 'circuit' => :circuit }.freeze

  # fn => [handler, case count]
  HANDLERS = {
    'vkId' => [->(vkey) { C.vk_id(vkey) }, 10],
    'circuitProvenance' => [->(a) { C.circuit_provenance(circuit: nil, source_sha256: nil, r1cs_sha256: nil, vkey: C::ABSENT, **kw(a, PROV)) }, 13],
    'checkCircuitProvenance' => [->(prov, e) { C.check_circuit_provenance(prov, circuit: nil, source_sha256: nil, vkey: nil, **kw(e, PROV)) }, 19],
    'transcriptSha256' => [->(t) { C.transcript_sha256(t) }, 3],
    'checkTranscript' => [->(t, opts = nil) { C.check_transcript(t, **kw(opts, OPTS)) }, 257],
    'ceremonyOf' => [->(vkey, evidence = nil) { C.ceremony_of(vkey, evidence) }, 19]
  }.freeze

  HANDLERS.each do |fn, (handler, count)|
    define_method("test_replay_#{fn}") do
      cases = BY_FN.fetch(fn)
      assert_equal count, cases.length
      # a provenance record without its circuit member has no JSON null for it
      Ref.run(self, cases, handler, compare: ->(got, out, _c) { Ref.canon(got.is_a?(Hash) ? got.compact : got) == Ref.canon(out) })
    end
  end

  def test_a_transcript_names_its_key_or_the_ceremony_is_single_party
    c = BY_FN['ceremonyOf'].find { |x| x['name'] == 'ceremonyOf/multi-party' }
    vkey, evidence = c['args']
    assert_equal 'multi-party', C.ceremony_of(vkey, evidence)
    assert_equal 'single-party', C.ceremony_of(vkey.merge('nPublic' => 14), evidence)
    assert_equal 'single-party', C.ceremony_of(vkey, evidence.merge('sha256' => '0' * 64))
    assert_equal 'single-party', C.ceremony_of(vkey)
    assert_equal 'single-party', C.ceremony_of(nil, evidence)
    assert_equal C.vk_id(vkey), evidence['transcript']['vkId']
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1429, BY_FN.values.sum(&:length), 'zk'
  end

end
