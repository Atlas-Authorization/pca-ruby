# frozen_string_literal: true

# Differential replay of the capability ratchet and risk accumulator against the TS-reference oracle
# (test-data/ref-ratchet.json.gz), an independent ristretto255 known-answer set (ref-ratchet-kat.json.gz) and prover
# roundtrips (the reference provers draw fresh randomness, so their proofs are compared by verdict).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/ratchet'
require 'minitest/autorun'

class TestRefRatchet < Minitest::Test
  R = AtlasPca::Ratchet
  A = AtlasPca::RatchetAccumulator
  GR = AtlasPca::RatchetGroup
  BY_FN = Ref.load('ratchet')
  AUTH = Digest::SHA256.digest('atlas-pca-conformance/ratchet-authority')

  # a reference bigint argument: the reference refuses a plain number where a bigint is required
  Big = Struct.new(:n)

  def self.rv(x)
    case x
    when Hash then x.size == 1 && x.key?('$bigint') ? Big.new(Integer(x['$bigint'], 10)) : x.transform_values { |v| rv(v) }
    when Array then x.map { |v| rv(v) }
    else x
    end
  end

  def self.ub(x) = x.is_a?(Big) ? x.n : x
  def self.big_out(x) = { '$bigint' => x.to_s }

  def self.need_big(b)
    raise TypeError, 'a bigint is required' unless b.is_a?(Big)

    b.n
  end

  def self.commit_risk(r, b)
    risk = ub(rv(r))
    A.as_units(risk) # the reference refuses a bad risk before it looks at the blinding
    b = rv(b)
    c = A.commit_risk(risk, need_big(b)) # a null blinding is not 'no blinding': the reference mixes it into BigInt arithmetic and throws
    { 'commitment' => c['commitment'], 'blinding' => big_out(c['blinding']) }
  end

  def self.open_commitment(c, r, b)
    b = rv(b)
    b.is_a?(Big) && A.open_commitment(c, ub(rv(r)), b.n)
  end

  def self.prove_budget(risks, blindings, b_max)
    risks = rv(risks)
    blindings = rv(blindings)
    blindings = blindings.map { |x| need_big(x) } if risks.length == blindings.length
    A.prove_budget(risks.map { |x| ub(x) }, blindings, ub(rv(b_max)))
  end

  def self.issue_risk_commitment(r, d, k = nil) = R.issue_risk_commitment(ub(rv(r)), d, k == 'short' ? ("\0".b * 3) : AUTH)

  def self.quantizer(rs)
    q = R::RiskQuantizer.new
    out = rs.map do |r|
      big_out(q.next(r))
    rescue StandardError # the reference records only that it refused
      { '$err' => true }
    end
    out << big_out(q.total_units)
  end

  def self.deep_dup(v)
    case v
    when Hash then v.transform_values { |x| deep_dup(x) }
    when Array then v.map { |x| deep_dup(x) }
    else v
    end
  end

  def self.clone_path(v, path, value)
    c = deep_dup(v)
    t = c
    path[0...-1].each do |k|
      t = if t.is_a?(Hash) then t[k]
          elsif t.is_a?(Array) && k.is_a?(Integer) && k >= 0 && k < t.length then t[k]
          end
    end
    key = path.empty? ? 'undefined' : path[-1] # the reference indexes path[-1], undefined for an empty path
    if t.is_a?(Hash)
      if value == '__DEL__'
        t.delete(key)
      else
        t[key.is_a?(String) ? key : key.to_s] = value
      end
    elsif t.is_a?(Array) && value != '__DEL__' && key.is_a?(Integer) && key >= 0 && key < t.length
      t[key] = value
    end
    c
  end

  class ThrowingStore
    def claim(_nullifier, _record) = raise('boom')
  end

  def self.scenario(spec)
    store = spec['store'] == 'throws' ? ThrowingStore.new : R.memory_spent_leaf_store
    state = nil
    root = nil
    sigs = []
    spec['ops'].map do |s|
      case s['op']
      when 'derive'
        d = R.derive_ratchet_root(s['seed'], s['depth'])
        state = d['state']
        root = d['rootCommitment']
        { 'root' => root, 'leafPubKeys' => state['leafPubKeys'], 'available' => R.available_leaves(state) }
      when 'sign'
        r = R.sign_at_leaf(state, s['leaf'], s['msg'])
        state = r['newState']
        sigs << r['signature']
        { 'signature' => r['signature'] }
      when 'avail' then R.available_leaves(state)
      when 'isAvail' then R.leaf_available?(state, s['leaf'])
      when 'verify', 'once'
        sig = sigs.fetch(s['sigRef'])
        (s['set'] || []).each { |p, v| sig = clone_path(sig, p, v) }
        rc = s['root'] == 'other' ? 'other-root' : root
        s['op'] == 'verify' ? R.verify_leaf_signature(rc, s['leaf'], s['msg'], sig) : R.verify_leaf_signature_once(rc, s['leaf'], s['msg'], sig, store)
      else raise 'bad op'
      end
    rescue StandardError => e # the reference records the error code or just that it refused
      { '$err' => e.respond_to?(:code) && e.code.is_a?(String) ? e.code : true }
    end
  end

  MAP = {
    'leafNullifier' => R.method(:leaf_nullifier),
    'counterToLeafIndex' => R.method(:counter_to_leaf_index),
    'leafIndexToCounter' => R.method(:leaf_index_to_counter),
    'leafIndexForAction' => R.method(:leaf_index_for_action),
    'riskToUnits' => ->(r) { big_out(R.risk_to_units(r)) },
    'budgetCeilingUnits' => ->(p) { big_out(R.budget_ceiling_units(p)) },
    'quantizer' => method(:quantizer),
    'ratchet' => method(:scenario),
    'commitRisk' => method(:commit_risk),
    'addCommitments' => A.method(:add_commitments),
    'openCommitment' => method(:open_commitment),
    'verifyRiskRange' => A.method(:verify_risk_range),
    'verifyBudget' => ->(s, b, p) { A.verify_budget(s, ub(rv(b)), p) },
    'verifyBoundedBudget' => ->(c, r, b, p) { A.verify_bounded_budget(c, r, ub(rv(b)), p) },
    'proveBudget' => method(:prove_budget),
    'proveRiskRange' => ->(r, b) { A.prove_risk_range(ub(rv(r)), need_big(rv(b))) },
    'issueRiskCommitment' => method(:issue_risk_commitment),
    'verifyRiskAttestation' => R.method(:verify_risk_attestation),
    'verifyAttestedBudget' => ->(i, d, k, b, p) { R.verify_attested_budget(i, d, k, ub(rv(b)), p) }
  }.freeze

  # a {"$bytes": <non-string>} argument: the shared decoder cannot represent it (the reference refuses it while decoding)
  def self.bad_bytes?(v)
    case v
    when Hash then v.size == 1 && v.key?('$bytes') ? !v['$bytes'].is_a?(String) : v.values.any? { |x| bad_bytes?(x) }
    when Array then v.any? { |x| bad_bytes?(x) }
    else false
    end
  end

  def test_corpus_is_the_full_oracle
    assert_equal 1095, BY_FN.values.sum(&:length)
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], skip: ->(c) { self.class.bad_bytes?(c['args']) }) }
  end

  # ---- independent known answers (ristretto255 and an accumulator transcript from other implementations) ----

  KAT = JSON.parse(Zlib::GzipReader.open(File.join(Ref::DATA, 'ref-ratchet-kat.json.gz'), &:read))

  def hex(b64) = Ref.b64d(b64).unpack1('H*')

  def test_base_multiples_and_generator_match_the_independent_encoding
    rs = KAT['ristretto']
    rs['baseMultiples'].each_with_index { |expected, i| assert_equal expected, GR.to_raw_bytes(GR.mul(GR::G, i)).unpack1('H*') }
    assert_equal rs['H'], GR.to_raw_bytes(GR::H).unpack1('H*')
  end

  def test_pedersen_commitments_match_the_independent_encoding
    KAT['ristretto']['pedersen'].each do |p|
      blinding = GR.le([p['b']].pack('H*'))
      assert_equal p['C'], hex(A.commit_risk(Integer(p['v'], 10), blinding)['commitment'])
    end
  end

  def test_budget_verdicts_match_the_independent_verifier
    KAT['ristretto']['budget'].each do |b|
      assert_equal b['oracle'] == '1', A.verify_budget(b['sum'], Integer(b['bMax'], 10), b['proof']), b['name']
    end
  end

  def test_recorded_transcript_verifies_and_is_bound_to_its_statement
    k = KAT['r2']
    cs = k['commitments']
    rps = k['rangeProofs']
    b_max = k['bMax']
    bp = k['budgetProof']
    total = k['sum']
    assert A.verify_risk_range(cs[0], rps[0]) && A.verify_risk_range(cs[1], rps[1])
    assert A.verify_budget(total, b_max, bp)
    assert A.verify_bounded_budget(cs, rps, b_max, bp)
    refute A.verify_risk_range(cs[1], rps[0])
    refute A.verify_budget(total, b_max + 1, bp)
    refute A.verify_bounded_budget(cs, rps + [rps[0]], b_max, bp)
  end

  # ---- provers (random coins): roundtrips ----

  def test_budget_prover_roundtrip
    risks = [30, 12]
    blindings = [11, 22]
    total = A.add_commitments(risks.zip(blindings).map { |r, b| A.commit_risk(r, b)['commitment'] })
    assert A.verify_budget(total, 42, A.prove_budget(risks, blindings, 42))
    refute A.verify_budget(total, 41, A.prove_budget(risks, blindings, 41))
  end

  def test_attested_pipeline_roundtrip
    pub = AtlasPca::KeyPair.new(AUTH).public
    iss = R.issue_risk_commitment(9, 'only', AUTH)
    items = [{ 'commitment' => iss['commitment'], 'rangeProof' => iss['rangeProof'], 'attestation' => iss['attestation'] }]
    proof = A.prove_budget([9], [iss['blinding']], 9)
    assert R.verify_attested_budget(items, ['only'], pub, 9, proof)
    refute R.verify_attested_budget(items, ['other'], pub, 9, proof)
  end
end
