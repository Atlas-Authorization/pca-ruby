# frozen_string_literal: true

# Revocation staleness (T9): replays packages/pca/conformance/staleness-vectors.json (`max_age`, `effective_reversibility`,
# `age`, `epoch`, `gate`, `membership`, `gate_ids`); a missing file fails.
#   ruby -Ilib test/test_revocation_staleness.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestRevocationStaleness < Minitest::Test
  FILE = File.expand_path('../conformance/staleness-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  GUARD = DOC['guardian_public']

  def num(v) = v == 'NaN' ? Float::NAN : v

  def policy(p)
    return nil if p.nil?

    AtlasPca::RevocationStaleness.new(max_revocation_age_ms: p['maxRevocationAgeMs'], staleness: p['staleness'],
                                      guardian_public: GUARD)
  end

  def same(name, want, got, ok_only: false)
    assert_equal want['ok'], got['ok'], "#{name}: #{got.inspect}"
    assert_equal want['reason'], got['reason'], name if !ok_only && !want['ok']
  end

  def test_corpus_is_complete
    assert_equal({ 'refresh_ms' => 60_000, 'validity_ms' => 300_000, 'irreversible_max_age_ms' => 120_000, 'skew_ms' => 60_000 },
                 DOC['constants'])
    assert_equal [15, 14, 13, 25, 28, 27, 10], %w[max_age effective_reversibility age epoch gate membership gate_ids].map { |k| DOC[k].length }
  end

  def test_max_age
    DOC['max_age'].each do |v|
      assert_equal v['max_age_ms'], AtlasPca.revocation_max_age_ms(policy(v['policy']), v['class']), v.inspect
    end
  end

  def test_effective_reversibility
    DOC['effective_reversibility'].each do |v|
      assert_equal v['effective'], AtlasPca.effective_reversibility(v['server_class'], v['signed_class']), v.inspect
    end
  end

  def test_age
    DOC['age'].each_with_index do |v, i|
      got = AtlasPca.check_revocation_age(num(v['issued_at']), v['now'], num(v['max_age_ms']), v.fetch('what', 'revocation state'))
      same("age #{i}", v['result'], got, ok_only: v['ok_only'])
    end
  end

  def test_epoch
    DOC['epoch'].each do |v|
      opts = {}
      opts[:max_age_ms] = num(v['max_age_ms']) if v.key?('max_age_ms')
      opts[:last_accepted_epoch] = v['last_accepted_epoch'] if v.key?('last_accepted_epoch')
      opts[:pcactn_epoch] = v['pcactn_epoch'] if v.key?('pcactn_epoch')
      args = [v['epoch'], v['guardian_public'], v['now']]
      args << v['grant_ref'] if v.key?('grant_ref')
      same(v['name'], v['result'], AtlasPca.check_revocation_epoch(*args, **opts), ok_only: v['ok_only'])
    end
  end

  def test_gate
    DOC['gate'].each do |v|
      pol = policy(v['policy'])
      pol.allow_unsigned_root_for_irreversible = true if pol && v['allow_unsigned_root_for_irreversible']
      state =
        case v['mode']
        when 'epoch' then { 'kind' => 'epoch', 'epoch' => v['epoch'] }.tap { |s| s['root'] = v['bare_root'] if v['bare_root'] }
        when 'root' then { 'kind' => 'root', 'root' => DOC['revocation_root'], 'issued_at' => v['root_issued_at'] }
        end
      got = AtlasPca.check_revocation_state(pol, state, now: v['now'], grant_ref: 'g1', signed_class: v['signed_class'],
                                                        server_class: v['server_class'], pcactn_epoch: 0, guardian_public: GUARD)
      same(v['name'], v['result'], got)
    end
  end

  def test_membership
    set = DOC['revocation_set']
    DOC['membership'].each do |v|
      assert_equal v['ok'], AtlasPca.verify_non_membership(v['root'], v['proof'], v['id']), v['name']
    end
    assert(DOC['membership'].any? { |v| v['set'] == 'main' && v['root'] == set['root'] })
    assert(DOC['membership'].any? { |v| v['set'] == 'empty' && v['root'] == set['empty_root'] })
    assert(DOC['membership'].any? { |v| v['set'] == 'one' && v['root'] == set['single']['root'] })
  end

  # The vectors' guardian signs (key: 32 bytes of 0x0b) an epoch over the main set, issued `issued`.
  def main_epoch(issued)
    set = DOC['revocation_set']
    ep = { 'instance_id' => 'i', 'grant_ref' => 'g1', 'epoch' => 0, 'set_size' => set['size'], 'root' => set['root'],
           'issued_at' => issued, 'not_after' => issued + 600_000 }
    sk = OpenSSL::PKey.new_raw_private_key('ED25519', "\x0b".b * 32)
    msg = AtlasPca::IntentV2.dmsg(AtlasPca::IntentV2::REVEPOCH_DOMAIN, ep)
    ep.merge('guardian' => AtlasPca.b64e(sk.raw_public_key), 'sig' => AtlasPca.b64e(sk.sign(nil, msg)))
  end

  def test_gate_ids
    DOC['gate_ids'].each do |v|
      ep = main_epoch(v['epoch_issued_at'])
      assert_equal GUARD, ep['guardian'], 'the test key must be the vectors guardian'
      pol = AtlasPca::RevocationStaleness.new(max_revocation_age_ms: 300_000, guardian_public: GUARD)
      got = AtlasPca.check_revocation_state(pol, { 'kind' => 'epoch', 'epoch' => ep }, now: v['now'], grant_ref: 'g1',
                                                                                         signed_class: 'costly', pcactn_epoch: 0, guardian_public: GUARD,
                                                                                         ids: v['ids'], proofs: v['proofs'])
      same(v['name'], v['result'], got)
    end
  end

  def test_authorize_every_chain_capability_needs_a_proof
    set = DOC['revocation_set']
    c = FIX['cases'].find { |x| x['name'] == 'envelope-max-spend-within' }
    chain_ids = c['steps'][0]['pcactn']['cap_chain'].map { |h| h['id'] }
    refute_empty chain_ids
    now = FIX['now']
    # a bare root issued now; the default ids are the cap_chain ids and no proof source denies
    pol = AtlasPca::RevocationStaleness.new(allow_unsigned_root_for_irreversible: true)
    st = { 'kind' => 'root', 'root' => set['empty_root'], 'issued_at' => now }
    r = run_authorize(st, pol)
    refute r.allow
    assert_equal "freshness: no non-membership proof for #{chain_ids[0]}", r.reason
    # a proof source that returns a proof of the wrong shape denies; the empty set proves every id absent
    pol = AtlasPca::RevocationStaleness.new(allow_unsigned_root_for_irreversible: true, proofs: ->(_id, _p) { { 'size' => 0 } })
    assert run_authorize(st, pol).allow
    pol = AtlasPca::RevocationStaleness.new(allow_unsigned_root_for_irreversible: true, proofs: ->(_id, _p) { { 'size' => 1 } })
    r = run_authorize(st, pol)
    refute r.allow
    assert_equal "freshness: capability #{chain_ids[0]} is revoked or proof invalid", r.reason
  end

  def test_policy_validation_is_a_construction_error
    [{ max_revocation_age_ms: -5 }, { max_revocation_age_ms: 0 }, { max_revocation_age_ms: true },
     { staleness: { 'irreversible' => 0 } }, { staleness: { 'costly' => 'x' } }, { staleness: 5 },
     { ids: [] }, { proofs: 5 }].each do |bad|
      assert_raises(ArgumentError, bad.inspect) { AtlasPca::RevocationStaleness.new(**bad) }
    end
  end

  # ---- authorize(): the staleness step ----------------------------------------------------------------------------------

  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'),
                            loose: true)

  def run_authorize(state, pol, server_class: nil)
    c = FIX['cases'].find { |x| x['name'] == 'envelope-max-spend-within' }
    st = c['steps'][0]
    ctx = {}
    ctx['reversibility_class'] = server_class if server_class
    ctx['revocation_state'] = state unless state.nil?
    AtlasPca.authorize(Marshal.load(Marshal.dump(st['pcactn'])), operation: st['operation'], audience: FIX['audience'],
                                                                 resolve_grant: ->(_r) { c['grant'] }, state_store: AtlasPca::MemoryStateStore.new,
                                                                 is_revoked: ->(_p, _g) { false }, now: FIX['now'], plan: 'single-step',
                                                                 context: ->(_p) { ctx }, revocation_staleness: pol)
  end

  def test_authorize_without_the_policy_ignores_state
    r = run_authorize({ 'kind' => 'root', 'root' => 'r', 'issued_at' => 0 }, nil)
    assert r.allow
    refute r.checks.key?('freshness')
  end

  def test_authorize_stale_root_denied_fresh_admitted
    pol = AtlasPca::RevocationStaleness.new(allow_unsigned_root_for_irreversible: true, staleness: { 'irreversible' => 10_000 },
                                            ids: ->(_p) { [] })
    now = FIX['now']
    fresh = run_authorize({ 'kind' => 'root', 'root' => 'r', 'issued_at' => now - 10_000 }, pol)
    assert fresh.allow
    assert_equal 'pass', fresh.checks['freshness']
    stale = run_authorize({ 'kind' => 'root', 'root' => 'r', 'issued_at' => now - 10_001 }, pol)
    refute stale.allow
    assert_equal 'fail', stale.checks['freshness']
    assert_equal "freshness: revocation root is 10001 ms old, over the verifier's maximum of 10000 ms (stale revocation state)", stale.reason
    unknown = run_authorize({ 'kind' => 'root', 'root' => 'r', 'issued_at' => nil }, pol)
    refute unknown.allow
    assert_equal 'freshness: revocation root age is unknown (unverifiable revocation state)', unknown.reason
    assert run_authorize(nil, pol).allow
  end

  def test_authorize_signed_epoch_for_another_grant_is_refused
    ep = DOC['gate'].find { |v| v['name'] == 'epoch-reversible-fresh' }['epoch']
    r = run_authorize({ 'kind' => 'epoch', 'epoch' => ep }, AtlasPca::RevocationStaleness.new(guardian_public: GUARD), server_class: 'irreversible')
    refute r.allow
    assert_equal 'freshness: revocation epoch is for a different grant', r.reason
  end

  def test_authorize_irreversible_needs_signed_state
    pol = AtlasPca::RevocationStaleness.new
    r = run_authorize(nil, pol)
    refute r.allow
    assert_equal 'fail', r.checks['freshness']
    assert r.reason.end_with?('no verifiable (guardian-signed) revocation state for an irreversible action')
    r = run_authorize({ 'kind' => 'root', 'root' => 'r', 'issued_at' => FIX['now'] }, pol)
    refute r.allow
    assert_includes r.reason, 'unsigned revocation root refused'
    assert run_authorize(nil, AtlasPca::RevocationStaleness.new(allow_unsigned_root_for_irreversible: true)).allow
  end

  def test_authorize_bad_policy_type_is_a_config_denial
    r = run_authorize(nil, { max_revocation_age_ms: 1 })
    refute r.allow
    assert_equal({ 'authorize_config' => 'fail' }, r.checks)
  end
end
