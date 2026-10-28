# frozen_string_literal: true

# Assurance labels and the high-assurance gate (T8 / B7): replays packages/pca/conformance/assurance-vectors.json
# (`signature_level`, `report`, `requirement`, `multi_root`) and checks the authorize wiring. Reports and reasons are compared
# exactly (key order is irrelevant). A missing vector file fails.
#   ruby -Ilib test/test_assurance_vectors.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestAssuranceVectors < Minitest::Test
  FILE = File.expand_path('../conformance/assurance-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'),
                            loose: true)

  # A verifier hook carrying the declared label, or an unlabelled one.
  def hook(label)
    h = Object.new
    return h if label == 'unlabelled'

    AtlasPca.set_assurance_label(h, label['level'], vendor: label['vendor'], preview: label['preview'], ceremony: label['ceremony'])
  end

  def build(v)
    hooks = (v['hooks'] || {}).transform_values { |x| hook(x) }
    AtlasPca.assurance_report(v['pcactn'], v['checks'], v['degraded'], hooks: hooks,
                                                                       attestation_hook: v.key?('attestation_hook') ? hook(v['attestation_hook']) : nil,
                                                                       threshold_t: v['threshold_t'], allow_unbound_pq: v['allow_unbound_pq'] == true)
  end

  def test_corpus_is_complete
    assert_equal [14, 37, 44, 10], %w[signature_level report requirement multi_root].map { |k| DOC[k].length }
  end

  def test_signature_level
    DOC['signature_level'].each { |v| assert_equal v['level'], AtlasPca.signature_level(v['alg']), v['alg'].inspect }
  end

  def test_report
    DOC['report'].each { |v| assert_equal v['report'], build(v), v['name'] }
  end

  def test_requirement
    DOC['requirement'].each do |v|
      got = AtlasPca.unmet_assurance(v['report'], v['require'])
      v['unmet'].nil? ? assert_nil(got, v['name']) : assert_equal(v['unmet'], got, v['name'])
    end
  end

  def test_multi_root
    DOC['multi_root'].each do |v|
      roots = v['roots'].map { |r| { 'verifier' => hook('level' => r['level']), 'required' => r['required'] } }
      assert_equal v['level'], AtlasPca.multi_root_level(roots, v['threshold']), v['name']
    end
  end

  def test_a_label_never_comes_from_the_presented_evidence
    r = AtlasPca.assurance_report({ 'attestation' => { 'level' => 'hardware' } }, { 'attestation' => 'pass' }, hooks: { 'attestation' => Object.new })
    assert_equal({ 'outcome' => 'pass', 'level' => 'unknown' }, r['attestation'])
  end

  def test_unknown_requirement_values_fail_closed
    ok = { 'attestation' => { 'outcome' => 'pass', 'level' => 'hardware' }, 'zk_compliance' => { 'outcome' => 'pass', 'level' => 'groth16' } }
    [{ 'attestation' => 'unknown' }, { 'attestation' => 'tpm' }, { 'zk' => 'magic' }, { 'threshold' => 'multisig' }, { 'signature' => 'any' }].each do |req|
      why = AtlasPca.unmet_assurance(ok, req)
      assert why&.start_with?('assurance: unknown ') && why.end_with?('(fail closed)'), "#{req.inspect}: #{why.inspect}"
    end
  end

  # ---- authorize(): require_assurance ----------------------------------------------------------------------------------

  def run_authorize(req, pcactn_edit: nil)
    c = FIX['cases'].find { |x| x['name'] == 'envelope-max-spend-within' }
    s = c['steps'][0]
    p = Marshal.load(Marshal.dump(s['pcactn']))
    pcactn_edit&.call(p)
    store = AtlasPca::MemoryStateStore.new
    r = AtlasPca.authorize(p, operation: s['operation'], audience: FIX['audience'], resolve_grant: ->(_r) { c['grant'] },
                              state_store: store, is_revoked: ->(_p, _g) { false }, now: FIX['now'], plan: 'single-step',
                              require_assurance: req)
    [r, store, p]
  end

  def test_authorize_carries_the_report_and_the_gate_is_off_by_default
    r, = run_authorize(nil)
    assert r.allow
    assert_equal 'ed25519', r.assurance['leaf_signature']['level']
    assert_equal 'pass', r.assurance['replay']['outcome']
    refute r.checks.key?('assurance')
  end

  def test_an_unmet_requirement_denies_before_any_replay_state_is_written
    r, store, p = run_authorize({ 'signature' => 'pq' })
    refute r.allow
    assert_equal 'fail', r.checks['assurance']
    assert_includes r.reasons, 'assurance: post-quantum signatures required but leaf_signature is ed25519'
    holder = p['cap_chain'][-1]['holder']
    assert_nil store.last(AtlasPca.state_key(p['grant_ref'], holder)), 'the counter must not be consumed'
  end

  def test_a_met_requirement_passes
    r, = run_authorize({ 'allowPreview' => false })
    assert r.allow
    assert_equal 'pass', r.checks['assurance']
  end

  def test_a_carried_bond_is_unsupported_and_refused
    r, = run_authorize({}, pcactn_edit: ->(p) { p['bond_ref'] = 'x' })
    refute r.allow
  end

  def test_an_invalid_requirement_type_fails_closed
    r, = run_authorize(5)
    refute r.allow
    assert_equal 'fail', r.checks['assurance']
  end
end
