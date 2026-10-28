# frozen_string_literal: true

# Caveat language v2: replays all six primitives of the shared vectors
# (packages/pca/conformance/caveat-lang-vectors.json) plus exact-outcome tests of hostile input.
#   ruby -Ilib test/test_caveat_lang.rb
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/rack_middleware'
require 'minitest/autorun'

module CaveatLangFixtures
  CONF = File.expand_path('../conformance', __dir__)
  DOC = AtlasPca.parse_json(File.read(File.join(CONF, 'caveat-lang-vectors.json'), encoding: 'UTF-8'), loose: true)['primitives']
end

class TestCaveatLangVectors < Minitest::Test
  V = CaveatLangFixtures::DOC

  def test_vector_files_are_non_empty
    assert_equal [60, 110, 52, 5, 12, 24],
                 %w[discharge_verify k1_eval caveat_shape uses_key uses_reserve spiffe_id].map { |k| V[k].length }
  end

  def test_discharge_verify
    supported = AtlasPca.supported_suites
    ran = 0
    V['discharge_verify'].each do |e|
      i = e['input']
      r = AtlasPca.verify_discharge(i['discharge'], i['caveat'], i['binding'])
      need = e['requires_suite']
      if need && !supported.include?(need)
        # a suite this runtime cannot run is refused with the distinct reason, never passed or failed silently
        refute r[:ok], e['name']
        assert_includes r[:reason], 'unsupported_suite', e['name']
        next
      end
      assert_equal e['expect']['ok'], r[:ok], "#{e['name']}: #{r[:reason]}"
      if r[:ok]
        assert_equal e['expect']['digest'], r[:digest], e['name']
        assert_equal e['expect']['claims'], r[:claims], e['name']
        assert_equal e['expect']['digest'], AtlasPca.discharge_digest(i['discharge']), e['name']
      else
        assert_includes r[:reason], e['expect']['reason_contains'], e['name']
      end
      ran += 1
    end
    assert_operator ran, :>=, 40
  end

  def test_k1_eval
    V['k1_eval'].each do |e|
      i = e['input']
      allow, failed = AtlasPca.evaluate_caveats_k1(i['grant'], i['chain'], i['k1'], i['context'])
      assert_equal [e['expect']['allow'], e['expect']['failed']], [allow, failed], e['name']
    end
  end

  SHAPE = {
    'needs_discharge' => :needs_discharge_error, 'max_uses' => :max_uses_error,
    'derive' => :derive_error, 'spiffe_bound' => :spiffe_bound_error
  }.freeze

  def test_caveat_shape
    V['caveat_shape'].each do |e|
      c = e['input']['caveat']
      err = AtlasPca.public_send(SHAPE.fetch(c['type']), c)
      assert_equal e['expect']['valid'], err.nil?, "#{e['name']}: #{err}"
    end
  end

  def test_uses_key
    V['uses_key'].each do |e|
      i = e['input']
      assert_equal e['expect']['key'], AtlasPca.max_uses_slot_key(i['cap_hash'], i['id'], i['i']), e['name']
    end
  end

  def test_uses_reserve
    V['uses_reserve'].each do |e|
      store = AtlasPca::MemoryStateStore.new
      want = e['expect']['results']
      assert_equal want.length, e['input']['calls'].length, e['name']
      e['input']['calls'].each_with_index do |call, n|
        r = AtlasPca.reserve_max_uses(store, e['input']['bound'], call['now'])
        w = want[n]
        assert_equal w['ok'], r[:ok], "#{e['name']} call #{n}: #{r[:reason]}"
        if w['ok']
          assert_equal w['spent'], r[:spent], "#{e['name']} call #{n}"
        else
          assert_includes r[:reason], w['reason_contains'], "#{e['name']} call #{n}"
        end
      end
    end
  end

  def test_k1_unconfigured
    assert_operator V['k1_unconfigured'].length, :>=, 9
    V['k1_unconfigured'].each do |e|
      i = e['input']
      allow, failed = AtlasPca.evaluate_caveats_k1(i['grant'], i['chain'], nil, i['context'])
      assert_equal [e['expect']['allow'], e['expect']['failed']], [allow, failed], e['name']
    end
  end

  def run_consume_once(store, steps)
    steps.map do |st|
      store.consume_once(st['key'], st['retain_until'], st['now']).to_s
    rescue ArgumentError
      'error'
    end
  end

  def test_consume_once_ttl_memory
    assert_operator V['consume_once_ttl'].length, :>=, 9
    V['consume_once_ttl'].each do |e|
      assert_equal e['expect']['results'], run_consume_once(AtlasPca::MemoryStateStore.new, e['input']['steps']), e['name']
    end
  end

  def test_consume_once_ttl_sqlite
    begin
      require 'sqlite3'
    rescue LoadError
      skip 'sqlite3 gem not installed'
    end
    V['consume_once_ttl'].each do |e|
      assert_equal e['expect']['results'], run_consume_once(AtlasPca::SqliteStateStore.new(':memory:'), e['input']['steps']), e['name']
    end
  end

  def test_k1_headers
    assert_operator V['k1_headers'].length, :>=, 15
    V['k1_headers'].each do |e|
      r = AtlasPca.presented_k1(e['input']['headers'])
      assert_equal e['expect']['ok'], r[:ok], "#{e['name']}: #{r[:reason]}"
      assert_equal e['expect']['value'], r[:value], e['name'] if r[:ok]
    end
  end

  def test_k1_headers_case_insensitive_and_hostile
    d = V['k1_headers'].find { |e| e['name'] == 'kh-discharges' }['input']['headers']['pca-discharges']
    assert_equal 1, AtlasPca.presented_k1('PCA-Discharges' => d)[:value]['discharges'].length
    refute AtlasPca.presented_k1(nil)[:ok]
    refute AtlasPca.presented_k1('pca-narrow' => 5)[:ok]
  end

  def test_spiffe_id
    V['spiffe_id'].each do |e|
      assert_equal e['expect']['valid'], AtlasPca.spiffe_id_error(e['input']['id']).nil?, e['name']
    end
  end
end

class TestCaveatLangTotal < Minitest::Test
  CTX = { 'now' => 1_800_000_000_000, 'action' => { 'verb' => 'v', 'resource' => 'r', 'params' => { 'amount' => 7 } } }.freeze

  def root(*caveats) = { 'id' => 'g', 'issuer' => 'i', 'holder' => 'h', 'caveats' => caveats }

  def test_hostile_inputs_do_not_raise
    [nil, 1, 'x', [], {}, [nil], { 'caveats' => 'x' }].each do |g|
      r = AtlasPca.evaluate_k1(g, [g], nil, nil)
      refute r[:ok]
      refute AtlasPca.evaluate_caveats_k1(g, g, g, g)[0]
      refute AtlasPca.verify_discharge(g, g, g)[:ok]
      refute AtlasPca.verify_narrow(g, g, g, g)[:ok]
    end
    uses = [{ 'caveat' => { 'type' => 'max_uses', 'id' => 'u', 'n' => 1, 'until' => CTX['now'] + 1 }, 'cap_hash' => 'x' }]
    refute AtlasPca.reserve_max_uses(nil, uses, CTX['now'])[:ok]
    assert_equal({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' },
                 AtlasPca.reserve_max_uses(AtlasPca::MemoryStateStore.new, [], 1.5))
  end

  def test_sealed_and_derive_exact_outcomes
    sealed = root({ 'type' => 'sealed' })
    r = AtlasPca.evaluate_k1(sealed, nil, {}, CTX)
    assert_equal [true, []], [r[:ok], r[:failed]]
    child = sealed.merge('caveats' => sealed['caveats'] + [{ 'type' => 'expires', 'at' => CTX['now'] + 1 }])
    r = AtlasPca.evaluate_k1(sealed, [sealed, child], {}, CTX)
    assert_equal [false, ['sealed'], ['a hop was appended below a sealed hop']], [r[:ok], r[:failed], r[:reasons]]

    d = { 'type' => 'derive', 'id' => 'd', 'defs' => [{ 'name' => 'p', 'kind' => 'param', 'path' => 'amount' }],
          'check' => { 'op' => 'lte', 'a' => { 'ref' => 'p' }, 'b' => { 'const' => 10 } } }
    assert_equal [true, []], AtlasPca.evaluate_caveats_k1(root(d), nil, {}, CTX)
    over = CTX.merge('action' => { 'params' => { 'amount' => 11 } })
    r = AtlasPca.evaluate_k1(root(d), nil, {}, over)
    assert_equal ['derive check is false'], r[:reasons]
    r = AtlasPca.evaluate_k1(root(d), nil, {}, CTX.merge('action' => { 'params' => {} }))
    assert_equal ['derive check is unknown (a fact is missing)'], r[:reasons]
  end

  def test_no_k1_input_refuses_every_k1_type_but_empty_object_is_configured
    not_configured = 'the caveat language is not configured (no k1 input)'
    [nil, 'x', 1, []].each do |k1|
      %w[sealed needs_discharge max_uses derive spiffe_bound].each do |t|
        r = AtlasPca.evaluate_k1(root({ 'type' => t }), nil, k1, CTX)
        assert_equal [false, [t], [not_configured]], [r[:ok], r[:failed], r[:reasons]], "#{t} #{k1.inspect}"
      end
    end
    assert AtlasPca.evaluate_k1(root({ 'type' => 'sealed' }), nil, {}, CTX)[:ok]
  end

  def test_consume_once_contract
    s = AtlasPca::MemoryStateStore.new
    assert s.consume_once('k', 10, 0)
    refute s.consume_once('k', 5, 1)
    refute s.consume_once('k', 10, 10)
    assert s.consume_once('k', 30, 11)
    [['', 10, 0], ['k2', 1, 2], ['k2', 1.5, 0], ['k2', 5, nil]].each do |a|
      assert_raises(ArgumentError) { s.consume_once(*a) }
    end
    assert s.consume_once('k2', 5, 2) # the refused calls left nothing behind
    # a custom store with only claim falls back to claim(slot, 1)
    claim_only = Class.new { def initialize = @m = AtlasPca::MemoryStateStore.new; def claim(k, c) = @m.claim(k, c) }.new
    uses = [{ 'caveat' => { 'type' => 'max_uses', 'id' => 'u', 'n' => 1, 'until' => CTX['now'] + 1 }, 'cap_hash' => 'x' }]
    assert AtlasPca.reserve_max_uses(claim_only, uses, CTX['now'])[:ok]
    refute AtlasPca.reserve_max_uses(claim_only, uses, CTX['now'])[:ok]
  end

  def test_unknown_types_stay_refused_and_failures_sort
    g = root({ 'type' => 'zzz' }, { 'type' => 'sealed' }, { 'type' => 'needs_discharge' })
    allow, failed = AtlasPca.evaluate_caveats_k1(g, nil, {}, CTX)
    assert_equal [false, %w[needs_discharge zzz]], [allow, failed]
  end
end

class TestCaveatLangAuthorize < Minitest::Test
  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'), loose: true)
  CASE = FIX['cases'].find { |c| c['steps'].length == 1 && c['steps'][0]['expect']['allow'] == true }
  STEP = CASE['steps'][0]

  def run_az(**opts)
    AtlasPca.authorize(STEP['pcactn'], operation: STEP['operation'], audience: FIX['audience'], resolve_grant: ->(_r) { CASE['grant'] },
                       state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: FIX['now'],
                       plan: 'single-step', **opts)
  end

  def test_k1_input_without_k1_caveats_changes_nothing
    assert run_az.allow
    assert run_az(k1: {}).allow
    assert run_az(k1: ->(_p) { { 'pins' => [] } }).allow
  end

  def refused_not_configured?(r)
    !r.allow && r.reasons.any? { |w| w.include?('the caveat language is not configured (no k1 input)') }
  end

  def test_k1_caveats_without_k1_option_are_refused_on_every_path
    cs = [{ 'type' => 'sealed' }]
    root_k1 = CASE['grant'].merge('caveats' => (CASE['grant']['caveats'] || []) + cs)
    # the K1 caveat is on the chain's root too (the chain hops carry the caveats evaluate_k1 reads); the unsigned edit also
    # breaks the chain signature, so the verdict is a deny whose reasons still name the unconfigured caveat language
    pcactn = Marshal.load(Marshal.dump(STEP['pcactn']))
    pcactn['cap_chain'][0] = root_k1
    r = AtlasPca.authorize(pcactn, operation: STEP['operation'], audience: FIX['audience'], resolve_grant: ->(_r) { root_k1 },
                           state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: FIX['now'], plan: 'single-step')
    assert refused_not_configured?(r), r.reasons.inspect
  end

  def test_middleware_k1_option_merges_headers_under_own_members
    mw = AtlasPca::RackMiddleware.allocate
    assert_nil mw.send(:k1_option, {}, nil)
    d = AtlasPca.b64e('[]')
    env = { 'HTTP_PCA_DISCHARGES' => d, 'HTTP_PCA_NARROW' => AtlasPca.b64e('{"a":1}') }
    assert_equal({ 'discharges' => [], 'narrow' => { 'a' => 1 }, 'pins' => [] }, mw.send(:k1_option, env, { pins: [] }).call({}))
    own = mw.send(:k1_option, env, ->(_p) { { 'narrow' => 7 } }).call({})
    assert_equal [[], 7], [own['discharges'], own['narrow']]
    bad = mw.send(:k1_option, { 'HTTP_PCA_DISCHARGES' => '!!' }, {}).call({})
    assert_equal({}, bad)
  end

  def test_unavailable_k1_state_is_refused
    r = run_az(k1: ->(_p) { raise 'down' })
    assert_equal [false, 403, 'fail'], [r.allow, r.status, r.checks['k1']]
    refute run_az(k1: 'nope').allow
  end
end
