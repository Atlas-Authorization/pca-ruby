# frozen_string_literal: true

# e07: PCA 0.5 hardening H19 (Ed25519Strict.verify runs the OpenSSL equation before the torsion checks), F1 (core
# plan_root_authorized: authorized_plan_roots / insecure_skip_plan_root_check), F6 (obligations: nil is a present JSON null),
# O6 (accPost wording: a2_history_mesh.rb; the zk text already matches TS), F10 (policy-vectors caveat projection gating; budget_alloc and
# runtime_pins coverage). Reuses the C06 authorize fixture (c06_authorize.rb loads first). AtlasPca is resolved at call time.

module MutationKill
  module E07
    module_function

    def gate?(*files) = (f = ENV['MUT_FILE']).nil? || f.empty? || files.include?(f)

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    def le(n) = (0...32).map { |i| (n >> (8 * i)) & 0xff }.pack('C*')
    def num(bytes) = bytes.bytes.each_with_index.sum { |b, i| b << (8 * i) }

    def enc(pt) # affine re-encoding of an extended point
      p = AtlasPca::Ed25519Strict::P
      zi = pt[2].pow(p - 2, p)
      le((pt[1] * zi % p) | (((pt[0] * zi % p) & 1) << 255))
    end

    def base_point
      e = AtlasPca::Ed25519Strict
      e.decode(le(4 * 5.pow(e::P - 2, e::P) % e::P))
    end

    # [pub, msg, sig] for A = a*B (+ the order-2 point (0,-1) when `mixed`), signed by hand with an EVEN reduced k so the
    # torsion component cancels in OpenSSL's equation [S]B = R + [k]A: the library accepts it, the strict rules must not.
    def hand_signed(mixed)
      e = AtlasPca::Ed25519Strict
      a = 12_345
      r = 777
      pt = e.mul(a, base_point)
      pt = e.add(pt, e.decode(le(e::P - 1))) if mixed
      pub = enc(pt)
      rr = enc(e.mul(r, base_point))
      (0..64).each do |i|
        msg = "m#{i}"
        k = num(OpenSSL::Digest::SHA512.digest(rr + pub + msg)) % e::L
        next if k.odd?

        return [pub, msg, rr + le((r + (k * a)) % e::L)]
      end
      nil
    end
  end

  t('e07 H19: a forged signature is refused by the library equation before any torsion check (acceptable_point never runs)') do
    next true unless E07.gate?('atlas_pca.rb')

    e = AtlasPca::Ed25519Strict
    k = OpenSSL::PKey.new_raw_private_key('ED25519', "\x07".b * 32)
    pub = k.raw_public_key
    forged = E07.le(4 * 5.pow(e::P - 2, e::P) % e::P) + ("\x03".b * 31) + "\x00".b # valid-looking R, S < L, wrong equation
    calls = 0
    res = Seam.with(e, { acceptable_point: ->(*) { calls += 1; nil } }) { e.verify(pub, 'm', forged) }
    good = Seam.with(e, { acceptable_point: ->(*) { calls += 100; nil } }) { e.verify(pub, 'm', k.sign(nil, 'm')) }
    E07.ck('forged refused', res, false) && E07.ck('no torsion work', [calls % 100, calls / 100], [0, 1]) && E07.ck('stub nil refuses a valid sig', good, false)
  end

  t('e07 H19: s >= L, bad lengths and a valid prime-order signature keep their exact outcomes') do
    next true unless E07.gate?('atlas_pca.rb')

    e = AtlasPca::Ed25519Strict
    k = OpenSSL::PKey.new_raw_private_key('ED25519', "\x07".b * 32)
    pub = k.raw_public_key
    sig = k.sign(nil, 'm')
    big_s = sig[0, 32] + E07.le(e::L) # S == L is out of range
    pub2, msg2, sig2 = E07.hand_signed(false)
    E07.ck('valid', e.verify(pub, 'm', sig), true) && E07.ck('wrong msg', e.verify(pub, 'n', sig), false) &&
      E07.ck('S == L', e.verify(pub, 'm', big_s), false) && E07.ck('short sig', e.verify(pub, 'm', sig[0, 63]), false) &&
      E07.ck('hand-signed prime-order', e.verify(pub2, msg2, sig2), true)
  end

  t('e07 H19: a mixed-order public key that the library accepts is still refused (torsion checks run on success)') do
    next true unless E07.gate?('atlas_pca.rb')

    e = AtlasPca::Ed25519Strict
    pub, msg, sig = E07.hand_signed(true)
    E07.ck('mixed A is not acceptable', e.acceptable_point(pub), nil) && E07.ck('refused', e.verify(pub, msg, sig), false)
  end

  t('e07 F1: core plan_root_authorized (listed / not listed / empty / unset / skipped / list wins over skip)') do
    next true unless E07.gate?('atlas_pca.rb')

    pc = C06.fixture_pcactn
    grant = C06.base['grant']
    root = pc['plan']['root']
    v = ->(**kw) { AtlasPca.verify_pcactn(pc, grant, now: C06::NOW, audience: C06.aud, **kw) }
    nope = 'plan_root_authorized: the plan root has not been authorized by the principal'
    unset = 'plan_root_authorized: no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)'
    listed = v.call(authorized_plan_roots: [root])
    other = v.call(authorized_plan_roots: ['x'])
    empty = v.call(authorized_plan_roots: [])
    none = v.call
    skip = v.call(insecure_skip_plan_root_check: true)
    skip_false = v.call(insecure_skip_plan_root_check: false)
    skip_truthy = v.call(insecure_skip_plan_root_check: 'yes')
    both = v.call(authorized_plan_roots: ['x'], insecure_skip_plan_root_check: true)
    not_array = v.call(authorized_plan_roots: root)
    E07.ck('listed', [listed.allow, listed.checks['plan_root_authorized'], listed.reason], [true, true, '']) &&
      E07.ck('other', [other.allow, other.checks['plan_root_authorized'], other.reason], [false, false, nope]) &&
      E07.ck('empty', [empty.allow, empty.checks['plan_root_authorized'], empty.reason], [false, false, nope]) &&
      E07.ck('unset', [none.allow, none.checks['plan_root_authorized'], none.reason], [false, false, unset]) &&
      E07.ck('skip', [skip.allow, skip.checks.key?('plan_root_authorized'), skip.reason], [true, false, '']) &&
      E07.ck('skip false', [skip_false.allow, skip_false.reason], [false, unset]) &&
      E07.ck('skip must be exactly true', [skip_truthy.allow, skip_truthy.reason], [false, unset]) &&
      E07.ck('list wins over skip', [both.allow, both.reason], [false, nope]) &&
      E07.ck('string is not a list', [not_array.allow, not_array.reason], [false, nope])
  end

  t('e07 F1: authorize hands the core the skip flag (it checks its own plan_root_authorized)') do
    next true unless E07.gate?('authorize.rb')

    cap = []
    C06.with_core(nil, cap) { C06.go }
    E07.ck('skip passed', cap[0] && cap[0][:insecure_skip_plan_root_check], true) && E07.ck('no roots passed', cap[0].key?(:authorized_plan_roots), false)
  end

  t('e07 F6: obligations: nil is a present JSON null (denied), NO_OBLIGATIONS is absent (allowed)') do
    next true unless E07.gate?('obligations.rb')

    m = AtlasPca
    absent = m::NO_OBLIGATIONS
    allow_empty = { 'decision' => 'allow', 'perform' => [], 'unsupported' => [] }
    null_deny = { 'decision' => 'deny', 'perform' => [], 'unsupported' => [], 'reason' => 'malformed obligations: obligations must be an array' }
    unmet = { 'outcome' => 'escalate', 'overdue' => [], 'status' => 'obligation_unmet' }
    E07.ck('gate null', m.pep_obligation_gate('allow', false, nil, []), null_deny) &&
      E07.ck('gate absent', m.pep_obligation_gate('allow', false, absent, []), allow_empty) &&
      E07.ck('gate empty list', m.pep_obligation_gate('allow', false, [], []), allow_empty) &&
      E07.ck('gate deny ignores obligations', m.pep_obligation_gate('deny', false, nil, []), { 'decision' => 'deny', 'perform' => [], 'unsupported' => [] }) &&
      E07.ck('error null', m.obligations_error(nil), 'obligations must be an array') && E07.ck('error absent', m.obligations_error(absent), nil) &&
      E07.ck('error no arg', m.obligations_error, nil) &&
      E07.ck('outcome null', m.obligation_outcome(nil, [], 0), unmet) &&
      E07.ck('outcome absent', m.obligation_outcome(absent, [], 0), { 'outcome' => 'ok', 'overdue' => [] }) &&
      E07.ck('merge nil (vector hole) is absent', m.merge_obligations([], nil, [{ 'kind' => 'log' }]), { 'ok' => true, 'obligations' => [{ 'kind' => 'log' }] })
  end

  t('e07 F10: budget_alloc monotone widening (equal ok, widen denied with the exact text, malformed limits)') do
    next true unless E07.gate?('atlas_pca.rb')

    m = AtlasPca
    ba = ->(l) { { 'type' => 'budget_alloc', 'limit' => l } }
    E07.ck('equal', m.allocations_monotone_error([ba.call(10), ba.call(10)]), nil) &&
      E07.ck('narrow', m.allocations_monotone_error([ba.call(10), ba.call(9)]), nil) &&
      E07.ck('widen', m.allocations_monotone_error([ba.call(10), ba.call(11)]),
             "budget_alloc caveat 1: allocation 11 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)") &&
      E07.ck('widen skips other caveats', m.allocations_monotone_error([ba.call(5), { 'type' => 'note' }, ba.call(6)]),
             "budget_alloc caveat 2: allocation 6 widens the parent's carried allocation 5 (monotone: a child can only allocate <= its parent)") &&
      E07.ck('negative', m.allocations_monotone_error([ba.call(-1)]), 'budget_alloc caveat 0: limit must be a finite number >= 0') &&
      E07.ck('string limit', m.allocations_monotone_error([ba.call('5')]), 'budget_alloc caveat 0: limit must be a finite number >= 0') &&
      E07.ck('not an array', m.allocations_monotone_error('x'), 'malformed caveats')
  end

  t('e07 F10: blueprint runtime_pins: a pinned blueprint denies admission_required, an unpinned one allows') do
    next true unless E07.gate?('blueprint.rb')

    m = AtlasPca
    kv = m::MemoryBlueprintKv.new
    reg = m::BlueprintRegistry.new(['op'], kv)
    bp = { 'id' => 'bp1', 'key' => 'bpkey', 'status' => 'active', 'ceiling' => [], 'epoch' => 1 }
    kv.set('blueprint/rec/bpkey', bp.merge('runtime_pins' => [{ 'model_id' => 'm' }]))
    chain = [{ 'issuer' => 'op', 'holder' => 'bpkey' }, { 'issuer' => 'bpkey', 'holder' => 'inst' }]
    pinned = m.check_blueprints(chain, reg, 1, 'require')
    kv.set('blueprint/rec/bpkey', bp)
    plain = m.check_blueprints(chain, reg, 1, 'require')
    E07.ck('pinned', pinned, { 'decision' => 'deny', 'code' => 'admission_required', 'blueprint' => 'bp1' }) &&
      E07.ck('unpinned', plain, { 'decision' => 'allow', 'governed' => ['bp1'] })
  end

  t('e07 F10: policy-vectors.json caveat projection (evaluate_caveats over policy_caveats) is gating for the implemented types') do
    next true unless E07.gate?('atlas_pca.rb', 'authorize.rb')

    file = File.expand_path('../../conformance/policy-vectors.json', __dir__)
    next true unless File.exist?(file)

    m = AtlasPca
    doc = m.parse_json(File.read(file, encoding: 'UTF-8'), loose: true)
    implemented = %w[max_spend expires not_before rate max_blast_radius reversibility_max delegation_depth budget_alloc]
    n = 0
    bad = []
    doc['policy_decision'].each do |v|
      cavs = m.policy_caveats(v['grant'], v['chain'])
      next unless cavs.is_a?(Array) && cavs.all? { |c| c.is_a?(Hash) && implemented.include?(c['type']) }

      ctx = v['context']
      got = m.evaluate_agent_caveats(cavs, ctx, { 'action' => ctx['action'] })
      bad << v['name'] unless got == [v['expect']['caveats']['allow'], v['expect']['caveats']['failed']]
      n += 1
    end
    E07.ck('mismatching vectors', bad, []) && E07.ck('enough vectors ran', n >= 50, true)
  end
end
