# frozen_string_literal: true
# Parity with the TS reference, audit items B, F, G, H: capability.ts:174-193 (allocationsMonotone), blueprint.ts:86-90, :202-205
# (runtime_pins), pca-need.ts:69 (scope whitespace), and one writer at a time in the lease, break-glass and blueprint registries.
module MutationKill
  module Parity
    module_function

    def kp(name) = (@kps ||= {})[name] ||= AtlasPca::KeyPair.generate

    # A signed blueprint record, content as given (the signature is genuine, so only the content rule can refuse it).
    def blueprint(over = {})
      b = { 'v' => 1, 'id' => 'bp', 'key' => 'bp-key', 'ceiling' => [], 'runtime_pins' => [{ 'model_id' => 'm' }], 'epoch' => 1, 'status' => 'active',
            'issued_at' => 1, 'operator' => kp(:op).public }.merge(over)
      body = AtlasPca::BLUEPRINT_BODY_KEYS.each_with_object({}) { |k, h| h[k] = b[k] if b.key?(k) }
      b.merge('sig' => AtlasPca.b64e(kp(:op).sign(AtlasPca::AGENT_BLUEPRINT_DOMAIN + AtlasPca.canon_bytes(body))))
    end

    def registry = AtlasPca::BlueprintRegistry.new([kp(:op).public], AtlasPca::MemoryBlueprintKv.new)

    def deny(code) = { 'decision' => 'deny', 'code' => code, 'blueprint' => 'bp' }

    CHAIN = [{ 'issuer' => 'root', 'holder' => 'bp-key' }, { 'issuer' => 'bp-key', 'holder' => 'inst' }].freeze

    # Runs `call` from three threads with `name` slowed under it: the most callers ever inside at once, and the results.
    def peak(mod, name, ret, &call)
      inside = 0
      top = 0
      m = Mutex.new
      slow = lambda do |*|
        m.synchronize do
          inside += 1
          top = [top, inside].max
        end
        sleep 0.02
        m.synchronize { inside -= 1 }
        ret
      end
      Seam.with(mod, { name => slow }) { Array.new(3) { Thread.new(&call) }.map(&:value) }
      top
    end

    def cav(*limits) = limits.map { |l| { 'type' => 'budget_alloc', 'limit' => l } }
  end

  t('allocations: monotone lists pass, whatever else they carry') do
    e = ->(c) { AtlasPca.allocations_monotone_error(c) }
    e.call([]).nil? && e.call(Parity.cav(10, 10, 0)).nil? && e.call(Parity.cav(10.5, 10)).nil? &&
      e.call([nil, 5, 'x', [], { 'type' => 'other', 'limit' => -1 }] + Parity.cav(1)).nil?
  end

  t('allocations: a widening child is refused, with the reference reason') do
    AtlasPca.allocations_monotone_error(Parity.cav(10, 100)) ==
      "budget_alloc caveat 1: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)" &&
      AtlasPca.allocations_monotone_error([{ 'type' => 'x' }] + Parity.cav(5, 2, 2.5)) ==
        "budget_alloc caveat 3: allocation 2.5 widens the parent's carried allocation 2 (monotone: a child can only allocate <= its parent)"
  end

  t('allocations: limit must be a finite number >= 0, and the list a list') do
    bad = [nil, '5', -1, -0.5, Float::INFINITY, Float::NAN, true, 10**400]
    AtlasPca.allocations_monotone_error(nil) == 'malformed caveats' && AtlasPca.allocations_monotone_error({}) == 'malformed caveats' &&
      bad.all? { |l| AtlasPca.allocations_monotone_error([{}] + Parity.cav(l)) == 'budget_alloc caveat 1: limit must be a finite number >= 0' } &&
      AtlasPca.allocations_monotone_error([{ 'type' => 'budget_alloc' }]) == 'budget_alloc caveat 0: limit must be a finite number >= 0'
  end

  t('verify_chain: a child that widens its parent allocation fails the chain, on real signatures') do
    root = AtlasPca.mint_root(Parity.kp(:p), Parity.kp(:h).public, Parity.cav(10))
    hop = ->(l) { AtlasPca.delegate_cap(root, Parity.kp(:h), added: Parity.cav(l)) }
    run = ->(l) { AtlasPca.verify_chain([root, hop.call(l)], Parity.kp(:p).public, true, nil, nil, root) }
    run.call(5) == ['', true] && run.call(100) ==
      ["budget_alloc caveat 1: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)", false]
  end

  t('blueprint: a pinned record is accepted, signed over its pins, and denies admission_required') do
    b = Parity.blueprint
    r = Parity.registry
    AtlasPca.verify_blueprint(b) && r.accept(b) == { 'ok' => true, 'replaced' => true } &&
      !AtlasPca.verify_blueprint(b.merge('runtime_pins' => [{ 'model_id' => 'other' }])) &&
      AtlasPca.check_blueprints(Parity::CHAIN, r, 2, 'any') == Parity.deny('admission_required') &&
      AtlasPca.check_blueprints(Parity::CHAIN, r, 2, 'require') == Parity.deny('admission_required')
  end

  t('blueprint: a group kill carrying pins is disabled, too_deep and expiry come first, an unpinned record still allows') do
    run = lambda do |over, chain = Parity::CHAIN|
      r = Parity.registry
      r.accept(Parity.blueprint(over))['ok'] && AtlasPca.check_blueprints(chain, r, 2, 'any')
    end
    deep = Parity::CHAIN + [{ 'issuer' => 'inst', 'holder' => 'sub' }]
    unpinned = Parity.blueprint.reject { |k, _| %w[runtime_pins sig].include?(k) }
    run.call({ 'status' => 'disabled' }) == Parity.deny('blueprint_disabled') &&
      run.call({ 'expires_at' => 2 }) == Parity.deny('blueprint_expired') &&
      run.call({ 'max_depth' => 1 }, deep) == Parity.deny('too_deep') &&
      run.call({ 'max_depth' => 1 }) == Parity.deny('admission_required') &&
      begin
        body = AtlasPca::BLUEPRINT_BODY_KEYS.each_with_object({}) { |k, h| h[k] = unpinned[k] if unpinned.key?(k) }
        rec = unpinned.merge('sig' => AtlasPca.b64e(Parity.kp(:op).sign(AtlasPca::AGENT_BLUEPRINT_DOMAIN + AtlasPca.canon_bytes(body))))
        r = Parity.registry
        r.accept(rec)['ok'] && AtlasPca.check_blueprints(Parity::CHAIN, r, 2, 'any') == { 'decision' => 'allow', 'governed' => ['bp'] }
      end
  end

  t('blueprint: runtime_pins bounds and shape, exactly') do
    good = [[{ 'model_id' => 'm' }], [{ 'runtime_measurement' => 'a', 'model_id' => 'b', 'weights_digest' => 'c', 'operator' => 'd', 'spiffe_id' => 'e' }],
            Array.new(16) { { 'model_id' => 'm' } }, [{ 'model_id' => 'x' * 256 }]]
    bad = [nil, 'x', {}, [], Array.new(17) { { 'model_id' => 'm' } }, [{}], ['x'], [nil], [{ 'nope' => 'x' }], [{ 'model_id' => '' }], [{ 'model_id' => 1 }],
           [{ 'model_id' => 'x' * 257 }], [{ 'model_id' => 'm' }, {}]]
    good.all? { |p| AtlasPca.verify_blueprint(Parity.blueprint('runtime_pins' => p)) } &&
      bad.none? { |p| AtlasPca.verify_blueprint(Parity.blueprint('runtime_pins' => p)) }
  end

  t('registries: one writer at a time (a slow check under each entry never overlaps)') do
    bad = { 'ok' => false, 'code' => 'bad_record' }
    lease = AtlasPca::LeaseRegistry.new({ 'authorities' => [] }, AtlasPca::MemoryLeaseKv.new)
    glass = AtlasPca::BreakGlassRegistry.new({ 'authorities' => [], 'reviewers' => [] }, AtlasPca::MemoryBreakGlassKv.new)
    blue = AtlasPca::BlueprintRegistry.new([], AtlasPca::MemoryBlueprintKv.new)
    res = []
    tops = [
      Parity.peak(AtlasPca, :verify_lease, false) { res << lease.accept({}) },
      Parity.peak(AtlasPca, :verify_lease_revocation, false) { res << lease.revoke({}) },
      Parity.peak(AtlasPca, :verify_blueprint, false) { res << blue.accept({}) },
      Parity.peak(AtlasPca, :verify_break_glass, false) { res << glass.accept({}, 1) },
      Parity.peak(AtlasPca, :verify_break_glass_review, false) { res << glass.review({}, 'h', 1) }
    ]
    use = Parity.peak(AtlasPca, :k3_str?, false) { glass.use('i', 'h', 'd', 1, true) }
    frozen = Parity.peak(AtlasPca, :k3_str?, false) { glass.frozen('h', 1) }
    tops == [1] * 5 && use == 1 && frozen == 1 && res.length == 15 && res.all? { |x| x == bad } &&
      glass.use('i', 'h', 'd', 1, true) == { 'decision' => 'deny', 'code' => 'unknown_break_glass', 'id' => 'i' } && glass.frozen('h', 1) == false
  end

  t('a2a need: a scope with any ECMAScript whitespace is bad_field; other characters are not whitespace') do
    need = ->(s) { AtlasPca.a2a_need_error({ 'v' => 1, 'kind' => 'scope', 'verb' => 'v', 'resource' => 'r', 'scopes' => [s] }) }
    ws = ["\t", "\n", "\v", "\f", "\r", ' ', " ", " ", " ", " ", " ", " ", " ", " ", " ", "　", "﻿"]
    ws.all? { |c| need.call("a#{c}b") == 'bad_field' } && need.call('ab').nil? && need.call("a​b").nil? && need.call("a\u0085b").nil?
  end
end
