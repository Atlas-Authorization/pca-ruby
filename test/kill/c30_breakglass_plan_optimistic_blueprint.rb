# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'digest'
require 'set'

# Exact-outcome kill tests for blueprint.rb, break_glass.rb, optimistic.rb and plan_lifecycle.rb. Every AtlasPca constant,
# class and helper is resolved at CALL time (the oracle replaces the module per mutant); nothing derived from AtlasPca is
# memoised. Expected values come from reading the lib and packages/pca/src (optimistic.ts evidenceClass path, plan/break-glass
# vectors); signed fixtures are built in-test from sha256("c30/<label>") Ed25519 seeds.
module MutationKill
  module C30
    class DuckH # answers [] / key? / reject like a Hash but is not one
      def initialize(h)
        @h = h
      end

      def [](k) = @h[k]
      def key?(k) = @h.key?(k)
      def reject(&blk) = @h.reject(&blk)
      def empty? = @h.empty?
      def all?(&blk) = @h.all?(&blk)
      def length = @h.length
    end

    class Eq # == answers true to everything
      def ==(_other)
        true
      end
    end

    class EqTrue # claims to be a TrueClass and equal to everything, yet is not `true`
      def ==(_other)
        true
      end

      def class
        TrueClass
      end
    end

    class KindLike # a non-String that String#== / === accept as 'policy-denied'
      def to_str = 'policy-denied'

      def ==(_other)
        true
      end
    end

    class ClassLike # a non-String that hashes / eql?s like a reversibility class key
      def hash = 'reversible'.hash

      def eql?(_other)
        true
      end

      def to_s = 'CL'
    end

    class OddErr < StandardError
      def message = 'by-message'
      def to_s = 'by-to_s'
    end

    class Odd # every lookup raises OddErr
      def [](_key)
        raise OddErr
      end
    end

    class RaiseSig < Hash # a Hash whose 'sig' lookup raises
      def [](k)
        k == 'sig' ? raise('boom') : super
      end
    end

    module_function

    def on?(file)
      m = ENV['MUT_FILE']
      m.nil? || m.empty? || m == file
    end

    def same(label, want, got)
      return true if want == got && want.class == got.class

      warn "c30 #{label}: want #{want.inspect} got #{got.inspect}" if defined?($mn_verbose) && $mn_verbose
      false
    end

    def table(label, rows)
      rows.each_with_index.map { |(w, g), i| same("#{label}[#{i}]", w, g) }.all?
    end

    def b64(bin) = Base64.urlsafe_encode64(bin, padding: false)

    def key(label)
      (@keys ||= {})[label] ||= OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest("c30/#{label}"))
    end

    def pk(label) = b64(key(label).raw_public_key)

    def wo(hash, *keys) = hash.reject { |k, _| keys.include?(k) }

    # ---- blueprint
    def bp(over = {})
      { 'v' => 1, 'id' => 'bp1', 'key' => 'K1', 'ceiling' => [], 'epoch' => 1, 'status' => 'active', 'issued_at' => 1,
        'operator' => 'OP' }.merge(over)
    end

    def sign_bp(rec, label)
      body = AtlasPca::BLUEPRINT_BODY_KEYS.each_with_object({}) { |k, h| h[k] = rec[k] if rec.key?(k) }
      rec.merge('sig' => b64(key(label).sign(nil, AtlasPca::AGENT_BLUEPRINT_DOMAIN.b + AtlasPca.canon_bytes(body))))
    end

    # ---- break glass
    def grant(over = {})
      { 'v' => 1, 'id' => 'g1', 'holder' => 'h1', 'grant_ref' => 'gr1', 'reason_digest' => 'rd1', 'max_uses' => 2,
        'issued_at' => 1000, 'expires_at' => 2000, 'review_within' => 500, 'notify_to' => 'n@x',
        'authority' => pk('auth') }.merge(over)
    end

    def sign_grant(rec, label = 'auth')
      body = AtlasPca::BREAK_GLASS_BODY_KEYS.to_h { |k| [k, rec[k]] }
      rec.merge('sig' => b64(key(label).sign(nil, AtlasPca::BREAK_GLASS_DOMAIN.b + AtlasPca.canon_bytes(body))))
    end

    def review(over = {})
      { 'v' => 1, 'id' => 'g1', 'outcome' => 'justified', 'notes_digest' => 'nd1', 'at' => 1100, 'reviewer' => pk('rev') }.merge(over)
    end

    def sign_review(rec, label = 'rev')
      body = AtlasPca::BREAK_GLASS_REVIEW_KEYS.to_h { |k| [k, rec[k]] }
      rec.merge('sig' => b64(key(label).sign(nil, AtlasPca::BREAK_GLASS_REVIEW_DOMAIN.b + AtlasPca.canon_bytes(body))))
    end

    def bg_reg = AtlasPca::BreakGlassRegistry.new({ 'authorities' => [pk('auth')], 'reviewers' => [pk('rev')] }, AtlasPca::MemoryBreakGlassKv.new)

    def uses_of(reg, holder, id) = reg.uses(holder, id)

    # ---- plan lifecycle
    def pl_nodes
      [{ 'id' => 'a', 'verb' => 'read', 'resource' => '/r' },
       { 'id' => 'b', 'verb' => 'write', 'resource' => '/w', 'reversibility_class' => 'reversible' }]
    end

    # => [registry, kv, clock (a 1-element array)]
    def pl_reg(validator: nil)
      clk = [0]
      kv = AtlasPca::MemoryAtomicKv.new
      [AtlasPca::PlanRegistry.new(kv: kv, now: -> { clk[0] }, validator: validator), kv, clk]
    end

    def pl_committed(reg, grant = 'g', nodes = pl_nodes)
      root = reg.draft(grant, nodes)['record']['root']
      reg.validate(grant, root)
      reg.commit(grant, root)
      root
    end

    def pl_authorized(reg, approval = { 'by' => 'principal' }, grant = 'g', nodes = pl_nodes)
      root = pl_committed(reg, grant, nodes)
      reg.authorize(grant, root, approval)
      root
    end

    def pl_put(kv, reg, grant, root, rec) = kv.set(reg.send(:key, grant, root), rec)

    def rec_of(root, nodes, state, extra = {})
      { 'grantRef' => 'g', 'root' => root, 'nodes' => nodes, 'state' => state, 'createdAt' => 0 }.merge(extra)
    end
  end

  # ======================================================================================== blueprint.rb
  t('c30 blueprint: constants are binary strings') do
    next true unless C30.on?('blueprint.rb')

    AtlasPca::AGENT_BLUEPRINT_DOMAIN.encoding == Encoding::BINARY && AtlasPca::AGENT_BLUEPRINT_DOMAIN == "atlas-pca/agent-blueprint/v1\x00".b
  end

  t('c30 blueprint: blueprint_well_formed? table') do
    next true unless C30.on?('blueprint.rb')

    bp = C30.method(:bp)
    wo = C30.method(:wo)
    d = C30::DuckH
    rows = []
    add = ->(want, rec) { rows << [want, AtlasPca.blueprint_well_formed?(rec)] }
    add.call(true, bp.call)
    [nil, 5, [], 'x', 1.5, true].each { |x| add.call(false, x) }
    add.call(false, d.new(bp.call))
    add.call(false, bp.call('v' => 2))
    add.call(false, bp.call('v' => 1.0))
    add.call(false, bp.call('v' => '1'))
    add.call(false, wo.call(bp.call, 'v'))
    %w[id key operator].each do |f|
      add.call(true, bp.call(f => 'a' * 128))
      add.call(false, bp.call(f => 'a' * 129))
      add.call(false, bp.call(f => ''))
      add.call(false, bp.call(f => 5))
      add.call(false, wo.call(bp.call, f))
    end
    %w[epoch issued_at].each do |f|
      add.call(true, bp.call(f => 0))
      add.call(false, bp.call(f => -1))
      add.call(false, bp.call(f => '1'))
      add.call(false, wo.call(bp.call, f))
    end
    add.call(true, bp.call('status' => 'disabled'))
    add.call(false, bp.call('status' => 'other'))
    add.call(false, bp.call('status' => 5))
    add.call(false, wo.call(bp.call, 'status'))
    [1, 5].each { |n| add.call(true, bp.call('max_depth' => n)) }
    [0, -1, '1', nil, 1.5].each { |n| add.call(false, bp.call('max_depth' => n)) }
    [0, 100].each { |n| add.call(true, bp.call('expires_at' => n)) }
    [-1, '5', nil, false, 1.5].each { |n| add.call(false, bp.call('expires_at' => n)) }
    add.call(true, bp.call('runtime_pins' => [{ 'model_id' => 'm' }]))
    add.call(true, bp.call('runtime_pins' => Array.new(16) { { 'model_id' => 'm' } }))
    add.call(true, bp.call('runtime_pins' => [{ 'model_id' => 'm' * 256 }]))
    add.call(false, bp.call('runtime_pins' => Array.new(17) { { 'model_id' => 'm' } }))
    add.call(false, bp.call('runtime_pins' => [{ 'model_id' => 'm' * 257 }]))
    [[], 'x', nil, {}, [{}], [5], [{ 'bogus' => 'v' }], [{ 'model_id' => 5 }], [{ 'model_id' => '' }]].each do |p|
      add.call(false, bp.call('runtime_pins' => p))
    end
    add.call(true, bp.call('ceiling' => [{ 'type' => 't' }]))
    add.call(true, bp.call('ceiling' => Array.new(32) { { 'type' => 't' } }))
    add.call(false, bp.call('ceiling' => Array.new(33) { { 'type' => 't' } }))
    [nil, 'x', {}, [5], ['type'], [{}], [{ 'type' => 5 }], [{ 'type' => 't' }, {}]].each { |c| add.call(false, bp.call('ceiling' => c)) }
    add.call(false, wo.call(bp.call, 'ceiling'))
    C30.table('bp-wf', rows)
  end

  t('c30 blueprint: verify_blueprint is exact and total') do
    next true unless C30.on?('blueprint.rb')

    ok = C30.sign_bp(C30.bp('operator' => C30.pk('op1')), 'op1')
    bad_shape = C30.sign_bp(C30.bp('operator' => C30.pk('op1'), 'status' => 'bogus'), 'op1')
    C30.table('bp-verify', [
      [true, AtlasPca.verify_blueprint(ok)],
      [false, AtlasPca.verify_blueprint(ok.merge('epoch' => 2))],
      [false, AtlasPca.verify_blueprint(ok.merge('sig' => 5))],
      [false, AtlasPca.verify_blueprint(nil)],
      [false, AtlasPca.verify_blueprint(5)],
      [false, AtlasPca.verify_blueprint(bad_shape)]
    ])
  end

  t('c30 blueprint: registry accept, operator change and epoch') do
    next true unless C30.on?('blueprint.rb')

    k1 = C30.pk('op1')
    k2 = C30.pk('op2')
    reg = AtlasPca::BlueprintRegistry.new([k1, k2], AtlasPca::MemoryBlueprintKv.new)
    r1 = C30.sign_bp(C30.bp('operator' => k1, 'epoch' => 1), 'op1')
    r2 = C30.sign_bp(C30.bp('operator' => k2, 'epoch' => 2), 'op2')
    r3 = C30.sign_bp(C30.bp('operator' => k1, 'epoch' => 1, 'issued_at' => 2), 'op1')
    empty = AtlasPca::BlueprintRegistry.new([k1], AtlasPca::MemoryBlueprintKv.new)
    rows = [[0, empty.epoch],
            [{ 'ok' => true, 'replaced' => true }, reg.accept(r1)],
            [1, reg.epoch],
            [{ 'ok' => false, 'code' => 'operator_changed' }, reg.accept(r2)],
            [1, reg.epoch],
            [{ 'ok' => false, 'code' => 'epoch_fork' }, reg.accept(r3)],
            [{ 'ok' => true, 'replaced' => false }, reg.accept(r1)],
            [{ 'ok' => false, 'code' => 'bad_record' }, reg.accept(nil)],
            [{ 'ok' => false, 'code' => 'unknown_operator' }, AtlasPca::BlueprintRegistry.new([], AtlasPca::MemoryBlueprintKv.new).accept(r1)]]
    C30.table('bp-registry', rows) && reg.get('K1') == r1
  end

  t('c30 blueprint: check_blueprints input validation, links, expiry and store faults') do
    next true unless C30.on?('blueprint.rb')

    bad = { 'decision' => 'deny', 'code' => 'bad_input' }
    reg = AtlasPca::BlueprintRegistry.new([], AtlasPca::MemoryBlueprintKv.new)
    hop = { 'issuer' => 'a', 'holder' => 'h' }
    chk = ->(chain, now = 1, mode = 'any') { AtlasPca.check_blueprints(chain, reg, now, mode) }
    rows = [[bad, chk.call(nil)], [bad, chk.call([])], [bad, chk.call(Set.new([hop]))], [bad, chk.call([5])],
            [bad, chk.call(['issuerholder'])], [bad, chk.call([hop], 'x')], [bad, chk.call([hop], -1)],
            [bad, chk.call([{ 'issuer' => 'a' * 129, 'holder' => 'h' }])],
            [bad, chk.call([{ 'issuer' => 'a', 'holder' => 'h' * 129 }])],
            [bad, chk.call([{ 'issuer' => '', 'holder' => 'h' }])],
            [bad, chk.call([{ 'issuer' => 'a' }])],
            [{ 'decision' => 'allow', 'governed' => [] }, chk.call([{ 'issuer' => 'a' * 128, 'holder' => 'h' }])],
            [{ 'decision' => 'allow', 'governed' => [] }, chk.call([{ 'issuer' => 'a', 'holder' => 'h' * 128 }])],
            [{ 'decision' => 'deny', 'code' => 'no_blueprint' }, chk.call([hop], 1, 'require')],
            [{ 'decision' => 'deny', 'code' => 'store_unreachable' }, AtlasPca.check_blueprints([hop], nil, 1, 'any')]]
    C30.table('bp-check-input', rows)
  end

  t('c30 blueprint: check_blueprints governed chains') do
    next true unless C30.on?('blueprint.rb')

    kv = AtlasPca::MemoryBlueprintKv.new
    reg = AtlasPca::BlueprintRegistry.new([], kv)
    kv.set('blueprint/rec/K', { 'id' => 'b1', 'key' => 'K', 'status' => 'active', 'ceiling' => [] })
    chain2 = [{ 'issuer' => 'root', 'holder' => 'K' }, { 'issuer' => 'K', 'holder' => 'leaf' }]
    chain1 = [{ 'issuer' => 'K', 'holder' => 'K' }]
    rows = [[{ 'decision' => 'allow', 'governed' => ['b1'] }, AtlasPca.check_blueprints(chain2, reg, 100, 'require')],
            [{ 'decision' => 'deny', 'code' => 'broken_link', 'blueprint' => 'b1' }, AtlasPca.check_blueprints(chain1, reg, 100, 'any')]]
    kv.set('blueprint/rec/K', reg.get('K').merge('expires_at' => 200))
    rows << [{ 'decision' => 'allow', 'governed' => ['b1'] }, AtlasPca.check_blueprints(chain2, reg, 199, 'require')]
    rows << [{ 'decision' => 'deny', 'code' => 'blueprint_expired', 'blueprint' => 'b1' }, AtlasPca.check_blueprints(chain2, reg, 200, 'require')]
    C30.table('bp-check-chain', rows)
  end

  # ======================================================================================== break_glass.rb
  t('c30 break_glass: constants') do
    next true unless C30.on?('break_glass.rb')

    AtlasPca::BREAK_GLASS_DOMAIN.encoding == Encoding::BINARY && AtlasPca::BREAK_GLASS_DOMAIN == "atlas-pca/break-glass/v1\x00".b &&
      AtlasPca::MAX_BREAK_GLASS_WINDOW_MS == 86_400_000 && AtlasPca::MAX_BREAK_GLASS_USES == 16 &&
      AtlasPca::MAX_REVIEW_WITHIN_MS == 2_592_000_000
  end

  t('c30 break_glass: break_glass_well_formed? table') do
    next true unless C30.on?('break_glass.rb')

    g = C30.method(:grant)
    wo = C30.method(:wo)
    rows = []
    add = ->(want, rec) { rows << [want, AtlasPca.break_glass_well_formed?(rec)] }
    add.call(true, g.call)
    [nil, 5, [], 'x', 1.5, true].each { |x| add.call(false, x) }
    add.call(false, C30::DuckH.new(g.call))
    [2, 1.0, '1'].each { |v| add.call(false, g.call('v' => v)) }
    add.call(false, wo.call(g.call, 'v'))
    [%w[id 128], %w[holder 128], %w[grant_ref 256], %w[reason_digest 128], %w[notify_to 256], %w[authority 128]].each do |f, max|
      add.call(true, g.call(f => 'a' * max.to_i))
      add.call(false, g.call(f => 'a' * (max.to_i + 1)))
      add.call(false, g.call(f => ''))
      add.call(false, g.call(f => 5))
      add.call(false, wo.call(g.call, f))
    end
    add.call(true, g.call('max_uses' => 1))
    add.call(true, g.call('max_uses' => 16))
    [0, 17, -1, '2', 2.5, nil].each { |n| add.call(false, g.call('max_uses' => n)) }
    add.call(true, g.call('issued_at' => 0, 'expires_at' => 86_400_000))
    add.call(false, g.call('issued_at' => 0, 'expires_at' => 86_400_001))
    add.call(true, g.call('issued_at' => 5, 'expires_at' => 6))
    add.call(false, g.call('issued_at' => 5, 'expires_at' => 5))
    add.call(false, g.call('issued_at' => 6, 'expires_at' => 5))
    add.call(false, g.call('issued_at' => '1'))
    add.call(false, g.call('expires_at' => '9'))
    add.call(false, g.call('issued_at' => nil))
    add.call(false, g.call('expires_at' => 2000.5))
    add.call(true, g.call('review_within' => 1))
    add.call(true, g.call('review_within' => 2_592_000_000))
    [0, 2_592_000_001, -1, '5', 5.5, nil].each { |n| add.call(false, g.call('review_within' => n)) }
    C30.table('bg-wf', rows)
  end

  t('c30 break_glass: verify_break_glass exact, total and fail-closed') do
    next true unless C30.on?('break_glass.rb')

    ok = C30.sign_grant(C30.grant)
    over = C30.sign_grant(C30.grant('max_uses' => 17))
    raiser = C30::RaiseSig[ok]
    C30.table('bg-verify', [
      [true, AtlasPca.verify_break_glass(ok)],
      [false, AtlasPca.verify_break_glass(ok.merge('max_uses' => 1))],
      [false, AtlasPca.verify_break_glass(C30.sign_grant(C30.grant, 'rev'))],
      [false, AtlasPca.verify_break_glass(over)],
      [false, AtlasPca.verify_break_glass(nil)],
      [false, AtlasPca.verify_break_glass(5)],
      [false, AtlasPca.verify_break_glass(raiser)]
    ])
  end

  t('c30 break_glass: break_glass_review_well_formed? table') do
    next true unless C30.on?('break_glass.rb')

    r = C30.method(:review)
    wo = C30.method(:wo)
    rows = []
    add = ->(want, rec) { rows << [want, AtlasPca.break_glass_review_well_formed?(rec)] }
    add.call(true, r.call)
    add.call(true, r.call('outcome' => 'unjustified'))
    [nil, 5, [], 'x', 1.5, true].each { |x| add.call(false, x) }
    add.call(false, C30::DuckH.new(r.call))
    [2, 1.0, '1'].each { |v| add.call(false, r.call('v' => v)) }
    add.call(false, wo.call(r.call, 'v'))
    %w[id notes_digest reviewer].each do |f|
      add.call(true, r.call(f => 'a' * 128))
      add.call(false, r.call(f => 'a' * 129))
      add.call(false, r.call(f => ''))
      add.call(false, r.call(f => 5))
      add.call(false, wo.call(r.call, f))
    end
    ['other', 5, nil, 'Justified'].each { |o| add.call(false, r.call('outcome' => o)) }
    add.call(true, r.call('at' => 0))
    ['1', -1, 1.5, nil].each { |a| add.call(false, r.call('at' => a)) }
    C30.table('bg-review-wf', rows)
  end

  t('c30 break_glass: verify_break_glass_review exact, total and fail-closed') do
    next true unless C30.on?('break_glass.rb')

    ok = C30.sign_review(C30.review)
    bad_shape = C30.sign_review(C30.review('outcome' => 'bogus'))
    raiser = C30::RaiseSig[ok]
    C30.table('bg-review-verify', [
      [true, AtlasPca.verify_break_glass_review(ok)],
      [false, AtlasPca.verify_break_glass_review(ok.merge('at' => 1101))],
      [false, AtlasPca.verify_break_glass_review(C30.sign_review(C30.review, 'auth'))],
      [false, AtlasPca.verify_break_glass_review(bad_shape)],
      [false, AtlasPca.verify_break_glass_review(nil)],
      [false, AtlasPca.verify_break_glass_review(5)],
      [false, AtlasPca.verify_break_glass_review(raiser)]
    ])
  end

  t('c30 break_glass: accept validates now and reports store faults') do
    next true unless C30.on?('break_glass.rb')

    g = C30.sign_grant(C30.grant)
    bad = { 'ok' => false, 'code' => 'bad_record' }
    rows = ['x', nil, -1, 1.5].map { |n| [bad, C30.bg_reg.accept(g, n)] }
    reg = C30.bg_reg
    rows << [{ 'ok' => true, 'replaced' => true }, reg.accept(g, 1000)]
    rows << [{ 'ok' => true, 'replaced' => false }, reg.accept(g, 1000)]
    rows << [{ 'ok' => false, 'code' => 'unknown_authority' }, AtlasPca::BreakGlassRegistry.new({ 'authorities' => [], 'reviewers' => [] }, AtlasPca::MemoryBreakGlassKv.new).accept(g, 1000)]
    rows << [{ 'ok' => false, 'code' => 'store_unreachable' }, AtlasPca::BreakGlassRegistry.new({}, AtlasPca::MemoryBreakGlassKv.new).accept(g, 1000)]
    C30.table('bg-accept', rows)
  end

  t('c30 break_glass: use validates its inputs to the exact bound') do
    next true unless C30.on?('break_glass.rb')

    bad = { 'decision' => 'deny', 'code' => 'bad_input' }
    reg = C30.bg_reg
    u = ->(*a) { reg.use(*a) }
    rows = [[bad, u.call('', 'h', 'd', 1, true)], [bad, u.call(5, 'h', 'd', 1, true)],
            [bad, u.call('a' * 129, 'h', 'd', 1, true)],
            [bad, u.call('g', '', 'd', 1, true)], [bad, u.call('g', 5, 'd', 1, true)], [bad, u.call('g', 'h' * 129, 'd', 1, true)],
            [bad, u.call('g', 'h', '', 1, true)], [bad, u.call('g', 'h', 5, 1, true)], [bad, u.call('g', 'h', 'd' * 129, 1, true)],
            [bad, u.call('g', 'h', 'd', 'x', true)], [bad, u.call('g', 'h', 'd', -1, true)],
            [bad, u.call('g', 'h', 'd', 1, nil)], [bad, u.call('g', 'h', 'd', 1, 'yes')], [bad, u.call('g', 'h', 'd', 1, 1)],
            [{ 'decision' => 'deny', 'code' => 'unknown_break_glass', 'id' => 'a' * 128 }, u.call('a' * 128, 'h', 'd', 1, true)],
            [{ 'decision' => 'deny', 'code' => 'unknown_break_glass', 'id' => 'g' }, u.call('g', 'h' * 128, 'd', 1, true)],
            [{ 'decision' => 'deny', 'code' => 'unknown_break_glass', 'id' => 'g' }, u.call('g', 'h', 'd' * 128, 1, false)]]
    C30.table('bg-use-input', rows)
  end

  t('c30 break_glass: use lifecycle, recorded uses and review due') do
    next true unless C30.on?('break_glass.rb')

    reg = C30.bg_reg
    rows = [[{ 'ok' => true, 'replaced' => true }, reg.accept(C30.sign_grant(C30.grant), 1000)]]
    deny = ->(code, id = 'g1') { { 'decision' => 'deny', 'code' => code, 'id' => id } }
    rows << [deny.call('not_yet_valid'), reg.use('g1', 'h1', 'dg1', 999, true)]
    rows << [deny.call('not_notified'), reg.use('g1', 'h1', 'dg1', 1000, false)]
    rows << [[], C30.uses_of(reg, 'h1', 'g1')]
    rows << [{ 'decision' => 'allow', 'id' => 'g1', 'use' => 1, 'remaining' => 1, 'review_due' => 1500 }, reg.use('g1', 'h1', 'dg1', 1000, true)]
    rows << [[{ 'n' => 1, 'action_digest' => 'dg1', 'at' => 1000 }], C30.uses_of(reg, 'h1', 'g1')]
    rows << [{ 'decision' => 'allow', 'id' => 'g1', 'use' => 2, 'remaining' => 0, 'review_due' => 1500 }, reg.use('g1', 'h1', 'dg2', 1200, true)]
    rows << [[{ 'n' => 1, 'action_digest' => 'dg1', 'at' => 1000 }, { 'n' => 2, 'action_digest' => 'dg2', 'at' => 1200 }],
             C30.uses_of(reg, 'h1', 'g1')]
    rows << [deny.call('budget_exhausted'), reg.use('g1', 'h1', 'dg3', 1300, true)]
    rows << [deny.call('holder_frozen'), reg.use('g1', 'h1', 'dg3', 1500, true)]
    rows << [true, reg.frozen('h1', 1500)]
    rows << [false, reg.frozen('h1', 1499)]
    rows << [deny.call('unknown_break_glass', 'zz'), reg.use('zz', 'h1', 'dg3', 1300, true)]

    reg2 = C30.bg_reg
    reg2.accept(C30.sign_grant(C30.grant), 1000)
    rows << [deny.call('expired'), reg2.use('g1', 'h1', 'dg1', 2000, true)]
    rows << [{ 'decision' => 'allow', 'id' => 'g1', 'use' => 1, 'remaining' => 1, 'review_due' => 2499 }, reg2.use('g1', 'h1', 'dg1', 1999, true)]
    C30.table('bg-use-flow', rows)
  end

  t('c30 break_glass: review validates its inputs and runs the justified path') do
    next true unless C30.on?('break_glass.rb')

    rv = C30.sign_review(C30.review)
    badr = { 'ok' => false, 'code' => 'bad_record' }
    unk = { 'ok' => false, 'code' => 'unknown_break_glass' }
    rows = [[badr, C30.bg_reg.review(rv, '', 1200)], [badr, C30.bg_reg.review(rv, 5, 1200)],
            [badr, C30.bg_reg.review(rv, 'h' * 129, 1200)], [badr, C30.bg_reg.review(rv, 'h1', 'x')],
            [badr, C30.bg_reg.review(rv, 'h1', -1)], [badr, C30.bg_reg.review(rv, 'h1', nil)],
            [unk, C30.bg_reg.review(rv, 'h' * 128, 1200)], [unk, C30.bg_reg.review(rv, 'h1', 1200)],
            [{ 'ok' => false, 'code' => 'unknown_reviewer' }, AtlasPca::BreakGlassRegistry.new({ 'authorities' => [], 'reviewers' => [] }, AtlasPca::MemoryBreakGlassKv.new).review(rv, 'h1', 1200)],
            [{ 'ok' => false, 'code' => 'store_unreachable' }, AtlasPca::BreakGlassRegistry.new({}, AtlasPca::MemoryBreakGlassKv.new).review(rv, 'h1', 1200)]]
    reg = C30.bg_reg
    reg.accept(C30.sign_grant(C30.grant), 1000)
    rows << [{ 'ok' => false, 'code' => 'nothing_to_review' }, reg.review(rv, 'h1', 1200)]
    reg.use('g1', 'h1', 'dg1', 1000, true)
    rows << [{ 'ok' => false, 'code' => 'bad_time' }, reg.review(C30.sign_review(C30.review('at' => 999)), 'h1', 1200)]
    rows << [{ 'ok' => false, 'code' => 'bad_time' }, reg.review(C30.sign_review(C30.review('at' => 1201)), 'h1', 1200)]
    rows << [{ 'ok' => true, 'replaced' => true }, reg.review(rv, 'h1', 1200)]
    rows << [{ 'ok' => true, 'replaced' => false }, reg.review(rv, 'h1', 1200)]
    rows << [{ 'decision' => 'allow', 'id' => 'g1', 'use' => 2, 'remaining' => 0, 'review_due' => 1500 }, reg.use('g1', 'h1', 'dg2', 1250, true)]
    rows << [false, reg.frozen('h1', 5000)]
    C30.table('bg-review-flow', rows)
  end

  t('c30 break_glass: frozen fails closed on bad input to the exact bound') do
    next true unless C30.on?('break_glass.rb')

    reg = C30.bg_reg
    C30.table('bg-frozen', [[false, reg.frozen('h' * 128, 1)], [true, reg.frozen('h' * 129, 1)], [true, reg.frozen('', 1)],
                            [true, reg.frozen(5, 1)], [true, reg.frozen('h', 'x')], [true, reg.frozen('h', -1)], [true, reg.frozen('h', nil)]])
  end

  t('c30 break_glass: a stored unjustified review freezes its holder; a justified one does not') do
    next true unless C30.on?('break_glass.rb')

    kv = AtlasPca::MemoryBreakGlassKv.new
    reg = AtlasPca::BreakGlassRegistry.new({ 'authorities' => [], 'reviewers' => [] }, kv)
    rec = ->(h) { { 'holder' => h, 'issued_at' => 0, 'expires_at' => 10**9, 'max_uses' => 5, 'review_within' => 1 } }
    shard = ->(h) { "breakglass/16/#{AtlasPca.kv_shard_of(h, 16)}" }
    kv.set(shard.call('h'), { 'grants' => { 'g1' => { 'rec' => rec.call('h'), 'uses' => [], 'review' => { 'outcome' => 'unjustified', 'sig' => 's' } } } })
    kv.set(shard.call('j'), { 'grants' => { 'g2' => { 'rec' => rec.call('j'), 'uses' => [], 'review' => { 'outcome' => 'justified', 'sig' => 's' } } } })
    C30.table('bg-revoked', [
      [{ 'decision' => 'deny', 'code' => 'holder_frozen', 'id' => 'g1' }, reg.use('g1', 'h', 'd', 5, true)],
      [{ 'decision' => 'allow', 'id' => 'g2', 'use' => 1, 'remaining' => 4, 'review_due' => 6 }, reg.use('g2', 'j', 'd', 5, true)]
    ])
  end

  t('c30 break_glass: a fault in the store denies / freezes (fail closed)') do
    next true unless C30.on?('break_glass.rb')

    kv = AtlasPca::MemoryBreakGlassKv.new
    reg = AtlasPca::BreakGlassRegistry.new({ 'authorities' => [], 'reviewers' => [] }, kv)
    kv.set("breakglass/16/#{AtlasPca.kv_shard_of('h1', 16)}", { 'grants' => { 'g1' => { 'rec' => nil, 'uses' => [], 'review' => nil } } })
    C30.table('bg-store-fault', [
      [{ 'decision' => 'deny', 'code' => 'store_unreachable', 'id' => 'g1' }, reg.use('g1', 'h1', 'd', 1, true)],
      [true, reg.frozen('h1', 1)]
    ])
  end

  # ======================================================================================== optimistic.rb
  t('c30 optimistic: window policy constant') do
    next true unless C30.on?('optimistic.rb')

    C30.same('policy', { 'minWindowMs' => 1000, 'maxWindowMs' => 86_400_000, 'defaultWindowMs' => 300_000, 'maxSkewMs' => 5000 },
             AtlasPca::DEFAULT_WINDOW_POLICY)
  end

  t('c30 optimistic: opt_num?, opt_get') do
    next true unless C30.on?('optimistic.rb')

    rows = [[true, AtlasPca.opt_num?(1)], [true, AtlasPca.opt_num?(1.5)], [true, AtlasPca.opt_num?(0)],
            [false, AtlasPca.opt_num?(Float::INFINITY)], [false, AtlasPca.opt_num?(-Float::INFINITY)],
            [false, AtlasPca.opt_num?(Float::NAN)], [false, AtlasPca.opt_num?('1')], [false, AtlasPca.opt_num?(nil)],
            [false, AtlasPca.opt_num?(true)]]
    miss = AtlasPca::OPT_MISSING
    rows << [true, AtlasPca.opt_get({}, 'x').equal?(miss)]
    rows << [true, AtlasPca.opt_get({ 'y' => 1 }, 'x').equal?(miss)]
    rows << [nil, AtlasPca.opt_get({ 'x' => nil }, 'x')]
    rows << [5, AtlasPca.opt_get({ 'x' => 5 }, 'x')]
    C30.table('opt-num', rows)
  end

  t('c30 optimistic: opt_same? is JS strict equality') do
    next true unless C30.on?('optimistic.rb')

    eq = C30::Eq.new
    rows = [[true, true, true], [false, false, true], [true, false, false], [false, true, false], [true, 1, false], [1, true, false],
            [nil, false, false], [false, nil, false], [false, 0, false], [0, false, false],
            [1, 1.0, true], [1.0, 1, true], [1, 2, false], [1.5, 1.5, true], ['a', 'a', true], ['a', 'b', false], ['1', 1, false],
            [nil, nil, true], [nil, 0, false],
            [C30::EqTrue.new, true, false], [true, C30::EqTrue.new, false],
            [1, eq, false], [eq, 1, false], [eq, 'x', false], ['x', eq, false]]
    C30.table('opt-same', rows.map { |a, b, want| [want, AtlasPca.opt_same?(a, b)] })
  end

  t('c30 optimistic: opt_validate_window exact reasons and bounds') do
    next true unless C30.on?('optimistic.rb')

    pol = { 'minWindowMs' => 10, 'maxWindowMs' => 100, 'defaultWindowMs' => 50, 'maxSkewMs' => 5 }
    v = ->(i, w, n) { AtlasPca.opt_validate_window(i, w, n, pol) }
    finite = 'server time is not finite'
    malformed = 'malformed challenge window'
    skew = 'issued_at is outside the allowed skew of server time'
    below = 'challenge window is below the minimum'
    above = 'challenge window exceeds the maximum'
    C30.table('opt-window', [
      [nil, v.call(100, 50, 100)], [nil, v.call(105, 50, 100)], [skew, v.call(106, 50, 100)], [nil, v.call(95, 50, 100)],
      [skew, v.call(94, 50, 100)], [nil, v.call(100, 10, 100)], [below, v.call(100, 9, 100)], [nil, v.call(100, 100, 100)],
      [above, v.call(100, 101, 100)], [skew, v.call(500, 1, 100)],
      [finite, v.call(nil, nil, 'x')], [finite, v.call(100, 50, Float::NAN)], [finite, v.call(100, 50, Float::INFINITY)],
      [finite, v.call(100, 50, nil)],
      [malformed, v.call(nil, 50, 100)], [malformed, v.call(100, 'a', 100)], [malformed, v.call(Float::NAN, 50, 100)],
      [malformed, v.call(100, nil, 100)]
    ])
  end

  t('c30 optimistic: claim_check exact reasons, default policy and fault') do
    next true unless C30.on?('optimistic.rb')

    cb = { 'pcactn_digest' => 'D', 'claimed_r' => 1, 'issued_at' => 1000, 'challenge_window_ms' => 1000, 'sig' => 'S',
           'reversibility_class' => 'reversible' }
    cc = ->(claim, pol = nil) { AtlasPca.claim_check(claim, 'D', 'P', 1000, pol) }
    custom = { 'minWindowMs' => 100, 'maxWindowMs' => 1000, 'maxSkewMs' => 10 }
    C30.table('opt-claim', [
      ['malformed', cc.call(C30::DuckH.new({ 'reversibility_class' => 'irreversible' }))],
      ['malformed', cc.call(nil)], ['malformed', cc.call('x')],
      ['irreversible', cc.call(cb.merge('reversibility_class' => 'irreversible'))],
      ['window', cc.call(cb.merge('challenge_window_ms' => 1))],
      ['window', cc.call(cb.merge('challenge_window_ms' => 999))],
      ['signature', cc.call(cb.merge('challenge_window_ms' => 1000))],
      ['signature', cc.call(cb.merge('challenge_window_ms' => 500), custom)],
      ['window', cc.call(cb.merge('challenge_window_ms' => 99), custom)],
      ['malformed', cc.call(cb, Object.new)]
    ])
  end

  t('c30 optimistic: claim_check signs domain || canonical(body without sig) and only a String sig reaches verification') do
    next true unless C30.on?('optimistic.rb')

    cb = { 'pcactn_digest' => 'D', 'claimed_r' => 1, 'issued_at' => 1000, 'challenge_window_ms' => 1000, 'sig' => 'S',
           'reversibility_class' => 'reversible' }
    calls = []
    res = []
    MutationKill::Seam.with(AtlasPca, { verify_b64u: ->(*a) { calls << a; true } }) do
      res << AtlasPca.claim_check(cb, 'D', 'PUB', 1000)
      res << AtlasPca.claim_check(cb.merge('sig' => 5), 'D', 'PUB', 1000)
      res << AtlasPca.claim_check(cb.reject { |k, _| k == 'sig' }, 'D', 'PUB', 1000)
    end
    want_msg = AtlasPca::OPTIMISTIC_CLAIM_DOMAIN.b + AtlasPca.canon_bytes(cb.reject { |k, _| k == 'sig' })
    pub, msg, sig = calls[0]
    C30.same('results', %w[ok signature signature], res) && C30.same('call count', 1, calls.length) &&
      C30.same('args', %w[PUB S], [pub, sig]) && msg == want_msg && msg.encoding == Encoding::BINARY
  end

  t('c30 optimistic: fraud_proof_wire_check shape, kinds and margins') do
    next true unless C30.on?('optimistic.rb')

    claim = { 'pcactn_digest' => 'D', 'bond_ref' => 'B', 'claimed_r' => 1, 'reversibility_class' => 'reversible' }
    dec = ->(rel, allowed, r) { { 'releaseGuardianShare' => rel, 'optimisticAllowed' => allowed, 'r' => r } }
    proof = lambda do |kind, d, extra = {}|
      { 'pcactn_digest' => 'D', 'bond_ref' => 'B', 'reason' => 'why', 'claimed_r' => 1, 'kind' => kind, 'decision' => d }.merge(extra)
    end
    fc = ->(c, p) { AtlasPca.fraud_proof_wire_check(c, p) }
    duck = C30::DuckH
    irrev = proof.call('irreversible', dec.call(true, true, 1))
    rows = [
      ['ok', fc.call(claim, proof.call('policy-denied', dec.call(false, true, 1)))],
      ['malformed', fc.call(claim, duck.new(proof.call('policy-denied', dec.call(false, true, 1))))],
      ['malformed', fc.call(duck.new(claim), proof.call('policy-denied', dec.call(false, true, 1)))],
      ['malformed', fc.call(nil, nil)], ['malformed', fc.call(claim, 'x')], ['malformed', fc.call('x', proof.call('policy-denied', dec.call(false, true, 1)))],
      ['malformed', fc.call(claim, proof.call('policy-denied', duck.new(dec.call(false, true, 1))))],
      ['malformed', fc.call(claim, proof.call('policy-denied', dec.call(false, 1, 1)))],
      ['malformed', fc.call(claim, proof.call('policy-denied', dec.call(false, nil, 1)))],
      ['malformed', fc.call(claim, proof.call('policy-denied', dec.call(1, true, 1)))],
      ['malformed', fc.call(claim, proof.call('policy-denied', dec.call(false, true, 'x')))],
      ['kind', fc.call(claim, proof.call(C30::KindLike.new, dec.call(false, true, 1)))],
      ['kind', fc.call(claim, proof.call('nope', dec.call(false, true, 1)))],
      ['kind', fc.call(claim, proof.call(5, dec.call(false, true, 1)))],
      ['digest', fc.call(claim, proof.call('policy-denied', dec.call(false, true, 1), 'pcactn_digest' => 'X'))],
      ['bond', fc.call(claim, proof.call('policy-denied', dec.call(false, true, 1), 'bond_ref' => 'X'))],
      ['claimed_r', fc.call(claim, proof.call('policy-denied', dec.call(false, true, 1), 'claimed_r' => 2))],
      # irreversible: the claim class, else evidence.action.action.reversibility_class (optimistic.ts:477)
      ['ok', fc.call(claim.merge('reversibility_class' => 'irreversible'), irrev)],
      ['consistency', fc.call(claim, irrev)],
      ['ok', fc.call(claim, irrev.merge('evidence' => { 'action' => { 'action' => { 'reversibility_class' => 'irreversible' } } }))],
      ['consistency', fc.call(claim, irrev.merge('evidence' => { 'action' => { 'action' => { 'reversibility_class' => 'reversible' } } }))],
      ['consistency', fc.call(claim, irrev.merge('evidence' => duck.new({ 'action' => { 'action' => { 'reversibility_class' => 'irreversible' } } })))],
      ['consistency', fc.call(claim, irrev.merge('evidence' => { 'action' => duck.new({ 'action' => { 'reversibility_class' => 'irreversible' } }) }))],
      ['consistency', fc.call(claim, irrev.merge('evidence' => { 'action' => { 'action' => duck.new({ 'reversibility_class' => 'irreversible' }) } }))],
      ['consistency', fc.call(claim, irrev.merge('evidence' => 'x'))],
      # optimistic-not-allowed / policy-denied
      ['ok', fc.call(claim, proof.call('optimistic-not-allowed', dec.call(true, false, 0)))],
      ['consistency', fc.call(claim, proof.call('optimistic-not-allowed', dec.call(true, true, 0)))],
      ['consistency', fc.call(claim, proof.call('optimistic-not-allowed', dec.call(false, false, 0)))],
      ['consistency', fc.call(claim, proof.call('policy-denied', dec.call(true, true, 0)))],
      # risk-understated: r > claimed_r + margin, margin = max(0, r_margin) or 1e-9
      ['consistency', fc.call(claim, proof.call('risk-understated', dec.call(true, true, 3), 'r_margin' => 2))],
      ['ok', fc.call(claim, proof.call('risk-understated', dec.call(true, true, 4), 'r_margin' => 2))],
      ['ok', fc.call(claim, proof.call('risk-understated', dec.call(true, true, 1.0000001)))],
      ['consistency', fc.call(claim, proof.call('risk-understated', dec.call(true, true, 1)))],
      ['ok', fc.call(claim, proof.call('risk-understated', dec.call(true, true, 1.5), 'r_margin' => -5))],
      ['consistency', fc.call(claim, proof.call('risk-understated', dec.call(true, true, 1), 'r_margin' => -5))],
      ['consistency', fc.call(claim, proof.call('risk-understated', dec.call(false, true, 100)))],
      ['consistency', fc.call(claim, proof.call('risk-understated', dec.call(true, false, 100)))],
      ['malformed', fc.call(claim.merge('claimed_r' => 'x'), proof.call('risk-understated', dec.call(true, true, 5), 'claimed_r' => 'x'))]
    ]
    C30.table('opt-fraud', rows)
  end

  t('c30 optimistic: settlement_wire_check shape, split arithmetic, signed message and faults') do
    next true unless C30.on?('optimistic.rb')

    open_rec = { 'claimId' => 'c1', 'action' => 'open', 'amount' => 1, 'from' => 'a', 'to' => 'b', 'at' => 5, 'evidenceDigest' => '', 'sig' => 'S' }
    split = { 'amount' => 10, 'challengerAccount' => 'ch', 'challengerReward' => 3, 'victimCompensation' => 4, 'treasuryRemainder' => 3,
              'victimAccount' => 'v', 'treasuryAccount' => 'T' }
    slash = { 'claimId' => 'c1', 'action' => 'slash', 'amount' => 10, 'from' => 'a', 'to' => 'T', 'at' => 5, 'evidenceDigest' => 'ev',
              'sig' => 'S', 'split' => split }
    nilc = lambda do |c, v, t, amount = 100|
      slash.merge('amount' => amount, 'split' => split.merge('amount' => amount, 'challengerAccount' => nil, 'challengerReward' => c,
                                                              'victimCompensation' => v, 'treasuryRemainder' => t))
    end
    big = 9_007_199_254_740_992
    rows = []
    MutationKill::Seam.with(AtlasPca::IntentV2, { verify_pinned_suite: ->(*_a) { true } }) do
      sw = ->(r) { AtlasPca.settlement_wire_check(r, 'GP') }
      rows = [
        ['ok', sw.call(open_rec)], ['ok', sw.call(open_rec.merge('amount' => 1.5))],
        ['shape', sw.call(open_rec.merge('amount' => 0))], ['shape', sw.call(open_rec.merge('amount' => -1))],
        ['shape', sw.call(open_rec.merge('amount' => 'x'))], ['shape', sw.call(open_rec.merge('sig' => 5))],
        ['shape', sw.call(open_rec.merge('evidenceDigest' => 'x'))], ['shape', sw.call(open_rec.merge('evidenceDigest' => nil))],
        ['shape', sw.call(open_rec.merge('split' => split))], ['shape', sw.call(open_rec.merge('action' => 'bogus'))],
        ['shape', sw.call(open_rec.merge('claimId' => ''))],
        ['malformed', sw.call(nil)], ['malformed', sw.call('x')], ['malformed', sw.call(C30::DuckH.new(open_rec))],
        ['ok', sw.call(slash)],
        ['shape', sw.call(slash.merge('evidenceDigest' => ['x']))], ['shape', sw.call(slash.merge('evidenceDigest' => ''))],
        ['shape', sw.call(slash.merge('evidenceDigest' => 5))],
        ['shape', sw.call(slash.merge('split' => 5))], ['shape', sw.call(slash.merge('split' => ['x']))],
        ['shape', sw.call(slash.merge('split' => 'split'))],
        ['split', sw.call(slash.merge('split' => split.merge('challengerReward' => 4)))],
        ['split', sw.call(slash.merge('split' => split.merge('victimAccount' => '')))],
        ['split', sw.call(slash.merge('split' => split.merge('treasuryAccount' => 'U')))],
        ['split', sw.call(slash.merge('split' => split.merge('amount' => 11)))],
        ['split', sw.call(slash.merge('split' => split.merge('challengerAccount' => '')))],
        ['ok', sw.call(nilc.call(0, 0, 100))],
        ['split', sw.call(nilc.call(1e-20, 0, 100))],
        ['split', sw.call(nilc.call(0, 1e-20, 100))],
        ['split', sw.call(nilc.call(1, 0, 99))],
        ['split', sw.call(nilc.call(0.0, 0.0, big + 1, big))],
        # the split holds, then strict canonical refuses an unsafe integer / float zero: 'malformed', never 'split'
        ['malformed', sw.call(nilc.call(0.0, 0.0, big, big))]
      ]
    end
    C30.table('opt-settle', rows)
  end

  t('c30 optimistic: settlement_wire_check passes the exact message, suite arguments and pins to verification') do
    next true unless C30.on?('optimistic.rb')

    open_rec = { 'claimId' => 'c1', 'action' => 'open', 'amount' => 1, 'from' => 'a', 'to' => 'b', 'at' => 5, 'evidenceDigest' => '', 'sig' => 'S',
                 'pq_sig' => 'PQ' }
    calls = []
    a = b = c = d = nil
    MutationKill::Seam.with(AtlasPca::IntentV2, { verify_pinned_suite: ->(*x) { calls << x; true } }) do
      a = AtlasPca.settlement_wire_check(open_rec.reject { |k, _| k == 'pq_sig' }, 'GP')
      b = AtlasPca.settlement_wire_check(open_rec.merge('pq_pk' => 'PK'), 'GP', { 'GP' => 'PK' })
    end
    MutationKill::Seam.with(AtlasPca::IntentV2, { verify_pinned_suite: ->(*_x) { false } }) { c = AtlasPca.settlement_wire_check(open_rec, 'GP') }
    MutationKill::Seam.with(AtlasPca::IntentV2, { verify_pinned_suite: ->(*_x) { raise 'down' } }) { d = AtlasPca.settlement_wire_check(open_rec, 'GP') }
    undef_ = AtlasPca::V2JS::UNDEF
    body1 = { 'claimId' => 'c1', 'action' => 'open', 'amount' => 1, 'from' => 'a', 'to' => 'b', 'at' => 5, 'evidenceDigest' => '' }
    want1 = AtlasPca::OPTIMISTIC_SETTLEMENT_DOMAIN.b + AtlasPca.canon_bytes(body1)
    c1 = calls[0]
    c2 = calls[1]
    body2 = body1.merge('pq_pk' => 'PK')
    want2 = AtlasPca::OPTIMISTIC_SETTLEMENT_DOMAIN.b + AtlasPca.canon_bytes(body2)
    C30.same('a', 'ok', a) && C30.same('b', 'ok', b) && C30.same('c', 'signature', c) && C30.same('d', 'malformed', d) &&
      C30.same('ncalls', 2, calls.length) &&
      c1[0].equal?(undef_) && c1[1] == 'GP' && c1[2].equal?(undef_) && c1[3] == want1 && c1[3].encoding == Encoding::BINARY &&
      c1[4] == 'S' && c1[5].equal?(undef_) && c1[6].nil? &&
      c2[0].equal?(undef_) && c2[2] == 'PK' && c2[3] == want2 && c2[5] == 'PQ' && c2[6] == { 'GP' => 'PK' }
  end

  # ======================================================================================== plan_lifecycle.rb
  t('c30 plan: PLAN_STATES, plan_uri_component and create_plan_registry') do
    next true unless C30.on?('plan_lifecycle.rb')

    r = AtlasPca.create_plan_registry(now: -> { 9 })
    d = r.draft('g', C30.pl_nodes)
    C30.same('states', %w[draft validated committed authorized revoked], AtlasPca::PLAN_STATES) &&
      C30.same('uri', "a%20b%2F%C3%A9%25-_.!~*'()", AtlasPca.plan_uri_component("a b/é%-_.!~*'()")) &&
      C30.same('uri2', 'AZaz09', AtlasPca.plan_uri_component('AZaz09')) &&
      C30.same('uri3', '%00%7F%2B%3A', AtlasPca.plan_uri_component("\x00\x7F+:")) &&
      r.is_a?(AtlasPca::PlanRegistry) && d['ok'] == true && d['record']['createdAt'] == 9
  end

  t('c30 plan: plan_root hashes the pre and post conditions of every node') do
    next true unless C30.on?('plan_lifecycle.rb')

    n = { 'id' => 'a', 'verb' => 'v', 'resource' => '/r', 'pre' => { 'x' => 1 }, 'post' => { 'y' => 2 } }
    want = AtlasPca.merkle_root([AtlasPca.plan_leaf('a', n, AtlasPca.conditions_digest({ 'x' => 1 }, { 'y' => 2 }))])
    r0 = AtlasPca.plan_root([n])
    r1 = AtlasPca.plan_root([n.merge('pre' => { 'x' => 2 })])
    r2 = AtlasPca.plan_root([n.merge('post' => { 'y' => 3 })])
    r0 == want && r0 != r1 && r0 != r2 && r1 != r2
  end

  t('c30 plan: plan_structural_problem exact reasons') do
    next true unless C30.on?('plan_lifecycle.rb')

    node = ->(over = {}) { { 'id' => 'a', 'verb' => 'v', 'resource' => '/r' }.merge(over) }
    one = 'a plan needs at least one node'
    noid = 'every node needs an id'
    vr = "node 'a' needs a verb and a resource"
    sp = ->(nodes) { AtlasPca.plan_structural_problem(nodes) }
    rows = [[one, sp.call(nil)], [one, sp.call(5)], [one, sp.call([])], [one, sp.call({ 'a' => 1 })], [one, sp.call('x')],
            [noid, sp.call([5])], [noid, sp.call(['id'])], [noid, sp.call([{}])], [noid, sp.call([node.call('id' => 5)])],
            [noid, sp.call([node.call('id' => '')])], [noid, sp.call([node.call('id' => nil)])],
            ["duplicate node id 'a'", sp.call([node.call, node.call])],
            [vr, sp.call([node.call('verb' => nil)])], [vr, sp.call([node.call('verb' => '')])], [vr, sp.call([node.call('verb' => 5)])],
            [vr, sp.call([node.call('resource' => nil)])], [vr, sp.call([node.call('resource' => '')])], [vr, sp.call([node.call('resource' => 5)])],
            [vr, sp.call([{ 'id' => 'a' }])],
            ["node 'a' has an unknown reversibility class 'bogus'", sp.call([node.call('reversibility_class' => 'bogus')])],
            ["node 'a' has an unknown reversibility class '5'", sp.call([node.call('reversibility_class' => 5)])],
            ["node 'a' has an unknown reversibility class 'null'", sp.call([node.call('reversibility_class' => nil)])],
            ["node 'a' has an unknown reversibility class '#{AtlasPca::V2JS.js_str(1.0)}'", sp.call([node.call('reversibility_class' => 1.0)])],
            ["node 'a' has an unknown reversibility class 'CL'", sp.call([node.call('reversibility_class' => C30::ClassLike.new)])],
            [nil, sp.call([node.call])], [nil, sp.call(C30.pl_nodes)]]
    %w[reversible rate_limited costly irreversible].each { |c| rows << [nil, sp.call([node.call('reversibility_class' => c)])] }
    rows << [nil, sp.call([node.call, node.call('id' => 'b')])]
    C30.table('plan-structural', rows)
  end

  t('c30 plan: constructor defaults, store, prefix and clock') do
    next true unless C30.on?('plan_lifecycle.rb')

    nodes = C30.pl_nodes
    t0 = (Time.now.to_f * 1000).to_i
    d0 = AtlasPca::PlanRegistry.new.draft('g', nodes)
    t1 = (Time.now.to_f * 1000).to_i
    c = d0['record']['createdAt']
    root = d0['record']['root']
    kv = AtlasPca::MemoryAtomicKv.new
    reg = AtlasPca::PlanRegistry.new(kv: kv, now: -> { 3 })
    reg.draft('g', nodes)
    stored = kv.get(reg.send(:key, 'g', root))
    pre = AtlasPca::PlanRegistry.new(prefix: 'x:')
    C30.same('default clock', true, c.is_a?(Integer) && c >= t0 && c <= t1) &&
      C30.same('default store', 'draft', AtlasPca::PlanRegistry.new.tap { |r| r.draft('g', nodes) }.get('g', root)['state']) &&
      C30.same('kv used', ['draft', 3], [stored['state'], stored['createdAt']]) &&
      C30.same('key', "pca-plan:g:#{root}", reg.send(:key, 'g', root)) &&
      C30.same('key enc', 'pca-plan:a%2Fb:r', reg.send(:key, 'a/b', 'r')) &&
      C30.same('prefix', 'x:g:r', pre.send(:key, 'g', 'r')) &&
      C30.same('no validator', true, C30.pl_reg[0].tap { |r| r.draft('g', nodes) }.validate('g', root)['ok'])
  end

  t('c30 plan: get ignores anything that is not a plan record') do
    next true unless C30.on?('plan_lifecycle.rb')

    reg, kv, = C30.pl_reg
    key = reg.send(:key, 'g', 'R')
    junk = ['junk', 'root nodes', { 'root' => 5, 'nodes' => [] }, { 'root' => 'R', 'nodes' => 'n' }, { 'root' => 'R' }, { 'nodes' => [] }, 5,
            C30::DuckH.new({ 'root' => 'R', 'nodes' => [] })]
    rows = junk.map { |j| kv.set(key, j); [nil, reg.get('g', 'R')] }
    good = { 'root' => 'R', 'nodes' => [], 'state' => 'draft' }
    kv.set(key, good)
    rows << [good, reg.get('g', 'R')]
    C30.table('plan-get', rows)
  end

  t('c30 plan: draft refuses bad grants, unhashable plans and copies the nodes') do
    next true unless C30.on?('plan_lifecycle.rb')

    reg, = C30.pl_reg
    nogrant = { 'ok' => false, 'state' => 'unknown', 'reason' => 'a plan needs a grant' }
    rows = [nil, '', 5, :g, []].map { |g| [nogrant, reg.draft(g, C30.pl_nodes)] }
    rows << [{ 'ok' => false, 'state' => 'unknown', 'reason' => 'the plan cannot be committed: merkleRoot: by-message' }, reg.draft('g', [C30::Odd.new])]
    rows << [{ 'ok' => false, 'state' => 'unknown', 'reason' => 'the plan cannot be committed: merkleRoot: empty leaf set' }, reg.draft('g', [])]
    nodes = C30.pl_nodes
    d = reg.draft('g', nodes)
    root = d['record']['root']
    rows << [{ 'grantRef' => 'g', 'root' => root, 'nodes' => C30.pl_nodes, 'state' => 'draft', 'createdAt' => 0 }, d['record']]
    nodes[0]['verb'] = 'changed'
    rows << ['read', d['record']['nodes'][0]['verb']]
    rows << [{ 'ok' => false, 'state' => 'draft', 'reason' => "plan #{root} already exists (draft)" }, reg.draft('g', C30.pl_nodes)]
    C30.table('plan-draft', rows) && !d['record']['nodes'].equal?(nodes)
  end

  t('c30 plan: validate checks structure and root, runs the validator and fails closed') do
    next true unless C30.on?('plan_lifecycle.rb')

    reg, kv, clk = C30.pl_reg
    root = reg.draft('g', C30.pl_nodes)['record']['root']
    clk[0] = 7
    v = reg.validate('g', root)
    rows = [[true, v['ok']], [{ 'grantRef' => 'g', 'root' => root, 'nodes' => C30.pl_nodes, 'state' => 'validated', 'createdAt' => 0, 'validatedAt' => 7 }, v['record']],
            [{ 'ok' => false, 'state' => 'unknown', 'reason' => 'plan nope is unknown for this grant' }, reg.validate('g', 'nope')],
            [{ 'ok' => false, 'state' => 'validated', 'reason' => "plan #{root} is validated: cannot validate" }, reg.validate('g', root)]]
    dup = [{ 'id' => 'a', 'verb' => 'v', 'resource' => '/r' }, { 'id' => 'a', 'verb' => 'v', 'resource' => '/r' }]
    C30.pl_put(kv, reg, 'g', 'WRONG', C30.rec_of('WRONG', dup, 'draft'))
    rows << [{ 'ok' => false, 'state' => 'draft', 'reason' => "plan WRONG is invalid: duplicate node id 'a'" }, reg.validate('g', 'WRONG')]
    C30.pl_put(kv, reg, 'g', 'WRONG2', C30.rec_of('WRONG2', C30.pl_nodes, 'draft'))
    rows << [{ 'ok' => false, 'state' => 'draft', 'reason' => 'plan WRONG2 is invalid: the stored nodes no longer hash to the root' }, reg.validate('g', 'WRONG2')]
    unhashable = [{ 'id' => 'a', 'verb' => 'v', 'resource' => '/r', 'pre' => :sym }]
    C30.pl_put(kv, reg, 'g', 'WRONG3', C30.rec_of('WRONG3', unhashable, 'draft'))
    rows << [{ 'ok' => false, 'state' => 'draft', 'reason' => 'plan WRONG3 is invalid: the stored nodes no longer hash to the root' }, reg.validate('g', 'WRONG3')]
    C30.table('plan-validate', rows)
  end

  t('c30 plan: validate reads the validator verdict exactly') do
    next true unless C30.on?('plan_lifecycle.rb')

    duck = C30::DuckH
    refused = 'refused by the validator'
    table = [[nil, refused], [true, refused], [{ 'ok' => false }, refused], [{ 'ok' => false, 'reason' => '' }, refused],
             [{ 'ok' => false, 'reason' => 'because' }, 'because'], [{ 'ok' => nil, 'reason' => 'x' }, refused],
             [{ 'ok' => 'yes', 'reason' => 'x' }, refused], [{ 'ok' => 1, 'reason' => 'x' }, refused], [duck.new({ 'ok' => true }), refused],
             [duck.new({ 'ok' => false, 'reason' => 'x' }), refused], [{ 'ok' => true }, :accepted], [{ 'ok' => true, 'reason' => 'ignored' }, :accepted]]
    rows = table.map do |ret, why|
      reg, = C30.pl_reg(validator: ->(_r) { ret })
      root = reg.draft('g', C30.pl_nodes)['record']['root']
      got = reg.validate('g', root)
      if why == :accepted
        [['validated', true], [got['record']['state'], got['ok']]]
      else
        [{ 'ok' => false, 'state' => 'draft', 'reason' => "plan #{root} is invalid: #{why}" }, got]
      end
    end
    C30.table('plan-validator', rows)
  end

  t('c30 plan: validate fails closed on a validator fault, passes a copy, and is not run twice') do
    next true unless C30.on?('plan_lifecycle.rb')

    reg, = C30.pl_reg(validator: ->(_r) { raise C30::OddErr })
    root = reg.draft('g', C30.pl_nodes)['record']['root']
    rows = [[{ 'ok' => false, 'state' => 'draft', 'reason' => "plan #{root} is invalid: validator error (fail closed): by-message" }, reg.validate('g', root)]]

    seen = []
    reg2, = C30.pl_reg(validator: lambda { |r|
      seen << r.dup
      r['state'] = 'mutated'
      { 'ok' => false, 'reason' => 'no' }
    })
    root2 = reg2.draft('g', C30.pl_nodes)['record']['root']
    rows << [{ 'ok' => false, 'state' => 'draft', 'reason' => "plan #{root2} is invalid: no" }, reg2.validate('g', root2)]
    rows << [1, seen.length]
    rows << [{ 'grantRef' => 'g', 'root' => root2, 'nodes' => C30.pl_nodes, 'state' => 'draft', 'createdAt' => 0 }, seen[0]]

    mode = [:accept]
    calls = []
    reg3, = C30.pl_reg(validator: ->(r) { calls << r['state']; mode[0] == :accept ? { 'ok' => true } : { 'ok' => false, 'reason' => 'nope' } })
    root3 = reg3.draft('g', C30.pl_nodes)['record']['root']
    reg3.validate('g', root3)
    mode[0] = :refuse
    rows << [{ 'ok' => false, 'state' => 'validated', 'reason' => "plan #{root3} is validated: cannot validate" }, reg3.validate('g', root3)]
    rows << [['draft'], calls]

    reg4 = nil
    reg4, = C30.pl_reg(validator: ->(r) { reg4.revoke('g', r['root'], 'x'); { 'ok' => true } })
    root4 = reg4.draft('g', C30.pl_nodes)['record']['root']
    rows << [{ 'ok' => false, 'state' => 'revoked', 'reason' => "plan #{root4} is revoked: cannot validate" }, reg4.validate('g', root4)]
    C30.table('plan-validator-fault', rows)
  end

  t('c30 plan: commit, authorize and revoke transitions') do
    next true unless C30.on?('plan_lifecycle.rb')

    reg, kv, clk = C30.pl_reg
    root = reg.draft('g', C30.pl_nodes)['record']['root']
    rows = [[{ 'ok' => false, 'state' => 'draft', 'reason' => "plan #{root} is draft: cannot commit" }, reg.commit('g', root)],
            [{ 'ok' => false, 'state' => 'unknown', 'reason' => 'plan nosuch is unknown for this grant' }, reg.commit('g', 'nosuch')],
            [true, kv.get(reg.send(:key, 'g', 'nosuch')).nil?]]
    reg.validate('g', root)
    clk[0] = 11
    rows << [11, reg.commit('g', root)['record']['committedAt']]
    bad = 'an approval names who approved (`by`)'
    [nil, 'by', {}, { 'by' => 5 }, { 'by' => '' }, [], { 'by' => nil }].each do |a|
      rows << [{ 'ok' => false, 'state' => 'committed', 'reason' => bad }, reg.authorize('g', root, a)]
    end
    rows << [{ 'ok' => false, 'state' => 'unknown', 'reason' => bad }, reg.authorize('g', 'nosuch', nil)]
    badexp = 'approval.expiresAt must be a time (epoch ms)'
    [Float::INFINITY, -Float::INFINITY, Float::NAN, '5', nil, 10**400, true, [5]].each do |e|
      rows << [{ 'ok' => false, 'state' => 'committed', 'reason' => badexp }, reg.authorize('g', root, { 'by' => 'p', 'expiresAt' => e })]
    end
    rows << [{ 'ok' => false, 'state' => 'unknown', 'reason' => badexp }, reg.authorize('g', 'nosuch', { 'by' => 'p', 'expiresAt' => '5' })]
    approval = { 'by' => 'p', 'expiresAt' => 5.5 }
    clk[0] = 12
    a = reg.authorize('g', root, approval)
    rows << [true, a['ok']]
    rows << [{ 'by' => 'p', 'expiresAt' => 5.5 }, a['record']['approval']]
    rows << [['authorized', 12], [a['record']['state'], a['record']['authorizedAt']]]
    rows << [{ 'ok' => false, 'state' => 'authorized', 'reason' => "plan #{root} is authorized: cannot authorize" }, reg.authorize('g', root, approval)]
    C30.table('plan-transitions', rows) && !a['record']['approval'].equal?(approval)
  end

  t('c30 plan: authorize accepts finite epoch-ms numbers') do
    next true unless C30.on?('plan_lifecycle.rb')

    rows = [5, 5.5, 0, -3, 10**18].map do |e|
      reg, = C30.pl_reg
      root = C30.pl_committed(reg)
      [true, reg.authorize('g', root, { 'by' => 'p', 'expiresAt' => e })['ok']]
    end
    reg, = C30.pl_reg
    root = C30.pl_committed(reg)
    rows << [true, reg.authorize('g', root, { 'by' => 'p' })['ok']]
    C30.table('plan-authorize-ok', rows)
  end

  t('c30 plan: revoke records the reason') do
    next true unless C30.on?('plan_lifecycle.rb')

    rows = [[nil, ''], [5, '5'], ['because', 'because'], ['', ''], [1.0, AtlasPca::V2JS.js_str(1.0)]].map do |reason, want|
      reg, _kv, clk = C30.pl_reg
      root = reg.draft('g', C30.pl_nodes)['record']['root']
      clk[0] = 21
      r = reg.revoke('g', root, reason)
      [[true, 'revoked', 21, want], [r['ok'], r['record']['state'], r['record']['revokedAt'], r['record']['revokedReason']]]
    end
    reg, = C30.pl_reg
    root = reg.draft('g', C30.pl_nodes)['record']['root']
    reg.revoke('g', root, 'x')
    rows << [{ 'ok' => false, 'state' => 'revoked', 'reason' => "plan #{root} is revoked: cannot revoke" }, reg.revoke('g', root, 'y')]
    rows << [{ 'ok' => false, 'state' => 'unknown', 'reason' => 'plan nosuch is unknown for this grant' }, reg.revoke('g', 'nosuch', 'y')]
    C30.table('plan-revoke', rows)
  end

  t('c30 plan: status reasons, expiry boundary and clock') do
    next true unless C30.on?('plan_lifecycle.rb')

    reg, kv, clk = C30.pl_reg
    root = C30.pl_authorized(reg, { 'by' => 'p', 'expiresAt' => 1000 })
    rec = reg.get('g', root)
    rows = [[{ 'state' => 'authorized', 'executable' => true, 'record' => rec }, reg.status('g', root, 999)],
            [{ 'state' => 'authorized', 'executable' => false, 'record' => rec, 'reason' => "plan #{root}: the principal's approval expired at 1000" },
             reg.status('g', root, 1000)],
            [{ 'state' => 'authorized', 'executable' => false, 'record' => rec, 'reason' => "plan #{root}: the principal's approval expired at 1000" },
             reg.status('g', root, 1001)],
            [true, reg.status('g', root)['executable']],
            [{ 'state' => 'unknown', 'executable' => false, 'reason' => 'plan nope is unknown for this grant' }, reg.status('g', 'nope')]]
    clk[0] = 2000
    rows << [false, reg.status('g', root)['executable']]
    rows << [true, reg.status('g', root, 5)['executable']]
    reg2, = C30.pl_reg
    root2 = C30.pl_authorized(reg2, { 'by' => 'p', 'expiresAt' => 1000.0 })
    rows << ["plan #{root2}: the principal's approval expired at 1000", reg2.status('g', root2, 1000)['reason']]
    rows << [false, reg2.plan_authorized?('g', root2.reverse)]

    reg3, kv3, = C30.pl_reg
    nodes = C30.pl_nodes
    r3 = AtlasPca.plan_root(nodes)
    [nil, 'expiresAt', 5, []].each do |ap|
      C30.pl_put(kv3, reg3, 'g', r3, C30.rec_of(r3, nodes, 'authorized', 'approval' => ap))
      rows << [{ 'state' => 'authorized', 'executable' => true, 'record' => C30.rec_of(r3, nodes, 'authorized', 'approval' => ap) }, reg3.status('g', r3, 1)]
    end

    wrong = C30.rec_of('WRONG', C30.pl_nodes, 'authorized', 'approval' => { 'by' => 'p' })
    C30.pl_put(kv3, reg3, 'g', 'WRONG', wrong)
    rows << [{ 'state' => 'authorized', 'executable' => false, 'reason' => 'plan WRONG: the stored nodes no longer hash to the root', 'record' => wrong },
             reg3.status('g', 'WRONG', 1)]
    unhashable = C30.rec_of('WRONG2', [{ 'id' => 'a', 'verb' => 'v', 'resource' => '/r', 'pre' => :sym }], 'authorized', 'approval' => { 'by' => 'p' })
    C30.pl_put(kv3, reg3, 'g', 'WRONG2', unhashable)
    rows << [{ 'state' => 'authorized', 'executable' => false, 'reason' => 'plan WRONG2: the stored nodes no longer hash to the root', 'record' => unhashable },
             reg3.status('g', 'WRONG2', 1)]
    C30.table('plan-status', rows)
  end

  t('c30 plan: status explains each non-authorized state') do
    next true unless C30.on?('plan_lifecycle.rb')

    reg, kv, = C30.pl_reg
    nodes = C30.pl_nodes
    cases = [['draft', {}, 'draft, not authorized'], ['validated', {}, 'validated, not authorized'],
             ['committed', {}, 'committed but not authorized by the principal'],
             ['revoked', {}, 'revoked (no reason given)'], ['revoked', { 'revokedReason' => '' }, 'revoked ()'],
             ['revoked', { 'revokedReason' => 'gone' }, 'revoked (gone)']]
    rows = cases.map do |state, extra, why|
      rec = C30.rec_of('R', nodes, state, extra)
      C30.pl_put(kv, reg, 'g', 'R', rec)
      [{ 'state' => state, 'executable' => false, 'reason' => "plan R is #{why}", 'record' => rec }, reg.status('g', 'R')]
    end
    C30.table('plan-status-states', rows)
  end

  t('c30 plan: plan_authorized? and context') do
    next true unless C30.on?('plan_lifecycle.rb')

    reg, _kv, clk = C30.pl_reg
    root = C30.pl_authorized(reg, { 'by' => 'p', 'expiresAt' => 100 })
    clk[0] = 50
    ctx = reg.context('g', root)
    st = reg.status('g', root)
    boom = AtlasPca::PlanRegistry.new(kv: AtlasPca::MemoryAtomicKv.new, now: -> { raise 'clock' })
    rows = [[true, reg.plan_authorized?('g', root)], [false, reg.plan_authorized?('g', 'nope')],
            [false, boom.plan_authorized?('g', root)],
            [{ 'plan' => C30.pl_nodes, 'planAuthorized' => true, 'status' => st }, ctx],
            [false, reg.context('g', root, 100)['planAuthorized']], [true, reg.context('g', root, 99)['planAuthorized']],
            [nil, reg.context('g', 'nope')], [nil, reg.context('g', 'nope', 5)]]
    clk[0] = 500
    rows << [false, reg.plan_authorized?('g', root)]
    rows << [false, reg.context('g', root)['planAuthorized']]
    reg2, = C30.pl_reg
    croot = C30.pl_committed(reg2)
    rows << [false, reg2.plan_authorized?('g', croot)]
    rows << [false, reg2.context('g', croot)['planAuthorized']]
    C30.table('plan-context', rows) && !ctx['plan'].equal?(ctx['status']['record']['nodes'])
  end

  t('c30 plan: check applies the per-action rules') do
    next true unless C30.on?('plan_lifecycle.rb')

    reg, _kv, clk = C30.pl_reg
    c_nodes = [{ 'id' => 'c', 'verb' => 'v', 'resource' => '/c', 'params_digest' => AtlasPca.params_digest({ 'q' => 1 }) }]
    root = C30.pl_authorized(reg, { 'by' => 'p', 'expiresAt' => 100 })
    croot = C30.pl_authorized(reg, { 'by' => 'p' }, 'gc', c_nodes)
    s = reg.status('g', root)
    na = ->(msg) { s.merge('executable' => false, 'reason' => "plan #{root}: #{msg}") }
    notok = ->(verb, res) { na.call("the operation (#{verb} on #{res} with these params) is not what the principal approved") }
    op = ->(verb, res, params = nil) { { 'verb' => verb, 'resource' => res, 'params' => params } }
    cs = reg.status('gc', croot)
    rows = [[s, reg.check('g', root)], [s, reg.check('g', root, node_id: 'a')], [s, reg.check('g', root, node_id: 'b')],
            [s.merge('executable' => false, 'reason' => "plan #{root} has no node 'zz'"), reg.check('g', root, node_id: 'zz')],
            [s.merge('executable' => false, 'reason' => "plan #{root} has no node 'zz'"), reg.check('g', root, node_id: 'zz', operation: op.call('read', '/r'))],
            [s, reg.check('g', root, operation: op.call('read', '/r'))], [s, reg.check('g', root, operation: op.call('write', '/w'))],
            [s, reg.check('g', root, node_id: 'a', operation: op.call('read', '/r'))],
            [notok.call('read', '/r'), reg.check('g', root, node_id: 'b', operation: op.call('read', '/r'))],
            [notok.call('read', '/x'), reg.check('g', root, operation: op.call('read', '/x'))],
            [notok.call('exec', '/r'), reg.check('g', root, operation: op.call('exec', '/r'))],
            [notok.call('read', '/r'), reg.check('g', root, operation: op.call('read', '/r', { 'z' => 1 }))],
            [na.call("the operation's params cannot be hashed"), reg.check('g', root, operation: op.call('read', '/r', :sym))],
            [cs, reg.check('gc', croot, node_id: 'c', operation: op.call('v', '/c', { 'q' => 1 }))],
            [cs.merge('executable' => false, 'reason' => "plan #{croot}: the operation (v on /c with these params) is not what the principal approved"),
             reg.check('gc', croot, node_id: 'c', operation: op.call('v', '/c', { 'q' => 2 }))],
            [cs.merge('executable' => false, 'reason' => "plan #{croot}: the operation (v on /c with these params) is not what the principal approved"),
             reg.check('gc', croot, node_id: 'c', operation: op.call('v', '/c'))]]
    # a status that is not executable is returned as is, whatever the node / operation asked
    reg2, = C30.pl_reg
    croot2 = C30.pl_committed(reg2)
    st2 = reg2.status('g', croot2)
    rows << [st2, reg2.check('g', croot2, node_id: 'zz')]
    rows << [st2, reg2.check('g', croot2, operation: op.call('read', '/x'))]
    rows << [reg2.status('g', 'nope'), reg2.check('g', 'nope', node_id: 'a')]
    # an executable status without a record is returned as is (a registry subclass may answer so)
    stub = { 'state' => 'authorized', 'executable' => true }
    reg2.define_singleton_method(:status) { |*_a| stub }
    rows << [stub, reg2.check('g', croot2, node_id: 'a')]
    rows << [stub, reg2.check('g', croot2, operation: op.call('read', '/x'))]
    # the clock is used when no `now` is passed
    clk[0] = 100
    rows << [false, reg.check('g', root)['executable']]
    rows << [false, reg.check('g', root, node_id: 'a')['executable']]
    clk[0] = 99
    rows << [true, reg.check('g', root, node_id: 'a')['executable']]
    rows << [true, reg.check('g', root, now: 50)['executable']]
    rows << [false, reg.check('g', root, now: 100)['executable']]
    C30.table('plan-check', rows)
  end
end
