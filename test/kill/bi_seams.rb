# frozen_string_literal: true
# Fail-closed checks no input reaches through the public entry (an earlier check always passes first): each is pinned through
# a seam or a direct call instead of a ledger entry, so a regression stays visible if the earlier check ever moves.
module MutationKill
  module Seam
    module_function

    def with(mod, stubs)
      orig = stubs.keys.to_h { |n| [n, mod.method(n)] }
      stubs.each { |n, impl| mod.define_singleton_method(n, &impl) }
      yield
    ensure
      orig.each { |n, m| mod.define_singleton_method(n, m) }
    end
  end

  t('check_sig: a body digest that does not decode is a bad signature, exactly (seam)') do
    Seam.with(AtlasPca, { signable_hop_body: ->(_c) { [{}, nil] }, hash_canonical: ->(_b) { 'x' } }) do
      AtlasPca.check_sig({ 'body_digest' => 'x', 'id' => 'x' }, 'k', 'L') == 'L: bad signature (not signed by expected key)'
    end
  end

  t('verify_b64u: a fault under it is exactly false (seam)') do
    Seam.with(AtlasPca, { b64d: ->(*) { raise TypeError, 'seam' } }) { AtlasPca.verify_b64u('a', 'm', 'b').equal?(false) }
  end

  t('rack strict_object: parsed JSON that is not an object is a DecodeError (seam)') do
    Seam.with(AtlasPca, { parse_json: ->(*) { [] } }) do
      AtlasPca::RackMiddleware.allocate.send(:strict_object, '[]')
      false
    rescue AtlasPca::RackMiddleware::DecodeError => e
      e.message == 'PCActn is not an object'
    end
  end

  t('decide_param_provenance: overlapping prov paths deny, as param-provenance.ts:210 (seam over the wire checks)') do
    Seam.with(AtlasPca, { validate_provenance_policy: ->(_p) {}, validate_prov_wire: ->(_p) {} }) do
      r = AtlasPca.decide_param_provenance({ 'policy' => {}, 'prov' => { 'action.params.a' => {}, 'action.params.a.b' => {} },
                                             'action' => { 'params' => { 'a' => { 'b' => 1 } } } })
      r['outcome'] == 'deny' && r['reason'] == "provenance: prov paths 'action.params.a' and 'action.params.a.b' overlap"
    end
  end

  t('check_session_revocation: one epoch number with two roots is equivocation (seam over the list check)') do
    v = V2
    iv = AtlasPca::IntentV2
    ev = v.evidence(%w[pca-intent:map:a])
    c = lambda do |last|
      iv.check_session_revocation(ev, session: v.session, authority: v.pk(v.rev_auth), ids: ["pca-intent:session:#{v.session}"],
                                      now: V2::NOW, max_age_ms: 60_000, last: last)
    end
    forged = ev.merge('epoch' => ev['epoch'].merge('root' => V2Schema::D32))
    Seam.with(iv, { revoked_list_error: ->(_e) {} }) do
      r = c.call(forged)
      r['ok'] == false && r['reason'] == 'two different revocation sets under one epoch number (equivocation)' && c.call(ev)['ok'] == true
    end
  end

  t('intent_v2 helpers answer exactly nil on a well-formed input (TS null), not just something falsy') do
    v = AtlasPca::IntentV2
    d = V2Schema::D32
    other = { 'kind' => 'other', 'value' => v::MAP_OTHER }
    v.param_decl_error('action.params.p0', { 'type' => 'datetime', 'semantic' => 'generic.datetime', 'sensitivity' => 'free' }, nil, true).nil? &&
      v.map_dim_error({ 'kind' => 'num', 'path' => 'action.params.x', 'lo' => 0, 'hi' => 9, 'cuts' => [] }, 0).nil? &&
      v.map_dim_error({ 'kind' => 'cat', 'path' => 'action.resource', 'values' => [other] }, 0).nil? &&
      v.map_entry_shape({ 'index' => 0, 'salt' => d, 'leaf' => d, 'path' => [] }, 'cell').nil? &&
      v.session_ctx_error({}).nil? && v.acc_ctx_error({}).nil? &&
      v.unsupported_suite_reason({}, 5).nil? && v.unsupported_suite_reason({}, nil).nil?
  end

  t('param_decl_error: min on a v2 duration is allowed, on a string refused (action-schema.ts:249)') do
    v = AtlasPca::IntentV2
    e = ->(t) { v.param_decl_error('action.params.p0', { 'type' => t, 'min' => 1, 'semantic' => 'generic.duration', 'sensitivity' => 'free' }, nil, true) }
    want = 'action.params.p0: min must be a safe integer on an integer parameter'
    e.('duration') != want && e.('string') == want
  end

  t('LeaseRegistry maxTtlCeiling: at and below accepted, above ttl_ceiling (after over_max_ttl), absent unbounded; a malformed one raises (lease.ts:219, :245)') do
    day = 86_400_000
    rec = ->(ttl, exp = 1000) { { 'authority' => 'a', 'requester' => 'r', 'holder' => 'h', 'approvers' => ['x'], 'lease_id' => "l#{ttl}", 'seq' => 1, 'issued_at' => 0, 'expires_at' => exp, 'max_ttl' => ttl } }
    reg = ->(pol = { 'maxTtlCeiling' => day }) { AtlasPca::LeaseRegistry.new({ 'authorities' => ['a'] }.merge(pol)) }
    Seam.with(AtlasPca, { verify_lease: ->(_r) { true } }) do
      reg.().accept(rec.(day + 1)) == { 'ok' => false, 'code' => 'ttl_ceiling' } && reg.().accept(rec.(day))['ok'] == true && reg.().accept(rec.(day - 1))['ok'] == true &&
        reg.({}).accept(rec.(day + 1))['ok'] == true && reg.().accept(rec.(day + 1, (2 * day) + 2)) == { 'ok' => false, 'code' => 'over_max_ttl' } &&
        [0, -1, '5', 1.5, nil, 2**53].all? do |bad|
          reg.({ 'maxTtlCeiling' => bad })
          false
        rescue RangeError => e
          e.message == 'LeaseRegistry: maxTtlCeiling must be a positive integer'
        end && reg.({ 'maxTtlCeiling' => 1 }).is_a?(AtlasPca::LeaseRegistry) && reg.({ 'maxTtlCeiling' => (2**53) - 1 }).is_a?(AtlasPca::LeaseRegistry)
    end
  end

  t('BigDecimalLike.plain: exact on every branch (no fraction, point 0, point inside the digits, trailing zero strip)') do
    p = ->(s) { AtlasPca::BigDecimalLike.plain(s) }
    p.('12e0') == '12' && p.('1.5e-1') == '0.15' && p.('1.5e0') == '1.5' && p.('1.0e0') == '1' && p.('1.25e1') == '12.5' && p.('1.5e-2') == '0.015'
  end

  # Number() per ECMAScript StringNumericLiteral: Python and Rust parsed some of the NaN forms, and a forged floor passed.
  t('SvfJS.num is JS Number(): every form the reference reads as NaN refuses; the rest parse') do
    n = ->(s) { AtlasPca::Actions::SvfJS.num(s) }
    nan = ['+-Infinity', '-+Infinity', '+0x1', '-0x1', '0x+1', '0x-1', '0x1_0', '0x 1', '0x', '0b2', '0o8', '1_000', "١", "１",
           'infinity', 'INFINITY', 'nan', 'NaN', '1e', '.', '+', '1f', '1d', '1L', "\u0000 12", "᠎12"]
    ok = { '' => 0.0, " \t\n" => 0.0, "﻿ " => 0.0, ' 12 ' => 12.0, "﻿12 " => 12.0, 'Infinity' => Float::INFINITY,
           '+Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY, '0x10' => 16.0, '0X1f' => 31.0, '0o7' => 7.0, '0b1' => 1.0,
           '1.' => 1.0, '.5' => 0.5, '1e3' => 1000.0, '+1.5' => 1.5, "0x#{'f' * 300}" => Float::INFINITY }
    nan.all? { |s| n.(s).nan? } && ok.all? { |s, x| n.(s) == x } && 1.0 / n.('-0') == -Float::INFINITY && !AtlasPca::Actions::SvfJS.le(0, '+-Infinity')
  end

  # the same table through the other Number() helper (measurement indexes and RIM attributes: attest loads without Actions)
  t('Attest::Common.js_number is JS Number() over the whole sweep table') do
    n = ->(x) { AtlasPca::Attest::Common.js_number(x) }
    nan = ['+-Infinity', '-+Infinity', '+0x1', '-0x1', '0x+1', '0x-1', '0x1_0', '0x 1', '0x', '0b2', '0o8', '1_000', "\u0661", "\uff11", 'infinity', 'INFINITY',
           'nan', 'NaN', '1e', '.', '+', '1f', '1d', '1L', "1\u0000", "\u0085" + '1', "\u180e" + '1', '0x1p3']
    ok = { '' => 0.0, " \t\n" => 0.0, ' 12 ' => 12.0, "\ufeff12\u00a0" => 12.0, 'Infinity' => Float::INFINITY, '+Infinity' => Float::INFINITY,
           '-Infinity' => -Float::INFINITY, '0x10' => 16.0, '0X1f' => 31.0, '0o7' => 7.0, '0b1' => 1.0, '1.' => 1.0, '1.e3' => 1000.0, '.5' => 0.5, '-.5' => -0.5,
           '+.5' => 0.5, '1e3' => 1000.0, '+1.5' => 1.5, "0x#{'f' * 300}" => Float::INFINITY }
    nan.all? { |x| n.(x).nan? } && ok.all? { |x, w| n.(x) == w } && 1.0 / n.('-0') == -Float::INFINITY
  end

  t('k3 compare_version reads each part as JS Number() (pca-grants bundle.ts:55): a NaN difference is greater, never a pass or a throw') do
    c = ->(a, b) { AtlasPca.compare_version(a, b) }
    c.('1', '1e3') == -1 && c.('1', '0x10') == -1 && c.(' 1', '1').zero? && c.('1', '-1') == 1 && c.('1', 'x') == 1 && c.('x', '1') == 1 && c.('x', 'x') == 1 &&
      c.('1', '+-Infinity') == 1 && c.('1', 'Infinity') == -1 && c.('1.', '1').zero? && c.('1.0', '1').zero? && c.('1', "1\u0000") == 1 && c.('1.2', '1.10') == -1 &&
      c.('2', '10') == -1
  end

  t('SvfJS.leq: a floor the reference reads as NaN never satisfies the order (rule 22: a forged floor is caught)') do
    j = AtlasPca::Actions::SvfJS
    b = { 'risk' => 1, 'rev' => 'reversible', 'blast_ppm' => 0, 'esc' => 0, 'caveats' => [], 'context' => [], 'prules' => [] }
    q = ->(risk) { j.leq(b, b.merge('risk' => risk)) }
    q.(3) && q.('+Infinity') && %w[+-Infinity -+Infinity 0x+1 1_000].none? { |x| q.(x) }
  end

  t('monitor_step responds_within reads the pending count as JS Number()') do
    m = { 'id' => 'm', 'kind' => 'responds_within', 'p' => { 'verb' => 'shop.buy', 'resource' => '*' }, 'q' => { 'verb' => 'shop.confirm', 'resource' => '*' }, 'within' => 2 }
    s = ->(q) { AtlasPca.monitor_step(m, q, { 'verb' => 'shop.verify', 'resource' => 'shop.example/r', 'params' => {}, 'status' => 'reserved' }) }
    s.("pending: 1") == 'missed' && s.('pending:1.') == 'missed' && s.("pending:\u0000 1") == 'pending:NaN' && s.('pending:+-Infinity') == 'pending:NaN' && s.('pending:3') == 'pending:2'
  end
end
