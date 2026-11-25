# frozen_string_literal: true

# zc forbid certificate: clause validation, rank, the malformed answer for every kind of bad action context, signer gating,
# and the precedence / fail-closed paths of check_forbid_certificate.
module MutationKill
  module ZCForbid
    module_function

    W = { 'verb' => 'payments.send' }.freeze
    CTX = { 'action' => { 'verb' => 'payments.send', 'resource' => 'acct/1', 'params' => {} } }.freeze
    MALFORMED = { 'decision' => 'deny', 'witness' => { 'winner' => { 'kind' => 'malformed', 'id' => nil }, 'shadowed' => [] }, 'values' => [] }.freeze
    NONE = { 'decision' => 'deny', 'witness' => { 'winner' => { 'kind' => 'none', 'id' => nil }, 'shadowed' => [] }, 'values' => [] }.freeze

    def clause(id, kind, signer = nil)
      h = { 'id' => id, 'kind' => kind, 'when' => W }
      h['signer'] = signer unless signer.nil?
      h
    end

    # equal to 'permit' for Array#include? / String#== purposes, but not a String
    class FakeKind
      def to_str = 'permit'
      def ==(_other) = true
    end

    # answers [] like a Hash would for the action, but is not one
    class LookCtx
      def [](key) = key == 'action' ? { 'verb' => 'v', 'resource' => 'r' } : nil
    end

    class LookAction
      def [](key) = key == 'verb' ? 'v' : (key == 'resource' ? 'r' : nil)
    end
  end

  t('zc forbid certificate: clauses_error needs a String id and a String kind') do
    next true unless ZC.gate?('forbid_certificate.rb')

    ce = ->(c) { AtlasPca.clauses_error([c]) }
    base = { 'id' => 'a', 'kind' => 'permit', 'when' => ZCForbid::W }
    id_msg = 'clauses[0].id must be a string of 1..128 characters'
    kind_msg = 'clauses[0].kind must be permit, forbid or escalate'
    ZC.eq('valid', ce.call(base), nil) &&
      ZC.eq('int id', ce.call(base.merge('id' => 5)), id_msg) && ZC.eq('nil id', ce.call(base.merge('id' => nil)), id_msg) &&
      ZC.eq('empty id', ce.call(base.merge('id' => '')), id_msg) && ZC.eq('long id', ce.call(base.merge('id' => 'x' * 129)), id_msg) &&
      ZC.eq('int kind', ce.call(base.merge('kind' => 5)), kind_msg) && ZC.eq('nil kind', ce.call(base.merge('kind' => nil)), kind_msg) &&
      ZC.eq('unknown kind', ce.call(base.merge('kind' => 'bogus')), kind_msg) &&
      ZC.eq('a String lookalike kind', ce.call(base.merge('kind' => ZCForbid::FakeKind.new)), kind_msg) &&
      ZC.eq('duplicate', AtlasPca.clauses_error([base, base]), "clauses[1].id 'a' is a duplicate") &&
      ZC.eq('same ids after a different one', AtlasPca.clauses_error([base, base.merge('id' => 'b'), base.merge('id' => 'b')]), "clauses[2].id 'b' is a duplicate")
  end

  t('zc forbid certificate: clause_rank puts an absent or unlisted signer last') do
    next true unless ZC.gate?('forbid_certificate.rb')

    ZC.eq('absent signer, nil in the list', AtlasPca.clause_rank(nil, [nil, 'x']), 2) && ZC.eq('absent signer', AtlasPca.clause_rank(nil, %w[a b]), 2) &&
      ZC.eq('listed', AtlasPca.clause_rank('x', [nil, 'x']), 1) && ZC.eq('first', AtlasPca.clause_rank('a', %w[a b]), 0) &&
      ZC.eq('unlisted', AtlasPca.clause_rank('zz', %w[a]), 1)
  end

  t('zc forbid certificate: decide_clauses answers malformed for every unusable action and never raises') do
    next true unless ZC.gate?('forbid_certificate.rb')

    dc = ->(ctx, opts = nil) { AtlasPca.decide_clauses([], ctx, opts) }
    act = ->(a) { { 'action' => a } }
    m = ZCForbid::MALFORMED
    [nil, 5, 'x', [], {}, 'action'].each { |bad| ZC.eq("ctx #{bad.inspect}", dc.call(bad), m) }
    ZC.eq('a ctx that is not a Hash', dc.call(ZCForbid::LookCtx.new), m) &&
      ZC.eq('action nil', dc.call(act.call(nil)), m) && ZC.eq('action string', dc.call(act.call('x')), m) && ZC.eq('action int', dc.call(act.call(5)), m) &&
      ZC.eq('an action that is not a Hash', dc.call(act.call(ZCForbid::LookAction.new)), m) &&
      ZC.eq('verb int', dc.call(act.call({ 'verb' => 5, 'resource' => 'r' })), m) && ZC.eq('verb nil', dc.call(act.call({ 'resource' => 'r' })), m) &&
      ZC.eq('resource int', dc.call(act.call({ 'verb' => 'v', 'resource' => 5 })), m) && ZC.eq('resource nil', dc.call(act.call({ 'verb' => 'v' })), m) &&
      ZC.eq('both wrong', dc.call(act.call({ 'verb' => 5, 'resource' => 5 })), m) &&
      ZC.eq('valid, no clauses', dc.call(ZCForbid::CTX), ZCForbid::NONE) &&
      ZC.eq('an options object that is not a Hash is a fault, answered malformed', dc.call(ZCForbid::CTX, Object.new), m) &&
      ZC.eq('malformed clauses', AtlasPca.decide_clauses('x', ZCForbid::CTX), m)
  end

  t('zc forbid certificate: permitSigners gate permit clauses, an absent signer only passes when nil is listed explicitly') do
    next true unless ZC.gate?('forbid_certificate.rb')

    p0 = ZCForbid.clause('p', 'permit')
    p1 = ZCForbid.clause('p', 'permit', 'x')
    denied = lambda do |value|
      { 'decision' => 'deny', 'witness' => { 'winner' => { 'kind' => 'none', 'id' => nil }, 'shadowed' => [] }, 'values' => [{ 'id' => 'p', 'kind' => 'permit', 'value' => value }] }
    end
    allowed = { 'decision' => 'allow', 'witness' => { 'winner' => { 'kind' => 'permit', 'id' => 'p' }, 'shadowed' => [] }, 'values' => [{ 'id' => 'p', 'kind' => 'permit', 'value' => 'true' }] }
    dc = ->(c, opts) { AtlasPca.decide_clauses([c], ZCForbid::CTX, opts) }
    ZC.eq('no signer list: everyone', dc.call(p0, nil), allowed) &&
      ZC.eq('a signer-less permit with a list', dc.call(p0, { 'permitSigners' => ['x'] }), denied.call('false')) &&
      ZC.eq('a signer-less permit with nil in the list', dc.call(p0, { 'permitSigners' => [nil, 'x'] }), denied.call('false')) &&
      ZC.eq('listed signer', dc.call(p1, { 'permitSigners' => ['x'] }), allowed) &&
      ZC.eq('unlisted signer', dc.call(p1, { 'permitSigners' => ['y'] }), denied.call('false')) &&
      ZC.eq('an empty list', dc.call(p1, { 'permitSigners' => [] }), denied.call('false'))
  end

  t('zc forbid certificate: check_forbid_certificate honours the precedence and fails closed') do
    next true unless ZC.gate?('forbid_certificate.rb')

    clauses = [ZCForbid.clause('a', 'forbid', 's1'), ZCForbid.clause('b', 'forbid', 's2')]
    ctx = ZCForbid::CTX
    prec = { 'precedence' => %w[s2 s1] }
    cert_default = AtlasPca.certify_clauses(clauses, ctx, nil)
    cert_prec = AtlasPca.certify_clauses(clauses, ctx, prec)
    ZC.eq('default winner', cert_default['winner'], { 'kind' => 'forbid', 'id' => 'a' }) &&
      ZC.eq('precedence winner', cert_prec['winner'], { 'kind' => 'forbid', 'id' => 'b' }) &&
      ZC.eq('no options', AtlasPca.check_forbid_certificate(cert_default, clauses, ctx), { 'ok' => true }) &&
      ZC.eq('nil options', AtlasPca.check_forbid_certificate(cert_default, clauses, ctx, nil), { 'ok' => true }) &&
      ZC.eq('empty options', AtlasPca.check_forbid_certificate(cert_default, clauses, ctx, {}), { 'ok' => true }) &&
      ZC.eq('with precedence', AtlasPca.check_forbid_certificate(cert_prec, clauses, ctx, prec), { 'ok' => true }) &&
      ZC.eq('a certificate for another precedence', AtlasPca.check_forbid_certificate(cert_default, clauses, ctx, prec),
            { 'ok' => false, 'reason' => 'certificate table does not entail its decision' }) &&
      ZC.eq('a precedence certificate checked without it', AtlasPca.check_forbid_certificate(cert_prec, clauses, ctx),
            { 'ok' => false, 'reason' => 'certificate table does not entail its decision' }) &&
      ZC.eq('a consistent table over another policy', AtlasPca.check_forbid_certificate(cert_default.merge('policy' => 'other'), clauses, ctx),
            { 'ok' => false, 'reason' => 'certificate does not match the recomputed decision' }) &&
      ZC.eq('malformed clauses', AtlasPca.check_forbid_certificate(cert_default, 'x', ctx), { 'ok' => false, 'reason' => 'malformed clauses' }) &&
      ZC.eq('an options object that is not a Hash', AtlasPca.check_forbid_certificate(cert_default, clauses, ctx, Object.new),
            { 'ok' => false, 'reason' => 'certificate check error (fail closed)' })
  end
end
