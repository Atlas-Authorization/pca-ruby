# frozen_string_literal: true

# d43: round-3 survivors of actions.rb, assurance.rb, decision.rb, authorize.rb, caveat_lang.rb, rack_middleware.rb and
# lib/atlas_pca.rb. Each test names the operand it isolates. AtlasPca is resolved at CALL time (the oracle re-evaluates it per mutant).
require 'timeout'
require 'digest'
require 'stringio'

module MutationKill
  module D43
    module_function

    def skip?(*names)
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !names.include?(f)
    end

    def eq(label, got, want)
      ok = want == true || want == false || want.nil? ? got.equal?(want) : got == want
      raise "#{label}: got #{got.inspect}, want #{want.inspect}" unless ok

      true
    end

    def act = AtlasPca::Actions
    def js = AtlasPca::V2JS

    # not a String, but a String compares equal to it (Array#include? asks "x" == duck, String#== defers to duck.==);
    # == is true only against a String so `duck == true` stays false
    class Duck
      def initialize(str)
        @str = str
      end

      def to_str = @str
      def ==(other)
        other.is_a?(String)
      end
    end

    def base_def
      { 'v' => 1, 'kind' => 'pca-action-def', 'verb' => 'acme.invoice.pay', 'title' => 'Pay', 'effects' => ['pay'],
        'resource' => { 'type' => 'invoice', 'id' => '*', 'scope' => 'one' }, 'params' => {}, 'review' => { 'state' => 'authored' } }
    end

    # validate_def over a def the strict JSON profile would refuse before the operand under test is reached
    def loose_validate(d)
      MutationKill::Seam.with(act, { json_profile_error: ->(*) { nil } }) do
        MutationKill::Seam.with(js, { jsnorm: ->(x) { x } }) { act.validate_def(d) }
      end
    end

    # a report entry whose level reads 'frost' twice (the threshold block's own checks) and 'zzz' afterwards
    class Flip
      def initialize
        @n = 0
      end

      def [](key)
        case key
        when 'outcome' then 'pass'
        when 'awaiting_audit' then true
        when 'level' then (@n += 1) <= 2 ? 'frost' : 'zzz'
        end
      end
    end

    # escalation_principals answers ['x'] on its first read and nil afterwards
    class OptsSeq
      def initialize(*vals)
        @vals = vals
        @n = 0
      end

      def escalation_principals
        v = @vals[[@n, @vals.length - 1].min]
        @n += 1
        v
      end
    end

    def slot(cap, id, i)
      AtlasPca.b64e(Digest::SHA256.digest("atlas-pca/max-uses/v1\x00".b + cap.to_s.b + "\x00".b + id.to_s.b + "\x00".b + i.to_s.b))
    end
  end

  # ---- actions.rb -------------------------------------------------------------------------------------------------

  t('d43 actions: reversibility.by must be a String even when a declared name compares equal to it (isolates the is_a?(String) operand)') do
    next true if D43.skip?('actions.rb')

    d = D43.base_def.merge('params' => { 'x' => { 'type' => 'string' } })
    msg = 'reversibility.by must name a declared parameter'
    D43.eq('duck', D43.loose_validate(d.merge('reversibility' => { 'by' => D43::Duck.new('x'), 'map' => { 'a' => 'reversible' } })), msg) &&
      D43.eq('integer', D43.loose_validate(d.merge('reversibility' => { 'by' => 5, 'map' => { 'a' => 'reversible' } })), msg) &&
      D43.eq('undeclared name', D43.loose_validate(d.merge('reversibility' => { 'by' => 'zz', 'map' => { 'a' => 'reversible' } })), msg) &&
      D43.eq('declared name', D43.loose_validate(d.merge('reversibility' => { 'by' => 'x', 'map' => { 'a' => 'reversible' } })), nil)
  end

  t('d43 actions: idempotency.param of a key_param must be a String even when a declared name compares equal to it') do
    next true if D43.skip?('actions.rb')

    d = D43.base_def.merge('params' => { 'x' => { 'type' => 'string' } })
    msg = 'idempotency.param is required for key_param (a declared parameter) and forbidden otherwise'
    D43.eq('duck', D43.loose_validate(d.merge('idempotency' => { 'mode' => 'key_param', 'param' => D43::Duck.new('x') })), msg) &&
      D43.eq('undeclared name', D43.loose_validate(d.merge('idempotency' => { 'mode' => 'key_param', 'param' => 'zz' })), msg) &&
      D43.eq('declared name', D43.loose_validate(d.merge('idempotency' => { 'mode' => 'key_param', 'param' => 'x' })), nil)
  end

  t('d43 actions: a role that reads as an integer role but is not a String is not refused by the integer-role rule') do
    next true if D43.skip?('actions.rb')

    # the key is absent, so the earlier role? guard never runs; the Hash default answers a look-alike of 'money.amount'
    p = Hash.new(D43::Duck.new('money.amount'))
    p['type'] = 'string'
    D43.eq('look-alike role', D43.act.param_error('a', p, ['a']), nil) &&
      D43.eq('real role', D43.act.param_error('a', { 'type' => 'string', 'role' => 'money.amount' }, ['a']), 'a: role money.amount requires an integer parameter') &&
      D43.eq('integer parameter', D43.act.param_error('a', { 'type' => 'integer', 'role' => 'money.amount' }, ['a']), nil)
  end

  t('d43 actions: a resource.id prefix that is not a well-formed string is refused by js.ustr? itself') do
    next true if D43.skip?('actions.rb')

    pat = { 'prefix' => 'ab', 'class' => 'digits', 'len' => [1, 2] }
    msg = 'resource.id.prefix must be up to 32 safe characters'
    D43.eq('plain', D43.act.id_pattern_error(pat), nil) &&
      D43.eq('ustr? says no', MutationKill::Seam.with(D43.js, { ustr?: ->(_s) { false } }) { D43.act.id_pattern_error(pat) }, msg)
  end

  t('d43 actions: resource.type and compensates need a String (rx? alone is not enough when it says yes to anything)') do
    next true if D43.skip?('actions.rb')

    yes = ->(_re, _s) { true }
    ty = MutationKill::Seam.with(D43.act, { rx?: yes }) do
      D43.act.validate_def(D43.base_def.merge('resource' => { 'type' => 5, 'id' => '*', 'scope' => 'one' }))
    end
    cp = MutationKill::Seam.with(D43.act, { rx?: yes }) { D43.act.validate_def(D43.base_def.merge('compensates' => 5)) }
    D43.eq('type', ty, 'resource.type is malformed') && D43.eq('compensates', cp, 'compensates must be a verb') &&
      D43.eq('real compensates', D43.act.validate_def(D43.base_def.merge('compensates' => 'acme.invoice.void')), nil)
  end

  # ---- assurance.rb -----------------------------------------------------------------------------------------------

  t('d43 assurance: LEGACY_POLARITY_DEGRADED is the reference reason, verbatim') do
    next true if D43.skip?('assurance.rb')

    D43.eq('text', AtlasPca::LEGACY_POLARITY_DEGRADED, "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)")
  end

  t('d43 assurance: only a threshold check flags a threshold-scheme level as awaiting audit') do
    next true if D43.skip?('assurance.rb')

    lab = ->(level) { AtlasPca.set_assurance_label(Object.new, level) }
    a = AtlasPca.assurance_report({}, { 'attestation' => 'pass' }, hooks: { 'attestation' => lab.call('frost') })
    z = AtlasPca.assurance_report({}, { 'zk_compliance' => 'pass' }, hooks: { 'zk' => lab.call('mpc') })
    th = AtlasPca.assurance_report({}, { 'threshold' => 'pass' }, hooks: { 'threshold' => lab.call('mpc') })
    D43.eq('attestation', a, { 'attestation' => { 'outcome' => 'pass', 'level' => 'frost' } }) &&
      D43.eq('zk', z, { 'zk_compliance' => { 'outcome' => 'pass', 'level' => 'mpc' } }) &&
      D43.eq('threshold', th, { 'threshold' => { 'outcome' => 'pass', 'level' => 'mpc', 'awaiting_audit' => true } })
  end

  t('d43 assurance: a listed threshold scheme is accepted only while the level the loop reads is still in the list') do
    next true if D43.skip?('assurance.rb')

    # level reads 'frost' for the threshold block's two reads, then 'zzz' for the awaiting-audit loop: the loop must test inclusion itself
    r = AtlasPca.unmet_assurance({ 'threshold' => D43::Flip.new }, { 'threshold' => ['frost'] })
    D43.eq('loop', r, 'assurance: threshold rests on crypto awaiting audit (zzz); set allowAwaitingAudit or list the scheme to accept it') &&
      D43.eq('stable listed', AtlasPca.unmet_assurance({ 'threshold' => { 'outcome' => 'pass', 'level' => 'frost', 'awaiting_audit' => true } }, { 'threshold' => ['frost'] }), nil)
  end

  # ---- decision.rb ------------------------------------------------------------------------------------------------

  t('d43 decision: utf16_slice pairs a surrogate only with the unit that follows it') do
    next true if D43.skip?('decision.rb')

    sl = ->(s, n) { Timeout.timeout(2) { AtlasPca.utf16_slice(s, n) } }
    D43.eq('lone high last', sl.call("x\u{1F600}", 2).b, "x\xED\xA0\xBD".b) &&
      D43.eq('pair after a low unit', sl.call("x\u{1F600}y", 3), "x\u{1F600}") &&
      D43.eq('pair after a unit above the surrogates', sl.call("\uE000\u{1F600}y", 3), "\uE000\u{1F600}") &&
      D43.eq('pair first', sl.call("\u{1F600}y", 2), "\u{1F600}")
  end

  # ---- authorize.rb -----------------------------------------------------------------------------------------------

  t('d43 authorize: the tool_schema binding digest hashes String(signature_digest), not the raw value') do
    next true if D43.skip?('authorize.rb')

    schema = { 'props' => { 'a' => { 'type' => 'array', 'maxItems' => 4096, 'items' => { 'type' => 'array', 'maxItems' => 4096, 'items' => { 'type' => 'boolean' } } } } }
    call = { 'tool' => 'pay', 'args' => { 'a' => [[true]] } }
    cv = lambda do |sd, shown|
      { 'type' => 'tool_schema', 'tool' => 'pay', 'signature_digest' => sd, 'schema' => schema, 'schema_digest' => AtlasPca.hash_canonical(schema),
        'binding_digest' => AtlasPca.hash_canonical({ 'tool' => 'pay', 'signature_digest' => shown, 'schema' => schema }) }
    end
    D43.eq('string', AtlasPca.evaluate_tool_schema(cv.call('sd', 'sd'), call), [true, nil]) &&
      D43.eq('integer', AtlasPca.evaluate_tool_schema(cv.call(5, '5'), call), [true, nil]) &&
      D43.eq('true', AtlasPca.evaluate_tool_schema(cv.call(true, 'true'), call), [true, nil]) &&
      D43.eq('null', AtlasPca.evaluate_tool_schema(cv.call(nil, 'null'), call), [true, nil]) &&
      D43.eq('raw integer digest', AtlasPca.evaluate_tool_schema(cv.call(5, 5), call), [false, 'binding digest mismatch'])
  end

  t('d43 authorize: a state store is missing when nil even if nil answered claim') do
    next true if D43.skip?('authorize.rb')

    kw = { audience: 'a', resolve_grant: -> {}, is_revoked: -> {} }
    NilClass.send(:define_method, :claim) { |*| true }
    begin
      got = AtlasPca.missing_authorize_components(**kw, state_store: nil)
    ensure
      NilClass.send(:remove_method, :claim)
    end
    D43.eq('nil store', got, ['state_store']) && D43.eq('nil store, unpatched', AtlasPca.missing_authorize_components(**kw, state_store: nil), ['state_store'])
  end

  t('d43 authorize: on_epoch_accepted is read, nil-checked, then read again to be called (a hook that vanishes is not called)') do
    next true if D43.skip?('authorize.rb')

    c6 = MutationKill::C06
    ctx = ->(_pc) { { 'revocation_state' => { 'kind' => 'root' } } }
    reads = 0
    recorded = []
    rec = ->(e, pc) { recorded << [e, pc] }
    pol = AtlasPca::RevocationStaleness.new
    pol.define_singleton_method(:on_epoch_accepted) do
      reads += 1
      reads == 1 ? rec : nil
    end
    r = MutationKill::Seam.with(AtlasPca, { check_revocation_state: ->(*, **) { { 'ok' => true, 'epoch' => 7 } } }) do
      c6.go(context: ctx, revocation_staleness: pol)
    end
    D43.eq('allowed', r.allow, true) && D43.eq('read twice', reads, 2) && D43.eq('not called', recorded, [])
  end

  # ---- caveat_lang.rb ---------------------------------------------------------------------------------------------

  t('d43 caveat_lang: max_uses_slot_key hashes the bytes of parts of different encodings') do
    next true if D43.skip?('caveat_lang.rb')

    D43.eq('binary cap, utf-8 id', AtlasPca.max_uses_slot_key("\xFF".b, "é", 0), D43.slot("\xFF".b, "é", 0)) &&
      D43.eq('utf-8 cap, binary id', AtlasPca.max_uses_slot_key("é", "\xFE".b, 7), D43.slot("é", "\xFE".b, 7))
  end

  t('d43 caveat_lang: a fault inside verify_discharge is a fail-closed reason carrying the error text (seam)') do
    next true if D43.skip?('caveat_lang.rb')

    r = MutationKill::Seam.with(AtlasPca, { needs_discharge_error: ->(_c) { raise 'boom' } }) { AtlasPca.verify_discharge({}, {}, { 'now' => 1 }) }
    D43.eq('fault', r, { ok: false, reason: 'discharge error (fail closed): boom' })
  end

  # ---- rack_middleware.rb -----------------------------------------------------------------------------------------

  t('d43 rack: escalation_answer reads escalation_principals again and a fault there is no answer') do
    next true if D43.skip?('rack_middleware.rb')

    env = -> { { 'rack.input' => StringIO.new('{"escalation_answer":{"a":"b"}}') } }
    mw = AtlasPca::RackMiddleware.allocate
    ask = ->(opts) { mw.send(:escalation_answer, env.call, opts) }
    D43.eq('pinned', ask.call(D43::OptsSeq.new(['x'])), { 'a' => 'b' }) &&
      D43.eq('none pinned', ask.call(D43::OptsSeq.new(nil)), nil) &&
      D43.eq('empty list', ask.call(D43::OptsSeq.new([])), nil) &&
      D43.eq('pinned then gone', ask.call(D43::OptsSeq.new(['x'], nil)), nil)
  end

  # ---- lib/atlas_pca.rb -------------------------------------------------------------------------------------------

  t('d43 core: CAVEAT_LIMIT_REASON is the reference text, frozen') do
    next true if D43.skip?('atlas_pca.rb')

    D43.eq('text', AtlasPca::CAVEAT_LIMIT_REASON, 'chain exceeds caveat limit (max 256 per hop, 1024 per chain)') &&
      D43.eq('frozen', AtlasPca::CAVEAT_LIMIT_REASON.frozen?, true)
  end
end
