# frozen_string_literal: true

# e04: PCA 0.5 hardening H14
# (a host callback that raises ScriptError / SecurityError / SystemStackError denies; Interrupt-class errors are never swallowed).
# Reuses the C06 authorize helpers and the C27P passport helpers (both files load before this one). AtlasPca is resolved at call time.

module MutationKill
  module E04
    module_function

    def gate? = (f = ENV['MUT_FILE']).nil? || f.empty? || %w[authorize.rb passport.rb].include?(f)

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    BROAD = [NotImplementedError, SecurityError, SystemStackError].freeze
  end

  t('e04 H14: a passport revocation hook raising a broad error is revocation_unavailable; fatal errors still propagate') do
    next true unless E04.gate?

    sp = C27P.mk
    ok = E04::BROAD.all? { |k| E04.ck(k.name, C27P.vp(sp, 500, revoked: ->(*) { raise k, 'x' }), 'revocation_unavailable') }
    ok && [NoMemoryError, SystemExit].all? do |k|
      got = begin
        C27P.vp(sp, 500, revoked: ->(*) { raise k })
        :swallowed
      rescue k
        :propagated
      end
      E04.ck("#{k.name} propagates", got, :propagated)
    end
  end

  t('e04 H14: a passport attestation hook raising a broad error is hardware_attestation_failed; fatal errors still propagate') do
    next true unless E04.gate?

    sp = C27P.hw
    n = C27P::NOW
    ok = E04::BROAD.all? { |k| E04.ck(k.name, C27P.vp(sp, n, attest: ->(*) { raise k, 'x' }), 'hardware_attestation_failed') }
    ok && E04.ck('control', C27P.vp(sp, n, attest: C27P.att), nil) &&
      E04.ck('NoMemoryError propagates', begin
        C27P.vp(sp, n, attest: ->(*) { raise NoMemoryError })
        :swallowed
      rescue NoMemoryError
        :propagated
      end, :propagated)
  end

  t('e04 H14: authorize denies when resolve_grant, context, is_revoked or the verifier raise a broad error') do
    next true unless E04.gate?

    p = C06.fixture_pcactn
    sh = ->(r) { [r.status, r.checks, r.reason, r.pcactn] }
    E04::BROAD.all? do |k|
      boom = ->(*) { raise k, 'x' }
      rv = C06.go(is_revoked: boom)
      core = Seam.with(AtlasPca, { verify_pcactn: ->(*, **) { raise k, 'seam' } }) { C06.go }
      E04.ck("#{k.name} resolve", sh.call(C06.go(resolve_grant: boom)), [403, { 'resolve_grant' => 'fail' }, 'resolve_grant: grant resolution failed (fail closed)', p]) &&
        E04.ck("#{k.name} context", sh.call(C06.go(context: boom)), [403, { 'context' => 'fail' }, 'context: the context callback failed (fail closed)', p]) &&
        E04.ck("#{k.name} revoked", [rv.allow, rv.checks['revocation'], rv.reasons.include?('revocation: the revocation check failed (fail closed)')], [false, 'fail', true]) &&
        E04.ck("#{k.name} core", [core.allow, core.status, core.checks, core.reason], [false, 403, { 'authorize' => 'fail' }, "authorize: error (fail closed): #{k.name}"])
    end
  end

  t('e04 H14: an undo hook or a replay-head read raising a broad error leaves the escalation standing') do
    next true unless E04.gate?

    stubs = { decision_of: ->(_v) { 'escalate' }, build_escalation_request: ->(**) { { 'req' => 1 } } }
    E04::BROAD.all? do |k|
      r = Seam.with(AtlasPca, stubs) do
        C06.with_core { C06.go(is_revoked: ->(_p, _g) { true }, undo: ->(*) { raise k, 'x' }) }
      end
      st = C06.store_class.new
      st.define_singleton_method(:last) { |_key| raise k, 'x' }
      r2 = Seam.with(AtlasPca, stubs) { C06.with_core { C06.go(is_revoked: ->(_p, _g) { true }, state_store: st) } }
      E04.ck("#{k.name} undo", [r.allow, r.decision, r.escalation], [false, 'escalate', { 'req' => 1 }]) &&
        E04.ck("#{k.name} last", [r2.allow, r2.decision, r2.escalation], [false, 'escalate', { 'req' => 1 }])
    end
  end
end
