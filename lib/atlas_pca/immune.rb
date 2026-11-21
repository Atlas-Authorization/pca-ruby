# frozen_string_literal: true

require 'openssl'
require 'digest'
require_relative 'js_compat'
require_relative 'predicates'
require_relative 'intent_v2'
require_relative 'harness'
require_relative 'atomic_kv'
require_relative 'actions_import_common'

module AtlasPca
  # The behavioral immune system: the per-principal risk baseline, the observation fold (observe), the state validation and the threat
  # read (assess), the adaptation of a base risk policy (adapt, never widening it), guardian-signed tightening proposals and a durable
  # store over an atomic kv. A heuristic (EWMA and z-score over one principal's history): it can be gamed by a slow attacker who drifts
  # the baseline and is no proof that an agent is compromised or benign.
  #
  # An immune state is {'baseline' => {'n','mean','m2'}, 'ewma', 'stepUps', 'denies', 'lastAt', 'seeded'}; an observation is
  # {'r', 'at', 'stepUp'?, 'denied'?}. JavaScript number coercions of the reference are reproduced (null is 0, an absent member is NaN).
  module Immune
    UNDEF = V2JS::UNDEF
    MAX_COUNT = 1e9
    ALPHA = 0.3
    HALF_LIFE_MS = 3_600_000
    DRIFT_Z_SAT = 3
    STEP_UP_SAT = 5
    DENY_SAT = 3
    TIGHTENING_DOMAIN = "atlas-pca/immune-tightening/v1\x00".b.freeze

    module_function

    # o[k] with JS property semantics: null throws, a non-object has no members, an absent member is UNDEF.
    def jv(o, k)
      raise TypeError, "Cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')" if o.nil? || o.equal?(UNDEF)

      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    end

    def fin?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)

    # ToNumber of a JSON value (an object or array reads as NaN here).
    def to_num(x)
      case x
      when Integer then x.to_f
      when Float then x
      when nil then 0.0
      when true then 1.0
      when false then 0.0
      when String
        t = Js.trim(x)
        return 0.0 if t.empty?
        return t.start_with?('-') ? -Float::INFINITY : Float::INFINITY if t.match?(/\A[+-]?Infinity\z/)

        t.match?(/\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z/) ? Float(t) : Float::NAN
      else Float::NAN
      end
    end

    def clamp01(x) = x.nan? ? x : [[x, 1.0].min, 0.0].max

    # ---- baseline (Welford running mean / variance)
    def empty_baseline = { 'n' => 0, 'mean' => 0, 'm2' => 0 }

    def initial_state = { 'baseline' => empty_baseline, 'ewma' => 0, 'stepUps' => 0, 'denies' => 0, 'lastAt' => 0, 'seeded' => false }

    # Welford update with one risk sample (a non-finite sample counts as 0).
    def update_baseline(b, r)
      x = fin?(r) ? r.to_f : 0.0
      n = to_num(jv(b, 'n')) + 1
      mean0 = to_num(jv(b, 'mean'))
      delta = x - mean0
      mean = mean0 + (delta / n)
      m2 = to_num(jv(b, 'm2')) + (delta * (x - mean))
      { 'n' => n, 'mean' => mean, 'm2' => m2 }
    end

    # Population standard deviation of the baseline (0 until at least 2 samples).
    def baseline_std(b)
      n = to_num(jv(b, 'n'))
      n >= 2 ? Math.sqrt(to_num(jv(b, 'm2')) / n) : 0.0
    end

    def decay(count, dt_ms, half_life_ms = HALF_LIFE_MS)
      return count if dt_ms <= 0 || count.zero?

      count * (0.5**(dt_ms / half_life_ms))
    end

    # One tunable of an ImmuneConfig ({'alpha', 'halfLifeMs', 'driftZSat', 'stepUpSat', 'denySat'}): the default when the config or the member is absent.
    def cfg_of(cfg, key, default) = cfg.is_a?(Hash) && cfg.key?(key) && !cfg[key].nil? ? cfg[key] : default

    # Fold one observation into the immune state (baseline, recent EWMA, decayed step-up and deny counters).
    def observe(state, obs, cfg = nil)
      o = jv(obs, 'r')
      r = clamp01(fin?(o) ? o.to_f : 0.0)
      last_at = to_num(jv(state, 'lastAt'))
      oa = jv(obs, 'at')
      at = fin?(oa) ? oa.to_f : last_at
      seeded = truthy_member?(state, 'seeded')
      dt = seeded ? [0.0, at - last_at].max : 0.0
      baseline = update_baseline(jv(state, 'baseline'), r)
      alpha = cfg_of(cfg, 'alpha', ALPHA)
      half_life = cfg_of(cfg, 'halfLifeMs', HALF_LIFE_MS)
      ewma = seeded ? (alpha * r) + ((1 - alpha) * to_num(jv(state, 'ewma'))) : r
      step_ups = decay(to_num(jv(state, 'stepUps')), dt, half_life) + (truthy_member?(obs, 'stepUp') ? 1 : 0)
      denies = decay(to_num(jv(state, 'denies')), dt, half_life) + (truthy_member?(obs, 'denied') ? 1 : 0)
      { 'baseline' => baseline, 'ewma' => ewma, 'stepUps' => step_ups, 'denies' => denies, 'lastAt' => at, 'seeded' => true }
    end

    def truthy_member?(o, k)
      v = jv(o, k)
      !v.equal?(UNDEF) && Js.truthy?(v)
    end

    def in_range?(x, lo, hi) = fin?(x) && x >= lo && x <= hi

    # The reason a state is malformed (non-finite, negative, out of bound), or nil.
    def validate_immune_state(s)
      return 'state must be an object' unless s.is_a?(Hash) || s.is_a?(Array)

      g = ->(o, k) { o.is_a?(Hash) ? o[k] : nil }
      b = g.call(s, 'baseline')
      return 'baseline missing' unless b.is_a?(Hash) || b.is_a?(Array)

      n = g.call(b, 'n')
      return 'baseline.n must be an integer in [0, 1e9]' if !in_range?(n, 0, MAX_COUNT) || n != n.floor || Js.neg_zero?(n)
      return 'baseline.mean must be in [0, 1]' unless in_range?(g.call(b, 'mean'), 0, 1)
      return 'baseline.m2 must be finite and >= 0' unless in_range?(g.call(b, 'm2'), 0, MAX_COUNT)
      return 'ewma must be in [0, 1]' unless in_range?(g.call(s, 'ewma'), 0, 1)
      return 'stepUps must be finite and >= 0' unless in_range?(g.call(s, 'stepUps'), 0, MAX_COUNT)
      return 'denies must be finite and >= 0' unless in_range?(g.call(s, 'denies'), 0, MAX_COUNT)
      return 'lastAt must be a finite non-negative time' unless in_range?(g.call(s, 'lastAt'), 0, 9_007_199_254_740_991)
      return 'seeded must be a boolean' unless [true, false].include?(g.call(s, 'seeded'))

      nil
    end

    # The current threat: {'level' => calm|elevated|high, 'score', 'signals', 'components' => {drift, volatility, violation}}. The score is
    # the maximum of the drift, step-up volatility and violation signals; levels switch at 0.33 and 0.66. A malformed state is the maximal threat.
    def assess(state, cfg = nil)
      bad = validate_immune_state(state)
      return threat('high', 1, ["invalid immune state: #{bad}"], 1, 1, 1) if bad

      base = state['baseline']
      std = baseline_std(base)
      signals = []
      drift = 0.0
      if base['n'] >= 5 && std > 1e-9
        z = (state['ewma'] - base['mean']) / std
        drift = clamp01(z / cfg_of(cfg, 'driftZSat', DRIFT_Z_SAT))
        signals << "risk drifted #{Harness.to_fixed(z, 1)}σ above baseline" if drift > 0.33
      end
      volatility = clamp01(state['stepUps'].to_f / cfg_of(cfg, 'stepUpSat', STEP_UP_SAT))
      signals << "elevated step-up rate (#{Harness.to_fixed(state['stepUps'], 1)})" if volatility > 0.33
      violation = clamp01(state['denies'].to_f / cfg_of(cfg, 'denySat', DENY_SAT))
      signals << "repeated policy violations (#{Harness.to_fixed(state['denies'], 1)})" if violation > 0.33
      score = [drift, volatility, violation].max
      threat(score >= 0.66 ? 'high' : (score >= 0.33 ? 'elevated' : 'calm'), score, signals, drift, volatility, violation)
    end

    def threat(level, score, signals, drift, volatility, violation)
      { 'level' => level, 'score' => score, 'signals' => signals, 'components' => { 'drift' => drift, 'volatility' => volatility, 'violation' => violation } }
    end

    # ---- adaptation
    # The adapted policy for a threat assessment, derived from the BASE policy (never compounded): {'policy', 'changed', 'rationale'}.
    # Default caps: kappa x3, theta x0.4.
    def adapt(base, assessment, max_kappa_mult = 3, min_theta_mult = 0.4)
      sc = jv(assessment, 'score')
      s = fin?(sc) ? clamp01(sc.to_f) : 1.0 # a non-finite score is the worst case, never calm
      return adaptation(base, false, "calm — baseline policy") if s.zero?

      kappa_mult = 1 + ((max_kappa_mult - 1) * s)
      theta_mult = 1 - ((1 - min_theta_mult) * s)
      w = jv(base, 'weights')
      policy = base.is_a?(Hash) ? base.dup : {}
      policy['weights'] = w.is_a?(Hash) ? w.dup : {}
      policy['kappa'] = to_num(jv(base, 'kappa')) * kappa_mult
      policy['theta1'] = clamp01(to_num(jv(base, 'theta1')) * theta_mult)
      policy['theta2'] = clamp01(to_num(jv(base, 'theta2')) * theta_mult)
      bad = AtlasPca.risk_policy_error(policy) || no_widen_violation(base, policy)
      return adaptation(base, false, "adaptation rejected (#{bad}) — kept baseline") if bad

      sig = jv(assessment, 'signals')
      raise TypeError, "Cannot read properties of #{sig.nil? ? 'null' : 'undefined'} (reading 'length')" unless sig.is_a?(Array)

      lvl = jv(assessment, 'level')
      why = sig.empty? ? "threat score #{Harness.to_fixed(s, 2)}" : sig.map { |e| e.nil? ? '' : Js.string(e) }.join('; ')
      adaptation(policy, true, "#{lvl.equal?(UNDEF) ? 'undefined' : Js.string(lvl)}: #{why} → κ ×#{Harness.to_fixed(kappa_mult, 2)}, " \
                               "θ ×#{Harness.to_fixed(theta_mult, 2)}")
    end

    def adaptation(policy, changed, rationale) = { 'policy' => policy, 'changed' => changed, 'rationale' => rationale }

    # JS `!==` negated on two members (numbers by value, an absent member only equals an absent one, objects by identity).
    def same?(a, b)
      return a.equal?(b) if a.equal?(UNDEF) || b.equal?(UNDEF)
      return a == b if Js.num?(a) && Js.num?(b)
      return a.equal?(b) if a.is_a?(Hash) || a.is_a?(Array)

      a == b && a.class == b.class
    end

    # Why adapted is looser than base, or nil when it only tightens (kappa up, thetas down, the rest identical). A non-number reads as looser.
    def no_widen_violation(base, adapted)
      return 'kappa decreased' unless to_num(jv(adapted, 'kappa')) >= to_num(jv(base, 'kappa'))
      return 'theta1 increased' unless to_num(jv(adapted, 'theta1')) <= to_num(jv(base, 'theta1'))
      return 'theta2 increased' unless to_num(jv(adapted, 'theta2')) <= to_num(jv(base, 'theta2'))

      %w[lambda rho bMax].each { |k| return "#{k} changed" unless same?(jv(adapted, k), jv(base, k)) }
      bw = jv(base, 'weights')
      raise TypeError, 'Cannot convert undefined or null to object' if bw.nil? || bw.equal?(UNDEF)

      (bw.is_a?(Hash) ? bw.keys : []).each do |k|
        aw = jv(adapted, 'weights')
        return "weights.#{k} changed" unless same?(jv(aw, k), jv(bw, k))
      end
      nil
    end

    # Raises unless adapted only tightens base.
    def assert_no_widen(base, adapted)
      v = no_widen_violation(base, adapted)
      raise "immune: adaptation widens the policy (#{v})" if v
    end

    # ---- signed tightening proposals
    def hash_lenient(v) = ActionsImportCommon.hash_canonical_lenient(v)
    def policy_digest(p) = hash_lenient(p)
    def immune_state_digest(s) = hash_lenient(s)

    def tightening_message(claim) = TIGHTENING_DOMAIN + V2JS.te_bytes(ActionsImportCommon.lenient(claim))

    # Derive and sign the tightening for state; raises on a malformed base, an epoch that is not an integer >= 1, a non-finite now or a
    # malformed state (never an unsigned loosening). guardian_secret is the 32-byte Ed25519 seed.
    def issue_tightening_proposal(base, state, epoch, now, guardian_secret)
      bad = AtlasPca.risk_policy_error(base)
      raise ArgumentError, "issueTighteningProposal: #{bad}" if bad
      raise ArgumentError, 'issueTighteningProposal: epoch must be an integer >= 1' unless Js.safe_integer?(epoch) && epoch >= 1
      raise ArgumentError, 'issueTighteningProposal: now must be finite' unless fin?(now)

      key = OpenSSL::PKey.new_raw_private_key('ED25519', guardian_secret.b)
      ad = adapt(base, assess(state))
      claim = { 'v' => 1, 'base_digest' => policy_digest(base), 'state_digest' => hash_lenient(state), 'epoch' => epoch, 'issued_at' => now,
                'policy' => ad['policy'], 'rationale' => ad['rationale'], 'guardian' => AtlasPca.b64e(key.raw_public_key) }
      claim.merge('sig' => AtlasPca.b64e(key.sign(nil, tightening_message(claim))))
    end

    def refused(reason) = { 'ok' => false, 'reason' => reason }

    # JS `!(a <= b)` where b is an option member (UNDEF is NaN, so stale), with a fail-closed answer for a non-numeric b.
    def stale_age?(age, max)
      return true if max.equal?(UNDEF)
      return true unless max.nil? || Js.num?(max) || max == true || max == false || max.is_a?(String)

      !(age <= to_num(max))
    end

    # Verify a proposal: {'ok' => true, 'policy', 'epoch'} or {'ok' => false, 'reason'}; never raises. o holds the pinned 'guardian' (b64u,
    # required), 'lastEpoch', 'now', 'maxAgeMs' and optionally 'state' (a recompute check).
    def apply_tightening(base, p, o)
      return refused('malformed') unless p.is_a?(Hash) && Js.num?(p['v']) && p['v'] == 1 && p['sig'].is_a?(String) && p['guardian'].is_a?(String)

      pin = jv(o, 'guardian')
      return refused('guardian') unless pin.is_a?(String) && pin == p['guardian']

      claim = p.reject { |k, _| k == 'sig' }
      return refused('signature') unless AtlasPca.verify_b64u(p['guardian'], tightening_message(claim), p['sig'])
      return refused('invalid-policy') if AtlasPca.risk_policy_error(base) || AtlasPca.risk_policy_error(p['policy'])
      return refused('base') unless p['base_digest'] == policy_digest(base)

      now = jv(o, 'now')
      at = p['issued_at']
      return refused('stale') if !fin?(now) || !fin?(at) || !(at <= now) || stale_age?(now - at, jv(o, 'maxAgeMs'))

      epoch = p['epoch']
      last = jv(o, 'lastEpoch')
      return refused('replayed-epoch') if !Js.safe_integer?(epoch) || Js.neg_zero?(epoch) || !(epoch > (last.equal?(UNDEF) ? Float::NAN : to_num(last)))
      return refused('widens') if no_widen_violation(base, p['policy'])

      st = jv(o, 'state')
      if !st.equal?(UNDEF) && Js.truthy?(st) &&
         (p['state_digest'] != hash_lenient(st) || policy_digest(adapt(base, assess(st))['policy']) != policy_digest(p['policy']))
        return refused('state-mismatch')
      end
      { 'ok' => true, 'policy' => p['policy'], 'epoch' => epoch }
    rescue StandardError
      refused('malformed')
    end

    # ---- durable state
    # Immune state and applied epoch for one subject over an atomic kv (get / update, see AtomicKv), so a restart keeps the history and the
    # replay floor. A stored JSON null reads as absent in this kv.
    def create_immune_store(kv, subject) = ImmuneStore.new(kv, subject)

    class ImmuneStore
      def initialize(kv, subject)
        raise ArgumentError, 'immune store: kv must support get and update' unless AtlasPca.kv_usable?(kv)

        @kv = kv
        @s_key = "immune/state/#{subject}"
        @e_key = "immune/epoch/#{subject}"
      end

      # The stored state, or the initial one.
      def get
        v = @kv.get(@s_key)
        v.nil? ? Immune.initial_state : v
      end

      # Folds one observation atomically; raises when the stored state is malformed (it is never silently reset to calm).
      def observe(obs)
        @kv.update(@s_key) do |prev|
          cur = prev.nil? ? Immune.initial_state : prev
          bad = Immune.validate_immune_state(cur)
          raise "immune store: stored state invalid (#{bad})" if bad

          Immune.observe(cur, obs)
        end
      end

      def last_epoch
        v = @kv.get(@e_key)
        Js.num?(v) ? v : 0
      end

      # Verify and apply a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win. o is as for
      # apply_tightening without lastEpoch.
      def apply(base, p, o)
        out = Immune.refused('malformed')
        @kv.update(@e_key) do |prev|
          oo = o.is_a?(Hash) ? o.dup : {}
          oo['lastEpoch'] = Js.num?(prev) ? prev : 0
          out = Immune.apply_tightening(base, p, oo)
          out['ok'] == true ? out['epoch'] : nil
        end
        out
      end
    end
  end
end
