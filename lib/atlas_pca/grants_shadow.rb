# frozen_string_literal: true

# Shadow policy rollout (the TypeScript reference, @atlasauth/pca-grants): run candidate policy bundles beside the enforced one, record
# every divergence as a verifier-signed diff, and gate promotion on zero unexplained widenings. The enforced decision is computed first
# and returned untouched, so a candidate that raises, returns junk or mutates its input cannot change the answer. Nothing here decides
# an action; it is analysis and rollout tooling.
#
# `decide` hooks are callables returning "allow", "deny" or "escalate"; gate options are a Hash with the reference's member names
# ('shadow_digest', 'enforced_digest', 'minSamples', 'principals', 'explanations', 'surface', 'approval').
require_relative 'grants'

module AtlasPca
  module GrantsShadow
    SHADOW_DIFF_DOMAIN = "atlas-pca/shadow-diff/v1\x00".b.freeze
    WIDENING_EXPLANATION_DOMAIN = "atlas-pca/shadow-widening-explanation/v1\x00".b.freeze
    PROMOTION_APPROVAL_DOMAIN = "atlas-pca/shadow-promotion-approval/v1\x00".b.freeze
    DIFF_KEYS = %w[v shadow_digest enforced_digest action_digest enforced shadow widening at signer].freeze

    module_function

    def kind?(x) = x.is_a?(String) && Grants::RANK.key?(x)
    def one?(x) = x.is_a?(Integer) && x == 1
    def obj?(x) = x.is_a?(Hash)

    # The enforced decision, plus what each candidate ({'digest', 'decide'}) would have said: { 'decision', 'shadow' => [outcome] } with
    # outcome { 'digest', 'decision' | 'error', 'diverged', 'widening' }. The returned decision is the enforced one, always.
    def run_shadow(input, enforced, candidates)
      decision = enforced.call(input)
      shadow = candidates.map do |c|
        d = c['decide'].call(Grants.deep_copy(input))
        if kind?(d)
          { 'digest' => c['digest'], 'decision' => d, 'diverged' => d != decision, 'widening' => Grants.rank_gt?(Grants.rank(d), Grants.rank(decision)) }
        else
          { 'digest' => c['digest'], 'decision' => 'error', 'diverged' => false, 'widening' => false }
        end
      rescue StandardError # a failing candidate is an error outcome, never an answer
        { 'digest' => c['digest'], 'decision' => 'error', 'diverged' => false, 'widening' => false }
      end
      { 'decision' => decision, 'shadow' => shadow }
    end

    # The `shadow` member of a decision record, from the outcomes.
    def shadow_record_field(outcomes) = outcomes.map { |o| { 'digest' => o['digest'], 'decision' => o['decision'], 'diverged' => o['diverged'] } }

    def diff_body(d) = DIFF_KEYS.to_h { |k| [k, d[k]] }

    # A well formed diff signed by its own signer (and by `signer` when given). Never raises.
    def verify_shadow_diff(d, signer = nil)
      return false if !obj?(d) || !one?(d['v']) || !(AtlasPca.k3_str?(d['shadow_digest'], 128) && AtlasPca.k3_str?(d['enforced_digest'], 128) && AtlasPca.k3_str?(d['action_digest'], 128)) ||
                      !kind?(d['enforced']) || !kind?(d['shadow']) || ![true, false].include?(d['widening']) || !AtlasPca.k3_int?(d['at']) || !AtlasPca.k3_str?(d['signer'], 128)
      return false if d['enforced'] == d['shadow'] || d['widening'] != Grants.rank_gt?(Grants.rank(d['shadow']), Grants.rank(d['enforced']))
      return false if !signer.nil? && d['signer'] != signer

      AtlasPca.k3_verify_body(SHADOW_DIFF_DOMAIN, diff_body(d), d['signer'], d['sig'])
    rescue StandardError
      false
    end

    def zero_stats = { 'total' => 0, 'diverged' => 0, 'widened' => 0, 'tightened' => 0, 'errors' => 0 }

    # Collects the signed diffs and counters per candidate. In memory: persist diffs() to the decision log for the audit trail.
    class ShadowLog
      def initialize(key)
        @key = key
        @stat = {}
        @list = {}
      end

      def signer = @key.public

      # Count one observation; sign and keep a diff when the candidate diverged.
      def observe(enforced_digest, action_digest, enforced, outcome, at)
        s = (@stat[outcome['digest']] ||= GrantsShadow.zero_stats)
        s['total'] += 1
        if outcome['decision'] == 'error'
          s['errors'] += 1
          return nil
        end
        return nil unless outcome['diverged']

        s['diverged'] += 1
        s[outcome['widening'] ? 'widened' : 'tightened'] += 1
        base = { 'v' => 1, 'shadow_digest' => outcome['digest'], 'enforced_digest' => enforced_digest, 'action_digest' => action_digest,
                 'enforced' => enforced, 'shadow' => outcome['decision'], 'widening' => outcome['widening'], 'at' => at, 'signer' => signer }
        diff = base.merge('sig' => Grants.sign_body(SHADOW_DIFF_DOMAIN, GrantsShadow.diff_body(base), @key))
        (@list[outcome['digest']] ||= []) << diff
        diff
      end

      def stats(digest) = (@stat[digest] || GrantsShadow.zero_stats).dup
      def diffs(digest) = (@list[digest] || []).dup
    end

    def exp_body(e) = %w[v shadow_digest action_digest reason_digest principal].to_h { |k| [k, e[k]] }

    # A principal states that this widening is intended (reason_digest binds the display-only reason text).
    def sign_widening_explanation(key, e)
      base = { 'v' => 1 }.merge(Grants.spread(e)).merge('principal' => Grants.signer_of(key))
      base.merge('sig' => Grants.sign_body(WIDENING_EXPLANATION_DOMAIN, exp_body(base), key))
    end

    def verify_explanation(e)
      return false if !obj?(e) || !one?(e['v']) || !(AtlasPca.k3_str?(e['shadow_digest'], 128) && AtlasPca.k3_str?(e['action_digest'], 128) &&
                                                     AtlasPca.k3_str?(e['reason_digest'], 128) && AtlasPca.k3_str?(e['principal'], 128))

      AtlasPca.k3_verify_body(WIDENING_EXPLANATION_DOMAIN, exp_body(e), e['principal'], e['sig'])
    rescue StandardError
      false
    end

    def ap_body(a) = %w[v shadow_digest enforced_digest at principal].to_h { |k| [k, a[k]] }

    def sign_promotion_approval(key, a)
      base = { 'v' => 1 }.merge(Grants.spread(a)).merge('principal' => Grants.signer_of(key))
      base.merge('sig' => Grants.sign_body(PROMOTION_APPROVAL_DOMAIN, ap_body(base), key))
    end

    def verify_approval(a)
      return false if !obj?(a) || !one?(a['v']) || !(AtlasPca.k3_str?(a['shadow_digest'], 128) && AtlasPca.k3_str?(a['enforced_digest'], 128)) ||
                      !AtlasPca.k3_int?(a['at']) || !AtlasPca.k3_str?(a['principal'], 128)

      AtlasPca.k3_verify_body(PROMOTION_APPROVAL_DOMAIN, ap_body(a), a['principal'], a['sig'])
    rescue StandardError
      false
    end

    def num_s(x) = x.is_a?(Float) && x == x.to_i ? x.to_i.to_s : Js.string(x)

    # May this candidate be promoted? Enough samples, no candidate failures, every diff verifies, zero unexplained widenings, and a
    # principal-signed approval when the static verdict on the declared surfaces is wider or unknown. Fails closed.
    def promotion_gate(log, o)
      no = lambda do |code, reason, unexplained = nil|
        { 'ok' => false, 'code' => code, 'reason' => reason }.merge(unexplained.nil? || unexplained.empty? ? {} : { 'unexplained' => unexplained })
      end
      principals = o['principals']
      if !AtlasPca.k3_str?(o['shadow_digest'], 128) || !AtlasPca.k3_str?(o['enforced_digest'], 128) || !AtlasPca.k3_int?(o['minSamples']) ||
         o['minSamples'] < 1 || !principals.is_a?(Array) || !%w[narrower equal wider unknown].include?(o['surface'])
        return no.call('bad_input', 'bad gate options')
      end

      sd = o['shadow_digest']
      ed = o['enforced_digest']
      s = log.stats(sd)
      return no.call('too_few_samples', "#{s['total']} observation(s), need #{num_s(o['minSamples'])}") if s['total'] < o['minSamples']
      return no.call('shadow_errors', "#{s['errors']} observation(s) where the candidate failed") if s['errors'].positive?

      diffs = log.diffs(sd)
      if !diffs.all? { |d| verify_shadow_diff(d, log.signer) && d['shadow_digest'] == sd && d['enforced_digest'] == ed } || diffs.length != s['diverged']
        return no.call('bad_diff', 'a recorded diff does not verify, belongs to another pair, or is missing')
      end

      explained = {}
      exps = o['explanations']
      exps = [] if exps.nil?
      raise TypeError, 'explanations is not iterable' if exps.is_a?(Hash)

      exps = exps.chars if exps.is_a?(String)

      exps.each { |e| explained[e['action_digest']] = true if verify_explanation(e) && principals.include?(e['principal']) && e['shadow_digest'] == sd }
      unexplained = diffs.select { |d| d['widening'] && !explained.key?(d['action_digest']) }.map { |d| d['action_digest'] }.uniq.sort_by { |x| AtlasPca.utf16_key(x) }
      return no.call('unexplained_widening', "#{unexplained.length} widening(s) without a principal's explanation", unexplained) unless unexplained.empty?

      if %w[wider unknown].include?(o['surface'])
        a = o['approval']
        if !verify_approval(a) || !principals.include?(a['principal']) || a['shadow_digest'] != sd || a['enforced_digest'] != ed
          return no.call('advisory_wider', "the analyzer reports the candidate #{o['surface'] == 'wider' ? 'wider' : 'not provably narrower'} on the declared surfaces: a principal-signed approval is required")
        end
      end
      { 'ok' => true, 'samples' => s['total'], 'widenings' => diffs.count { |d| d['widening'] }, 'surface' => o['surface'] }
    rescue StandardError
      { 'ok' => false, 'code' => 'bad_input', 'reason' => 'evaluation error (fail closed)' }
    end

    # The body of the bundle revision that makes the candidate the enforced policy: its content at revision + 1, chained to the enforced
    # revision, with the shadow list cleared. Needs a passing gate for this candidate, and the candidate must be listed in the enforced
    # revision's `shadow`. Sign it with sign_bundle / assemble_bundle like any revision.
    def promote_shadow(enforced, candidate, gate, now)
      digest = AtlasPca.bundle_digest(candidate)
      raise ArgumentError, "promoteShadow: the gate did not pass (#{gate['code']})" unless Js.truthy?(gate['ok'])
      raise ArgumentError, "promoteShadow: the candidate is not listed in the enforced revision's shadow" unless (enforced['shadow'].nil? ? [] : enforced['shadow']).include?(digest)
      raise ArgumentError, 'promoteShadow: bad time' unless AtlasPca.k3_int?(now)

      Grants.without(candidate, 'sigs', 'shadow', 'prev').merge('revision' => enforced['revision'] + 1, 'prev' => AtlasPca.bundle_digest(enforced), 'issued_at' => now)
    end
  end
end
