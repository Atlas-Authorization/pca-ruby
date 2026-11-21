# frozen_string_literal: true

require_relative 'intent_omega'

# Trust ramp and drift: start narrow, widen only through confirmed behaviour, veto on every negative runtime signal, and a
# one-sided Bernoulli CUSUM that freezes widening on drift. Native port of the TypeScript reference (@atlasauth/pca-intent). A
# "learner" is any object with #cells, #admits_outcome(o) and #observe(o, y, source).
module AtlasPca
  module IntentRamp
    module_function

    def signal_label(s) = s == 'jit-approve' || s == 'principal-confirm' ? 1 : 0

    # The narrow starting configuration for a learner that will be ramped.
    def narrow_start(omega, slots, opts = nil)
      opts ||= {}
      slot_mass = opts['slotNullMass']
      other_mass = opts['otherNullMass']
      null_mass = {}
      omega['verbs'].each do |vs|
        null_mass[vs['verb']] = if slots['verbs'].include?(vs['verb'])
                                  slot_mass.nil? ? 0.5 : slot_mass
                                else
                                  other_mass.nil? ? 0.95 : other_mass
                                end
      end
      { 'eta' => 0, 'tau' => 1, 'nullMass' => null_mass }
    end

    def fresh = { 'statistic' => 0, 'alarm' => false, 'informative' => 0, 'divergences' => 0 }

    class DriftDetector
      attr_reader :rho0, :rho1, :h

      def initialize(o = nil)
        o ||= {}
        @rho0 = o['rho0'].nil? ? 0.02 : o['rho0']
        @rho1 = o['rho1'].nil? ? 0.25 : o['rho1']
        @h = o['h'].nil? ? Math.log(100) : o['h']
        raise ArgumentError, 'DriftDetector: need 0 < rho0 < rho1 < 1' unless @rho0 > 0 && @rho0 < @rho1 && @rho1 < 1
        raise ArgumentError, 'DriftDetector: h must be positive' unless @h > 0

        @s = IntentRamp.fresh
      end

      # Feed one signal about an action that was inside the grant: diverged = true for a negative signal.
      def update(diverged)
        inc = diverged ? Math.log(@rho1 / @rho0) : Math.log((1 - @rho1) / (1 - @rho0))
        statistic = IntentOmega.js_max(0, @s['statistic'] + inc)
        @s = { 'statistic' => statistic, 'alarm' => @s['alarm'] || statistic >= @h,
               'informative' => @s['informative'] + 1, 'divergences' => @s['divergences'] + (diverged ? 1 : 0) }
        state
      end

      def state = @s.dup

      def reset
        @s = IntentRamp.fresh
      end
    end

    class TrustRamp
      attr_reader :drift, :log, :learner

      def initialize(learner, drift = nil)
        @learner = learner
        @drift = DriftDetector.new(drift)
        @queued = []
        @log = []
      end

      # Widening is frozen while a drift alarm stands.
      def frozen = @drift.state['alarm']

      # Positive signals held back by a freeze (released only by rebase).
      def pending = @queued

      def grant_size = @learner.cells.count { |c| c['inGrant'] }
      private :grant_size

      def record(o, signal)
        y = IntentRamp.signal_label(signal)
        was_in_grant = @learner.admits_outcome(o)
        before = grant_size
        drift = @drift.state
        drift = @drift.update(y.zero?) if was_in_grant
        applied = true
        if y == 1 && frozen
          @queued << { 'o' => o, 'signal' => signal }
          applied = false
        else
          @learner.observe(o, y, 'runtime')
        end
        rec = { 'signal' => signal, 'y' => y, 'wasInGrant' => was_in_grant, 'before' => before, 'after' => grant_size, 'applied' => applied, 'drift' => drift }
        @log << rec
        rec
      end

      # Record a SIGNED runtime observation: the signature must verify (ctx['verify_observation'] is the core observation verifier,
      # returning {ok, reason?}), the signer must be trusted and the observation must be about this map.
      def record_observation(obs, ctx)
        verify = ctx['verify_observation']
        return { 'ok' => false, 'reason' => 'no observation verifier configured' } if verify.nil?

        v = verify.call(obs, ctx['verify'] || {})
        return { 'ok' => false, 'reason' => v['reason'] } unless v['ok']
        return { 'ok' => false, 'reason' => 'untrusted observation signer' } unless ctx['trustedSigners'].include?(obs['signer'])
        return { 'ok' => false, 'reason' => 'observation is about a different map' } if obs['map_digest'] != ctx['mapDigest']
        return { 'ok' => false, 'reason' => 'only runtime observations feed the ramp' } if obs['source'] != 'runtime'

        sig = obs['y'] == 1 ? 'principal-confirm' : 'postcondition-violation'
        { 'ok' => true, 'record' => record({ 'verb' => obs['verb'], 'values' => obs['values'] }, sig) }
      end

      # Re-base on a new, signed intent statement (the only way to clear an alarm); queued positive signals are discarded.
      def rebase(nxt)
        @learner = nxt
        @queued = []
        @drift.reset
      end
    end
  end
end
