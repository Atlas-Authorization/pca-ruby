# frozen_string_literal: true

require 'json'

module AtlasPca
  # Fraud proofs and one-shot dispute adjudication for bonded optimistic claims (the reference's `optimistic`): verify_fraud_proof RE-RUNS the
  # policy VM on the server-held frozen open-time snapshot under the grant the verifier trusts, and adjudicate_dispute re-adjudicates with an
  # objective oracle's authoritative value substituted for the single disputed input. A slash is never authorized by a challenger's assertion.
  # Both are total (never raise) and FAIL CLOSED. Snapshots are decide inputs (AtlasPca.decide).
  module OptimisticAdjudication
    INPUTS = %w[reversibility_class reversibility blastRadius semanticDistance].freeze

    module_function

    def fin?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)
    def fixed3(x) = AtlasPca::AnalyzerJs.to_fixed(x, 3)
    def num_s(x) = fin?(x) ? AtlasPca::Predicates.js_number_string(x.to_f) : x.to_s
    def js_s(v) = v.nil? ? 'undefined' : AtlasPca::AnalyzerJs.js_json(v)
    def dig_h(h, *ks) = ks.reduce(h) { |a, k| a.is_a?(Hash) ? a[k] : nil }

    # Independently verify a fraud proof against a bonded claim: {'fraudulent', 'slashBondRef'?, 'reason'}.
    def verify_fraud_proof(claim, proof, grant, open_snapshot)
      # `!proof || typeof proof !== 'object'`: an array is an object with no members
      proof = {} if proof.is_a?(Array)
      return { 'fraudulent' => false, 'reason' => 'malformed fraud proof' } unless proof.is_a?(Hash)
      return { 'fraudulent' => false, 'reason' => 'fraud proof targets a different PCActn than the claim' } if proof['pcactn_digest'] != claim['pcactn_digest']
      return { 'fraudulent' => false, 'reason' => 'fraud proof names a different bond than the claim' } if proof['bond_ref'] != claim['bond_ref']
      open_snapshot = open_snapshot.each_with_index.to_h { |v, i| [i.to_s, v] } if open_snapshot.is_a?(Array) # `{...array}` spreads the indices
      return { 'fraudulent' => false, 'reason' => 'no frozen open-time snapshot supplied; cannot judge the claim' } unless open_snapshot.is_a?(Hash)

      rec = AtlasPca.decide(open_snapshot.merge('grant' => grant))
      summary = { 'releaseGuardianShare' => rec['releaseGuardianShare'], 'r' => rec['r'], 'optimisticAllowed' => rec['requiredThreshold']['optimisticAllowed'] }
      # proof.decision.releaseGuardianShare throws on a missing or null decision; any other non-object reads as no members
      raise TypeError, "Cannot read properties of #{proof.key?('decision') ? 'null' : 'undefined'} (reading 'releaseGuardianShare')" if proof['decision'].nil?

      d = proof['decision'].is_a?(Hash) ? proof['decision'] : {}
      if summary['releaseGuardianShare'] != d['releaseGuardianShare'] || summary['optimisticAllowed'] != d['optimisticAllowed'] ||
         !((summary['r'] - d.fetch('r')).abs <= 1e-9)
        return { 'fraudulent' => false, 'reason' => 'proof decision does not match an independent recomputation' }
      end

      margin = fin?(proof['r_margin']) ? [0, proof['r_margin']].max : DEFAULT_R_MARGIN
      snap_class = dig_h(open_snapshot, 'action', 'action', 'reversibility_class')
      irreversible = claim['reversibility_class'] == IRREVERSIBLE_CLASS || snap_class == IRREVERSIBLE_CLASS
      ref = claim['bond_ref']
      return { 'fraudulent' => true, 'slashBondRef' => ref, 'reason' => 'irreversible action is ineligible for the optimistic path' } if irreversible
      unless summary['releaseGuardianShare']
        why = rec['reasons'].empty? ? 'not compliant' : rec['reasons'].join('; ')
        return { 'fraudulent' => true, 'slashBondRef' => ref, 'reason' => "Policy VM denies the action: #{why}" }
      end
      unless summary['optimisticAllowed']
        return { 'fraudulent' => true, 'slashBondRef' => ref, 'reason' => "optimistic path not allowed at real r=#{fixed3(summary['r'])}" }
      end
      if summary['r'] > claim.fetch('claimed_r') + margin
        return { 'fraudulent' => true, 'slashBondRef' => ref, 'reason' => "risk understated: claimed #{num_s(claim['claimed_r'])}, real #{fixed3(summary['r'])}" }
      end

      { 'fraudulent' => false, 'reason' => 'claim is compliant under independent recomputation; bond stands' }
    rescue StandardError => e
      { 'fraudulent' => false, 'reason' => "fraud-proof verification error: #{e.message.to_s.empty? ? 'unknown' : e.message}" }
    end

    def summarize(d) = { 'releaseGuardianShare' => d['releaseGuardianShare'], 'r' => d['r'], 'optimisticAllowed' => d['requiredThreshold']['optimisticAllowed'] }

    def fast_path_admits?(s, claimed_r, margin) = s['releaseGuardianShare'] && s['optimisticAllowed'] && s['r'] <= claimed_r + margin

    def snapshot_value(snap, input)
      if input == 'reversibility_class'
        v = dig_h(snap, 'caveatContext', 'reversibilityClass')
        return v.nil? ? dig_h(snap, 'action', 'action', 'reversibility_class') : v
      end
      dig_h(snap, 'risk', input)
    end

    def substitute(snap, res)
      if res['input'] == 'reversibility_class'
        raise ArgumentError, 'oracle reversibility_class resolution carries no class' unless res['class'].is_a?(String) && !res['class'].empty?

        out = snap.dup
        act = (snap['action'] || {}).dup
        act['action'] = (act['action'] || {}).merge('reversibility_class' => res['class'])
        out['action'] = act
        out['caveatContext'] = snap['caveatContext'].merge('reversibilityClass' => res['class']) unless dig_h(snap, 'caveatContext', 'reversibilityClass').nil?
        return out
      end
      raise ArgumentError, "oracle #{res['input']} resolution carries no finite value" unless fin?(res['value'])

      out = snap.merge('risk' => (snap['risk'] || {}).merge(res['input'] => res['value']))
      out['caveatContext'] = snap['caveatContext'].merge('blastRadius' => res['value']) if res['input'] == 'blastRadius' && !dig_h(snap, 'caveatContext', 'blastRadius').nil?
      out
    end

    # Adjudicate a contestable dispute: RE-RUN the policy VM on the frozen open-time snapshot with the ORACLE's authoritative value substituted
    # for the single disputed input (`oracle.resolve(input, snapshot)` returns {'input', 'value'?, 'class'?, 'valid', 'reason'?}). 'outcome':
    # 'agent-fraud' (slash the agent's bond), 'claim-upheld' (slash the challenger's counter-bond) or 'indeterminate' (slash neither). The
    # challenger's asserted value is never read for the verdict.
    def adjudicate_dispute(claim, dispute, grant, open_snapshot, oracle, r_margin = nil)
      margin = fin?(r_margin) ? [0, r_margin].max : DEFAULT_R_MARGIN
      worst = { 'releaseGuardianShare' => false, 'r' => 1, 'optimisticAllowed' => false }
      indeterminate = lambda do |input, reason, extra = {}|
        # `agentValue` / `oracleValue` are undefined (absent from the verdict) unless the run reached them
        { 'outcome' => 'indeterminate', 'fraudulent' => false, 'slashCounterBond' => false, 'input' => input,
          'baseline' => worst, 'adjudicated' => worst, 'reason' => reason }.merge(extra).reject { |_k, v| v.nil? }
      end
      begin
        dispute = {} if dispute.is_a?(Array) # an array is an object with no members
        return indeterminate.call('reversibility_class', 'malformed dispute') unless dispute.is_a?(Hash)

        input = dispute['input']
        return indeterminate.call('reversibility_class', "unknown disputed input: #{input.nil? ? 'undefined' : input}") unless INPUTS.include?(input)
        return indeterminate.call(input, 'dispute targets a different PCActn than the claim') if dispute['pcactn_digest'] != claim['pcactn_digest']
        return indeterminate.call(input, 'dispute names a different bond than the claim') if dispute['bond_ref'] != claim['bond_ref']
        open_snapshot = open_snapshot.each_with_index.to_h { |v, i| [i.to_s, v] } if open_snapshot.is_a?(Array) # `{...array}` spreads the indices
        return indeterminate.call(input, 'no frozen open-time snapshot supplied; cannot adjudicate') unless open_snapshot.is_a?(Hash)
        return indeterminate.call(input, 'no objective oracle supplied') if oracle.nil? || !oracle.respond_to?(:resolve)

        snap = open_snapshot.merge('grant' => grant)
        baseline = summarize(AtlasPca.decide(snap))
        agent_value = snapshot_value(snap, input)
        res = oracle.resolve(input, snap)
        if !res.is_a?(Hash) || res['input'] != input || !(res['valid'] && res['valid'] != 0 && res['valid'] != '')
          tail = res.is_a?(Hash) && res['reason'] && res['reason'] != '' ? ": #{res['reason']}" : ''
          return indeterminate.call(input, "objective oracle could not authoritatively resolve #{input}#{tail}", 'baseline' => baseline, 'agentValue' => agent_value)
        end

        oracle_value = res['class'].nil? ? res['value'] : res['class']
        adjudicated = summarize(AtlasPca.decide(substitute(snap, res)))
        unless fast_path_admits?(adjudicated, claim['claimed_r'], margin)
          why = if !adjudicated['releaseGuardianShare'] then 'the Policy VM denies the action'
                elsif !adjudicated['optimisticAllowed'] then "the optimistic path is not allowed (higher threshold) at r=#{fixed3(adjudicated['r'])}"
                else "the real r=#{fixed3(adjudicated['r'])} exceeds the claimed r=#{num_s(claim['claimed_r'])}"
                end
          return({ 'outcome' => 'agent-fraud', 'fraudulent' => true, 'slashBondRef' => claim['bond_ref'], 'slashCounterBond' => false, 'input' => input,
                   'agentValue' => agent_value, 'oracleValue' => oracle_value, 'baseline' => baseline, 'adjudicated' => adjudicated,
                   'reason' => "understated #{input}: agent relied on #{js_s(agent_value)}, oracle says #{js_s(oracle_value)} — #{why}" }.reject { |_k, v| v.nil? })
        end
        ({ 'outcome' => 'claim-upheld', 'fraudulent' => false, 'slashCounterBond' => true, 'input' => input, 'agentValue' => agent_value,
          'oracleValue' => oracle_value, 'baseline' => baseline, 'adjudicated' => adjudicated,
          'reason' => "the objective oracle upholds the agent's #{input} (#{js_s(oracle_value)}); fast-path admission survives — the dispute is frivolous" }).reject { |_k, v| v.nil? }
      rescue StandardError => e
        d_in = dispute.is_a?(Hash) && INPUTS.include?(dispute['input']) ? dispute['input'] : 'reversibility_class'
        indeterminate.call(d_in, "dispute adjudication error (fail closed): #{e.message.to_s.empty? ? 'unknown' : e.message}")
      end
    end

    # A deep, JSON-normalized copy of a decide input captured at claim open (store it with the claim, grant stripped).
    def freeze_open_snapshot(inp) = JSON.parse(JSON.generate(inp))
  end
end
