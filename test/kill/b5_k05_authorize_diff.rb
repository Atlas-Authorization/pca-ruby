# frozen_string_literal: true
# k05 the authorize pipeline's 0.5 additions (authorize.rb + the provenance gate in arg_provenance.rb) against server/
# authorize.ts, agent-native.ts tool_schema, risk.ts and envelope.ts: test-data/k05-authorize.json.gz (tools/pca-audit/
# k05-oracles/authorize-oracle.mts). An `authorize` case is a scenario {grant, config, steps}: one authorizer (fresh replay
# store, the TS createAuthorizer options mapped to AtlasPca.authorize keywords) runs every step; each step's result is projected
# exactly as the generator does (checks in the KEY set, failed checks, the gate's own reasons, escalation, undo).
module MutationKill
  module K05Authorize
    module_function

    KEY = %w[wire version audience validity cap_chain grant_ref_bound plan_inclusion plan_root_authorized leaf_signature counter_format
             fresh_at attestation revocation grant_ref operation params_digest delegated_caveats policy replay provenance_flow undo_window
             escalation].freeze
    OWN = ['provenance_flow: ', 'undo_window: ', 'escalation: ', 'fresh_at: '].freeze

    def scenario(sc)
      cfg = sc['config']
      grant = sc['grant']
      store = AtlasPca::MemoryStateStore.new
      revoked = false
      prov = { 'mediators' => cfg['mediators'] }
      prov['actions'] = ->(op) { cfg['actions'][op['verb']] } if cfg.key?('actions')
      prov['observed'] = ->(_p, _o, _s) { cfg['observed'] } if cfg.key?('observed')
      # the TS admit hook answers only a converted escalation, with a fresh copy of the configured admission for the verb
      undo = cfg.key?('undo') ? ->(_p, _g, op) { cfg['undo'].key?(op['verb']) ? Marshal.load(Marshal.dump(cfg['undo'][op['verb']])) : nil } : nil
      esc = cfg['escalation']
      sc['steps'].map do |s|
        revoked = s['revoked'] == true
        r = AtlasPca.authorize(
          s['pcactn'], operation: s['operation'], audience: cfg['audience'], resolve_grant: ->(ref) { ref == grant['id'] ? grant : nil },
                       state_store: store, is_revoked: ->(_p, _g) { revoked }, now: cfg['now'], plan: 'single-step',
                       fresh_at: cfg['freshAt'], provenance: prov, provenance_bundle: s['provenance'], undo: undo,
                       escalation_principals: esc && esc['principals'],
                       escalation_render: esc && esc['render_digest'] ? ->(_p) { esc['render_digest'] } : nil,
                       insecure_unbound_approval: esc ? esc['insecureUnboundApproval'] == true : false,
                       escalation_answer: s['escalationAnswer']
        )
        checks = (r.checks || {}).transform_keys { |k| k == 'chain' ? 'cap_chain' : k } # this SDK's verdict names it `chain`
        { 'allow' => r.allow, 'decision' => r.decision, 'status' => r.status,
          'checks' => KEY.select { |k| checks.key?(k) }.to_h { |k| [k, checks[k]] },
          'failed' => KEY.select { |k| checks[k] == 'fail' },
          'reasons' => (r.reasons || []).select { |x| OWN.any? { |o| x.start_with?(o) } }.map { |x| ts_names(x) },
          'escalation' => r.escalation.nil? ? nil : (r.allow ? r.escalation : { 'request' => true }),
          'undo' => r.undo }
      end
    end

    # the reference names its options escalation.render / insecureUnboundApproval; this SDK's are its keyword arguments
    def ts_names(reason) = reason.sub('(pass escalation_render:, or insecure_unbound_approval: true)', '(set escalation.render, or insecureUnboundApproval)')

    def tool_call(c)
      return c unless c.is_a?(Hash)

      c.to_h { |k, v| [{ 'toolSignatureDigest' => 'tool_signature_digest', 'toolSignature' => 'tool_signature' }.fetch(k, k), v] }
    end

    def tool_result(r)
      ok, reason = r
      reason.nil? ? { 'ok' => ok } : { 'ok' => ok, 'reason' => reason }
    end

    FNS = {
      'validateArgSchema' => ->(a, _) { AtlasPca.validate_arg_schema(a[0]) },
      'evaluateToolSchema' => ->(a, _) { tool_result(AtlasPca.evaluate_tool_schema(a[0], tool_call(a[1]))) },
      'validateRiskPolicy' => ->(a, _) { AtlasPca.risk_policy_error(a[0]) },
      'readEnvelope' => ->(a, _) { AtlasPca.read_envelope(a[0]) },
      'requiresAttestation' => ->(a, _) { AtlasPca.requires_attestation?(a[0]) },
      'authorize' => ->(a, _) { scenario(a[0]) }
    }.freeze
    SPEC = K05::Spec.new(file: 'k05-authorize.json.gz', libs: %w[authorize.rb arg_provenance.rb], fns: FNS, cmp: { default: K05::EXACT },
                         title: 'authorize')
  end
  K05.register(K05Authorize::SPEC, K05Authorize::FNS.keys)
end
