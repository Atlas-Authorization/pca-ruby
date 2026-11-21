# frozen_string_literal: true

# Approval-render wrappers, the facade view of a def and the provenance-gate facts (native port of the wrapper half of approval-render.ts,
# facade-spec.ts and provenance.ts of the TypeScript reference @atlasauth/pca-actions). The render itself is approval.rb render_approval.
# `verifier` is the caller's confirmation verifier (absent: nothing is confirmed).
require_relative 'actions'
require_relative 'actions_derive'
require_relative 'actions_effective'
require_relative 'approval'

module AtlasPca
  module ActionsRender
    A = AtlasPca::Actions
    E = AtlasPca::ActionsEffective

    module_function

    # render_approval, with the confirmation decided by the verifier (asked only after the render itself succeeded).
    def render_approval_with(d, params, verifier = nil)
      r = AtlasPca.render_approval(d, params, false)
      r['unreviewed'] = !E.confirmed?(d, verifier)
      r
    end

    # H(R) for an executed action; refuses unless the params are the ones the PCActn signed and the verb is the PCActn's verb.
    def render_digest_for_action(d, params, pcactn, verifier = nil)
      raise A::ActionKitError.new('render_verb_mismatch', "the PCActn is for '#{pcactn['action']['verb']}', the definition for '#{d['verb']}'") if pcactn['action']['verb'] != d['verb']
      raise A::ActionKitError.new('render_params_mismatch', 'the supplied params are not the params the PCActn signed') if pcactn['action']['params_digest'] != AtlasPca.params_digest(params)

      AtlasPca.approval_render_digest(render_approval_with(d, params, verifier))
    end

    # The approver client's check before it signs: re-render from the pinned def and require the requested digest. Returns the digest to sign.
    def approver_render_check(d, params, requested_render_digest, verifier = nil)
      dg = AtlasPca.approval_render_digest(render_approval_with(d, params, verifier))
      raise A::ActionKitError.new('render_mismatch', 'the approval request commits to a render this definition and these params do not produce') if dg != requested_render_digest

      dg
    end

    # Single-tap (one-gesture) approval is allowed only for a confirmed definition.
    def single_tap_allowed(r) = !A.js.truthy?(r['unreviewed'])

    # The step-up renderer derived from the pinned defs (found by verb or alias); an unknown verb raises, which makes the review a deny.
    def renderers_from_defs(defs, verifier = nil)
      by_verb = {}
      defs.each do |d|
        by_verb[d['verb']] = d
        (d['aliases'] || []).each { |a| by_verb[a] = d unless by_verb.key?(a) }
      end
      lambda do |verb, _resource, params|
        d = by_verb[verb]
        raise A::ActionKitError.new('render_unknown_verb', "no pinned action definition for '#{verb}'") if d.nil?

        render_approval_with(d, params.nil? ? {} : params, verifier)
      end
    end

    # ---- facade-spec.ts -------------------------------------------------------------------------------------------

    # One def to one facade row: reversibility and blast are the EFFECTIVE values; `reviewed` prices the def as reviewed (release-attested catalog only).
    def spec_of_def(d, reg = nil, verifier = nil, reviewed = false)
      reg ||= A::CORE_REGISTRY
      full = E.effective_with(d, reg, verifier)
      e = reviewed == true ? full['hint'] : full
      parts = d['verb'].split('.', -1)
      amount = begin
        ActionsDerive.param_by_role(d, 'money.amount')
      rescue A::ActionKitError
        nil
      end
      out = { 'connector' => parts[0], 'action' => parts[1..].join('.'), 'verb' => d['verb'], 'reversibility' => e['eff']['rev'], 'blastRadius' => e['eff']['blast_ppm'].to_f / 1_000_000 }
      out['amountField'] = amount unless amount.nil?
      out['description'] = d['description'].nil? ? d['title'] : d['description']
      out['aliases'] = d['aliases'].sort_by { |s| A.u16key(s) } if d['aliases'] && !d['aliases'].empty?
      out['traits'] = e['closure']
      out
    end

    def facade_specs(defs, reg = nil, verifier = nil, reviewed = false) = defs.map { |d| spec_of_def(d, reg, verifier, reviewed) }

    # ---- provenance.ts --------------------------------------------------------------------------------------------

    # The gate facts of one def. Unconfirmed means maximally dangerous: no effects, the top trait set, provenance relaxations ignored.
    def provenance_info_of(d, reg = nil, verifier = nil)
      reg ||= A::CORE_REGISTRY
      traits = E.traits_of_with(d, reg, verifier)
      return { 'effects' => [], 'traits' => traits } unless E.confirmed?(d, verifier)

      n = A.normalize(d)
      params = n['params'].select { |_, p| p.key?('provenance_min') }.transform_values { |p| p['provenance_min'] }
      out = { 'effects' => n['effects'].dup, 'traits' => traits }
      out['params'] = params unless params.empty?
      out
    end

    # The `provenance.actions` resolver: the facts of the def whose verb (or alias) is the operation's verb, nil for an unknown verb. Two defs claiming one name raise.
    def provenance_actions(defs, reg = nil, verifier = nil)
      reg ||= A::CORE_REGISTRY
      by_verb = {}
      defs.each do |d|
        n = A.normalize(d)
        info = provenance_info_of(d, reg, verifier)
        ([n['verb']] + n['aliases']).each do |v|
          raise ArgumentError, "provenanceActions: two definitions claim the verb '#{v}'" if by_verb.key?(v)

          by_verb[v] = info
        end
      end
      ->(op) { by_verb[op['verb']] }
    end
  end
end
