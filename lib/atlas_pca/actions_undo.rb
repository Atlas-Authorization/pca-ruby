# frozen_string_literal: true

# Undo windows over action definitions, the structural and planning half (native port of the definition-level functions of undo.ts of
# the TypeScript reference @atlasauth/pca-actions). The window state machine, tokens and receipts are in undo.rb.
require_relative 'actions'
require_relative 'actions_effective'
require_relative 'actions_review'
require_relative 'approval'

module AtlasPca
  module ActionsUndo
    A = AtlasPca::Actions
    E = AtlasPca::ActionsEffective

    module_function

    # The class of a reversibility declaration for concrete params (an unmapped or absent value takes `default`, else irreversible).
    def reversibility_for(d, params)
      r = A.normalize(d)['reversibility']
      return r if r.is_a?(String)

      v = params.key?(r['by']) ? params[r['by']] : nil
      k = if v.is_a?(String) then v
          elsif v == true then 'true'
          elsif v == false then 'false'
          elsif (v.is_a?(Integer) || v.is_a?(Float)) && A.js.int?(v) then A.js.ival(v).to_s
          end
      !k.nil? && r['map'].key?(k) ? r['map'][k] : r.fetch('default', 'irreversible')
    end

    # True when some value of the declaration is `reversible` (a fixed class, a map value or the default).
    def may_be_reversible(d)
      r = d['reversibility']
      return false if r.nil?
      return r == 'reversible' if r.is_a?(String)

      r['map'].values.include?('reversible') || r['default'] == 'reversible'
    end

    def same_type?(a, b) = !a.nil? && a['type'] == b['type'] && a['items'] == b['items']

    # Can `comp` undo `orig` without the agent's help? {ok: true, shape: {copied, target?}} or {ok: false, reason}. Structural only.
    def compensation_shape(orig, comp)
      return { 'ok' => false, 'reason' => "the compensating action #{comp['verb']} only reads" } if A.read_only?(comp['effects'])
      if comp['resource']['type'] != orig['resource']['type']
        return { 'ok' => false, 'reason' => "the compensating action #{comp['verb']} acts on #{comp['resource']['type']}, not #{orig['resource']['type']}" }
      end

      nc = A.normalize(comp)
      copied = []
      target = nil
      idem = nc['idempotency']['mode'] == 'key_param' ? nc['idempotency']['param'] : nil
      nc['params'].sort_by { |name, _| A.u16key(name) }.each do |name, p|
        next if name == idem

        if same_type?(orig['params'][name], p)
          copied << name
          next
        end
        next unless p['required']

        if p['role'] == "id.#{comp['resource']['type']}" && target.nil?
          target = name
          next
        end
        return { 'ok' => false, 'reason' => "the compensating action #{comp['verb']} needs '#{name}', which neither the original call nor its result supplies" }
      end
      shape = { 'copied' => copied }
      shape['target'] = target unless target.nil?
      { 'ok' => true, 'shape' => shape }
    end

    # plan(op) -> {def_digest, compensation, render, render_digest} or nil. Answers only from CONFIRMED definitions (a valid signed review
    # by a pinned reviewer key; no pins: nothing is undoable), exact verb match only. Never raises: anything undecidable is not undoable.
    def undo_engine(defs, pins, registry = nil)
      reg = registry || A::CORE_REGISTRY
      by_verb = {}
      defs.each { |d| by_verb[d['verb']] ||= d }
      review = pins.nil? ? nil : ActionsReview.attestation_verifier(reg, pins)
      confirmed = lambda do |d|
        E.confirmed?(d, review)
      rescue StandardError
        false
      end
      lambda do |op|
        d = by_verb[op['verb']]
        params = op['params'] || {}
        return nil if d.nil? || !confirmed.call(d) || A.read_only?(d['effects']) || d['compensates'].nil?
        return nil if E.effective_with(d, reg, review)['eff']['rev'] != 'reversible' || reversibility_for(d, params) != 'reversible'

        c = by_verb[d['compensates']]
        return nil if c.nil? || !confirmed.call(c)

        s = compensation_shape(d, c)
        return nil unless s['ok']

        cparams = {}
        nc = A.normalize(c)
        s['shape']['copied'].each do |k|
          if params.key?(k) then cparams[k] = A.deep_copy(params[k])
          elsif nc['params'][k]['required'] then return nil
          end
        end
        render = AtlasPca.render_approval(d, params, true)
        comp = { 'verb' => c['verb'], 'params' => cparams, 'def_digest' => A.def_digest(c) }
        comp['target_param'] = s['shape']['target'] if s['shape'].key?('target')
        { 'def_digest' => A.def_digest(d), 'compensation' => comp, 'render' => render, 'render_digest' => AtlasPca.approval_render_digest(render) }
      rescue StandardError
        nil
      end
    end
  end
end
