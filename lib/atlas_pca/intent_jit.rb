# frozen_string_literal: true

require_relative 'intent_learner'
require_relative 'intent_omega'

# Lazy just-in-time elicitation: the ordered per-visit decision, the cell coordinates carried by a signed `pca-intent-required`, its
# wallet-side body, and the delta cells between two answers. Native port of the TypeScript reference (@atlasauth/pca-intent). A
# "learner" exposes #omega, #vetoed?(o), #acceptance(o) and (for deltas) #cells; signing / verifying the required notice and minting
# the signed delta grant belong to the core.
module AtlasPca
  module IntentJit
    INTENT_ACTION_DOMAIN = 'atlas-pca/intent-action/v1'

    module_function

    # The ordered lazy-elicitation decision: schema violation, ceiling, denied, admit, or intent_required.
    def decide_visit(i)
      conform = i['conform']
      return { 'kind' => 'schema_violation', 'reason' => "#{conform['code']}: #{conform['reason']}" } unless conform['ok']

      learner = i['learner']
      lifted = i['lifted']
      vs = learner.omega['verbs'].find { |v| v['verb'] == lifted['verb'] }
      cell = vs ? IntentOmega.cell_of(vs, lifted) : nil
      return { 'kind' => 'schema_violation', 'reason' => 'the lifted action lies outside Ω̃' } if vs.nil? || cell.nil?

      (i['ceilings'] || []).each { |ceiling| return { 'kind' => 'ceiling' } unless ceiling.call(vs, lifted) }
      vetoed = learner.vetoed?(lifted)
      p = learner.acceptance(lifted)
      return { 'kind' => 'intent_denied', 'vetoed' => vetoed } if vetoed || p <= 0
      return { 'kind' => 'admit', 'cell' => cell } if i['inEffective']

      { 'kind' => 'intent_required', 'cell' => cell, 'p' => p }
    end

    # The coordinates of one cell (numeric: [i, i]; categorical: the cell's value). Never text about the value.
    def cell_coords(vs, cell)
      out = {}
      vs['dims'].each_with_index { |d, k| out[d['path']] = d['kind'] == 'num' ? [cell[k], cell[k]] : [d['values'][cell[k]]['value']] }
      out
    end

    # Coordinates -> per-dimension cell indices (the inverse of cell_coords for one cell), or nil.
    def cell_from_coords(vs, coords)
      return nil if !coords.is_a?(Hash) || coords.length != vs['dims'].length

      out = []
      vs['dims'].each do |d|
        c = coords[d['path']]
        return nil if c.nil? || !c.is_a?(Array)

        if d['kind'] == 'num'
          return nil if c.length < 2 || !IntentOmega.number?(c[0]) || c[0] != c[1]

          out << c[0]
        else
          return nil if c.length != 1 || !c[0].is_a?(String)

          i = d['values'].index { |v| v['value'] == c[0] }
          return nil if i.nil?

          out << i
        end
      end
      out
    end

    # The action digest a JIT consent is bound to.
    def intent_action_digest(action)
      # a member the action lacks is `undefined` in the reference, which the canonicalizer refuses
      AtlasPca.hash_canonical({ 'd' => INTENT_ACTION_DOMAIN, 'action' => %w[verb resource params_digest reversibility_class].to_h do |k|
        raise TypeError, 'canonicalize: unsupported type undefined' unless action.is_a?(Hash) && action.key?(k)

        [k, action[k]]
      end })
    end

    # The site's `pca-intent-required` body for a visited uncertain cell (sign it with the core).
    def intent_required_body(i)
      { 'v' => 1, 'kind' => 'pca-intent-required', 'session' => i['session'], 'map_digest' => i['mapDigest'], 'schema' => i['schemaDigest'],
        'pcactn_digest' => AtlasPca.hash_canonical(i['pcactn']), 'action_digest' => intent_action_digest(i['pcactn']['action']),
        'cell' => { 'verb' => i['vs']['verb'], 'coords' => cell_coords(i['vs'], i['cell']) }, 'reason' => 'uncertain', 'question_id' => i['questionId'],
        'friction' => i['friction'], 'delivered_to' => i['deliveredTo'], 'expires_at' => i['expiresAt'] }
    end

    # The wallet's check of an intent_required: the injected verifier checks the site signature under its keys and the expiry
    # (verify(body, keys, now) -> {ok, reason?}); the session, map, action and the cell are then re-derived from the wallet's own
    # space. Any disagreement refuses the question.
    def wallet_check_intent_required(body, w, verify)
      v = verify.call(body, w['keys'], w['now'])
      return v unless v['ok']
      return { 'ok' => false, 'reason' => 'the question is for another session or map' } if body['session'] != w['session'] || body['map_digest'] != w['mapDigest']
      if body['pcactn_digest'] != AtlasPca.hash_canonical(w['pcactn']) || body['action_digest'] != intent_action_digest(w['pcactn']['action'])
        return { 'ok' => false, 'reason' => 'the question is about another action' }
      end

      lifted = w['lifted']
      vs = w['omegaTilde']['verbs'].find { |x| x['verb'] == lifted['verb'] }
      mine = vs ? IntentOmega.cell_of(vs, lifted) : nil
      return { 'ok' => false, 'reason' => 'the wallet cannot place the action in Ω̃' } if vs.nil? || mine.nil? || body['cell']['verb'] != vs['verb']

      theirs = cell_from_coords(vs, body['cell']['coords'])
      return { 'ok' => false, 'reason' => 'the site cell differs from the cell the wallet derives' } if theirs.nil? || theirs.each_with_index.any? { |x, k| x != mine[k] }

      { 'ok' => true, 'vs' => vs, 'cell' => mine }
    end

    # Per verb, the cells the next learner's grant adds over the previous one's (as 0/1 arrays over the flat cell index).
    def delta_cells(prev, nxt)
      out = {}
      prev_in = {}
      prev.cells.each { |c| prev_in["#{c['verb']}|#{c['cell'].join(',')}"] = true if c['inGrant'] }
      nxt.omega['verbs'].each do |vs|
        a = Array.new(IntentOmega.verb_cell_count(vs), 0)
        any = false
        nxt.cells.each do |c|
          next if c['verb'] != vs['verb'] || !c['inGrant'] || prev_in.key?("#{c['verb']}|#{c['cell'].join(',')}")

          a[IntentOmega.encode_cell(vs, c['cell'])] = 1
          any = true
        end
        out[vs['verb']] = a if any
      end
      out
    end

    # The predicates of a delta (one maximal box per covered region, per verb).
    def delta_predicates(omega_tilde, delta)
      out = []
      omega_tilde['verbs'].each { |vs| out.concat(IntentLearner.boxes_to_predicates(vs, delta[vs['verb']])) if delta.key?(vs['verb']) }
      out
    end

    # Mint D_k from the k-th answer: nil when the answer added no cell. `principal` is the PRINCIPAL key (the wallet holds it; the
    # agent's key never signs a grant); `kw` are the remaining mint_session_grant arguments (map_form:, caveats:, salt:, ...).
    def mint_delta(prev, nxt, prev_grant, principal, holder, session, seq, root, map_digest, prev_id = nil, **kw)
      delta = delta_cells(prev, nxt)
      cells = delta.values.sum { |v| v.sum }
      return nil if cells.zero?
      raise ArgumentError, 'mintDelta: prev must be the id of the previous session grant' if !prev_id.nil? && prev_id != prev_grant['id']

      r = AtlasPca.mint_session_grant(principal, holder, session: session, seq: seq, root: root, map_digest: map_digest,
                                                          predicates: delta_predicates(nxt.omega, delta), prev: prev_grant['id'], **kw)
      r.merge('cells' => cells)
    end
  end
end
