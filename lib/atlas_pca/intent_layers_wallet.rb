# frozen_string_literal: true

require_relative 'intent_layers'
require_relative 'intent_multi'
require_relative 'intent_omega'
require_relative 'intent_policy'
require_relative 'intent_v2'

# Wallet-side layered intent lattice and quorum-signed layer approvals: ceiling admitters, the lattice view of a task learner, owner
# risk, layer cell sets and k-of-n approvals of a shared-layer widening. Native port of the TypeScript reference
# (@atlasauth/pca-intent); the verifier-side layer checks live in IntentLayers.
module AtlasPca
  module IntentLayersWallet
    UNDEF = V2JS::UNDEF
    LAYER_APPROVAL_DOMAIN = "atlas-pca/intent-layer-approval/v1\0"
    STATEMENT_KEYS = %w[layer session seq map_digest prev].freeze

    module_function

    # Compile ceiling layers into admitters. ABSENT = no ceiling; a ceiling present as null or not an object is malformed.
    def ceiling_admitters(layers)
      out = {}
      AtlasPca::LAYER_CEILINGS.each do |k|
        l = layers.is_a?(Hash) && layers.key?(k) ? layers[k] : UNDEF
        if l.equal?(UNDEF)
          out[k] = nil
          next
        end
        raise ArgumentError, "ceilingAdmitters: the #{k} ceiling is malformed (null or not an object)" unless l.is_a?(Hash)

        out[k] = IntentPolicy.admitter(l)
      end
      out
    end

    # The first ceiling that excludes the outcome (nil when every ceiling admits it).
    def ceiling_of(c, vs, o)
      AtlasPca::LAYER_CEILINGS.each do |k|
        a = c[k]
        return k if a && !a.admits(vs, o)
      end
      nil
    end

    # The lattice of a task learner under ceiling layers (the learner exposes omega, cells and tau).
    def lattice_view(task, ceilings)
      out = { 'effective' => [], 'uncertain' => [], 'ceiling' => [] }
      by_verb = task.omega['verbs'].to_h { |v| [v['verb'], v] }
      task.cells.each do |c|
        vs = by_verb[c['verb']]
        layer = ceiling_of(ceilings, vs, IntentOmega.cell_rep(vs, c['cell']))
        if layer
          out['ceiling'] << { 'verb' => c['verb'], 'cell' => c['cell'], 'layer' => layer }
          next
        end
        next if c['vetoed']

        if c['inGrant']
          out['effective'] << { 'verb' => c['verb'], 'cell' => c['cell'] }
        elsif c['p'] > 1e-12 && c['p'] < task.tau - 1e-12
          out['uncertain'] << { 'verb' => c['verb'], 'cell' => c['cell'] }
        end
      end
      out
    end

    def decide_outcome_layers(task, ceilings, o)
      vs = task.omega['verbs'].find { |v| v['verb'] == o['verb'] }
      return { 'decision' => 'intent_denied' } if vs.nil?

      layer = ceiling_of(ceilings, vs, o)
      return { 'decision' => 'ceiling', 'layer' => layer } if layer
      return { 'decision' => 'intent_denied' } if task.vetoed?(o) || task.acceptance(o) <= 1e-12
      return { 'decision' => 'admit', 'by' => 0 } if task.admits_outcome(o)

      { 'decision' => 'intent_required' }
    end

    def key_of(c) = "#{c['verb']}|#{c['cell'].join(',')}"

    # A question may only be about a cell of U_k (inside every ceiling); raises otherwise.
    def assert_askable(view, c)
      key = key_of(c)
      raise ArgumentError, "layers: cell #{key} is not an uncertain cell inside every ceiling (never a question)" unless view['uncertain'].any? { |u| key_of(u) == key }
    end

    # Layer owner's own risk measure of a set of cells: sum of mu(c) (1 - a(c)) E[h | c].
    def owner_risk(omega, cells, acceptability, harm = IntentOmega::DEFAULT_HARM)
      r = 0.0
      by_verb = omega['verbs'].to_h { |v| [v['verb'], v] }
      cells.each do |c|
        vs = by_verb[c['verb']]
        next if vs.nil?

        st = IntentOmega.cell_stats(vs, c['cell'], harm)
        r += st['mass'] * (1 - acceptability.call(vs, IntentOmega.cell_rep(vs, c['cell']))) * st['harm']
      end
      r
    end

    # Every cell of the outcome space an admitter admits.
    def layer_cells(omega, a)
      out = []
      omega['verbs'].each do |vs|
        IntentOmega.verb_cell_count(vs).times do |f|
          cell = IntentOmega.decode_cell(vs, f)
          out << { 'verb' => vs['verb'], 'cell' => cell } if a.admits(vs, IntentOmega.cell_rep(vs, cell))
        end
      end
      out
    end

    def cell_key_of(omega, c)
      vs = omega['verbs'].find { |v| v['verb'] == c['verb'] }
      "#{c['verb']}|#{vs ? IntentOmega.encode_cell(vs, c['cell']) : c['cell'].join(',')}"
    end

    # ---- quorum-signed layer approvals -----------------------------------------------------------------------------

    def statement_of(a)
      g = ->(k) { a.is_a?(Hash) && a.key?(k) ? a[k] : UNDEF }
      { 'v' => 1, 'kind' => 'pca-intent-layer-approval' }.merge(STATEMENT_KEYS.to_h { |k| [k, g.call(k)] })
    end

    def approval_message(s) = LAYER_APPROVAL_DOMAIN.b + AtlasPca.strict_bytes(statement_of(s))

    # Sign an approval of a shared-layer widening (an Ed25519 seed).
    def sign_layer_approval(s, secret_key)
      st = statement_of(s)
      key = KeyPair.new(secret_key)
      st.merge('signer' => key.public, 'sig' => AtlasPca.b64e(key.sign(approval_message(st))))
    end

    # An approval counts iff its signer is a member, it is that member's first, its statement equals `expected` field by field and
    # its signature verifies; the rule is the multi-principal one over member keys.
    def verify_quorum_approvals(approvals, members, rule, expected)
      ignored = []
      if !approvals.is_a?(Array) || !members.is_a?(Array) || expected.nil? || !(expected.is_a?(Hash) || expected.is_a?(Array))
        return { 'ok' => false, 'signers' => [], 'ignored' => [{ 'index' => -1, 'reason' => 'approvals and members must be arrays and expected an object' }] }
      end
      if members.any? { |m| !m.is_a?(String) } || members.uniq.length != members.length || members.any? { |m| AtlasPca.b64d(m, 32).nil? }
        return { 'ok' => false, 'signers' => [], 'ignored' => [{ 'index' => -1, 'reason' => 'members must be distinct 32-byte keys' }] }
      end
      begin
        n = IntentMulti.normalize_rule(rule, members.dup)
      rescue StandardError => e
        return { 'ok' => false, 'signers' => [], 'ignored' => [{ 'index' => -1, 'reason' => e.message }] }
      end
      want = statement_of(expected)
      counted = {}
      approvals.each_with_index do |a, i|
        if a.nil? || a == false || a == 0 || a == '' || !(a.is_a?(Hash) || a.is_a?(Array))
          ignored << { 'index' => i, 'reason' => 'not an object' }
          next
        end
        signer = a.is_a?(Hash) && a.key?('signer') ? a['signer'] : UNDEF
        unless signer.is_a?(String) && members.include?(signer)
          ignored << { 'index' => i, 'reason' => 'signer is not a member' }
          next
        end
        if counted.key?(signer)
          ignored << { 'index' => i, 'reason' => 'second approval from the same member' }
          next
        end
        st = statement_of(a)
        get = ->(k) { a.is_a?(Hash) && a.key?(k) ? a[k] : UNDEF }
        same = want.keys.all? { |k| V2JS.strict_eq(st[k], want[k]) } && V2JS.strict_eq(get.call('v'), 1) &&
               V2JS.strict_eq(get.call('kind'), 'pca-intent-layer-approval')
        unless same
          ignored << { 'index' => i, 'reason' => 'approval is for another (layer, session, seq, map_digest, prev)' }
          next
        end
        ok = begin
          sig = get.call('sig')
          sig.is_a?(String) && AtlasPca.verify_b64u(signer, approval_message(st), sig) ? true : false
        rescue StandardError
          false
        end
        unless ok
          ignored << { 'index' => i, 'reason' => 'bad signature' }
          next
        end
        counted[signer] = true
      end
      signers = members.select { |m| counted.key?(m) }
      { 'ok' => IntentMulti.rule_admits(n, members.map { |m| counted.key?(m) }), 'signers' => signers, 'ignored' => ignored }
    end

    # An org layer that is itself a LEARNED map over a shared omega: the joint grant of the org approvers' maps under the org's rule.
    # Its uncertain cells go to the org's approvers; a widening needs an org delta with a quorum of signatures.
    def org_layer_from_maps(maps, rule)
      require_relative 'intent_multi_agg'
      m = IntentMultiAgg.aggregate_intent_maps(maps, rule)
      { 'map' => m, 'policy' => m['grant'] }
    end
  end
end
