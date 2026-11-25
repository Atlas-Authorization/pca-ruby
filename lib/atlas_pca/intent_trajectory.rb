# frozen_string_literal: true

require_relative 'intent_history'
require_relative 'intent_omega'
require_relative 'intent_learner'
require_relative 'intent_schema'
require_relative 'intent_v2'

# Trajectory intent as ordinary intent: the augmented outcome space (one numeric dimension per accumulator, one categorical dimension
# per monitor), the verifier-computed lift of an action, the trajectory step rule and the wallet's default accumulators. Native port
# of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentTrajectory
    ACC_DIM_PREFIX = 'env.acc.'
    MON_DIM_PREFIX = 'env.mon.'
    KINDS = [['action.params.', 'param'], [ACC_DIM_PREFIX, 'acc'], [MON_DIM_PREFIX, 'mon'], ['env.canon.', 'canon'], ['env.world.', 'world'],
             ['env.rel.', 'rel'], ['env.prov.', 'prov'], ['env.class.', 'class']].freeze

    module_function

    def utf8(s) = s.b
    def acc_dim_path(id) = "#{ACC_DIM_PREFIX}#{id}.post"
    def mon_dim_path(id) = "#{MON_DIM_PREFIX}#{id}.state"

    # The v2 dimension kind of a path (a naming convention over the v1 dimensions).
    def dim_kind_of(path)
      KINDS.each { |prefix, kind| return kind if path.start_with?(prefix) }
      'other'
    end

    def pred_verbs(p) = p['verb'].is_a?(Array) ? p['verb'].dup : [p['verb']]

    # The augmented space from the space and Psi (wallet-held accumulators are not dimensions).
    def augment_omega(omega, psi, opts = nil)
      opts ||= {}
      schema = opts['schema']
      selects = lambda do |a, verb|
        return true if ((a['sel'] || {})['verbs'] || []).include?(verb)

        unit = (a['sel'] || {})['accumulates_into']
        next false if unit.nil?

        v = schema ? schema['verbs'].find { |x| x['verb'] == verb } : nil
        !v.nil? && !IntentV2.accumulation_params(v, unit).empty?
      end
      verbs = omega['verbs'].map do |vs|
        extra = []
        psi['accumulators'].each do |a|
          next if a['holder']['kind'] == 'wallet'
          next if opts['scope'] == 'selected' && !selects.call(a, vs['verb'])
          raise ArgumentError, "augmentOmega: accumulator '#{a['id']}' needs domain_max (A_psi) to be a dimension" if a['domain_max'].nil?

          dm = a['domain_max']
          raw = (opts['cuts'] || {})[a['id']] || []
          cuts = raw.select { |c| IntentOmega.number?(c) && (c.is_a?(Integer) || (c.finite? && c == c.floor)) && c >= 0 && c <= dm && c.abs <= 9_007_199_254_740_991 }.uniq.sort
          extra << { 'kind' => 'num', 'path' => acc_dim_path(a['id']), 'lo' => 0, 'hi' => dm, 'cuts' => cuts, 'dist' => 'loguniform' }
        end
        psi['monitors'].each do |m|
          next if opts['scope'] == 'selected' && !(m['q'] ? (pred_verbs(m['q']).include?(vs['verb']) || pred_verbs(m['q']).include?('*')) : true)

          extra << { 'kind' => 'cat', 'path' => mon_dim_path(m['id']), 'values' => IntentV2.monitor_states!(m).map { |v| { 'kind' => 'exact', 'value' => v } } }
        end
        dims = vs['dims'].reject { |d| %w[acc mon].include?(dim_kind_of(d['path'])) } + extra
        vs.merge('dims' => dims.sort_by { |d| utf8(d['path']) })
      end
      { 'v' => 1, 'approximate' => omega['approximate'].dup, 'verbs' => verbs }
    end

    def own(d, k) = d.is_a?(Hash) && d.key?(k) ? d[k] : nil

    # lift(history, action, t) as an outcome of the augmented space; nil when the verb is not in it.
    def lift_action(omega_tilde, psi, history, cand, schema = nil)
      vs = omega_tilde['verbs'].find { |v| v['verb'] == cand['verb'] }
      return nil if vs.nil?

      decl = schema ? schema['verbs'].find { |v| v['verb'] == cand['verb'] } : nil
      values = {}
      params = cand['params']
      vs['dims'].each do |d|
        k = dim_kind_of(d['path'])
        if k == 'param'
          x = own(params, d['path']['action.params.'.length..])
          values[d['path']] = x if IntentOmega.number?(x) || x.is_a?(String)
        elsif k == 'canon'
          name = d['path']['env.canon.'.length..]
          pd = ((decl || {})['params'] || {})["action.params.#{name}"]
          values[d['path']] = IntentSchema.canon_value(pd, params[name]) if IntentLearner.truthy(pd) && params.is_a?(Hash) && params.key?(name)
        elsif k == 'acc'
          id = d['path'][ACC_DIM_PREFIX.length...-'.post'.length]
          a = psi['accumulators'].find { |x| x['id'] == id }
          values[d['path']] = AtlasPca.acc_post(a, history, { 'verb' => cand['verb'], 'params' => cand['params'], 't' => cand['t'] }, schema.nil? ? V2JS::UNDEF : schema) if a
        elsif k == 'mon'
          id = d['path'][MON_DIM_PREFIX.length...-'.state'.length]
          m = psi['monitors'].find { |x| x['id'] == id }
          values[d['path']] = AtlasPca.monitor_state(m, history) if m
        elsif d['path'] == 'action.resource'
          values[d['path']] = cand['resource']
        end
      end
      { 'verb' => cand['verb'], 'values' => values }
    end

    # The per-dimension cell of the lift, or nil when it lies outside the space (fail closed).
    def lifted_cell(omega_tilde, o)
      vs = omega_tilde['verbs'].find { |v| v['verb'] == o['verb'] }
      return nil if vs.nil?

      cell = IntentOmega.cell_of(vs, o)
      cell.nil? ? nil : { 'vs' => vs, 'cell' => cell }
    end

    # Admit the action iff its lift lies in a cell the grant accepts; the history grows by a `reserved` event on admission.
    def step_trajectory(omega_tilde, psi, history, cand, in_grant, schema = nil)
      lifted = lift_action(omega_tilde, psi, history, cand, schema)
      c = lifted ? lifted_cell(omega_tilde, lifted) : nil
      ok = !c.nil? && in_grant.call(cand['verb'], c['cell']) ? true : false
      hist = history.dup
      hist << { 'id' => cand['id'], 'verb' => cand['verb'], 'resource' => cand['resource'], 'params' => cand['params'], 't' => cand['t'], 'status' => 'reserved' } if ok
      { 'admitted' => ok, 'history' => hist, 'lifted' => lifted }
    end

    def sanitize(u) = u.gsub(/[^A-Za-z0-9_]/, '_')[0, 58]

    # The accumulators the wallet always adds: a per-task spend sum per accumulation unit, a per-verb spend sum for every untagged
    # money.amount parameter, and the wallet-held question counter.
    def default_accumulators(schema, o)
      holder = o['holder'] || { 'kind' => 'site_local' }
      units = {}
      untagged = []
      schema['verbs'].each do |v|
        v['params'].each do |path, d|
          into = d['accumulates_into'] || []
          into.each { |u| units[u] = nil }
          untagged << { 'verb' => v['verb'], 'path' => path } if d['type'] == 'integer' && d['semantic'] == 'money.amount' && into.empty?
        end
      end
      out = []
      units.keys.sort_by { |u| utf8(u) }.each do |u|
        out << { 'id' => "spend_#{sanitize(u)}", 'agg' => 'sum', 'unit' => u, 'sel' => { 'accumulates_into' => u }, 'win' => { 'kind' => 'task' },
                 'key' => nil, 'domain_max' => o['spendDomainMax'], 'holder' => holder }
      end
      untagged.sort_by { |x| utf8(x['verb'] + x['path']) }.each do |x|
        out << { 'id' => "spend_#{sanitize(x['verb'])}_#{sanitize(x['path']['action.params.'.length..])}"[0, 64], 'agg' => 'sum', 'val' => x['path'],
                 'sel' => { 'verbs' => [x['verb']] }, 'win' => { 'kind' => 'task' }, 'key' => nil, 'domain_max' => o['spendDomainMax'], 'holder' => holder }
      end
      cap = o['questionCap']
      out << { 'id' => 'questions', 'agg' => 'count', 'sel' => { 'event' => 'intent_required' }, 'win' => { 'kind' => 'task' }, 'key' => nil,
               'cap' => cap.nil? ? 6 : cap, 'holder' => { 'kind' => 'wallet' } }
      out
    end

    # The fact line for an accumulator dimension of a cell.
    def describe_acc_cell(d, cell_index, label, this_action = nil, fmt = ->(v) { V2JS.js_str(v) })
      cells = IntentOmega.num_cells(d)
      raise ArgumentError, 'describeAccCell: no such cell' if cell_index.negative? || cell_index >= cells.length

      c = cells[cell_index]
      rng = c['lo'] == c['hi'] ? "exactly #{fmt.call(c['lo'])}" : "between #{fmt.call(c['lo'])} and #{fmt.call(c['hi'])}"
      "#{label}: #{rng}#{this_action.nil? ? '' : " (this action: #{fmt.call(this_action)})"}"
    end

    # The per-session harm range of a trajectory Monte Carlo estimate is [0, L_max * H_max].
    def trajectory_harm_range(max_session_length, harm_max)
      ok_len = IntentOmega.number?(max_session_length) && (max_session_length.is_a?(Integer) || (max_session_length.finite? && max_session_length == max_session_length.floor)) &&
               max_session_length >= 0 && max_session_length <= 9_007_199_254_740_991
      ok_h = IntentOmega.number?(harm_max) && harm_max >= 0
      raise ArgumentError, 'trajectoryHarmRange: bad arguments' if !ok_len || !ok_h

      max_session_length * harm_max
    end
  end
end
