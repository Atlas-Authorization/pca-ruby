# frozen_string_literal: true

require_relative 'goal_js'
require_relative 'facade'

module AtlasPca
  # `lift_legacy`: the total, conservative lift of the facade's {permissions, limits} input to a Goal + Ontology (the TypeScript
  # reference is @atlasauth/pca-goal `legacy`). Corrected semantics of the four facade bugs: `$200/day` is a SLIDING 86 400 000 ms
  # sum bound (explicit window), not a per-call ceiling plus a one-day grant lifetime; a `$` limit on a verb with no amount field is
  # an error; every limit is its own bound, so adding a limit only narrows (co-sign tiers are not part of the goal); money
  # parameters are integers in MINOR units of USD (cents), the explicit unit the old facade left implicit.
  module GoalLegacy
    J = GoalJs
    USD = { 'k' => 'money', 'ccy' => 'USD' }.freeze
    MAX_SAFE = 9_007_199_254_740_991
    UNEXPRESSIBLE = /[*?]|\Are:/

    module_function

    def js_round(x)
      return x unless x.finite? # Math.round leaves NaN and the infinities as they are

      r = x.floor
      x - r >= 0.5 ? r + 1 : r
    end

    def safe?(n) = Js.num?(n) && (n.is_a?(Integer) || (n.finite? && n == n.floor)) && n.abs <= MAX_SAFE

    # `o`: {permissions, limits?, catalog?, principal, notAfter?, notBefore?, nlDigest?} (the money epoch `notAfter` defaults to the
    # largest safe integer). Returns {goal, ontology}.
    def lift_legacy(o)
      raw = o['limits']
      raw = {} if raw.nil?
      own = ->(k) { raw.is_a?(Hash) && k.is_a?(String) && raw.key?(k) ? raw[k] : J::UNDEF }
      # the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
      specs = AtlasPca.compile_policy(o['permissions'], nil, catalog: o['catalog'])['actions']
      grants = []
      bounds = []
      verbs = []
      specs.each do |s|
        gid = "g:#{s['verb']}"
        amount_path = s['amountField']
        amount_path = nil unless J.truthy(amount_path)
        verbs << { 'verb' => s['verb'], 'cls' => s['reversibility'], 'params' => amount_path ? [{ 'path' => amount_path, 'ty' => { 'k' => 'q', 'u' => USD } }] : [] }
        resource = s['resource'].nil? ? '*' : s['resource']
        if UNEXPRESSIBLE.match?(resource) && resource != '*'
          raise ArgumentError, "liftLegacy: resource pattern '#{resource}' of #{s['verb']} is not expressible; name exact resources or acknowledge a wildcard"
        end

        raw_limit = own.call(s['verb'])
        raw_limit = own.call(s['action']) if J.undef?(raw_limit) || raw_limit.nil? # `??`: a JSON null is no limit here
        cond = { 'k' => 'true' }
        unless J.undef?(raw_limit)
          lim = AtlasPca.parse_limit(raw_limit)
          if lim['unit'] == 'usd'
            raise ArgumentError, "liftLegacy: '$' limit on '#{s['verb']}' but the catalog gives that verb no amount field, so the limit could not be enforced" unless amount_path

            minor = js_round(lim['amount'] * 100)
            raise ArgumentError, "liftLegacy: limit for #{s['verb']} is out of range" unless safe?(minor)

            amt = { 'k' => 'param', 'path' => amount_path, 'ty' => { 'k' => 'q', 'u' => USD } }
            cond = { 'k' => 'and', 'a' => { 'k' => 'cmp', 'op' => 'gte', 'l' => amt, 'r' => { 'k' => 'lit', 'v' => { 'k' => 'q', 'q' => { 'u' => USD, 'n' => 0 } } } },
                     'b' => { 'k' => 'cmp', 'op' => 'lte', 'l' => amt, 'r' => { 'k' => 'lit', 'v' => { 'k' => 'q', 'q' => { 'u' => USD, 'n' => minor } } } } }
            unless lim['periodMs'].nil?
              bounds << { 'bid' => "b:#{s['verb']}", 'sel' => { 'k' => 'gids', 'gids' => [gid] }, 'agg' => 'sum', 'value' => amt, 'key' => '',
                          'window' => { 'k' => 'sliding', 'ms' => lim['periodMs'] }, 'scope' => { 'k' => 'session' }, 'cap' => { 'u' => USD, 'n' => minor }, 'onExceed' => 'deny' }
            end
          else
            raise ArgumentError, "liftLegacy: count limit for #{s['verb']} must be a whole number" unless safe?(lim['amount'])

            bounds << { 'bid' => "b:#{s['verb']}", 'sel' => { 'k' => 'gids', 'gids' => [gid] }, 'agg' => 'count',
                        'value' => { 'k' => 'lit', 'v' => { 'k' => 'q', 'q' => { 'u' => { 'k' => 'count' }, 'n' => 1 } } }, 'key' => '',
                        'window' => lim['periodMs'].nil? ? { 'k' => 'lifetime' } : { 'k' => 'sliding', 'ms' => lim['periodMs'] },
                        'scope' => { 'k' => 'session' }, 'cap' => { 'u' => { 'k' => 'count' }, 'n' => lim['amount'].to_i }, 'onExceed' => 'deny' }
          end
        end
        grants << { 'gid' => gid, 'verb' => s['verb'], 'res' => resource == '*' ? { 'k' => 'any', 'reason' => 'legacy default: no resource scope given' } : { 'k' => 'exact', 'id' => resource },
                    'cond' => cond }
      end
      grants = J.stable_sort_by(grants) { |g| J.u16key(g['gid']) }
      bounds = J.stable_sort_by(bounds) { |b| J.u16key(b['bid']) }
      (1...grants.length).each { |i| raise ArgumentError, "liftLegacy: duplicate grant #{grants[i]['gid']}" if grants[i]['gid'] == grants[i - 1]['gid'] }
      nb = o['notBefore']
      na = o['notAfter']
      nl = o['nlDigest']
      goal = {
        'v' => 1, 'principal' => o['principal'], 'ontDigest' => 'legacy-catalog', 'nlDigest' => nl.nil? ? '' : nl, 'sources' => [],
        'grants' => grants, 'prohibits' => [], 'bounds' => bounds,
        'validity' => { 'notBefore' => nb.nil? ? 0 : nb, 'notAfter' => na.nil? ? MAX_SAFE : na, 'maxIdle' => 0 },
        'deleg' => { 'maxDepth' => 16, 'narrowOnly' => true, 'mayTouch' => grants.map { |g| g['gid'] } },
        'escalateOn' => [], 'wildcardAck' => grants.select { |g| g['res']['k'] == 'any' }.map { |g| g['gid'] }, 'holes' => []
      }
      verbs = J.stable_sort_by(verbs) { |v| J.u16key(v['verb']) }
      ontology = { 'verbs' => verbs.each_with_index.select { |v, i| i.zero? || verbs[i - 1]['verb'] != v['verb'] }.map(&:first), 'rels' => [] }
      { 'goal' => goal, 'ontology' => ontology }
    end
  end
end
