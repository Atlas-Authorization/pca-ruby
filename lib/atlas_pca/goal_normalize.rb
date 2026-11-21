# frozen_string_literal: true

require_relative 'goal_js'

module AtlasPca
  # Stable JSON and canonical Goal order (the TypeScript reference is @atlasauth/pca-goal `normalize`).
  module GoalNormalize
    J = GoalJs

    module_function

    # JSON.stringify of a value (a string's lone surrogates are escaped).
    def jq(v) = Js.json(v)

    # Sorted-key JSON, undefined members dropped: an in-memory key for maps and sets, NOT a signed encoding.
    def stable(v)
      return jq(v) unless v.is_a?(Hash) || v.is_a?(Array)
      return "[#{v.map { |x| J.undef?(x) ? '' : stable(x) }.join(',')}]" if v.is_a?(Array)

      keys = v.keys.reject { |k| J.undef?(v[k]) }.sort_by { |k| J.u16key(k) }
      "{#{keys.map { |k| "#{jq(k)}:#{stable(v[k])}" }.join(',')}}"
    end

    def by_id(xs)
      J.stable_sort(xs) do |a, b|
        x = yield(a)
        y = yield(b)
        if x.is_a?(String) && y.is_a?(String)
          ka = J.u16key(x)
          kb = J.u16key(y)
          ka < kb ? -1 : (ka > kb ? 1 : 0)
        else
          0
        end
      end
    end

    def sorted_unique(xs)
      J.stable_sort_by(J.req_list(xs).uniq) { |x| J.u16key(J.js_str(x)) }
    end

    # Grants, prohibits, bounds and holes strictly increasing by id (code-unit order), wildcardAck / mayTouch sorted and
    # de-duplicated. Duplicated ids are NOT merged: they stay and the typechecker refuses them.
    def canonicalize_goal(g)
      raise TypeError, 'goal must be an object' unless g.is_a?(Hash)

      out = g.dup
      out['grants'] = by_id(J.req_list(g['grants']).dup) { |x| x['gid'] }
      out['prohibits'] = by_id(J.req_list(g['prohibits']).dup) { |x| x['pid'] }
      out['bounds'] = by_id(J.req_list(g['bounds']).dup) { |x| x['bid'] }
      out['holes'] = by_id(J.req_list(g['holes']).dup) { |x| x['hid'] }
      out['wildcardAck'] = sorted_unique(g['wildcardAck'])
      d = g['deleg'].dup
      d['mayTouch'] = sorted_unique(g['deleg']['mayTouch'])
      out['deleg'] = d
      out
    end
  end
end
