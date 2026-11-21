# frozen_string_literal: true

require_relative 'goal_js'
require_relative 'goal_normalize'

module AtlasPca
  # The human-readable PolicyCard text: a fixed phrase table over the IR, every clause with its exact numbers (the TypeScript
  # reference is @atlasauth/pca-goal `card`). Two different goals never print the same card.
  module GoalCard
    J = GoalJs
    OPW = { 'eq' => '=', 'ne' => '!=', 'lt' => '<', 'lte' => '<=', 'gt' => '>', 'gte' => '>=', 'in' => 'is one of', 'nin' => 'is none of' }.freeze

    module_function

    def q(x) = J.undef?(x) ? 'undefined' : GoalNormalize.jq(x)
    def unit(u) = J.jget(u, 'k') == 'money' ? "#{J.js_str(J.jget(u, 'ccy'))} minor units" : J.js_str(J.jget(u, 'k'))
    def quantity(x) = "#{J.js_str(J.jget(x, 'n'))} #{unit(J.jget(x, 'u'))}"

    def value(v)
      k = J.jget(v, 'k')
      return quantity(J.jget(v, 'q')) if k == 'q'
      return q(J.jget(v, 's')) if k == 's'

      "{#{J.req_list(J.jget(v, 'items')).map { |i| value(i) }.join(', ')}}"
    end

    def term(t)
      k = J.jget(t, 'k')
      if k == 'param'
        ty = J.jget(t, 'ty')
        return "param #{q(J.jget(t, 'path'))} (#{J.jget(ty, 'k') == 'q' ? unit(J.jget(ty, 'u')) : 'text'})"
      end
      return value(J.jget(t, 'v')) if k == 'lit'

      "running total of bound #{q(J.jget(t, 'bid'))} (#{unit(J.jget(t, 'u'))})"
    end

    def cond(c)
      k = J.jget(c, 'k')
      case k
      when 'true' then 'always'
      when 'cmp'
        op = J.jget(c, 'op')
        "#{term(J.jget(c, 'l'))} #{op.is_a?(String) && OPW.key?(op) ? OPW[op] : 'undefined'} #{term(J.jget(c, 'r'))}"
      when 'and' then "(#{cond(J.jget(c, 'a'))}) AND (#{cond(J.jget(c, 'b'))})"
      when 'or' then "(#{cond(J.jget(c, 'a'))}) OR (#{cond(J.jget(c, 'b'))})"
      when 'not' then "NOT (#{cond(J.jget(c, 'c'))})"
      else 'undefined' # the reference switch has no default
      end
    end

    def res(s)
      k = J.jget(s, 'k')
      case k
      when 'exact' then "exactly #{q(J.jget(s, 'id'))}"
      when 'oneof' then "one of [#{J.req_list(J.jget(s, 'ids')).map { |i| q(i) }.join(', ')}]"
      when 'related' then "#{J.js_str(J.jget(s, 'rel'))} of #{q(J.jget(s, 'anchor'))}"
      when 'all_of' then "ALL OF (#{J.req_list(J.jget(s, 'parts')).map { |p| res(p) }.join(' AND ')})"
      else "ANY RESOURCE (reason: #{q(J.jget(s, 'reason'))})"
      end
    end

    def win(w)
      k = J.jget(w, 'k')
      return 'per task' if k == 'task'
      return 'over the lifetime' if k == 'lifetime'
      return "in any #{J.js_str(J.jget(w, 'ms'))} ms window" if k == 'sliding'

      "per #{J.js_str(J.jget(w, 'ms'))} ms period starting at #{J.js_str(J.jget(w, 't0'))}"
    end

    def scope(s)
      return "fleet [#{J.req_list(J.jget(s, 'agents')).map { |a| q(a) }.join(', ')}]" if J.jget(s, 'k') == 'fleet'

      J.js_str(J.jget(s, 'k'))
    end

    def grant_line(x)
      "ALLOW #{q(J.jget(x, 'gid'))}: verb #{q(J.jget(x, 'verb'))} on #{res(J.jget(x, 'res'))} when #{cond(J.jget(x, 'cond'))}"
    end

    def prohibit_line(x)
      t = J.jget(x, 'target')
      tgt = J.jget(t, 'k') == 'verb' ? "verb #{q(J.jget(t, 'verb'))}" : "every verb of effect class #{q(J.jget(t, 'cls'))}"
      "NEVER #{q(J.jget(x, 'pid'))}: #{tgt} on #{res(J.jget(x, 'res'))} when #{cond(J.jget(x, 'cond'))}"
    end

    def bound_line(b)
      sel = J.jget(b, 'sel')
      over = if J.jget(sel, 'k') == 'gids'
               "grants [#{J.req_list(J.jget(sel, 'gids')).map { |g| q(g) }.join(', ')}]"
             else
               "effect class #{q(J.jget(sel, 'cls'))}"
             end
      agg = J.jget(b, 'agg')
      mid = agg == 'count' ? '' : (agg == 'distinct' ? " of #{q(J.jget(b, 'key'))}" : " of #{term(J.jget(b, 'value'))}")
      exc = J.jget(b, 'onExceed') == 'deny' ? 'deny' : 'ask the principal'
      "LIMIT #{q(J.jget(b, 'bid'))}: #{J.js_str(agg)}#{mid} over #{over}, #{win(J.jget(b, 'window'))}, scope #{scope(J.jget(b, 'scope'))}, " \
        "at most #{quantity(J.jget(b, 'cap'))}; beyond that: #{exc}"
    end

    def validity_line(v)
      mi = J.jget(v, 'maxIdle')
      "VALID from #{J.js_str(J.jget(v, 'notBefore'))} to #{J.js_str(J.jget(v, 'notAfter'))}; idle limit " \
        "#{J.js_gt(mi, 0) ? "#{J.js_str(mi)} ms" : 'none'}"
    end

    def delegation_line(d)
      "DELEGATION depth at most #{J.js_str(J.jget(d, 'maxDepth'))}, narrow only #{J.js_str(J.jget(d, 'narrowOnly'))}, " \
        "delegates may use grants [#{J.req_list(J.jget(d, 'mayTouch')).map { |g| q(g) }.join(', ')}]"
    end

    def escalate_line(c) = "ASK THE PRINCIPAL when #{cond(c)}"

    def hole_line(h)
      aff = J.truthy(J.jget(h, 'global')) ? 'everything' : "[#{J.req_list(J.jget(h, 'affects')).map { |a| q(a) }.join(', ')}]"
      "UNRESOLVED #{q(J.jget(h, 'hid'))}: #{q(J.jget(h, 'q'))} options [#{J.req_list(J.jget(h, 'domain')).map { |d| q(d) }.join(', ')}] affects #{aff}"
    end

    # One line per clause, in the goal's canonical order; `warnings` lists what the principal must look at twice.
    def render_card(g)
      lines = ["Goal v#{J.js_str(J.jget(g, 'v'))} for principal #{q(J.jget(g, 'principal'))}; ontology #{q(J.jget(g, 'ontDigest'))}; " \
               "request text digest #{q(J.jget(g, 'nlDigest'))}"]
      warnings = []
      J.req_list(J.jget(g, 'sources')).each { |s| lines << "Source #{q(s)}" }
      J.req_list(J.jget(g, 'grants')).each do |x|
        lines << grant_line(x)
        next unless J.jget(J.jget(x, 'res'), 'k') == 'any'

        ack = J.includes(J.jget(g, 'wildcardAck'), J.jget(x, 'gid'))
        warnings << "grant #{q(J.jget(x, 'gid'))} applies to every resource#{ack ? ' (acknowledged)' : ' (NOT acknowledged)'}"
      end
      J.req_list(J.jget(g, 'prohibits')).each { |x| lines << prohibit_line(x) }
      J.req_list(J.jget(g, 'bounds')).each { |b| lines << bound_line(b) }
      lines << validity_line(J.jget(g, 'validity'))
      lines << delegation_line(J.jget(g, 'deleg'))
      J.req_list(J.jget(g, 'escalateOn')).each { |c| lines << escalate_line(c) }
      J.req_list(J.jget(g, 'wildcardAck')).each { |a| lines << "Wildcard acknowledged for #{q(a)}" }
      J.req_list(J.jget(g, 'holes')).each { |h| lines << hole_line(h) }
      warnings << 'this goal has unresolved questions and cannot be signed' if J.req_list(J.jget(g, 'holes')).length.positive?
      { 'lines' => lines, 'warnings' => warnings }
    end
  end
end
