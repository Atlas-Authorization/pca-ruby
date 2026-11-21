# frozen_string_literal: true

require_relative 'goal_js'
require_relative 'goal_normalize'

module AtlasPca
  # N-version interpretation: the enforced policy is the semantic meet of the readings (the TypeScript reference is
  # @atlasauth/pca-goal `nversion`). Allow(meet gs) a implies Allow(g) a for every g in gs. Grants are the cross product of the
  # readings' grants on equal verbs (a merged grant is named `x&y&z`), resources intersect through `all_of`, conditions conjoin; a
  # bound of one reading counts the actions admitted by the merged grants derived from the grants that bound selected.
  module GoalNVersion
    J = GoalJs

    module_function

    def parts_of(s)
      k = J.jget(s, 'k')
      k == 'all_of' ? J.req_list(J.jget(s, 'parts')) : (k == 'any' ? [] : [s])
    end

    def intersect(a, b)
      return b if J.jget(a, 'k') == 'any'
      return a if J.jget(b, 'k') == 'any'

      m = {}
      (parts_of(a) + parts_of(b)).each { |p| m[GoalNormalize.stable(p)] = p }
      uniq = m.values
      uniq.length == 1 ? uniq[0] : { 'k' => 'all_of', 'parts' => uniq }
    end

    def conj(a, b)
      return b if J.jget(a, 'k') == 'true'

      J.jget(b, 'k') == 'true' ? a : { 'k' => 'and', 'a' => a, 'b' => b }
    end

    def cross(a, b)
      out = []
      a.each do |x|
        b.each do |y|
          next unless J.strict_eq(J.jget(x['g'], 'verb'), J.jget(y['g'], 'verb'))

          out << { 'g' => { 'gid' => "#{J.js_str(J.jget(x['g'], 'gid'))}&#{J.js_str(J.jget(y['g'], 'gid'))}", 'verb' => J.jget(x['g'], 'verb'),
                            'res' => intersect(J.jget(x['g'], 'res'), J.jget(y['g'], 'res')), 'cond' => conj(J.jget(x['g'], 'cond'), J.jget(y['g'], 'cond')) },
                   'from' => x['from'] + y['from'] }
        end
      end
      out
    end

    # Cross product on equal verbs, resource intersection, conjoined conditions.
    def meet_grants(a, b)
      cross(J.req_list(a).map { |g| { 'g' => g, 'from' => [J.jget(g, 'gid')] } }, J.req_list(b).map { |g| { 'g' => g, 'from' => [J.jget(g, 'gid')] } }).map { |t| t['g'] }
    end

    def sorted(xs) = J.stable_sort_by(xs) { |x| J.u16key(J.js_str(x)) }

    # The semantic meet of readings that share principal, ontology and text.
    def meet(goals)
      goals = J.req_list(goals)
      raise ArgumentError, 'meet: no goals' if goals.empty?

      first = goals[0]
      goals.each do |g|
        if !J.strict_eq(J.jget(g, 'principal'), J.jget(first, 'principal')) || !J.strict_eq(J.jget(g, 'ontDigest'), J.jget(first, 'ontDigest')) ||
           !J.strict_eq(J.jget(g, 'nlDigest'), J.jget(first, 'nlDigest'))
          raise ArgumentError, 'meet: readings must share principal, ontology and text'
        end
      end
      return first if goals.length == 1

      tracked = J.req_list(J.jget(first, 'grants')).map { |g| { 'g' => g, 'from' => [J.jget(g, 'gid')] } }
      goals[1..].each { |g| tracked = cross(tracked, J.req_list(J.jget(g, 'grants')).map { |x| { 'g' => x, 'from' => [J.jget(x, 'gid')] } }) }
      grants = tracked.map { |t| t['g'] }
      derived = ->(i, gids) { tracked.select { |t| J.includes(gids, t['from'][i]) }.map { |t| t['g']['gid'] } }

      prohibits = []
      pseen = {}
      goals.each_with_index do |g, i|
        J.req_list(J.jget(g, 'prohibits')).each do |p|
          body = GoalNormalize.stable(p.merge('pid' => ''))
          next if pseen.key?(body)

          taken = pseen.values.any? { |v| J.strict_eq(v, J.jget(p, 'pid')) }
          pseen[body] = J.jget(p, 'pid')
          prohibits << (taken ? p.merge('pid' => "#{J.js_str(J.jget(p, 'pid'))}##{i}") : p)
        end
      end
      bounds = []
      bseen = {}
      goals.each_with_index do |g, i|
        J.req_list(J.jget(g, 'bounds')).each do |b|
          bsel = J.jget(b, 'sel')
          sel = J.jget(bsel, 'k') == 'gids' ? { 'k' => 'gids', 'gids' => sorted(derived.call(i, J.jget(bsel, 'gids'))) } : bsel
          next if J.jget(sel, 'k') == 'gids' && sel['gids'].empty? # no merged grant derives from the selected grants: nothing to count

          cap = J.jget(b, 'cap')
          key = GoalNormalize.stable({ 'sel' => sel, 'agg' => J.jget(b, 'agg'), 'value' => J.jget(b, 'value'), 'key' => J.jget(b, 'key'),
                                       'window' => J.jget(b, 'window'), 'scope' => J.jget(b, 'scope'), 'unit' => J.jget(cap, 'u') })
          prev = bseen[key]
          unless prev.nil? # the same aggregate over the same counted grants in several readings: the minimum cap, the stricter exceed action
            prev['cap'] = cap if J.jget(cap, 'n') < J.jget(prev['cap'], 'n')
            prev['onExceed'] = 'deny' if J.jget(b, 'onExceed') == 'deny'
            next
          end
          bid = bounds.any? { |x| J.strict_eq(x['bid'], J.jget(b, 'bid')) } ? "#{J.js_str(J.jget(b, 'bid'))}##{i}" : J.jget(b, 'bid')
          nb = b.merge('sel' => sel, 'bid' => bid)
          bounds << nb
          bseen[key] = nb
        end
      end
      esc = {}
      goals.each { |g| J.req_list(J.jget(g, 'escalateOn')).each { |c| esc[GoalNormalize.stable(c)] = c } }
      idle = goals.map { |g| J.jget(J.jget(g, 'validity'), 'maxIdle') }.select { |x| x > 0 }
      touch = tracked.select { |t| goals.each_with_index.all? { |g, i| J.includes(J.jget(J.jget(g, 'deleg'), 'mayTouch'), t['from'][i]) } }.map { |t| t['g']['gid'] }
      ack_ok = lambda do |g, i, t|
        x = J.req_list(J.jget(g, 'grants')).find { |y| J.strict_eq(J.jget(y, 'gid'), t['from'][i]) }
        x.nil? || J.jget(J.jget(x, 'res'), 'k') != 'any' || J.includes(J.jget(g, 'wildcardAck'), t['from'][i])
      end
      ack = tracked.select { |t| J.jget(t['g']['res'], 'k') == 'any' && goals.each_with_index.all? { |g, i| ack_ok.call(g, i, t) } }.map { |t| t['g']['gid'] }
      holes = {}
      goals.each_with_index do |g, i|
        J.req_list(J.jget(g, 'holes')).each do |h|
          prev = holes[J.jget(h, 'hid')]
          affects = sorted(((prev.nil? ? [] : J.jget(prev, 'affects')) + derived.call(i, J.jget(h, 'affects'))).uniq)
          gl = J.jget(h, 'global')
          holes[J.jget(h, 'hid')] = h.merge('affects' => affects, 'global' => J.truthy(gl) ? gl : (prev.nil? ? false : J.jget(prev, 'global')))
        end
      end
      sources = goals.flat_map { |g| J.req_list(J.jget(g, 'sources')) }
      vs = goals.map { |g| J.jget(g, 'validity') }
      GoalNormalize.canonicalize_goal(first.merge(
                                        'grants' => grants, 'prohibits' => prohibits, 'bounds' => bounds, 'escalateOn' => esc.values, 'sources' => sources.uniq,
                                        'validity' => { 'notBefore' => vs.map { |v| J.jget(v, 'notBefore') }.max, 'notAfter' => vs.map { |v| J.jget(v, 'notAfter') }.min,
                                                        'maxIdle' => idle.empty? ? 0 : idle.min },
                                        'deleg' => { 'maxDepth' => goals.map { |g| J.jget(J.jget(g, 'deleg'), 'maxDepth') }.min, 'narrowOnly' => true, 'mayTouch' => touch },
                                        'holes' => holes.values, 'wildcardAck' => ack
                                      ))
    end

    # Panel requirements: k >= 3, at least one deterministic non-LLM interpreter, at least two distinct model families.
    def check_panel(readings)
      out = []
      out << { 'code' => 'too_few', 'msg' => 'need at least 3 interpreters' } if readings.length < 3
      out << { 'code' => 'no_deterministic', 'msg' => 'need at least one deterministic template interpreter' } unless readings.any? { |r| J.truthy(J.jget(r, 'deterministic')) }
      if readings.reject { |r| J.truthy(J.jget(r, 'deterministic')) }.map { |r| J.jget(r, 'family') }.uniq.length < 2
        out << { 'code' => 'no_family_diversity', 'msg' => 'need at least two distinct model families' }
      end
      out
    end

    # `opts`: the question options plus `massThreshold`. Auto-signable only when the panel is valid and no hole remains.
    def n_version(readings, opts)
      require_relative 'goal_disambiguate'
      merged = meet(readings.map { |r| r['goal'] })
      panel_issues = check_panel(readings)
      verb_sets = readings.map { |r| r['goal']['grants'].map { |g| g['verb'] }.uniq }
      all_verbs = verb_sets.flatten.uniq
      holes = []
      all_verbs.sort_by { |v| J.u16key(v) }.each do |v|
        next unless verb_sets.any? { |s| !s.include?(v) }

        holes << { 'hid' => "nv:verb:#{v}", 'q' => "Only some readings allow \"#{v}\". Should it be allowed at all?", 'domain' => [], 'affects' => [], 'global' => false }
      end
      mass = GoalDisambiguate.disagreement_mass(readings, opts['ont'])
      thr = opts['massThreshold']
      if mass > (thr.nil? ? 0 : thr)
        qs = GoalDisambiguate.questions(readings, opts)
        holes << { 'hid' => 'nv:split', 'q' => qs.empty? ? 'The readings disagree.' : qs[0]['text'], 'domain' => [], 'affects' => [], 'global' => true }
      end
      all_h = merged['holes'] + holes
      by_hid = {}
      all_h.each { |h| by_hid[h['hid']] = h }
      { 'merged' => GoalNormalize.canonicalize_goal(merged.merge('holes' => by_hid.values)), 'panelIssues' => panel_issues, 'disagreementHoles' => holes, 'mass' => mass,
        'signable' => panel_issues.empty? && all_h.empty? }
    end
  end
end
