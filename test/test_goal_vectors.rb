# frozen_string_literal: true

# Replays the pca-goal vectors (packages/pca-conformance/vectors/goal): goal digest, decision + witness for every probe, and
# the fn vectors (canon, units, polarity, meet, pep, commit, claim). Independent port of the reference semantics (the same
# as the Python, Go and Rust runners); a missing corpus FAILS (set PCA_GOAL_VECTORS to a directory to override the search).
#   ruby test/test_goal_vectors.rb
require 'minitest/autorun'
require 'json'
require 'digest'
require 'base64'

module GoalRef
  module_function

  def canon(v)
    case v
    when nil then 'null'
    when true then 'true'
    when false then 'false'
    when Integer then v.to_s
    when String then canon_str(v)
    when Array then "[#{v.map { |x| canon(x) }.join(',')}]"
    when Hash then "{#{v.keys.sort_by(&:b).map { |k| "#{canon_str(k)}:#{canon(v[k])}" }.join(',')}}"
    else raise "canon: unsupported #{v.class}"
    end
  end

  def canon_str(s)
    out = +'"'
    s.each_char do |ch|
      out << case ch
             when '"' then '\\"'
             when '\\' then '\\\\'
             when "\b" then '\\b'
             when "\t" then '\\t'
             when "\n" then '\\n'
             when "\f" then '\\f'
             when "\r" then '\\r'
             else ch.ord < 0x20 ? format('\\u%04x', ch.ord) : ch
             end
    end
    out << '"'
  end

  def b64(bytes) = Base64.urlsafe_encode64(bytes, padding: false)

  def hash_canon(v) = b64(Digest::SHA256.digest(canon(v)))
  def goal_digest(g) = hash_canon({ 'd' => 'atlas-pca/goal-ir/v1', 'goal' => g })

  # Kleene truth 0/1/2 (false/unknown/true); decisions 0/1/2 (deny/escalate/allow)
  def k_not(a) = 2 - a
  def b2k(b) = b ? 2 : 0

  def eq_v(x, y)
    case x['k']
    when 'q' then y['k'] == 'q' && x['q']['u'] == y['q']['u'] ? b2k(x['q']['n'] == y['q']['n']) : 1
    when 's' then y['k'] == 's' ? b2k(x['s'] == y['s']) : 1
    else 1
    end
  end

  def lt_v(x, y) = x['k'] == 'q' && y['k'] == 'q' && x['q']['u'] == y['q']['u'] ? b2k(x['q']['n'] < y['q']['n']) : 1

  def cmp_(op, x, y)
    return 1 if x.nil? || y.nil?

    case op
    when 'eq' then return eq_v(x, y)
    when 'ne' then return k_not(eq_v(x, y))
    when 'lt' then return lt_v(x, y)
    when 'gte' then return k_not(lt_v(x, y))
    when 'gt' then return lt_v(y, x)
    when 'lte' then return k_not(lt_v(y, x))
    end
    t = 1
    t = y['items'].map { |it| eq_v(x, it) }.push(0).max if y['k'] == 'set'
    op == 'in' ? t : k_not(t)
  end

  def term(t, a, h)
    case t['k']
    when 'param' then a['params'][t['path']]
    when 'lit' then t['v']
    else
      q = h['aggs'][t['bid']]
      q.nil? ? nil : { 'k' => 'q', 'q' => q }
    end
  end

  def cond(c, a, h)
    case c['k']
    when 'true' then 2
    when 'cmp' then cmp_(c['op'], term(c['l'], a, h), term(c['r'], a, h))
    when 'and' then [cond(c['a'], a, h), cond(c['b'], a, h)].min
    when 'or' then [cond(c['a'], a, h), cond(c['b'], a, h)].max
    else k_not(cond(c['c'], a, h))
    end
  end

  def part_ids(o, p)
    case p['k']
    when 'exact' then [p['id']]
    when 'oneof' then p['ids']
    else
      r = o['rels'].find { |x| x['rel'] == p['rel'] && x['anchor'] == p['anchor'] }
      r.nil? ? [] : r['members']
    end
  end

  # nil means "any resource"
  def resolve(o, s)
    return nil if s['k'] == 'any'
    return part_ids(o, s) unless s['k'] == 'all_of'

    acc = nil
    s['parts'].reverse_each do |p|
      ids = part_ids(o, p)
      acc = acc.nil? ? ids : ids.select { |i| acc.include?(i) }
    end
    acc
  end

  def res_ok(p, r) = p.nil? || p.include?(r)
  def verbs_of_class(o, cls) = o['verbs'].select { |v| v['cls'] == cls }.map { |v| v['verb'] }
  def proh_verbs(o, p) = p['target']['k'] == 'verb' ? [p['target']['verb']] : verbs_of_class(o, p['target']['cls'])
  def lsel(o, b) = b['sel']['k'] == 'gids' ? [b['sel']['gids'], []] : [[], verbs_of_class(o, b['sel']['cls'])]
  def applies(s, gid, verb) = s[0].include?(gid) || s[1].include?(verb)

  def in_scope(b, a, x)
    s = b['scope']
    case s['k']
    when 'session' then a['sess'] == x['sess']
    when 'principal' then a['prin'] == x['prin']
    when 'org' then a['org'] == x['org']
    else s['agents'].include?(a['agent']) && s['agents'].include?(x['agent'])
    end
  end

  def in_window(w, a, x)
    case w['k']
    when 'sliding' then a['t'] - w['ms'] < x['t'] && x['t'] <= a['t']
    when 'period' then w['ms'].positive? && (a['t'] - w['t0']).div(w['ms']) == (x['t'] - w['t0']).div(w['ms'])
    else true
    end
  end

  def exceeded(b, s, a, h)
    items = h['adms'].select { |m| applies(s, m['gid'], m['act']['verb']) && in_scope(b, a, m['act']) && in_window(b['window'], a, m['act']) }
                     .map { |m| m['act'] } + [a]
    return b2k(items.length > b['cap']['n']) if b['agg'] == 'count'

    if b['agg'] == 'distinct'
      vs = {}
      items.each do |x|
        return 1 unless x['params'].key?(b['key'])

        vs[canon(x['params'][b['key']])] = true
      end
      return b2k(vs.length > b['cap']['n'])
    end
    ns = []
    items.each do |x|
      v = term(b['value'], x, h)
      return 1 if v.nil? || v['k'] != 'q' || v['q']['u'] != b['cap']['u']

      ns << v['q']['n']
    end
    b2k((b['agg'] == 'sum' ? ns.sum : ns.max) > b['cap']['n'])
  end

  def bound_dec(b, s, a, h)
    e = exceeded(b, s, a, h)
    return b['onExceed'] == 'deny' ? 0 : 1 if e == 2

    e == 1 ? 1 : 2
  end

  def strip(g)
    keep = g['grants'].reject { |x| g['holes'].any? { |h| h['global'] || h['affects'].include?(x['gid']) } }
    g.merge('grants' => keep, 'holes' => [])
  end

  def grant_dec(g, o, gr, a, h)
    deleg_ok = a['depth'].zero? || g['deleg']['mayTouch'].include?(gr['gid'])
    m = [b2k(a['verb'] == gr['verb'] && deleg_ok), b2k(res_ok(resolve(o, gr['res']), a['res'])), cond(gr['cond'], a, h)].min
    g['bounds'].each do |b|
      s = lsel(o, b)
      m = [m, bound_dec(b, s, a, h)].min if applies(s, gr['gid'], a['verb'])
    end
    m
  end

  def decide(goal, o, a, h)
    g = strip(goal)
    v = g['validity']
    d = 2
    if a['t'] < v['notBefore'] || a['t'] > v['notAfter']
      d = 0
    elsif v['maxIdle'].positive? && h['last'] >= 0 && a['t'] - h['last'] > v['maxIdle']
      d = 0
    elsif a['depth'].negative? || a['depth'] > g['deleg']['maxDepth']
      d = 0
    end
    g['prohibits'].each do |p|
      m = [b2k(proh_verbs(o, p).include?(a['verb'])), b2k(res_ok(resolve(o, p['res']), a['res'])), cond(p['cond'], a, h)].min
      d = [d, m == 2 ? 0 : (m == 1 ? 1 : 2)].min
    end
    g['escalateOn'].each { |c| d = [d, cond(c, a, h).zero? ? 2 : 1].min }
    per = g['grants'].map { |gr| grant_dec(g, o, gr, a, h) }
    d = [d, per.empty? ? 0 : per.max].min
    return { 'decision' => d == 1 ? 'escalate' : 'deny', 'witness' => nil } if d != 2

    gr = g['grants'][per.index(2)]
    bids = g['bounds'].select { |b| applies(lsel(o, b), gr['gid'], a['verb']) }.map { |b| b['bid'] }
    { 'decision' => 'allow', 'witness' => { 'gid' => gr['gid'], 'bids' => bids } }
  end

  # lowering for the policy digest
  NEG = { 'eq' => 'ne', 'ne' => 'eq', 'lt' => 'gte', 'gte' => 'lt', 'gt' => 'lte', 'lte' => 'gt', 'in' => 'nin', 'nin' => 'in' }.freeze

  def nnf(c, pos)
    case c['k']
    when 'true' then { 'k' => pos ? 'true' : 'false' }
    when 'cmp' then { 'k' => 'atom', 'op' => pos ? c['op'] : NEG[c['op']], 'l' => c['l'], 'r' => c['r'] }
    when 'and' then { 'k' => pos ? 'and' : 'or', 'a' => nnf(c['a'], pos), 'b' => nnf(c['b'], pos) }
    when 'or' then { 'k' => pos ? 'or' : 'and', 'a' => nnf(c['a'], pos), 'b' => nnf(c['b'], pos) }
    else nnf(c['c'], !pos)
    end
  end

  def pat(p) = p.nil? ? { 'k' => 'star' } : { 'k' => 'set', 'ids' => p }

  def lower(o, goal)
    g = strip(goal)
    ceils = g['bounds'].map do |b|
      s = lsel(o, b)
      { 'bid' => b['bid'], 'selGids' => s[0], 'selVerbs' => s[1], 'agg' => b['agg'], 'value' => b['value'], 'key' => b['key'],
        'window' => b['window'], 'scope' => b['scope'], 'cap' => b['cap'], 'onExceed' => b['onExceed'] }
    end
    {
      'preds' => g['grants'].map { |x| { 'gid' => x['gid'], 'verb' => x['verb'], 'res' => pat(resolve(o, x['res'])), 'cond' => nnf(x['cond'], true) } },
      'prohs' => g['prohibits'].map { |p| { 'pid' => p['pid'], 'verbs' => proh_verbs(o, p), 'res' => pat(resolve(o, p['res'])), 'cond' => nnf(p['cond'], true) } },
      'ceils' => ceils,
      'escs' => g['escalateOn'].map { |c| nnf(c, true) },
      'validity' => g['validity'],
      'deleg' => g['deleg']
    }
  end

  RANK = { 'deny' => 0, 'escalate' => 1, 'allow' => 2 }.freeze

  def meet(d, s) = s.is_a?(String) && RANK.key?(s) && RANK[s] < RANK[d] ? s : d

  MODEL = %w[env.class. env.prov. env.judge. env.world.].freeze

  def polarity(ws)
    out = {}
    walk = lambda do |c|
      case c['k']
      when 'and', 'or' then [c['a'], c['b']].each { |x| walk.call(x) }
      when 'not' then walk.call(c['c'])
      when 'cmp'
        [c['l'], c['r']].each { |t| out[t['path']] = true if t['k'] == 'param' && MODEL.any? { |m| t['path'].start_with?(m) } }
      end
    end
    ws.each { |w| walk.call(w) }
    out.keys.sort_by(&:b)
  end

  def units(schema, terms)
    terms.keys.select { |p| !schema.key?(p) || canon(schema[p]) != canon(terms[p]) }.sort_by(&:b)
  end

  def pep(d, ctx, ans)
    return true if d == 'allow'
    return false if d == 'deny'

    !ans.nil? && ans['valid'] ? %w[policy_digest action_digest history_head].all? { |k| ans[k] == ctx[k] } : false
  end

  def commit(g, p, s) = b64(Digest::SHA256.digest("pca-goal:v3:commit:#{g}:#{p}:#{s}"))
  def claim(base, min_ppm, _claimed, replayed) = !replayed.nil? && replayed < min_ppm ? meet(base, 'escalate') : base

  def run_fn(v)
    i = v['input']
    case v['fn']
    when 'canon' then { 'canon' => canon(i), 'digest' => goal_digest(i) }
    when 'units' then units(i['schema'], i['terms'])
    when 'polarity' then polarity(i)
    when 'meet' then meet(i['decision'], i['signal'])
    when 'pep' then pep(i['decision'], i['ctx'], i['answer'])
    when 'commit' then { 'commit' => commit(i['goal_digest'], i['policy_digest'], i['salt']), 'opens_other_goal' => false }
    when 'claim' then claim(i['base'], i['min_ppm'], i['claimed_ppm'], i['replayed_ppm'])
    else raise "unknown fn #{v['fn']}"
    end
  end
end

class TestGoalVectors < Minitest::Test
  CANDIDATES = [ENV['PCA_GOAL_VECTORS'],
                File.expand_path('../../../packages/pca-conformance/vectors/goal', __dir__),
                File.expand_path('../packages/pca-conformance/vectors/goal', __dir__)].compact

  def dir
    d = CANDIDATES.find { |c| File.directory?(c) }
    flunk "goal vectors not found (looked in #{CANDIDATES.join(', ')})" if d.nil?
    d
  end

  def test_vectors
    bad = []
    n = probes = 0
    Dir.children(dir).sort.each do |f|
      next if f == 'index.json' || !f.end_with?('.json')

      v = JSON.parse(File.read(File.join(dir, f), encoding: 'UTF-8'))
      n += 1
      if v['kind'] == 'fn'
        bad << v['id'] if GoalRef.canon(GoalRef.run_fn(v)) != GoalRef.canon(v['expect'])
        next
      end
      bad << "#{v['id']}:goal_digest" if GoalRef.goal_digest(v['goal']) != v['goal_digest']
      bad << "#{v['id']}:policy_digest" if v['compile']['ok'] && GoalRef.hash_canon(GoalRef.lower(v['ontology'], v['goal'])) != v['policy_digest']
      next unless v['compile']['ok']

      v['probes'].each_with_index do |p, i|
        probes += 1
        got = GoalRef.decide(v['goal'], v['ontology'], p['action'], p['history'])
        bad << "#{v['id']}##{i}" if GoalRef.canon(got) != GoalRef.canon(p['expect'])
      end
    end
    assert_operator n, :>, 200
    assert_operator probes, :>, 5000
    assert_equal [], bad.first(20)
  end

  def test_the_reference_is_sensitive
    # a one-bit change in a goal changes its digest; meet never widens
    refute_equal GoalRef.goal_digest({ 'a' => 1 }), GoalRef.goal_digest({ 'a' => 2 })
    assert_equal 'deny', GoalRef.meet('deny', 'ok')
    assert_equal 'escalate', GoalRef.meet('allow', 'escalate')
  end
end
