# frozen_string_literal: true

# The pure logic of the store conformance kit (port of the TypeScript reference, @atlasauth/pca-store-conformance): the sequential
# register specification both store operations share, the verdict-preserving reductions, the budgeted linearizability search, the
# per-key checker with minimal counterexamples, the recorder history parser and the workload PRNG.
#
# One model for both operations. An operation is a Hash {'client','kind','key','lo','w','call','ret','res'}: kind is 'consume' or
# 'advance'; each carries a threshold lo and a write value w (consume: lo = now, w = retainUntil; advance: lo = w = the counter);
# call / ret bound the interval (ret is Infinity when the outcome is unknown); res is 'true', 'false' or 'unknown'. The register
# starts at -Infinity. A TRUE answer is legal iff s < lo and then s = max(s, w); a FALSE answer is legal iff s >= lo and leaves s;
# an UNKNOWN outcome may or may not have taken effect. Operation identity matters (deletion removes the very object it is given).
#
# A PASS is evidence, not proof; a violation is a recorded history no sequential order explains.
require 'json'
require 'set'
require_relative 'js_compat'
require_relative 'predicates'

module AtlasPca
  module StoreConformanceModel
    DEFAULT_SEARCH_BUDGET = 200_000
    INF = Float::INFINITY
    M32 = 0xFFFFFFFF

    module_function

    # Python/JS max(a, b): b only wins when it is strictly greater (a NaN never wins).
    def fmax(a, b) = b > a ? b : a

    # A stable sort by a numeric key (Ruby's sort_by is not stable; the reference sorts are).
    def stable_by(list)
      list.each_with_index.sort do |(a, i), (b, j)|
        ka = yield(a)
        kb = yield(b)
        c = ka < kb ? -1 : (kb < ka ? 1 : 0)
        c.zero? ? i <=> j : c
      end.map(&:first)
    end

    # ---- the register model ------------------------------------------------------------------------------------------

    # The register's successor states after op from s (empty: the answer is impossible from s).
    def step(s, op)
      fresh = s < op['lo']
      case op['res']
      when 'true' then fresh ? [fmax(s, op['w'])] : []
      when 'false' then fresh ? [] : [s]
      else fresh ? [s, fmax(s, op['w'])] : [s]
      end
    end

    def definite_true?(o) = o['res'] == 'true'

    # Two definite TRUE answers whose [lo, w] intervals overlap can never both linearize: the minimal counterexample, or nil.
    def overlapping_trues(ops)
      ts = stable_by(ops.select { |o| definite_true?(o) }) { |o| o['lo'] }
      (1...ts.length).each { |i| return [ts[i - 1], ts[i]] if ts[i - 1]['w'] >= ts[i]['lo'] }
      nil
    end

    # Drop every definite FALSE that a definite TRUE explains (a TRUE with w >= lo that returned before the FALSE was invoked).
    def prune(ops)
      ts = stable_by(ops.select { |o| definite_true?(o) }) { |o| o['ret'] }
      pm = []
      ts.each { |t| pm << fmax(t['w'], pm.empty? ? -INF : pm.last) }
      ops.reject do |o|
        next false unless o['res'] == 'false'

        n = 0
        n += 1 while n < ts.length && ts[n]['ret'] < o['call']
        n.positive? && pm[n - 1] >= o['lo']
      end
    end

    # EXACT decision for a history with no unknown operation, in O(n log n); nil when one is unknown.
    def fast_check(ops)
      return nil if ops.any? { |o| o['res'] == 'unknown' }

      ts = stable_by(ops.select { |o| definite_true?(o) }) { |o| o['lo'] }
      t = []
      prev = -INF
      ts.each_with_index do |o, i|
        return false if i.positive? && ts[i - 1]['w'] >= o['lo']

        ti = fmax(o['call'], prev)
        return false if ti > o['ret']

        t << ti
        prev = ti
      end
      ops.each do |f|
        next unless f['res'] == 'false'

        j = ts.index { |x| x['w'] >= f['lo'] }
        return false if j.nil? || t[j] > f['ret']
      end
      true
    end

    # ---- the linearizability search ----------------------------------------------------------------------------------

    # A register value as a hash key: 5 and 5.0 are one state.
    def state_key(s) = s.is_a?(Float) && s.finite? && s == s.floor ? s.to_i : s

    # Wing-Gong / Lowe search for ONE key's history: 'ok', 'violation' or 'unresolved' (a key over the budget is never a pass).
    def search_linearizable(ops, budget = DEFAULT_SEARCH_BUDGET)
      order = stable_by(ops) { |o| o['call'] }
      n = order.length
      all_done = (1 << n) - 1
      seen = Set.new
      stack = [[0, -INF]]
      until stack.empty?
        done, s = stack.pop
        return 'ok' if done == all_done

        ident = [done, state_key(s)]
        next if seen.include?(ident)
        return 'unresolved' if seen.length >= budget

        seen << ident
        min_ret = INF
        n.times { |i| min_ret = order[i]['ret'] if (done & (1 << i)).zero? && order[i]['ret'] < min_ret }
        i = 0
        # sorted by invocation: once one starts after the earliest pending return, all later ones do too
        while i < n && order[i]['call'] <= min_ret
          step(s, order[i]).each { |s2| stack << [done | (1 << i), s2] } if (done & (1 << i)).zero?
          i += 1
        end
      end
      'violation'
    end

    # ---- the per-key checker -----------------------------------------------------------------------------------------

    # Decide one key's history: overlap, then prune, then the exact check, then the budgeted search. {verdict, method, kept}.
    def decide_key(ops, budget = DEFAULT_SEARCH_BUDGET)
      return { 'verdict' => 'violation', 'method' => 'overlap', 'kept' => ops.dup } if overlapping_trues(ops)

      kept = prune(ops)
      exact = fast_check(kept)
      return { 'verdict' => exact ? 'ok' : 'violation', 'method' => 'exact', 'kept' => kept } unless exact.nil?

      { 'verdict' => search_linearizable(kept, budget), 'method' => 'search', 'kept' => kept }
    end

    # The SOUND deletion step for op: deleting a FALSE never helps it; deleting a writer also removes the FALSEs it may have explained.
    def deletion(ops, op)
      return ops.reject { |o| o.equal?(op) } if op['res'] == 'false'

      ops.reject { |o| o.equal?(op) || (o['res'] == 'false' && o['lo'] <= op['w']) }
    end

    # Greedy sound deletion to a 1-minimal violating history.
    def minimize(ops, budget = DEFAULT_SEARCH_BUDGET)
      cur = ops.dup
      changed = true
      while changed
        changed = false
        cur.each do |op|
          nxt = deletion(cur, op)
          next unless decide_key(nxt, budget)['verdict'] == 'violation'

          cur = nxt
          changed = true
          break
        end
      end
      cur
    end

    # Check one key's history (all operations share kind and key). opts: 'budget', 'minimize' (default true), 'minimize_limit' (200).
    def check_key(ops, opts = nil)
      opts ||= {}
      budget = opts['budget'].nil? ? DEFAULT_SEARCH_BUDGET : opts['budget']
      first = ops[0]
      d = decide_key(ops, budget)
      kept = d['kept']
      r = { 'key' => first['key'], 'kind' => first['kind'], 'ops' => ops.length, 'searched' => kept.length, 'verdict' => d['verdict'], 'method' => d['method'] }
      return r unless d['verdict'] == 'violation'

      pair = overlapping_trues(ops)
      limit = opts['minimize_limit'].nil? ? 200 : opts['minimize_limit']
      if pair
        r['counterexample'] = stable_by(pair) { |o| o['call'] }
        r['minimized'] = true
      elsif opts['minimize'] != false && kept.length <= limit
        r['counterexample'] = minimize(kept, budget)
        r['minimized'] = true
      else
        r['counterexample'] = kept
        r['minimized'] = false
      end
      r
    end

    # Split a history by (kind, key) and check every key (P-compositionality).
    def check_history(ops, opts = nil)
      by_key = {}
      outcomes = { 'true' => 0, 'false' => 0, 'unknown' => 0 }
      ops.each do |o|
        outcomes[o['res']] += 1
        (by_key[[o['kind'], o['key']]] ||= []) << o
      end
      violations = []
      unresolved = []
      by_key.each_value do |lst|
        r = check_key(lst, opts)
        violations << r if r['verdict'] == 'violation'
        unresolved << r if r['verdict'] == 'unresolved'
      end
      { 'ops' => ops.length, 'keys' => by_key.length, 'ok' => violations.empty? && unresolved.empty?, 'outcomes' => outcomes,
        'violations' => violations, 'unresolved' => unresolved }
    end

    # ---- formatting --------------------------------------------------------------------------------------------------

    def js_number_str(x)
      return x ? 'true' : 'false' if x == true || x == false
      return Predicates.js_number_string(x) if x.is_a?(Integer) || x.is_a?(Float)

      x.to_s
    end

    # JavaScript toFixed(3): the exact binary value, ties away from zero.
    def to_fixed3(x)
      return x.nan? ? 'NaN' : (x.positive? ? 'Infinity' : '-Infinity') if x.is_a?(Float) && !x.finite?

      n = (Rational(x) * 1000).round(half: :up)
      sign = n.negative? ? '-' : ''
      format('%<s>s%<i>d.%<f>03d', s: sign, i: n.abs / 1000, f: n.abs % 1000)
    end

    def fmt_t(t, base) = t == INF ? 'open' : "+#{to_fixed3(t - base)}ms"

    def res_label(r) = r == 'true' ? 'TRUE' : (r == 'false' ? 'false' : 'unknown')

    # One line per operation, times relative to the first invocation.
    def format_ops(ops)
      base = ops.map { |o| o['call'] }.reduce(INF) { |m, c| c < m ? c : m }
      stable_by(ops) { |o| o['call'] }.map do |o|
        what = o['kind'] == 'consume' ? "consumeOnce(now=#{js_number_str(o['lo'])}, retainUntil=#{js_number_str(o['w'])})" : "advance(#{js_number_str(o['lo'])})"
        "#{o['client']}: #{what} [#{fmt_t(o['call'], base)} .. #{fmt_t(o['ret'], base)}] -> #{res_label(o['res'])}"
      end
    end

    # Fold test statuses: fail beats unresolved beats pass (a skip counts for nothing).
    def overall(tests)
      return 'fail' if tests.any? { |t| t['status'] == 'fail' }
      return 'unresolved' if tests.any? { |t| t['status'] == 'unresolved' }

      'pass'
    end

    OP_NAME = { 'consume' => 'consumeOnce', 'advance' => 'advance' }.freeze

    # Human-readable report: one line per test, then each violating key's minimal counterexample (at most max_keys per test).
    def format_report(r, max_keys = 3)
      out = ["pca-store-conformance: #{r['adapter']} -> #{r['status'].upcase}"]
      r['tests'].each do |t|
        name = "#{t['test']}/#{OP_NAME[t['kind']]}".ljust(24)
        stats = t['status'] == 'skip' ? '' : "#{js_number_str(t['ops'])} ops, #{js_number_str(t['keys'])} keys, #{js_number_str(t['errors'])} errors/timeouts"
        extra = [
          t['violations'].empty? ? '' : "#{t['violations'].length} NON-LINEARIZABLE key(s)",
          Js.truthy?(t['unresolved']) ? "#{js_number_str(t['unresolved'])} unresolved key(s) (over the search budget)" : '',
          Js.truthy?(t['note']) ? t['note'] : ''
        ].reject(&:empty?).join('; ')
        out << "  [#{t['status'].upcase}] #{name} #{[stats, extra].reject(&:empty?).join('; ')}"
        t['violations'].first([max_keys, 0].max).each do |v|
          out << "      key #{v['key']} (#{js_number_str(v['ops'])} ops, decided by #{v['method']}): " \
                 "#{v['minimized'] ? 'minimal counterexample' : 'violating history (not shrunk)'}:"
          format_ops(v['counterexample'] || []).each { |line| out << "        #{line}" }
        end
      end
      out.join("\n")
    end

    def finite_or_nil(v)
      case v
      when Float then v.finite? ? v : nil
      when Hash then v.transform_values { |x| finite_or_nil(x) }
      when Array then v.map { |x| finite_or_nil(x) }
      else v
      end
    end

    def pretty(v, ind = '')
      case v
      when Hash
        return '{}' if v.empty?

        inner = "#{ind}  "
        "{\n#{v.map { |k, x| "#{inner}#{Js.json_string(k.to_s)}: #{pretty(x, inner)}" }.join(",\n")}\n#{ind}}"
      when Array
        return '[]' if v.empty?

        inner = "#{ind}  "
        "[\n#{v.map { |x| "#{inner}#{pretty(x, inner)}" }.join(",\n")}\n#{ind}]"
      else Js.json(v)
      end
    end

    # JSON-safe form of a report (a non-finite number becomes null), two-space indented.
    def report_json(r) = pretty(finite_or_nil(r))

    # ---- the recorder's history parser and the PRNG ------------------------------------------------------------------

    DEC_RE = /\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z/
    RADIX_RE = /\A0([xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)\z/

    # JavaScript Number(string): trimmed, empty is 0, decimal / hex / octal / binary, Infinity; anything else NaN.
    def js_number_of_string(v)
      t = Js.trim(v)
      return 0 if t.empty?
      return t.to_f if DEC_RE.match?(t)
      return t[2..].to_i({ 'x' => 16, 'o' => 8, 'b' => 2 }[t[1].downcase]) if RADIX_RE.match?(t)

      { 'Infinity' => INF, '+Infinity' => INF, '-Infinity' => -INF }.fetch(t, Float::NAN)
    end

    # JavaScript Number(x) for a JSON value.
    def js_num(x)
      case x
      when nil, false then 0
      when true then 1
      when Integer, Float then x
      when String
        v = js_number_of_string(x)
        v.is_a?(Float) && v.finite? && v == v.floor && v.abs < 1e21 ? v.to_i : v
      when Array
        return 0 if x.empty?

        x.length == 1 && !x[0].is_a?(Array) && !x[0].is_a?(Hash) ? js_num(x[0]) : Float::NAN
      else Float::NAN
      end
    end

    # Rebuild the operations from recorder lines (any number of files concatenated). An invocation without a response is pending
    # (unknown, open-ended); an 'unknown' response stays open-ended too. Lines that do not parse are counted as torn.
    # Returns {'ops', 'torn', 'pending'}.
    def parse_history(text)
      open_ops = {}
      ops = []
      torn = 0
      text.split("\n", -1).each do |line|
        next if line.empty?

        e = begin
          Js.parse(line)
        rescue StandardError
          torn += 1
          next
        end
        unless e.is_a?(Array)
          torn += 1
          next
        end
        ident = "#{e.length > 1 ? Js.string(e[1]) : 'undefined'}/#{e.length > 2 ? Js.string(e[2]) : 'undefined'}"
        if e.length == 9 && e[0] == 'i'
          op = { 'client' => Js.string(e[4]), 'kind' => e[5], 'key' => Js.string(e[6]), 'lo' => js_num(e[7]), 'w' => js_num(e[8]), 'call' => js_num(e[3]),
                 'ret' => INF, 'res' => 'unknown' }
          open_ops[ident] = op
          ops << op
        elsif e.length == 5 && e[0] == 'r' && open_ops.key?(ident)
          op = open_ops.delete(ident)
          unless e[4] == 'unknown'
            op['ret'] = js_num(e[3])
            op['res'] = e[4] == 'true' ? 'true' : 'false'
          end
        else
          torn += 1
        end
      end
      { 'ops' => ops, 'torn' => torn, 'pending' => open_ops.length }
    end

    # Deterministic PRNG (mulberry32): the returned lambda maps n to an integer in [0, n).
    def prng(seed)
      a = [(seed.is_a?(Integer) || (seed.is_a?(Float) && seed.finite?)) ? seed.to_i & M32 : 0]
      lambda do |n|
        a[0] = (a[0] + 0x6D2B79F5) & M32
        t = a[0]
        t = ((t ^ (t >> 15)) * (t | 1)) & M32
        t = (t ^ ((t + (((t ^ (t >> 7)) * (t | 61)) & M32)) & M32)) & M32
        ((((t ^ (t >> 14)) & M32) / 4_294_967_296.0) * n).floor
      end
    end
  end
end
