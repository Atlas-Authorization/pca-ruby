# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'predicates'
require_relative 'catalog_builtin'

# The intent outcome space (omega): typed dimensions derived from the grant vocabulary, cells, representatives, the workload and
# harm measures, a seeded generator and the derivation from policies + slots. Native port of the TypeScript reference
# (@atlasauth/pca-intent). Dimensions, verb spaces and omegas are plain String-keyed Hashes, as in the reference.
module AtlasPca
  module IntentOmega
    OTHER = '⊥'
    DEFAULT_DOMAINS = {
      'action.params.amount' => { 'lo' => 0, 'hi' => 100_000, 'dist' => 'loguniform' },
      'env.hour' => { 'lo' => 0, 'hi' => 23, 'dist' => 'uniform' },
      'action.params.count' => { 'lo' => 0, 'hi' => 1000, 'dist' => 'loguniform' }
    }.freeze
    EXACT_SPAN = 4096
    HARM_QUADRATURE_PIECES = 1024
    EULER_GAMMA = 0.5772156649015329
    AMOUNT_RE = /(\A|\.)amount\z/

    # The harm measure: verb(vs), dim(d, x) and the optional closed-form dim_mean(d, lo, hi).
    class HarmModel
      attr_reader :verb, :dim, :dim_mean

      def initialize(verb, dim, dim_mean = nil)
        @verb = verb
        @dim = dim
        @dim_mean = dim_mean
      end
    end

    module_function

    def number?(x) = x.is_a?(Integer) || x.is_a?(Float)
    alias is_number number?

    def finite_number?(x) = number?(x) && (x.is_a?(Integer) || x.finite?)
    alias is_finite_number finite_number?

    # JS default string order is by UTF-16 code unit.
    def u16key(s) = s.dup.force_encoding('UTF-8').scrub.encode('UTF-16BE').b

    def js_round(x) = (x + 0.5).floor

    def u16len(s) = Js.len16(s)

    NUM_CELLS_MEMO = {} # rubocop:disable Style/MutableConstant

    # [[lo, hi], ...]: the ordered cells of a numeric dimension (inclusive integer ranges; empty cells dropped).
    def cells_of_dim(d)
      key = [d['lo'], d['hi'], d['cuts']]
      NUM_CELLS_MEMO[key] ||= begin
        out = []
        cur = d['lo']
        d['cuts'].each do |c|
          next if c < d['lo'] || c > d['hi']

          out << [cur, c - 1] if cur <= c - 1
          out << [c, c]
          cur = c + 1
        end
        out << [cur, d['hi']] if cur <= d['hi']
        out.map(&:freeze).freeze
      end
    end

    def num_cells(d) = cells_of_dim(d).map { |a, b| { 'lo' => a, 'hi' => b } }

    # seq[i] with the reference's out-of-range failure (a negative index must not wrap around).
    def at(seq, i)
      raise IndexError, "cell index #{i.inspect} out of range" if i.negative? || i >= seq.length

      seq[i]
    end

    def cell_count(d) = d['kind'] == 'num' ? cells_of_dim(d).length : d['values'].length

    def verb_cell_count(vs) = vs['dims'].reduce(1) { |n, d| n * cell_count(d) }

    def decode_cell(vs, flat)
      dims = vs['dims']
      idx = Array.new(dims.length, 0)
      (dims.length - 1).downto(0) do |i|
        n = cell_count(dims[i])
        idx[i] = (flat % n).to_i
        flat = flat.is_a?(Integer) ? flat.div(n) : (flat / n.to_f).floor
      end
      idx
    end

    def encode_cell(vs, idx)
      flat = 0
      vs['dims'].each_with_index { |d, i| flat = (flat * cell_count(d)) + idx[i] }
      flat
    end

    # Which cell of a categorical dimension a concrete string falls in (exact > longest prefix > OTHER).
    def cat_cell_of(d, s)
      best = -1
      best_len = -1
      d['values'].each_with_index do |v, i|
        return i if v['kind'] == 'exact' && v['value'] == s
        next unless v['kind'] == 'prefix' && s.start_with?(v['value']) && u16len(v['value']) > best_len

        best = i
        best_len = u16len(v['value'])
      end
      return best if best >= 0

      d['values'].each_with_index { |v, i| return i if v['kind'] == 'other' }
      -1
    end

    # Which cell a concrete value falls in, or -1 when it is outside the dimension's domain/type.
    def cell_of_value(d, x)
      if d['kind'] == 'num'
        return -1 unless finite_number?(x)

        cells_of_dim(d).each_with_index { |(lo, hi), i| return i if x >= lo && x <= hi }
        return -1
      end
      return -1 unless x.is_a?(String)

      cat_cell_of(d, x)
    end

    def cell_of(vs, o)
      idx = []
      values = o['values'] || {}
      vs['dims'].each do |d|
        i = cell_of_value(d, values[d['path']])
        return nil if i.negative?

        idx << i
      end
      idx
    end

    def cat_rep(d, i)
      v = at(d['values'], i)
      return v['value'] if v['kind'] == 'exact'

      base = v['kind'] == 'prefix' ? "#{v['value']}x" : 'other'
      64.times do |k|
        s = base + (k.zero? ? '' : k.to_s)
        return s if cat_cell_of(d, s) == i
      end
      base
    end

    def num_rep(d, i)
      lo, hi = at(cells_of_dim(d), i)
      i.positive? ? lo : hi
    end

    def rep_value(d, i) = d['kind'] == 'num' ? num_rep(d, i) : cat_rep(d, i)

    def cell_rep(vs, idx)
      values = {}
      vs['dims'].each_with_index { |d, i| values[d['path']] = rep_value(d, idx[i]) }
      { 'verb' => vs['verb'], 'values' => values }
    end

    # ---- workload and harm -----------------------------------------------------------------------------------------

    def loguniform?(d) = d['dist'] == 'loguniform' && d['lo'] >= 0

    def point_weight(d, x) = loguniform?(d) ? 1.0 / (x + 1) : 1

    def linear_amount?(d) = d['kind'] == 'num' && AMOUNT_RE.match?(d['path'])

    # Mean of x over [a, b] weighted by the law, as a ratio to the whole cell [cell_lo, b].
    def interval_mean_x(d, a, b, cell_lo)
      whole = interval_weight(d, cell_lo, b)
      whole.positive? ? interval_first_moment(d, a, b) / whole : 0
    end

    DEFAULT_HARM = HarmModel.new(
      ->(vs) { r = vs['reversibility']; r == 'irreversible' ? 10 : (r == 'rate_limited' ? 3 : 1) },
      ->(d, x) { linear_amount?(d) && number?(x) ? 1 + ([0, x].max / 100.0) : 1 },
      lambda do |d, lo, hi|
        next 1 unless linear_amount?(d)

        1 + ([0, interval_mean_x(d, [lo, 0].max, hi, lo)].max / 100.0)
      end
    )

    def harm_max(omega, harm = DEFAULT_HARM)
      m = 0
      omega['verbs'].each do |vs|
        f = harm.verb.call(vs)
        vs['dims'].each do |d|
          f *= if d['kind'] == 'num'
                 [harm.dim.call(d, d['lo']), harm.dim.call(d, d['hi'])].max
               else
                 d['values'].each_index.map { |i| harm.dim.call(d, cat_rep(d, i)) }.max
               end
        end
        m = [m, f].max
      end
      m
    end

    def harmonic(n)
      return 0 if n <= 0

      if n <= EXACT_SPAN
        s = 0.0
        n.to_i.downto(1) { |k| s += 1.0 / k }
        return s
      end
      n = n.to_f
      n2 = n * n
      Math.log(n) + EULER_GAMMA + (1.0 / (2 * n)) - (1.0 / (12 * n2)) + (1.0 / (120 * n2 * n2)) - (1.0 / (252 * n2 * n2 * n2))
    end

    # Sum of the dimension's law over the integers a..b (0 for an empty interval).
    def interval_weight(d, a, b)
      return 0 if b < a
      return b - a + 1 unless loguniform?(d)

      if b - a + 1 <= EXACT_SPAN
        s = 0.0
        x = b.to_i
        while x >= a
          s += 1.0 / (x + 1)
          x -= 1
        end
        return s
      end
      harmonic(b.to_f + 1) - harmonic(a)
    end

    def interval_first_moment(d, a, b)
      return 0 if b < a

      a = a.to_f
      b = b.to_f
      return ((a + b) * (b - a + 1)) / 2 unless loguniform?(d)

      b - a + 1 - interval_weight(d, a, b)
    end

    def interval_harm(d, a, b, harm)
      return harm.dim_mean.call(d, a, b) if harm.dim_mean

      n = b.to_f - a.to_f + 1
      w_tot = interval_weight(d, a, b)
      return harm.dim.call(d, a) unless w_tot.positive?

      if n <= EXACT_SPAN
        s = 0.0
        x = a
        while x <= b
          s += point_weight(d, x) * harm.dim.call(d, x)
          x += 1
        end
        return s / w_tot
      end
      s = 0.0
      fa = a.to_f
      HARM_QUADRATURE_PIECES.times do |i|
        pa = fa + ((i.to_f * n) / HARM_QUADRATURE_PIECES).floor
        pb = fa + (((i + 1).to_f * n) / HARM_QUADRATURE_PIECES).floor - 1
        next if pb < pa

        w = interval_weight(d, pa, pb)
        s += w * harm.dim.call(d, js_round((pa + pb) / 2))
      end
      s / w_tot
    end

    DIM_TOTAL_MEMO = {} # rubocop:disable Style/MutableConstant

    def dim_total(d)
      DIM_TOTAL_MEMO[[d['lo'], d['hi'], d['dist']]] ||= interval_weight({ 'lo' => d['lo'], 'dist' => d['dist'] }, d['lo'], d['hi'])
    end

    # mu_d(cell) and E[g_d | cell] for one dimension cell. Categorical values are uniform.
    def dim_cell_stats(d, i, harm = DEFAULT_HARM)
      return { 'mass' => 1.0 / d['values'].length, 'harm' => harm.dim.call(d, cat_rep(d, i)) } if d['kind'] == 'cat'

      lo, hi = at(cells_of_dim(d), i)
      wm = interval_weight(d, lo, hi)
      { 'mass' => wm / dim_total(d).to_f, 'harm' => wm.positive? ? interval_harm(d, lo, hi, harm) : harm.dim.call(d, lo) }
    end

    def quantile_value(d, target)
      acc = 0.0
      cells = cells_of_dim(d)
      cells.each_with_index do |(lo, hi), ci|
        w = interval_weight(d, lo, hi)
        next acc += w unless target < acc + w || ci == cells.length - 1

        r = target - acc
        if hi - lo + 1 <= EXACT_SPAN
          x = lo
          while x < hi
            r -= point_weight(d, x)
            return x if r.negative?

            x += 1
          end
          return hi
        end
        return [hi, lo + r.floor].min unless loguniform?(d)

        x = (((lo.to_f + 1) * Math.exp(r)) - 1).floor
        return [lo, [hi, x].min].max
      end
      d['hi']
    end

    def cell_stats(vs, idx, harm = DEFAULT_HARM)
      mass = vs['weight']
      h = harm.verb.call(vs)
      vs['dims'].each_with_index do |d, k|
        s = dim_cell_stats(d, idx[k], harm)
        mass *= s['mass']
        h *= s['harm']
      end
      { 'mass' => mass, 'harm' => h }
    end

    def harm_of(vs, o, harm = DEFAULT_HARM)
      h = harm.verb.call(vs)
      values = o['values'] || {}
      vs['dims'].each { |d| h *= harm.dim.call(d, values[d['path']]) }
      h
    end

    # A small seeded PRNG (mulberry32), bit-identical to the reference.
    def rng(seed)
      state = [seed.to_i & 0xFFFFFFFF]
      m = 0xFFFFFFFF
      lambda do
        state[0] = (state[0] + 0x6D2B79F5) & m
        t = state[0]
        t = ((t ^ (t >> 15)) * (t | 1)) & m
        t ^= (t + (((t ^ (t >> 7)) * (t | 61)) & m)) & m
        ((t ^ (t >> 14)) & m) / 4_294_967_296.0
      end
    end

    # Draw an outcome from the workload: [verb space, outcome].
    def sample_outcome(omega, rand, _harm = DEFAULT_HARM)
      u = rand.call
      vs = omega['verbs'][-1]
      omega['verbs'].each do |v|
        if u < v['weight']
          vs = v
          break
        end
        u -= v['weight']
      end
      values = {}
      vs['dims'].each do |d|
        if d['kind'] == 'cat'
          values[d['path']] = cat_rep(d, [d['values'].length - 1, (rand.call * d['values'].length).floor].min)
          next
        end
        values[d['path']] = quantile_value(d, rand.call * dim_total(d))
      end
      [vs, { 'verb' => vs['verb'], 'values' => values }]
    end

    # ---- derivation from policies + slots --------------------------------------------------------------------------

    class FieldLits
      attr_reader :nums, :exacts, :prefixes

      def initialize
        @nums = {}
        @exacts = {}
        @prefixes = {}
      end
    end

    def lits(m, path) = (m[path] ||= FieldLits.new)

    def int_if_integral(x) = x.is_a?(Float) && x.finite? && x == x.floor && x.abs < 2**63 ? x.to_i : x

    def add_num(f, x)
      return unless finite_number?(x)

      f.nums[int_if_integral(x.floor)] = nil
      f.nums[int_if_integral(x.ceil)] = nil
    end

    def collect_cond(c, m, approx)
      return unless c.is_a?(Hash)

      if Predicates.group?(c)
        if c.key?('all_of') && c['all_of'].is_a?(Array)
          c['all_of'].each { |x| collect_cond(x, m, approx) }
        elsif c.key?('any_of') && c['any_of'].is_a?(Array)
          c['any_of'].each { |x| collect_cond(x, m, approx) }
        elsif c.key?('not')
          collect_cond(c['not'], m, approx)
        end
        return
      end
      return unless Predicates.leaf?(c)

      field = c['field']
      op = c['op']
      approx << "cross-field ref on #{field}" unless c['ref'].nil?
      approx << "#{op} on #{field}" if %w[like matches is_a member_of].include?(op)
      if op == 'exists'
        lits(m, field)
        return
      end
      f = lits(m, field)
      value = c['value']
      (value.is_a?(Array) ? value : [value]).each do |v|
        if number?(v)
          add_num(f, v)
        elsif v.is_a?(String)
          (op == 'prefix' ? f.prefixes : f.exacts)[v] = nil
        end
      end
    end

    def add_resource(r, m, approx)
      return if !r.is_a?(String) || r == '*'

      if r.start_with?('re:')
        approx << 're: resource matcher'
        return
      end
      f = lits(m, 'action.resource')
      if r.end_with?('*')
        f.prefixes[r[0...-1]] = nil
      else
        f.exacts[r] = nil
      end
    end

    def verbs_of(p)
      v = p.is_a?(Hash) ? p['verb'] : nil
      return v == '*' ? '*' : [v] if v.is_a?(String)
      return v.include?('*') ? '*' : v.select { |x| x.is_a?(String) } if v.is_a?(Array)

      []
    end

    def catalog_all(catalog)
      catalog = BUILTIN_ACTIONS if catalog.nil?
      return catalog.values if catalog.is_a?(Hash)

      by = {}
      catalog.each { |s| by[s['verb']] = s }
      by.values
    end

    # Derive the outcome space from the vocabulary of the policies and the intent slots. Wildcard verbs expand to the catalog
    # verbs of every connector that appears anywhere (or the whole catalog when none does).
    def derive_omega(opts)
      require_relative 'intent_policy'
      pool_all = catalog_all(opts['catalog'])
      cat_by_verb = pool_all.to_h { |s| [s['verb'], s] }
      approx = {}
      preds = []
      opts['policies'].each { |p| preds.concat(IntentPolicy.normalize_policy(p)['predicates']) }
      slots = opts['slots']
      explicit = {}
      (opts['extraVerbs'] || []).each { |v| explicit[v] = nil }
      wildcard = false
      preds.each do |p|
        vs = verbs_of(p)
        if vs == '*'
          wildcard = true
        else
          vs.each { |v| explicit[v] = nil }
        end
      end
      ((slots.is_a?(Hash) ? slots['verbs'] : nil) || []).each { |v| explicit[v] = nil }
      if wildcard
        connectors = explicit.keys.to_h { |v| [v.partition('.')[0], nil] }
        pool = connectors.empty? ? pool_all : pool_all.select { |s| connectors.key?(s['connector']) }
        pool.each { |s| explicit[s['verb']] = nil }
      end
      domains = opts['domains'] || {}
      out = []
      explicit.keys.sort_by { |s| u16key(s) }.each do |verb|
        m = {}
        preds.each do |p|
          pv = verbs_of(p)
          next if pv != '*' && !pv.include?(verb)

          add_resource(p['resource'].is_a?(String) ? p['resource'] : nil, m, approx)
          p['where'].each { |c| collect_cond(c, m, approx) } if p['where'].is_a?(Array)
        end
        ((slots.is_a?(Hash) ? slots['constraints'] : nil) || []).each do |sc|
          next if !sc['verb'].nil? && sc['verb'] != verb

          f = lits(m, sc['path'])
          add_num(f, sc['max']) unless sc['max'].nil?
          add_num(f, sc['min']) unless sc['min'].nil?
          (sc['oneOf'] || []).each { |x| f.exacts[x] = nil }
          (sc['noneOf'] || []).each { |x| f.exacts[x] = nil }
          (sc['prefixOneOf'] || []).each { |x| f.prefixes[x] = nil }
        end
        dims = []
        m.keys.sort_by { |s| u16key(s) }.each do |path|
          f = m[path]
          if !f.nums.empty? || (f.exacts.empty? && f.prefixes.empty? && DEFAULT_DOMAINS.key?(path))
            cuts = f.nums.keys.sort
            dom = domains[path] || DEFAULT_DOMAINS[path]
            max_cut = cuts.empty? ? 0 : cuts[-1]
            min_cut = cuts.empty? ? 0 : cuts[0]
            lo = dom && !dom['lo'].nil? ? dom['lo'] : [0, min_cut - 1].min
            hi = dom && !dom['hi'].nil? ? dom['hi'] : [10, 2 * max_cut, max_cut + 10].max
            dist = dom && !dom['dist'].nil? ? dom['dist'] : (lo >= 0 ? 'loguniform' : 'uniform')
            dims << { 'kind' => 'num', 'path' => path, 'lo' => lo, 'hi' => hi, 'cuts' => cuts.select { |c| lo <= c && c <= hi }, 'dist' => dist }
          else
            values = f.exacts.keys.sort_by { |s| u16key(s) }.map { |v| { 'kind' => 'exact', 'value' => v } }
            values += f.prefixes.keys.sort_by { |s| u16key(s) }.map { |v| { 'kind' => 'prefix', 'value' => v } }
            values << { 'kind' => 'other', 'value' => OTHER }
            dims << { 'kind' => 'cat', 'path' => path, 'values' => values }
          end
        end
        spec = cat_by_verb[verb]
        out << { 'verb' => verb, 'reversibility' => (spec || {}).fetch('reversibility', 'irreversible'), 'weight' => 0, 'dims' => dims }
      end
      out.each { |v| v['weight'] = 1.0 / out.length }
      { 'v' => 1, 'verbs' => out, 'approximate' => approx.keys.sort_by { |s| u16key(s) } }
    end

    def verb_space(omega, verb) = omega['verbs'].find { |v| v['verb'] == verb }

    # ---- IEEE-754 behaviour of the JS Math functions (Ruby raises where JS returns NaN / Infinity) -----------------------

    def js_div(a, b)
      a.to_f / b.to_f
    end

    def nan?(x) = x.is_a?(Float) && x.nan?

    def js_sqrt(x) = nan?(x) || x.negative? ? Float::NAN : Math.sqrt(x)

    def js_log(x)
      return Float::NAN if nan?(x) || x.negative?
      return -Float::INFINITY if x.zero?

      Math.log(x)
    end

    def js_max(a, b) = nan?(a) || nan?(b) ? Float::NAN : [a, b].max
    def js_min(a, b) = nan?(a) || nan?(b) ? Float::NAN : [a, b].min
  end
end
