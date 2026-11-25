# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'detmath'
require_relative 'intent_policy'
require_relative 'intent_region'

# Elicitation as learning: the exact Bayesian posterior over a per-verb hypothesis class (boxes, unions of boxes, decision lists),
# the conservative grant it implies, the next question, the audit round and the synthesis of the grant as predicates. Native
# port of the TypeScript reference (@atlasauth/pca-intent, learner.ts). Omegas, verb spaces, options, observations and questions
# are plain String-keyed Hashes with the reference's field names; the posterior arithmetic keeps the reference's operation order.
module AtlasPca
  module IntentLearner
    ORDER = %w[reversible rate_limited irreversible].freeze

    # A cell mask / hypothesis set is an Array of 0/1 Integers (one per flat cell); this is its hash key.
    def self.key_of(mask) = mask.pack('C*')

    # JS `x || 1`: 0 and NaN are falsy there.
    def self.or1(x) = (x == x && x != 0) ? x : 1

    # JS `o.k ?? default`.
    def self.opt(o, k, default = nil)
      v = o.is_a?(Hash) ? o[k] : nil
      v.nil? ? default : v
    end

    # Python-style truthiness of an option value (None, 0, empty containers are falsy).
    def self.truthy(x) = !(x.nil? || x == false || x == 0 || x == '' || (x.respond_to?(:empty?) && x.empty?))

    def self.integer?(x)
      (x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)) && x == x.floor
    end

    # The canonical name of a hypothesis class (stored in the Intent Map).
    def self.hypothesis_class_name(h)
      case h['kind']
      when 'box' then 'per-verb-box/v1'
      when 'union' then 'per-verb-union/v1'
      else opt(h, 'conditions', 'box') == 'atomic' ? 'per-verb-decision-list/v1' : 'per-verb-decision-list/v2'
      end
    end

    # the binary entropy feeds the next-question argmax: det_log2 (not Math.log2) so that the chosen question is identical on every platform and
    # language; the same argument recurs for every cell of a model, so the value is memoized (bounded: cleared when it grows past 4096 entries)
    BIN_ENT_MEMO = {}

    def self.bin_ent(p)
      return 0 if p <= 0 || p >= 1
      return BIN_ENT_MEMO[p] if BIN_ENT_MEMO.key?(p)

      v = -((p * AtlasPca::DetMath.det_log2(p)) + ((1 - p) * AtlasPca::DetMath.det_log2(1 - p)))
      BIN_ENT_MEMO.clear if BIN_ENT_MEMO.size >= 4096
      BIN_ENT_MEMO[p] = v
    end

    def self.range_choices(n) = (0...n).flat_map { |i| (i...n).map { |j| [i, j] } }

    def self.build_box_tables(vs, n_cells_d)
      contains = []
      n_choice = []
      vs['dims'].each_with_index do |d, k|
        n = n_cells_d[k]
        if d['kind'] == 'num'
          ch = range_choices(n)
          t = Array.new(ch.length * n, 0)
          ch.each_with_index { |(i, j), c| (i..j).each { |x| t[(c * n) + x] = 1 } }
          contains << t
          n_choice << ch.length
        else
          raise ArgumentError, "pca-intent: categorical dimension #{d['path']} has #{n} values (max 20 for exact enumeration)" if n > 20

          m = (1 << n) - 1
          t = Array.new(m * n, 0)
          (1..m).each { |mask| n.times { |x| t[((mask - 1) * n) + x] = 1 if (mask & (1 << x)) != 0 } }
          contains << t
          n_choice << m
        end
      end
      [contains, n_choice]
    end

    def self.box_masks(vs, n_cells, cell_idx, n_cells_d, contains, n_choice, cap)
      dn = vs['dims'].length
      boxes = n_choice.reduce(1) { |a, c| a * c }
      raise ArgumentError, "pca-intent: #{boxes} boxes for #{vs['verb']} exceed the enumeration cap; coarsen the cuts" unless boxes <= cap

      out = []
      cur = Array.new(dn, 0)
      boxes.times do
        mask = Array.new(n_cells, 0)
        n_cells.times do |c|
          inside = true
          d = 0
          while d < dn && inside
            inside = false if contains[d][(cur[d] * n_cells_d[d]) + cell_idx[(c * dn) + d]].zero?
            d += 1
          end
          mask[c] = 1 if inside
        end
        out << mask
        (dn - 1).downto(0) do |d|
          cur[d] += 1
          break if cur[d] < n_choice[d]

          cur[d] = 0
        end
      end
      out
    end

    def self.enumerate_unions(boxes, k, cap, verb)
      seen = {}
      sets = []
      complexity = []
      frontier = []
      boxes.each do |b|
        key = key_of(b)
        next if seen.key?(key)

        seen[key] = sets.length
        sets << b
        complexity << 1
        frontier << b
      end
      work = 0
      (2..k).each do |level|
        nxt = []
        frontier.each do |s|
          boxes.each do |b|
            work += 1
            raise ArgumentError, "pca-intent: the union-of-#{k}-boxes class for #{verb} exceeds the enumeration cap; coarsen the cuts or lower k" unless work <= cap

            u = s.each_index.map { |i| s[i] | b[i] }
            key = key_of(u)
            next if seen.key?(key)

            seen[key] = sets.length
            sets << u
            complexity << level
            nxt << u
          end
        end
        frontier = nxt
      end
      [sets, complexity]
    end

    def self.atomic_tests(vs, n_cells, cell_idx, n_cells_d)
      dn = vs['dims'].length
      tests = []
      add = lambda do |k, pred|
        m = Array.new(n_cells, 0)
        any = false
        all = true
        n_cells.times do |c|
          if pred.call(cell_idx[(c * dn) + k])
            m[c] = 1
            any = true
          else
            all = false
          end
        end
        tests << m if any && !all
      end
      vs['dims'].each_with_index do |d, k|
        n = n_cells_d[k]
        if d['kind'] == 'num'
          (0...(n - 1)).each { |i| add.call(k, ->(x) { x <= i }) }
          (1...n).each { |i| add.call(k, ->(x) { x >= i }) }
          (1...(n - 1)).each { |i| add.call(k, ->(x) { x == i }) } if n > 2
        else
          n.times { |i| add.call(k, ->(x) { x == i }) }
        end
      end
      dedup_masks(tests)
    end

    def self.dedup_masks(masks)
      seen = {}
      masks.select do |t|
        key = key_of(t)
        next false if seen.key?(key)

        seen[key] = true
      end
    end

    def self.enumerate_decision_lists(tests, n_cells, max_rules, cap, verb)
      seen = {}
      sets = []
      complexity = []
      emit = lambda do |acc, decided, rules|
        [0, 1].each do |dflt|
          s = Array.new(n_cells, 0)
          any = false
          n_cells.times do |c|
            s[c] = decided[c].zero? ? dflt : acc[c]
            any = true if s[c] != 0
          end
          next unless any

          key = key_of(s)
          next if seen.key?(key)

          seen[key] = sets.length
          sets << s
          complexity << [1, rules].max
        end
      end
      frontier = [[Array.new(n_cells, 0), Array.new(n_cells, 0)]] # (decided, acc)
      emit.call(frontier[0][1], frontier[0][0], 0)
      work = 0
      (1..max_rules).each do |depth|
        states = {}
        frontier.each do |st_decided, st_acc|
          tests.each do |t|
            [0, 1].each do |label|
              work += 1
              raise ArgumentError, "pca-intent: the decision-list class (≤ #{max_rules} rules) for #{verb} exceeds the enumeration cap" unless work <= cap

              decided = Array.new(n_cells, 0)
              acc = Array.new(n_cells, 0)
              fresh = false
              n_cells.times do |c|
                if st_decided[c] != 0
                  decided[c] = 1
                  acc[c] = st_acc[c]
                elsif t[c] != 0
                  decided[c] = 1
                  acc[c] = label
                  fresh = true
                end
              end
              next unless fresh

              key = [key_of(decided), key_of(acc)]
              next if states.key?(key)

              states[key] = [decided, acc]
            end
          end
        end
        frontier = states.values
        frontier.each { |decided, acc| emit.call(acc, decided, depth) }
      end
      [sets, complexity]
    end

    class VerbModel
      attr_accessor :vs, :n_choice, :contains, :n_cells_d, :nh, :choice, :member, :complexity, :prior, :w, :err, :n_cells, :cell_idx,
                    :mass, :harm, :p, :veto, :seen, :dirty
    end

    def self.build_verb_model(vs, opts, harm)
      dn = vs['dims'].length
      n_cells_d = vs['dims'].map { |d| d['kind'] == 'num' ? IntentOmega.num_cells(d).length : d['values'].length }
      contains, n_choice = build_box_tables(vs, n_cells_d)
      n_cells = IntentOmega.verb_cell_count(vs)
      cell_idx = Array.new(n_cells * dn, 0)
      mass = Array.new(n_cells, 0.0)
      hm = Array.new(n_cells, 0.0)
      n_cells.times do |c|
        idx = IntentOmega.decode_cell(vs, c)
        dn.times { |d| cell_idx[(c * dn) + d] = idx[d] }
        s = IntentOmega.cell_stats(vs, idx, harm)
        mass[c] = s['mass']
        hm[c] = s['harm']
      end
      hc = opt(opts, 'hypothesisClass', { 'kind' => 'box' })
      choice = [0]
      member = nil
      complexity = nil
      if hc['kind'] == 'box'
        boxes = n_choice.reduce(1) { |a, c| a * c }
        raise ArgumentError, "pca-intent: |Θ_#{vs['verb']}| = #{boxes + 1} exceeds maxHypotheses #{opts['maxHypotheses']}; coarsen the cuts" unless boxes + 1 <= opts['maxHypotheses']

        nh = boxes + 1
        choice = Array.new([1, boxes * dn].max, 0)
        cur = Array.new(dn, 0)
        boxes.times do |h|
          dn.times { |d| choice[(h * dn) + d] = cur[d] }
          (dn - 1).downto(0) do |d|
            cur[d] += 1
            break if cur[d] < n_choice[d]

            cur[d] = 0
          end
        end
      else
        if hc['kind'] == 'union'
          k = hc['k']
          raise ArgumentError, 'pca-intent: union class needs an integer k ≥ 1' unless integer?(k) && k >= 1

          boxes_m = box_masks(vs, n_cells, cell_idx, n_cells_d, contains, n_choice, opts['maxEnumeration'])
          sets, cx = enumerate_unions(boxes_m, k.to_i, opts['maxEnumeration'], vs['verb'])
        else
          mr = hc['maxRules']
          raise ArgumentError, 'pca-intent: decision-list class needs an integer maxRules ≥ 1' unless integer?(mr) && mr >= 1

          cond = opt(hc, 'conditions', 'box')
          raise ArgumentError, "pca-intent: decision-list conditions must be 'box' or 'atomic'" if cond != 'box' && cond != 'atomic'

          tests = if cond == 'atomic'
                    atomic_tests(vs, n_cells, cell_idx, n_cells_d)
                  else
                    dedup_masks(box_masks(vs, n_cells, cell_idx, n_cells_d, contains, n_choice, opts['maxEnumeration']))
                  end
          sets, cx = enumerate_decision_lists(tests, n_cells, mr.to_i, opts['maxEnumeration'], vs['verb'])
        end
        raise ArgumentError, "pca-intent: |Θ_#{vs['verb']}| = #{sets.length + 1} exceeds maxHypotheses #{opts['maxHypotheses']}; coarsen the cuts" unless sets.length + 1 <= opts['maxHypotheses']

        nh = sets.length + 1
        member = [Array.new(n_cells, 0)] + sets
        complexity = [0] + cx
      end
      m = VerbModel.new
      m.vs = vs
      m.n_choice = n_choice
      m.contains = contains
      m.n_cells_d = n_cells_d
      m.nh = nh
      m.choice = choice
      m.member = member
      m.complexity = complexity
      m.prior = Array.new(nh, 0.0)
      m.w = Array.new(nh, 0.0)
      m.err = Array.new(nh, 0)
      m.n_cells = n_cells
      m.cell_idx = cell_idx
      m.mass = mass
      m.harm = hm
      m.p = Array.new(n_cells, 0.0)
      m.veto = Array.new(n_cells, 0)
      m.seen = Array.new(n_cells, 0)
      m.dirty = true
      m
    end

    # Does hypothesis h (>= 1) contain flat cell c?
    def self.holds?(m, h, c)
      return m.member[h][c] == 1 unless m.member.nil?

      dn = m.vs['dims'].length
      base = (h - 1) * dn
      dn.times do |d|
        n = m.n_cells_d[d]
        return false if m.contains[d][(m.choice[base + d] * n) + m.cell_idx[(c * dn) + d]].zero?
      end
      true
    end

    # The non-empty hypotheses of Theta_v for a class as cell masks over the verb's flat cells, each with its Occam complexity.
    def self.hypothesis_cell_sets(vs, hypothesis_class = nil, caps = nil)
      o = { 'maxHypotheses' => 400_000, 'maxEnumeration' => 4_000_000 }
      (caps || {}).each { |k, v| o[k] = v unless v.nil? }
      o['hypothesisClass'] = hypothesis_class.nil? ? { 'kind' => 'box' } : hypothesis_class
      m = build_verb_model(vs, o, IntentOmega::DEFAULT_HARM)
      sets = []
      complexity = []
      (1...m.nh).each do |h|
        sets << Array.new(m.n_cells) { |c| holds?(m, h, c) ? 1 : 0 }
        complexity << (m.complexity.nil? ? 1 : m.complexity[h])
      end
      { 'sets' => sets, 'complexity' => complexity }
    end

    def self.apply_monotone_prior(m, mono)
      off = opt(mono, 'offMass', 0)
      raise ArgumentError, 'pca-intent: monotone.offMass must be in [0, 1]' unless off >= 0 && off <= 1

      dn = m.vs['dims'].length
      paths = mono['paths']
      ks = m.vs['dims'].each_index.select { |k| d = m.vs['dims'][k]; d['kind'] == 'num' && paths.include?(d['path']) }
      return if ks.empty?

      stride = ks.map { |k| (m.n_cells_d[(k + 1)..] || []).reduce(1) { |a, x| a * x } }
      (1...m.nh).each do |h|
        is_mono = true
        c = 0
        while c < m.n_cells && is_mono
          if holds?(m, h, c)
            ks.each_index do |i|
              if m.cell_idx[(c * dn) + ks[i]].positive? && !holds?(m, h, c - stride[i])
                is_mono = false
                break
              end
            end
          end
          c += 1
        end
        m.w[h] = m.w[h] * off unless is_mono
      end
    end

    def self.holds_all?(m, h, cells)
      return false if h.zero?

      cells.all? { |c| holds?(m, h, c) }
    end

    def self.normalize(w)
      s = 0.0
      w.each { |x| s += x }
      return unless s > 0

      w.each_index { |i| w[i] = w[i] / s }
    end

    def self.mix_prior(m, mix)
      beta = mix['beta']
      raise ArgumentError, 'pca-intent: priorMix.beta must be in [0, 1)' unless beta >= 0 && beta < 1

      pop = Array.new(m.nh, 0.0)
      z = 0.0
      m.nh.times do |h|
        contains = ->(c) { h != 0 && integer?(c) && c >= 0 && c < m.n_cells && holds?(m, h, c.to_i) }
        x = mix['weight'].call(m.vs, contains)
        raise ArgumentError, 'pca-intent: priorMix.weight must be finite and >= 0' unless IntentOmega.finite_number?(x) && x >= 0

        x = x.to_f
        pop[h] = x
        z += x
      end
      return unless z > 0

      m.nh.times { |h| m.w[h] = ((1 - beta) * m.w[h]) + ((beta * pop[h]) / z) }
    end

    def self.flat(m, idx)
      f = 0
      idx.each_index { |d| f = (f * m.n_cells_d[d]) + idx[d] }
      f
    end

    # The exact posterior over Theta = prod_v Theta_v; options are the reference's plain-data LearnerOptions.
    class IntentLearner
      attr_reader :omega, :eta, :eta_pos, :eta_neg, :tau, :strategy, :harm, :hypothesis_class, :agnostic_slack, :observations
      attr_accessor :map_params

      def initialize(omega, opts = nil)
        h = AtlasPca::IntentLearner
        opts = {} if opts.nil?
        @omega = omega
        @opts = opts
        @eta = h.opt(opts, 'eta', 0)
        raise ArgumentError, 'pca-intent: eta must be in [0, 0.5)' unless @eta >= 0 && @eta < 0.5

        @eta_pos = h.opt(opts, 'etaPos', @eta)
        @eta_neg = h.opt(opts, 'etaNeg', @eta)
        raise ArgumentError, 'pca-intent: etaPos and etaNeg must be in [0, 0.5)' unless @eta_pos >= 0 && @eta_pos < 0.5 && @eta_neg >= 0 && @eta_neg < 0.5

        @noisy = @eta_pos != 0 || @eta_neg != 0
        @tau = h.opt(opts, 'tau', @noisy ? 0.95 : 1)
        @strategy = h.opt(opts, 'strategy', 'disagreement')
        @harm = h.opt(opts, 'harm', IntentOmega::DEFAULT_HARM)
        @hypothesis_class = h.opt(opts, 'hypothesisClass', { 'kind' => 'box' })
        @agnostic_slack = opts['agnosticSlack']
        unless @agnostic_slack.nil?
          raise ArgumentError, 'pca-intent: agnosticSlack must be a non-negative integer' unless h.integer?(@agnostic_slack) && @agnostic_slack >= 0
          raise ArgumentError, 'pca-intent: agnostic selection replaces the noise model; use eta = 0' if @noisy
        end
        full = { 'maxHypotheses' => 400_000, 'maxEnumeration' => 4_000_000 }
        opts.each { |k, v| full[k] = v unless v.nil? }
        @observations = []
        @models = omega['verbs'].map { |vs| h.build_verb_model(vs, full, @harm) }
        init_prior
      end

      def init_prior
        h = AtlasPca::IntentLearner
        opts = @opts
        anchors = (h.truthy(opts['anchor']) ? [opts['anchor']] : []) + (opts['anchors'] || [])
        anchors = anchors.select { |a| a['lambda'] > 0 }
        admitters = anchors.map { |a| [IntentPolicy.admitter(a['policy']), a['lambda']] }
        decay = @hypothesis_class['kind'] == 'box' ? 1 : h.opt(@hypothesis_class, 'decay', 0.25)
        raise ArgumentError, 'pca-intent: decay must be in (0, 1]' unless decay > 0 && decay <= 1

        @models.each do |m|
          nmo = opts['nullMass']
          nm = nmo.respond_to?(:call) ? nmo.call(m.vs) : (nmo.nil? ? 0.2 : nmo)
          raise ArgumentError, 'pca-intent: nullMass must be in [0, 1]' unless nm >= 0 && nm <= 1

          m.w[0] = nm
          z = 0.0
          (1...m.nh).each do |i|
            raw = m.complexity.nil? ? 1 : AtlasPca::DetMath.det_pow_int(decay.to_f, m.complexity[i] - 1)
            m.w[i] = raw
            z += raw
          end
          (1...m.nh).each { |i| m.w[i] = ((1 - nm) * m.w[i]) / h.or1(z) }
          h.apply_monotone_prior(m, opts['monotone']) if h.truthy(opts['monotone'])
          unless admitters.empty?
            tot = 0.0
            m.n_cells.times { |c| tot += m.mass[c] }
            accs = admitters.map do |adm, _lam|
              Array.new(m.n_cells) { |c| adm.admits(m.vs, IntentOmega.cell_rep(m.vs, IntentOmega.decode_cell(m.vs, c))) ? 1 : 0 }
            end
            m.nh.times do |i|
              mix = 0.0
              accs.each_with_index do |acc, j|
                dist = 0.0
                m.n_cells.times do |c|
                  in_h = i.zero? ? 0 : (h.holds?(m, i, c) ? 1 : 0)
                  dist += m.mass[c] if in_h != acc[c]
                end
                mix += AtlasPca::DetMath.det_exp((-admitters[j][1] * dist) / h.or1(tot))
              end
              m.w[i] = m.w[i] * (mix / admitters.length)
            end
          end
          h.normalize(m.w)
          h.mix_prior(m, opts['priorMix']) if h.truthy(opts['priorMix'])
          m.prior = m.w.dup
          m.dirty = true
        end
      end
      private :init_prior

      def in_grant?(m, c) = m.veto[c].zero? && m.p[c] >= @tau - 1e-12
      private :in_grant?

      def model_for(verb) = @models.find { |m| m.vs['verb'] == verb }
      private :model_for

      def refresh(m)
        h = AtlasPca::IntentLearner
        return unless m.dirty

        m.p = Array.new(m.n_cells, 0.0)
        # certainty is decided combinatorially (p = 1 iff every live hypothesis holds the cell), not by the float sum
        any_in = Array.new(m.n_cells, 0)
        any_out = Array.new(m.n_cells, 0)
        live = false
        m.nh.times do |i|
          w = m.w[i]
          next if w == 0

          live = true
          m.n_cells.times do |c|
            if i.positive? && h.holds?(m, i, c)
              m.p[c] = m.p[c] + w
              any_in[c] = 1
            else
              any_out[c] = 1
            end
          end
        end
        m.n_cells.times do |c|
          m.p[c] = if !live || any_in[c].zero? then 0
                   elsif any_out[c].zero? then 1
                   else IntentOmega.js_min(1, IntentOmega.js_max(0, m.p[c]))
                   end
        end
        m.dirty = false
      end
      private :refresh

      # p_n(omega) for a concrete outcome (0 if outside Omega: the conservative reading).
      def acceptance(o)
        m = model_for(o['verb'])
        return 0 if m.nil?

        idx = IntentOmega.cell_of(m.vs, o)
        return 0 if idx.nil?

        refresh(m)
        m.p[AtlasPca::IntentLearner.flat(m, idx)]
      end

      def admits_outcome(o)
        m = model_for(o['verb'])
        return false if m.nil?

        idx = IntentOmega.cell_of(m.vs, o)
        return false if idx.nil?

        refresh(m)
        in_grant?(m, AtlasPca::IntentLearner.flat(m, idx))
      end

      def vetoed?(o)
        m = model_for(o['verb'])
        idx = m.nil? ? nil : IntentOmega.cell_of(m.vs, o)
        !m.nil? && !idx.nil? && m.veto[AtlasPca::IntentLearner.flat(m, idx)] == 1
      end
      alias is_vetoed vetoed?

      def vetoed_cells
        out = []
        @models.each { |m| m.n_cells.times { |c| out << "#{m.vs['verb']}|#{c}" if m.veto[c] != 0 } }
        out
      end

      # Record the principal's answer y to "should omega be allowed?" (or, with a region, "should EVERY outcome in it be allowed?")
      # and update the posterior. nil when the outcome is outside Omega or the region covers no cell.
      def observe(o, y, source = 'elicitation', region = nil)
        h = AtlasPca::IntentLearner
        m = model_for(o['verb'])
        return nil if m.nil?

        idx = IntentOmega.cell_of(m.vs, o)
        return nil if idx.nil?

        cells = region.nil? ? [h.flat(m, idx)] : IntentRegion.region_cells(m.vs, region, y == 1 ? 'inner' : 'outer')
        return nil if cells.empty?

        refresh(m)
        obs = { 'verb' => o['verb'], 'values' => (o['values'] || {}).dup, 'cell' => idx, 'y' => y, 'source' => source }
        obs['region'] = region unless region.nil?
        # a "no" about a region every live hypothesis contains contradicts the whole class (the CONFLICT of spec 4.2c)
        region_p = 0.0
        (1...m.nh).each { |i| region_p += m.w[i] if m.w[i] > 0 && h.holds_all?(m, i, cells) }
        contradicts_all = y.zero? ? region_p >= 1 - 1e-12 : region_p <= 1e-12
        cells.each { |c| m.veto[c] = 1 } if source == 'runtime' && y.zero?
        cells.each { |c| m.seen[c] = 1 }
        if !@agnostic_slack.nil?
          m.nh.times { |i| m.err[i] += 1 if (h.holds_all?(m, i, cells) ? 1 : 0) != y }
          min_err = Float::INFINITY
          m.nh.times { |i| min_err = IntentOmega.js_min(min_err, m.err[i]) if m.prior[i] > 0 }
          m.nh.times { |i| m.w[i] = m.err[i] <= min_err + @agnostic_slack ? m.prior[i] : 0.0 }
          h.normalize(m.w)
          if contradicts_all
            obs['conflict'] = true
            cells.each { |c| m.veto[c] = 1 } if y.zero?
          end
        else
          prev = @eta_pos.zero? || @eta_neg.zero? ? m.w.dup : nil
          eta_pos = @eta_pos
          eta_neg = @eta_neg
          lik = lambda do |in_h|
            if in_h == 1
              y == 1 ? 1 - eta_neg : eta_neg
            else
              y == 1 ? eta_pos : 1 - eta_pos
            end
          end
          total = 0.0
          m.nh.times do |i|
            m.w[i] = m.w[i] * lik.call(h.holds_all?(m, i, cells) ? 1 : 0)
            total += m.w[i]
          end
          if total == 0 && !prev.nil?
            m.w = prev # every hypothesis contradicted: the truth is outside Theta; keep VS, flag the conflict
            obs['conflict'] = true
            cells.each { |c| m.veto[c] = 1 } if y.zero?
          else
            h.normalize(m.w)
          end
        end
        m.dirty = true
        @observations << obs
        obs
      end

      def cells
        out = []
        @models.each do |m|
          refresh(m)
          m.n_cells.times do |c|
            out << { 'verb' => m.vs['verb'], 'cell' => IntentOmega.decode_cell(m.vs, c), 'p' => m.p[c], 'mass' => m.mass[c], 'harm' => m.harm[c],
                     'inGrant' => in_grant?(m, c), 'vetoed' => m.veto[c] == 1 }
          end
        end
        out
      end

      def metrics
        r = b = u = hh = vs_bits = dis = mean_harm = 0.0
        @models.each do |m|
          refresh(m)
          m.n_cells.times do |c|
            p = m.p[c]
            mu = m.mass[c]
            mean_harm += mu * m.harm[c]
            if in_grant?(m, c)
              r += mu * (1 - p) * m.harm[c]
            else
              b += mu * p
            end
            u += mu * IntentOmega.js_min(p, 1 - p)
            dis += mu if p > 1e-12 && p < 1 - 1e-12
          end
          alive = 0
          m.nh.times do |i|
            w = m.w[i]
            if w > 0
              alive += 1
              hh -= w * AtlasPca::DetMath.det_log2(w)
            end
          end
          vs_bits += AtlasPca::DetMath.det_log2([1, alive].max)
        end
        { 'residualRisk' => r, 'burden' => b, 'uncertainty' => u, 'entropyBits' => hh,
          'log2VersionSpace' => @noisy ? nil : vs_bits,
          'disagreementMass' => dis, 'meanHarm' => mean_harm,
          'questions' => @observations.count { |o| o['source'] == 'elicitation' },
          'conflicts' => @observations.count { |o| AtlasPca::IntentLearner.truthy(o['conflict']) } }
      end

      # The next question: argmax expected information (x mu*h for the risk strategy). nil when nothing is uncertain.
      def next_question
        h = AtlasPca::IntentLearner
        best = nil
        h_pos = h.bin_ent(@eta_pos)
        h_neg = h.bin_ent(@eta_neg)
        @models.each do |m|
          refresh(m)
          m.n_cells.times do |c|
            next if m.veto[c] != 0

            p = m.p[c]
            next if p <= 1e-9 || p >= 1 - 1e-9

            pe = (p * (1 - @eta_neg)) + ((1 - p) * @eta_pos)
            score = h.bin_ent(pe) - (@eta_pos == @eta_neg ? h_pos : (p * h_neg) + ((1 - p) * h_pos))
            score *= m.mass[c] * m.harm[c] if @strategy == 'risk'
            next if score <= 1e-15

            if best.nil? || score > best['score'] + 1e-12
              cell = IntentOmega.decode_cell(m.vs, c)
              best = { 'verb' => m.vs['verb'], 'cell' => cell, 'outcome' => IntentOmega.cell_rep(m.vs, cell), 'p' => p, 'score' => score }
            end
          end
        end
        best
      end

      # Grant cells INFERRED but never directly observed, most consequential first.
      def unconfirmed_grant_cells
        out = []
        @models.each do |m|
          refresh(m)
          m.n_cells.times do |c|
            next if m.seen[c] != 0 || !in_grant?(m, c)

            out << { 'verb' => m.vs['verb'], 'cell' => IntentOmega.decode_cell(m.vs, c), 'weight' => m.mass[c] * m.harm[c] }
          end
        end
        out.each_with_index.sort_by { |x, i| [-x['weight'], i] }.map(&:first) # stable, like the reference's sort
      end

      # The conservative grant G_tau as a real PCA policy: allow only cells with p_n >= tau.
      def synthesize
        predicates = []
        worst = -1
        @models.each do |m|
          refresh(m)
          allowed = Array.new(m.n_cells, 0)
          any = false
          m.n_cells.times do |c|
            if in_grant?(m, c)
              allowed[c] = 1
              any = true
            end
          end
          next unless any

          rv = m.vs['reversibility']
          worst = [worst, ORDER.index(rv) || -1].max
          predicates.concat(AtlasPca::IntentLearner.boxes_to_predicates(m.vs, allowed))
        end
        caveats = worst >= 0 ? [{ 'type' => 'reversibility_max', 'class' => ORDER[worst] }] : []
        { 'predicates' => predicates, 'caveats' => caveats }
      end

      # Replay observations onto a fresh learner (used to verify an Intent Map).
      def self.replay(omega, opts, observations)
        l = new(omega, opts)
        observations.each { |o| l.observe({ 'verb' => o['verb'], 'values' => o['values'] }, o['y'], o['source'], o['region']) }
        l
      end
    end

    # ---- synthesis: allowed cells -> union of boxes -> predicates ----------------------------------------------------

    def self.encode(vs, idx)
      f = 0
      vs['dims'].each_with_index { |d, i| f = (f * IntentOmega.cell_count(d)) + idx[i] }
      f
    end

    def self.box_cells(ranges)
      vals = ranges.map { |r| r.is_a?(Array) ? (r[0]..r[1]).to_a : r.keys.sort }
      return [[]] if vals.empty?

      vals[0].product(*vals[1..])
    end

    def self.cat_condition(d, set)
      return nil if set.length == d['values'].length

      exacts = d['values'].select { |v| v['kind'] == 'exact' }.map { |v| v['value'] }
      prefixes = d['values'].select { |v| v['kind'] == 'prefix' }.map { |v| v['value'] }
      alts = []
      allowed_exacts = set.keys.select { |i| d['values'][i]['kind'] == 'exact' }.map { |i| d['values'][i]['value'] } # set insertion order
      if allowed_exacts.length == 1
        alts << { 'field' => d['path'], 'op' => 'eq', 'value' => allowed_exacts[0] }
      elsif allowed_exacts.length > 1
        alts << { 'field' => d['path'], 'op' => 'in', 'value' => allowed_exacts }
      end
      set.keys.sort.each do |i|
        v = d['values'][i]
        next if v['kind'] == 'exact'

        parts = []
        if v['kind'] == 'prefix'
          parts << { 'field' => d['path'], 'op' => 'prefix', 'value' => v['value'] }
          under = exacts.select { |e| e.start_with?(v['value']) }
          parts << { 'field' => d['path'], 'op' => 'nin', 'value' => under } unless under.empty?
          prefixes.each do |q|
            parts << { 'not' => { 'field' => d['path'], 'op' => 'prefix', 'value' => q } } if q != v['value'] && q.start_with?(v['value'])
          end
        else
          parts << { 'field' => d['path'], 'op' => 'nin', 'value' => exacts } unless exacts.empty?
          prefixes.each { |q| parts << { 'not' => { 'field' => d['path'], 'op' => 'prefix', 'value' => q } } }
        end
        if parts.length == 1
          alts << parts[0]
        elsif parts.length > 1
          alts << { 'all_of' => parts }
        end
      end
      return nil if alts.empty?

      alts.length == 1 ? alts[0] : { 'any_of' => alts }
    end

    def self.box_to_predicate(vs, ranges)
      where = []
      vs['dims'].each_with_index do |d, k|
        r = ranges[k]
        if d['kind'] == 'num' && r.is_a?(Array)
          cells = IntentOmega.num_cells(d)
          where << { 'field' => d['path'], 'op' => 'gte', 'value' => cells[r[0]]['lo'] }
          where << { 'field' => d['path'], 'op' => 'lte', 'value' => cells[r[1]]['hi'] }
        elsif d['kind'] == 'cat' && r.is_a?(Hash)
          c = cat_condition(d, r)
          where << c if c
        end
      end
      out = { 'verb' => vs['verb'], 'resource' => '*' }
      out['where'] = where unless where.empty?
      out
    end

    # Cover the allowed cell set exactly with greedily-grown maximal boxes; one predicate per box.
    def self.boxes_to_predicates(vs, allowed)
      covered = Array.new(allowed.length, 0)
      out = []
      all = ->(ranges) { box_cells(ranges).all? { |idx| allowed[encode(vs, idx)] == 1 } }
      allowed.length.times do |c|
        next if allowed[c].zero? || covered[c] != 0

        idx = IntentOmega.decode_cell(vs, c)
        ranges = vs['dims'].each_with_index.map { |d, k| d['kind'] == 'num' ? [idx[k], idx[k]] : { idx[k] => true } }
        vs['dims'].each_with_index do |d, k|
          if d['kind'] == 'num'
            n = IntentOmega.num_cells(d).length
            r = ranges[k]
            while r[1] + 1 < n
              r[1] += 1
              unless all.call(ranges)
                r[1] -= 1
                break
              end
            end
            while r[0].positive?
              r[0] -= 1
              unless all.call(ranges)
                r[0] += 1
                break
              end
            end
          else
            s = ranges[k]
            d['values'].each_index do |v|
              next if s.key?(v)

              s[v] = true
              s.delete(v) unless all.call(ranges)
            end
          end
        end
        box_cells(ranges).each { |bi| covered[encode(vs, bi)] = 1 }
        out << box_to_predicate(vs, ranges)
      end
      out
    end

    # ---- the stop rule ---------------------------------------------------------------------------------------------

    def self.seed_question(learner, s)
      vs = learner.omega['verbs'].find { |v| v['verb'] == s['verb'] }
      return nil if vs.nil? || s['cell'].length != vs['dims'].length

      outcome = IntentOmega.cell_rep(vs, s['cell'])
      p = learner.acceptance(outcome)
      return nil if p <= 1e-9 || p >= 1 - 1e-9 || learner.vetoed?(outcome)

      { 'verb' => s['verb'], 'cell' => s['cell'].dup, 'outcome' => outcome, 'p' => p, 'score' => 0 }
    end

    # Ask questions until the stop rule of spec 2.5 holds.
    def self.elicit(learner, answer, o)
      asked = []
      seed_questions = 0
      (o['seed'] || []).each do |s|
        break unless asked.length < o['maxQuestions']

        m = learner.metrics
        break if m['residualRisk'] <= o['epsRisk'] && m['burden'] <= o['epsBurden']

        q = seed_question(learner, s)
        next if q.nil?

        learner.observe(q['outcome'], answer.call(q), 'elicitation')
        asked << q
        seed_questions += 1
      end
      stop = nil
      while stop.nil?
        m = learner.metrics
        if m['residualRisk'] <= o['epsRisk'] && m['burden'] <= o['epsBurden']
          stop = 'converged'
        elsif !(asked.length < o['maxQuestions'])
          stop = 'budget'
        else
          q = learner.next_question
          if q.nil?
            stop = 'no-disagreement'
          else
            learner.observe(q['outcome'], answer.call(q), 'elicitation')
            asked << q
          end
        end
      end
      audit = audit_round(learner, answer, o, asked)
      stop = 'budget' if audit['exhausted']
      { 'stop' => stop, 'questions' => asked.length, 'auditQuestions' => audit['asked'], 'seedQuestions' => seed_questions, 'asked' => asked }
    end

    # The audit round on its own (spec 4.2c): the questions asked, and whether the budget ran out. Appends to `asked`.
    def self.audit_round(learner, answer, o, asked)
      n = 0
      return { 'asked' => 0, 'exhausted' => false } unless truthy(o['audit'])

      loop do
        pending = learner.unconfirmed_grant_cells
        mass = 0.0
        pending.each { |x| mass += x['weight'] }
        return { 'asked' => n, 'exhausted' => false } if pending.empty? || mass <= o['epsRisk']
        return { 'asked' => n, 'exhausted' => true } unless asked.length < o['maxQuestions']

        top = pending[0]
        vs = learner.omega['verbs'].find { |v| v['verb'] == top['verb'] }
        outcome = IntentOmega.cell_rep(vs, top['cell'])
        q = { 'verb' => top['verb'], 'cell' => top['cell'], 'outcome' => outcome, 'p' => learner.acceptance(IntentOmega.cell_rep(vs, top['cell'])), 'score' => top['weight'] }
        learner.observe(q['outcome'], answer.call(q), 'elicitation')
        asked << q
        n += 1
      end
    end
  end
end
