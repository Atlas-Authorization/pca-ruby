# frozen_string_literal: true

require 'openssl'
require_relative 'goal_js'
require_relative 'goal_examples'

module AtlasPca
  # Runtime drift monitoring, tighten-only (the TypeScript reference is @atlasauth/pca-goal `drift`). A monitor compares the action
  # stream to the goal's expected profile (verbs, resources, magnitude, rate, novelty). Anomalies convert Allow to Escalate; the
  # strike counter is a ratchet (never decreases); at `lockdown` strikes every Allow becomes Escalate. `apply_drift` never relaxes
  # a decision.
  module GoalDrift
    J = GoalJs
    DEFAULT_DRIFT = { 'windowMs' => 60_000, 'maxPerWindow' => 20, 'maxNovel' => 3, 'magnitudeFactor' => 3, 'warmup' => 5, 'lockdown' => 5 }.freeze

    module_function

    def expected_verbs(g) = J.req_list(J.jget(g, 'grants')).map { |x| J.jget(x, 'verb') }.uniq

    def res_ids(s)
      case J.jget(s, 'k')
      when 'exact' then [J.jget(s, 'id')]
      when 'oneof' then J.req_list(J.jget(s, 'ids')).dup
      when 'all_of' then J.req_list(J.jget(s, 'parts')).flat_map { |p| res_ids(p) }
      else []
      end
    end

    def known_resources(g) = J.req_list(J.jget(g, 'grants')).flat_map { |x| res_ids(J.jget(x, 'res')) }.uniq

    # Node's lenient Buffer.from(s, 'hex'): decoding stops at the first invalid pair.
    def node_hex(s)
      raise TypeError, 'the first argument must be a string' unless s.is_a?(String)

      out = []
      (0...(s.length - 1)).step(2) do |i|
        pair = s[i, 2]
        break unless pair.match?(/\A[0-9a-fA-F]{2}\z/)

        out << pair.to_i(16)
      end
      out.pack('C*')
    end

    class Monitor
      attr_accessor :st
      attr_reader :o

      def initialize(goal, opts = nil)
        @goal = goal
        @o = DEFAULT_DRIFT.merge(opts || {})
        @st = { 'strikes' => 0, 'times' => [], 'novel' => [], 'seen' => {} }
      end

      def observe(a, t)
        j = GoalJs
        reasons = []
        verb = j.jget(a, 'verb')
        reasons << "verb #{j.js_str(verb)} outside the goal profile" unless GoalDrift.expected_verbs(@goal).any? { |v| verb == v }
        known = GoalDrift.known_resources(@goal)
        res = j.jget(a, 'res')
        @st['novel'] << res if known.length.positive? && !known.include?(res) && !j.includes(@st['novel'], res)
        reasons << 'novel resources beyond the allowance' if @st['novel'].length > @o['maxNovel']
        @st['times'] = @st['times'].select { |x| x > t - @o['windowMs'] } + [t]
        reasons << 'rate above the profile' if @st['times'].length > @o['maxPerWindow']
        params = j.jget(a, 'params')
        params.each_pair.to_a.each do |p, l|
          next if j.jget(l, 'k') != 'q'

          hist = @st['seen'][p] || []
          v = j.jget(j.jget(l, 'q'), 'n')
          if hist.length >= @o['warmup']
            mean = hist.empty? ? Float::NAN : hist.sum.to_f / hist.length # warmup 0: 0 / 0 is NaN, never above
            reasons << "#{p} magnitude #{j.js_str(@o['magnitudeFactor'])}x above the running mean" if mean > 0 && v > mean * @o['magnitudeFactor']
          end
          @st['seen'][p] = (hist + [v]).last(50)
        end
        @st['strikes'] += 1 if reasons.length.positive? # ratchet: only ever increases
        { 'anomalous' => reasons.length.positive?, 'strikes' => @st['strikes'], 'lockdown' => @st['strikes'] >= @o['lockdown'], 'reasons' => reasons }
      end

      def state = @st

      def mac(state, key) = OpenSSL::HMAC.digest('SHA256', key.to_s.b, Js.json(state))

      # Sealed state: durable and not agent-writable (the monitor key is held outside the agent).
      def seal(key) = { 'state' => @st, 'mac' => mac(@st, key).unpack1('H*') }

      # Restore; a state that fails its MAC locks down (fail closed).
      def self.restore(goal, sealed, key, opts = nil)
        m = new(goal, opts)
        want = m.mac(GoalJs.jget(sealed, 'state'), key)
        got = GoalDrift.node_hex(GoalJs.jget(sealed, 'mac'))
        m.st = if got.bytesize == want.bytesize && OpenSSL.fixed_length_secure_compare(got, want)
                 GoalJs.jget(sealed, 'state')
               else
                 { 'strikes' => m.o['lockdown'], 'times' => [], 'novel' => [], 'seen' => {} }
               end
        m
      end
    end

    # Tighten-only: Allow becomes Escalate on an anomaly or lockdown; nothing else changes.
    def apply_drift(d, s) = d == 'allow' && (J.truthy(J.jget(s, 'anomalous')) || J.truthy(J.jget(s, 'lockdown'))) ? 'escalate' : d

    # Decide, observe, tighten.
    def guarded_decide(goal, ont, mon, c, t)
      base = GoalExamples.decide_case(goal, ont, c)['decision']
      signal = mon.observe(J.jget(c, 'act'), t)
      { 'decision' => apply_drift(base, signal), 'signal' => signal }
    end
  end
end
