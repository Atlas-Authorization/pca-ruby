# frozen_string_literal: true

require_relative 'goal_js'
require_relative 'goal_card'
require_relative 'goal_codec'
require_relative 'goal_interpret'
require_relative 'goal_normalize'

module AtlasPca
  # Round-trip checks (the TypeScript reference is @atlasauth/pca-goal `roundtrip`): the lossless card tape, semantic widening
  # mutations and the explainer + comparator detector, measured by mutation and tighten-only (it can only escalate). An explainer
  # is an object with `explain(prose_lines) -> String`; a comparator an object with `equivalent(goal_text, explanation) ->
  # {equivalent, reason?}`.
  module GoalRoundtrip
    J = GoalJs
    MUTATION_KINDS = %w[widen_cap widen_where drop_prohibit drop_bound swap_resource add_grant].freeze
    MINOR = /([0-9]+) ([A-Z]{3}) minor units/

    module_function

    # decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape.
    def card_round_trips?(g) = GoalNormalize.stable(GoalCodec.decode_goal(GoalCodec.encode_goal(g))) == GoalNormalize.stable(g)

    # The explainer sees ONLY the compiled card lines, never the goal text or the model's reasoning.
    def round_trip(goal, goal_text, explainer, comparator)
      e = explainer.explain(GoalCard.render_card(goal)['lines'])
      J.truthy(comparator.equivalent(goal_text, e)['equivalent']) ? 'ok' : 'escalate'
    rescue StandardError
      'escalate'
    end

    class Det
      def id = 'card-prose'
      def explain(p) = p.join("\n")
    end

    def deterministic_explainer = Det.new

    class Lexical
      attr_reader :o

      def initialize(o) = @o = o
      def id = 'lexical'
      def family = 'rule'

      def equivalent(text, explanation)
        a = GoalInterpret.extract_candidates(text, @o)
        b = GoalInterpret.extract_candidates(explanation, @o)
        # Number(): huge values are doubles
        b_amounts = explanation.scan(MINOR).map { |digits, ccy| { 'ccy' => ccy, 'minor' => Float(digits) } }
        ids = ->(x) { x.uniq.sort_by { |s| GoalJs.u16key(s) }.join(',') }
        return { 'equivalent' => false, 'reason' => 'ids differ' } if ids.call(a['ids']) != ids.call(b['ids'])

        # every amount stated in the policy must be one the principal wrote (the principal may write extras only as decoys)
        wrote = a['amounts'].map { |m| "#{m['ccy']}#{GoalJs.js_str(m['minor'])}" }
        b_amounts.each do |m|
          return { 'equivalent' => false, 'reason' => "amount #{m['ccy']} #{GoalJs.js_str(m['minor'])} not stated by the principal" } unless wrote.include?("#{m['ccy']}#{GoalJs.js_str(m['minor'])}")
        end
        return { 'equivalent' => false, 'reason' => 'no amount in the policy' } if a['amounts'].length.positive? && b_amounts.empty?

        { 'equivalent' => true }
      end
    end

    # Offline reference comparator: the card lines judged lexically (ids, amounts).
    def lexical_comparator(o) = Lexical.new(o)

    def scale(x, f)
      k = J.jget(J.jget(x, 'u'), 'k')
      %w[money count].include?(k) ? x.merge('n' => J.jget(x, 'n') * f) : x
    end

    def map_lits(c, f)
      case J.jget(c, 'k')
      when 'cmp'
        r = J.jget(c, 'r')
        hit = J.jget(r, 'k') == 'lit' && J.jget(J.jget(r, 'v'), 'k') == 'q' && %w[lte lt].include?(J.jget(c, 'op'))
        c.merge('r' => hit ? { 'k' => 'lit', 'v' => { 'k' => 'q', 'q' => f.call(J.jget(J.jget(r, 'v'), 'q')) } } : r)
      when 'and', 'or' then c.merge('a' => map_lits(J.jget(c, 'a'), f), 'b' => map_lits(J.jget(c, 'b'), f))
      else c
      end
    end

    # Semantic mutations that WIDEN the policy (or leave it equal); nil when the goal has nothing to mutate.
    def mutate_goal(g, kind, ontology)
      x = Marshal.load(Marshal.dump(g))
      ten = ->(z) { scale(z, 10) }
      case kind
      when 'widen_cap'
        return nil if x['bounds'].empty?

        x['bounds'][0]['cap'] = scale(x['bounds'][0]['cap'], 10)
        x
      when 'widen_where'
        gr = x['grants'].find { |y| Js.json(map_lits(y['cond'], ten)) != Js.json(y['cond']) }
        return nil if gr.nil?

        gr['cond'] = map_lits(gr['cond'], ten)
        x
      when 'drop_prohibit'
        return nil if x['prohibits'].empty?

        x['prohibits'].pop
        x
      when 'drop_bound'
        return nil if x['bounds'].empty?

        x['bounds'].pop
        x
      when 'swap_resource'
        gr = x['grants'].find { |y| y['res']['k'] == 'exact' }
        return nil if gr.nil?

        gr['res'] = { 'k' => 'exact', 'id' => "#{gr['res']['id']}9" }
        x
      when 'add_grant'
        have = x['grants'].map { |y| y['verb'] }
        v = J.req_list(J.jget(ontology, 'verbs')).find do |y|
          J.jget(y, 'effect') != 'read' && !have.include?(J.jget(y, 'id')) && x['prohibits'].none? { |p| p['target']['k'] == 'verb' && p['target']['verb'] == J.jget(y, 'id') }
        end
        return nil if v.nil?

        x['grants'] << { 'gid' => 'injected', 'verb' => J.jget(v, 'id'), 'res' => { 'k' => 'any', 'reason' => 'injected' }, 'cond' => { 'k' => 'true' } }
        x['wildcardAck'] << 'injected'
        GoalNormalize.canonicalize_goal(x)
      end
    end

    # Fraction of semantic widenings the explainer + comparator pair flags (they can only escalate; this is a measured detector).
    def measure_detection(cases, ontology, explainer, comparator)
      MUTATION_KINDS.map do |kind|
        applied = 0
        detected = 0
        cases.each do |c|
          m = mutate_goal(c['goal'], kind, ontology)
          next unless m

          applied += 1
          detected += 1 if round_trip(m, c['text'], explainer, comparator) == 'escalate'
        end
        { 'kind' => kind, 'applied' => applied, 'detected' => detected, 'rate' => applied.positive? ? detected.to_f / applied : 0 }
      end
    end
  end
end
