# frozen_string_literal: true

require_relative 'goal_js'
require_relative 'goal_examples'
require_relative 'goal_fmt'
require_relative 'goal_nversion'

module AtlasPca
  # Questions over the symmetric difference of competing readings and active disambiguation by version-space halving (the TypeScript
  # reference is @atlasauth/pca-goal `disambiguate`). A reading is {id, family, deterministic, goal, notes}; the question options are
  # {ont, riskOf?, massOf?, budget?}. The reference's asynchronous `ask` is a plain callable returning 'allow' or 'deny'.
  module GoalDisambiguate
    J = GoalJs
    DEFAULT_RISK = { 'read' => 1, 'reversible' => 2, 'external_send' => 8, 'irreversible' => 10 }.freeze

    module_function

    def h2(p) = p <= 0 || p >= 1 ? 0 : -((p * Math.log2(p)) + ((1 - p) * Math.log2(1 - p)))

    def allows_witness(g, ont, w)
      hist = GoalExamples.replay(g, ont, w['prior'], w['rels'])
      GoalExamples.decide_case(g, ont, { 'act' => w['act'], 'hist' => hist, 'rels' => w['rels'] })['decision'] == 'allow'
    end

    def allow_set?(r, w, ont) = allows_witness(r['goal'], ont, w)

    # Candidate witness actions: decision-cell representatives of the joint space plus every reading's cap sequences.
    def witnesses(readings, ont)
      goals = readings.map { |r| r['goal'] }
      out = GoalExamples.cells(GoalExamples.build_space(goals))['cases'].map { |c| { 'act' => c['act'], 'prior' => [], 'rels' => c['rels'] } }
      readings.each do |r|
        GoalExamples.boundary_examples(r['goal'], { 'ont' => ont, 'extra' => goals })['examples'].each do |e|
          out << { 'act' => e['act'], 'prior' => e['hist']['adms'].map { |a| a['act'] }, 'rels' => e['rels'] } if e['kind'] == 'cap_sequence'
        end
      end
      out
    end

    # Questions ranked by H2(vote) x risk x mass (best first).
    def questions(readings, opts)
      ont = opts['ont']
      k = readings.length
      cls = ont['verbs'].to_h { |v| [v['verb'], v['cls']] }
      risk_of = opts['riskOf'] || ->(a) { DEFAULT_RISK.fetch(cls.fetch(a['verb'], ''), 10) }
      mass_of = opts['massOf']
      out = []
      seen = {}
      witnesses(readings, ont).each do |w|
        yes = readings.select { |r| allow_set?(r, w, ont) }.map { |r| r['id'] }
        next if yes.empty? || yes.length == k

        qid = Js.json([w['act'], w['prior'].length])
        next if seen.key?(qid)

        seen[qid] = true
        n = w['prior'].length
        out << { 'id' => qid, 'act' => w['act'], 'prior' => w['prior'], 'rels' => w['rels'], 'allow' => yes,
                 'notAllow' => readings.reject { |r| yes.include?(r['id']) }.map { |r| r['id'] },
                 'text' => "Should this be allowed: #{GoalFmt.fmt_act(w['act'])}#{n.positive? ? " (after #{n} earlier identical action(s))" : ''}?",
                 'score' => h2(yes.length.to_f / k) * risk_of.call(w['act']) * (mass_of ? mass_of.call(w['act']) : 1) }
      end
      J.stable_sort(out) do |a, b|
        d = b['score'] - a['score']
        if d != 0
          d.negative? ? -1 : 1
        else
          J.u16key(a['id']) < J.u16key(b['id']) ? -1 : 1
        end
      end
    end

    # Fraction of witness cells on which the readings do not all agree on Allow.
    def disagreement_mass(readings, ont)
      w = witnesses(readings, ont)
      return 0 if w.empty?

      split = w.count do |x|
        n = readings.count { |r| allow_set?(r, x, ont) }
        n.positive? && n < readings.length
      end
      split.to_f / w.length
    end

    # Active disambiguation by version-space halving over the finite class of readings: every question strictly shrinks the class, so
    # at most k-1 questions. Realizability (assumption): the principal's intent is one of the readings.
    def disambiguate(readings, ask, opts)
      ont = opts['ont']
      budget = opts['budget']
      budget = readings.length if budget.nil?
      active = readings.dup
      asked = []
      while active.length > 1 && asked.length < budget
        qs = questions(active, opts)
        break if qs.empty? # the survivors agree on every witness cell

        q = qs[0]
        asked << q
        ans = ask.call(q)
        active = active.select { |r| allow_set?(r, q, ont) == (ans == 'allow') }
      end
      mass = disagreement_mass(active, ont)
      g = GoalNVersion.meet(active.map { |r| r['goal'] })
      if mass > 0
        hole = { 'hid' => 'budget', 'q' => 'Question budget exhausted with disagreement left.', 'domain' => [], 'affects' => [], 'global' => true }
        holes = J.stable_sort_by(g['holes'] + [hole]) { |h| J.u16key(h['hid']) }
        return { 'status' => 'budget_exhausted', 'goal' => g.merge('holes' => holes), 'asked' => asked, 'residualMass' => mass, 'remaining' => active.map { |r| r['id'] } }
      end
      { 'status' => 'resolved', 'goal' => g, 'asked' => asked, 'residualMass' => 0, 'remaining' => active.map { |r| r['id'] } }
    end
  end
end
