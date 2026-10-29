# frozen_string_literal: true
# Exact-outcome kill tests for decision.rb, escalation.rb and the rules 20-21 / escalation wiring of authorize.rb and
# intent_v2.rb: every table of the shared decision-vectors.json (units, tighten, decision_of, lattice, escalation answers incl.
# every PQ suite this runtime has, escalation folds) and the 32 signed model-rules cases through authorize. Bears on
# decision.rb, escalation.rb, authorize.rb, intent_v2.rb (model_rules), atlas_pca.rb (verify_pcactn reasons).
require_relative '../support/prov_harness'

module MutationKill
  module Decision
    module_function
    CONF = File.expand_path('../../conformance', __dir__)
    def doc = (@doc ||= AtlasPca.parse_json(File.read(File.join(CONF, 'decision-vectors.json'), encoding: 'UTF-8'), loose: true)['primitives'])
    def model = (@model ||= AtlasPca.parse_json(File.read(File.join(CONF, 'model-rules-vectors.json'), encoding: 'UTF-8'), loose: true))

    def all?(table) = doc[table].all? { |e| yield(e) }

    # `input_text` is raw JSON text each runner parses itself: key order is part of the input
    def input_of(e) = e.key?('input_text') ? AtlasPca.parse_json(e['input_text'], loose: true) : e['input']

    def answer_ok?(e)
      i = input_of(e)
      r = AtlasPca.verify_escalation_answer(i['answer'], i['principals'], i['bind'], i['now'])
      need = e['requires_suite']
      return !r[:ok] && r[:reason].include?('unsupported_suite') if need && !AtlasPca.supported_suites.include?(need)
      return r[:ok] == e['expect']['ok'] && r[:principal] == e['expect']['principal'] && r[:decision] == e['expect']['decision'] if r[:ok]

      !e['expect']['ok'] && r[:reason].include?(e['expect']['reason_contains'])
    end

    def model_case_ok?(c)
      ctx_env = c['context']
      r = AtlasPca.authorize(c['pcactn'], operation: c['operation'], audience: model['audience'], resolve_grant: ->(_r) { c['grant'] },
                                          state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false }, now: model['now'],
                                          plan: 'single-step', context: ctx_env.nil? ? nil : ->(_p) { ctx_env },
                                          intent_v2: c.key?('intent_v2') ? c['intent_v2'] : nil, provenance: ProvHarness::OPTION)
      e = c['expect']
      got = { 'allow' => r.allow, 'decision' => r.decision, 'status' => r.status, 'failed' => r.failed_checks, 'reasons' => r.reasons }
      want = e.reject { |k, _| %w[units tighten degraded].include?(k) }
      %w[units tighten].each { |k| (want[k] = e[k]; got[k] = r.checks[k]) if e.key?(k) }
      (want['degraded'] = e['degraded']; got['degraded'] = r.degraded) if e.key?('degraded')
      got == want && (e.key?('tighten') || !r.checks.key?('tighten')) && (e.key?('units') || !r.checks.key?('units'))
    end
  end

  t('decision: units vectors (ok and exact reason)') do
    Decision.all?('intent_units') { |e| r = AtlasPca.decide_units(Decision.input_of(e)); r['ok'] == e['expect']['ok'] && (e['expect']['ok'] || r['reason'] == e['expect']['reason']) }
  end
  t('decision: tighten vectors (outcome, legacy, offending, reason)') do
    Decision.all?('intent_tighten') { |e| AtlasPca.decide_tighten(Decision.input_of(e)) == e['expect'] }
  end
  t('decision: decision_of vectors') { Decision.all?('decision_of') { |e| AtlasPca.decision_of(e['input']) == e['expect']['decision'] } }
  t('decision: lattice vectors') do
    Decision.all?('decision_lattice') do |e|
      i = e['input']
      n = e['name']
      got = if n.start_with?('meet-') then AtlasPca.meet(i['a'], i['b'])
            elsif n.start_with?('pep-') then AtlasPca.pep_decision(i['decision'], i['answered'])
            else AtlasPca.tighten(i['decision'], i['signal'])
            end
      got == e['expect']['decision']
    end
  end
  t('decision: escalation fold vectors') do
    Decision.all?('escalation_fold') { |e| i = e['input']; AtlasPca.fold_escalation(i['core_reasons'], i['v2'], i['checks']) == e['expect'] }
  end
  t('escalation: answer vectors (every suite, exact refusal reasons)') { Decision.all?('escalation_answer') { |e| Decision.answer_ok?(e) } }
  t('escalation: request truncates reasons by UTF-16 units and keeps 16') do
    r = AtlasPca.build_escalation_request(aud: 'a', grant: { 'id' => 'g' }, pcactn: { 'action' => { 'verb' => 'v', 'resource' => 'r' } },
                                          last_counter: nil, reasons: Array.new(20) { |i| "r#{i}#{'x' * 600}" }, now: 10)
    r['reasons'].length == 16 && r['reasons'].all? { |x| x.length == 512 } && r['expires_at'] == 3_600_010 && r['verb'] == 'v'
  end
  t('escalation: UTF-16 slice splits a pair into a lone surrogate, units are counted') do
    s = ('x' * 511) + "\u{1F600}"
    cut = AtlasPca.utf16_slice(s, 512)
    cut.b.bytesize == 511 + 3 && AtlasPca.utf16_len("\u{1F600}") == 2 && AtlasPca.utf16_slice('abc', 512) == 'abc'
  end
  t('rules 20-21 end to end through authorize (model-rules-vectors.json)') { Decision.model['cases'].all? { |c| Decision.model_case_ok?(c) } }
  t('decision: safe int and meet fail closed') do
    AtlasPca.meet('allow', 'maybe') == 'deny' && AtlasPca.meet_all(%w[allow escalate allow]) == 'escalate' && AtlasPca.signal_ceiling('x') == 'deny' &&
      !AtlasPca.decision_safe_int?(2**53) && AtlasPca.decision_safe_int?(2**53 - 1) && !AtlasPca.decision_safe_int?(1.5)
  end
end
