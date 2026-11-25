# frozen_string_literal: true

# Replays the TS-reference oracle of goal interpret (test-data/ref-goal-interpret.json.gz): candidate extraction, slot filling, the
# rule, form and model interpreters, prompts and keys, grounding, vendor completions over an injected fetch, the typed refund form
# and the lexical comparator. A shipped ontology travels by name and is resolved from the shipped data.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_ontologies'
require_relative '../lib/atlas_pca/goal_interpret'
require_relative '../lib/atlas_pca/goal_roundtrip'
require 'minitest/autorun'

class TestRefGoalInterpret < Minitest::Test
  OS = AtlasPca::GoalOntologies
  I = AtlasPca::GoalInterpret
  RT = AtlasPca::GoalRoundtrip
  BY_FN = Ref.load('goal-interpret')
  Resp = Struct.new(:ok, :status, :json)

  def self.ont(x) = x.is_a?(String) && OS.shipped_ontology(x) ? OS.shipped_ontology(x) : x
  def self.src(s) = s.nil? ? {} : { 'sources' => s }

  FILL = lambda do |on, tid, text, lc|
    o = TestRefGoalInterpret.ont(on)
    I.fill_template(o['templates'].find { |z| z['id'] == tid }, o, text, lc)
  end

  LLM = lambda do |on, text, src, mode, inc, lc|
    complete = lambda do |_p|
      raise 'boom' if mode['throw']

      mode['raw']
    end
    I.llm_interpreter('m', 'f', complete, AtlasPca::GoalJs.truthy(inc), lc)
     .interpret({ 'principal' => 'p1', 'text' => text, 'ontology' => TestRefGoalInterpret.ont(on) }.merge(TestRefGoalInterpret.src(src)))
  end

  GROUNDED = lambda do |on, tid, sn, v, txt|
    o = TestRefGoalInterpret.ont(on)
    t = o['templates'].find { |z| z['id'] == tid }
    s = t['slots'].find { |z| z['name'] == sn }
    I.grounded(s, v, I.extract_candidates(txt, o), o)
  end

  VENDOR = lambda do |_x, kind, cfg, fake, system, user|
    req = {}
    if fake.nil? || fake.empty? # the generator's plain success stub
      fake = { 'ok' => true, 'status' => 200, 'body' => kind == 'anthropic' ? { 'content' => [{ 'type' => 'text', 'text' => 'x' }] } : { 'choices' => [{ 'message' => { 'content' => 'x' } }] } }
    end
    fetch = lambda do |url, init|
      req.merge!({ 'url' => url, 'method' => init['method'], 'headers' => init['headers'], 'body' => init['body'] })
      raise fake['throwMsg'] if AtlasPca::GoalJs.truthy(fake['throwMsg'])

      Resp.new(fake['ok'], fake['status'], fake['body'])
    end
    c = if kind == 'anthropic'
          I.anthropic_completion(cfg['apiKey'], cfg['model'], fetch, cfg.key?('maxTokens') ? cfg['maxTokens'] : 1024)
        else
          I.openai_completion(cfg['apiKey'], cfg['model'], fetch, cfg['baseUrl'])
        end
    begin
      { 'text' => c.call({ 'system' => system, 'user' => user }), 'req' => req }
    rescue StandardError => e
      { 'error' => e.message, 'req' => req }
    end
  end

  FNS = {
    'slotStemsOf' => I.method(:slot_stems), 'sourceDigest' => I.method(:source_digest),
    'extractCandidates' => ->(on, text, lc) { I.extract_candidates(text, TestRefGoalInterpret.ont(on), lc) }, 'fillTemplateById' => FILL,
    'interpretRule' => lambda { |on, text, src, lc|
      I.rule_interpreter('rule', lc).interpret({ 'principal' => 'p1', 'text' => text, 'ontology' => TestRefGoalInterpret.ont(on) }.merge(TestRefGoalInterpret.src(src)))
    },
    'buildPromptOf' => lambda { |on, text, src, inc|
      I.build_prompt({ 'principal' => 'p', 'text' => text, 'ontology' => TestRefGoalInterpret.ont(on) }.merge(TestRefGoalInterpret.src(src)), inc)
    },
    'interpretForm' => lambda { |on, f, text|
      req = { 'principal' => 'p1', 'text' => text, 'ontology' => TestRefGoalInterpret.ont(on) }
      req['form'] = f unless f.nil?
      req['sources'] = ['s'] if text == 'form text'
      I.form_interpreter.interpret(req)
    },
    'interpretLlm' => LLM, 'promptKeyOf' => ->(_x, m, s, u) { I.prompt_key(m, { 'system' => s, 'user' => u }) },
    'replayLookup' => ->(_x, m, rec, s, u) { I.replay_completion(m, rec).call({ 'system' => s, 'user' => u }) },
    'parseTemplateJSON' => I.method(:parse_template_json), 'groundedOf' => GROUNDED, 'vendor' => VENDOR,
    'interpretRefundForm' => ->(f, ont, pr) { I.interpret_form(f, ont, pr.nil? ? 'pr1' : pr) },
    'lexicalCompare' => ->(on, tx, ex) { RT.lexical_comparator(TestRefGoalInterpret.ont(on)).equivalent(tx, ex) }
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 4859, BY_FN.values.sum(&:length), 'goal-interpret'
  end

end
