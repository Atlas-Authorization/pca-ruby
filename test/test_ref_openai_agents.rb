# frozen_string_literal: true

# Replay of the TypeScript reference's OpenAI Agents adapter logic (proof sources, guard pipeline, per-tool option merging, guardrails,
# step-up). Tools, verifiers and hooks are rebuilt from the same declarative descriptors the reference's oracle recorded.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/openai_agents'
require 'minitest/autorun'

class TestRefOpenaiAgents < Minitest::Test
  OA = AtlasPca::OpenaiAgents
  BY_FN = Ref.load('openai-agents')

  # the language-specific tails of the reference's messages are cut on both sides
  def self.norm(m)
    m.to_s.sub(/proof could not be decoded: [\s\S]*\z/, 'proof could not be decoded: ').sub(/(full policy mode is missing)[\s\S]*\z/, '\1')
  end

  def self.clean(v)
    case v
    when String then norm(v)
    when Hash then v.transform_values { |x| clean(x) }
    when Array then v.map { |x| clean(x) }
    else v
    end
  end

  CMP = ->(got, out, _c) { Ref.canon(clean(got)) == Ref.canon(clean(out)) }

  def self.stub(d, calls)
    lambda do |p|
      v = p.is_a?(Hash) ? (p['action'] || {})['verb'] : nil
      calls << ['verify', d['stub'], v]
      raise d['throws'] if d['throws']

      out = { 'allow' => d['allow'], 'checks' => { 'sig' => d['allow'] ? 'pass' : 'fail' } }
      out['reason'] = d['reason'] if d.key?('reason')
      out
    end
  end

  class Rec
    def initialize(calls) = (@calls = calls)
    def tool(name, out) = @calls << ['recorded', name, out]
  end

  def self.build_opts(d, calls)
    out = %w[mode verb audience name].select { |k| d.key?(k) }.to_h { |k| [k, d[k]] }
    out['verify'] = stub(d['verify'], calls) if TRUTHY.call(d['verify'])
    out['authorize'] = d['authorize'] unless d['authorize'].nil?
    if TRUTHY.call(d['require'])
      r = d['require']
      out['require'] = r.key?('headers') ? OA.proof_from_input_headers(*r['headers']) : ->(*_a) { r['const'] }
    end
    out['on_deny'] = ->(e, i) { calls << ['onDeny', e.kind, i] } if TRUTHY.call(d['onDeny'])
    out['on_verified'] = ->(r, p, i) { calls << ['onVerified', AtlasPca::Adapters.get(r, 'allow'), (p['action'] || {})['verb'], i] } if TRUTHY.call(d['onVerified'])
    out['recorder'] = Rec.new(calls) if TRUTHY.call(d['recorder'])
    out
  end

  TRUTHY = ->(v) { AtlasPca::Js.truthy?(v) && !(v.respond_to?(:empty?) && v.empty?) }

  class Tool
    attr_reader :name, :description

    def initialize(td, calls)
      @name = td['name']
      @description = 'd'
      (td['extra'] || {}).each { |k, v| define_singleton_method(k) { v } }
      return if td['noExecute']

      define_singleton_method(:execute) do |input, _rc = nil|
        calls << ['exec', td['name'], input]
        raise td['throws'] if td['throws']

        { 'echo' => input, 'tool' => td['name'] }
      end
    end
  end

  def self.kind_of_error(e)
    case e
    when OA::PcaToolDenied then 'PcaToolDenied'
    when TypeError then 'TypeError'
    else 'Error'
    end
  end

  def self.err_of(e, calls)
    out = { 'err' => kind_of_error(e), 'message' => norm(e.message), 'calls' => calls }
    if e.is_a?(OA::PcaToolDenied)
      out['kind'] = e.kind
      out['verb'] = e.verb
      out['checks'] = e.checks unless e.checks.nil?
    end
    out
  end

  def self.outcome(t, input, rc, no_rc, calls)
    out = t.execute(input, no_rc ? nil : rc)
    { 'ok' => true, 'out' => out, 'calls' => calls, 'name' => t.name, 'extra' => t.respond_to?(:extra) ? t.extra : nil, 'hasNeedsApproval' => t.respond_to?(:needs_approval) }
  rescue StandardError => e
    err_of(e, calls)
  end

  def self.build_error(e, calls) = { 'err' => e.is_a?(TypeError) ? 'TypeError' : 'Error', 'message' => norm(e.message), 'calls' => calls, 'build' => true }

  def self.with_tool(a)
    calls = []
    begin
      t = OA.with_pca_tool(Tool.new(a['tool'], calls), build_opts(a['options'], calls))
    rescue StandardError => e
      return build_error(e, calls)
    end
    outcome(t, a['input'], a['runContext'], AtlasPca::Js.truthy?(a["noRunContext"]), calls)
  end

  def self.tools_of(a)
    calls = []
    tools = a['tools'].to_h { |k, v| [k, Tool.new(v, calls)] }
    o = a['options']
    opts = build_opts(o, calls)
    opts['per'] = o['per'].to_h { |k, v| [k, build_opts(v, calls)] } if o.key?('per')
    opts['only'] = o['only'] unless o['only'].nil?
    begin
      g = OA.pca_tools(tools, opts)
    rescue StandardError => e
      return build_error(e, calls)
    end
    g.to_h do |k, t|
      r = outcome(t, a['input'], a['runContext'], false, calls)
      r['same'] = t.equal?(tools[k])
      [k, r]
    end
  end

  CAMEL = { 'tripwire_triggered' => 'tripwireTriggered', 'output_info' => 'outputInfo' }.freeze

  def self.guardrail(a)
    calls = []
    kw = build_opts(a['options'], calls)
    kw.delete('mode')
    g = (a['kind'] == 'input' ? OA.pca_input_guardrail(kw) : OA.pca_tool_guard(kw))
    begin
      r = g.execute(a['args'])
    rescue StandardError => e
      return { 'err' => 'Error', 'message' => norm(e.message), 'calls' => calls }
    end
    { 'name' => g.name, 'result' => r.to_h { |k, v| [CAMEL[k], v] }, 'calls' => calls }
  end

  def self.intent_null(calls) = ->(t, i) { calls << ['intent', t, i]; nil }

  def self.review(a)
    calls = []
    r = OA.review_tool_call(nil, a['tool'], a['input'], { 'intent' => intent_null(calls) })
    { 'r' => r, 'calls' => calls }
  end

  class NeedsTool
    attr_accessor :name

    def description = 'd'
    def execute(*_a) = 1
  end

  def self.needs(a)
    calls = []
    kw = { 'intent' => intent_null(calls) }
    kw['tool_name'] = a['toolName'] unless a['toolName'].nil?
    return { 'value' => OA.pca_needs_approval(nil, kw).call({}, a['input'], 'c1'), 'calls' => calls } if a['via'] == 'direct'

    t = NeedsTool.new
    t.name = a['tool']['name']
    t = OA.with_approval(t, nil, kw)
    { 'value' => t.needs_approval({}, a['input'], 'c1'), 'calls' => calls, 'name' => t.name, 'extra' => nil, 'hasExecute' => t.respond_to?(:execute) }
  end

  MAP = {
    'proofFromRunContext' => ->(a) { OA.proof_from_run_context(a['input'], a['runContext']) },
    'guardrailProofFromContext' => ->(a) { OA.guardrail_proof_from_context(a['args']) },
    'provenanceFromRunContext' => ->(a) { OA.provenance_from_run_context(nil, a['runContext']) },
    'proofFromInputHeaders' => ->(a) { OA.proof_from_input_headers(a.fetch('field', 'headers'), a.fetch('header', 'PCA-Action')).call(a['input']) },
    'pendingStepUps' => ->(r) { OA.pending_step_ups(r) },
    'withPcaTool' => ->(a) { with_tool(a) },
    'pcaTools' => ->(a) { tools_of(a) },
    'guardrail' => ->(a) { guardrail(a) },
    'reviewToolCall' => ->(a) { review(a) },
    'needsApproval' => ->(a) { needs(a) }
  }.freeze

  def test_every_function_is_covered
    assert_equal [], BY_FN.keys.sort - MAP.keys
    assert_equal [], MAP.keys - BY_FN.keys
    assert_operator BY_FN.values.sum(&:length), :>=, 150
  end

  MAP.each_key do |fn|
    define_method("test_replay_#{fn}") do
      cmp = %w[withPcaTool pcaTools guardrail].include?(fn) ? CMP : nil
      Ref.run(self, BY_FN[fn], MAP[fn], compare: cmp)
    end
  end

  # withPCATools (the attach side, re-exported by the reference): listed tools are wrapped, unlisted ones pass through untouched
  def test_with_pca_tools_wraps_listed_tools_and_passes_the_rest_through
    p = AtlasPca::KeyPair.new("\x01".b * 32)
    h = AtlasPca::KeyPair.new("\x02".b * 32)
    env = { 'predicates' => [{ 'verb' => 'pay', 'resource' => 'invoice:*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    agent = AtlasPca::Agent.new(h, AtlasPca.mint_grant(p, h.public, env, 'g', salt: 's')['grant'], 'rs')
    seen = []
    pay = { 'name' => 'pay', 'on_invoke_tool' => ->(_ctx, raw) { "ok:#{raw}" } }
    other = { 'name' => 'other', 'on_invoke_tool' => ->(_ctx, _raw) { 'x' } }
    spec = { 'verb' => 'pay', 'resource' => ->(a) { "invoice:#{a['id']}" }, 'fail_fast' => false, 'on_proof' => ->(pca, args) { seen << [pca, args] } }
    out = OA.with_pca_tools(agent, { 'pay' => pay, 'other' => other }, { 'pay' => spec })
    assert_same other, out['other']
    assert_equal 'ok:{"id":"7"}', out['pay']['on_invoke_tool'].call({}, '{"id":"7"}')
    assert_equal [1, { 'id' => '7' }], [seen.length, seen[0][1]]
    assert_raises(ArgumentError) { OA.with_pca_tools(agent, { 'pay' => pay }, { 'pay' => spec.merge('aud' => 'elsewhere') }) }
  end
end
