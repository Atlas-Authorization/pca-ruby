# frozen_string_literal: true

# Replays the TS-reference oracle of the MCP adapter (test-data/ref-mcp.json.gz): the client step-up planner and its pca_need
# challenge parameter, the conformance matrix, tool-to-schema drafting and the closed-world check of a tool call; plus the
# agent-facing pieces the corpus does not reach (tool_call_of, pca_fetch, guard_tool_result).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/mcp'
require 'minitest/autorun'

class TestRefMcp < Minitest::Test
  M = AtlasPca::Mcp
  BY_FN = Ref.load('mcp')

  # JS JSON of the normalized values: a lone surrogate (WTF-8) in a string must not break the comparison
  EQ = ->(got, out, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(got))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(out))) }

  MAP = {
    'parseChallenges' => ->(h) { M.parse_challenges(h) },
    'checkAuthorizationResponseIss' => ->(a) { M.check_authorization_response_iss(a) },
    'pcaNeedProblem' => ->(h) { M.pca_need_problem(h) },
    'planStepUp' => ->(status, www, state) { M.plan_step_up(status, www, state) },
    'matrix' => -> { { 'revisions' => M::MCP_CLIENT_REVISIONS.dup, 'rows' => M::MCP_AUTH_CLIENT_ROWS } },
    'guardToolResult' => ->(pca, result) { M.guard_tool_result(pca, result) },
    'draftActionSchemaFromMcp' => ->(tools, site) { M.draft_action_schema_from_mcp(tools, site) },
    'applySchemaDecisions' => ->(draft, d) { M.apply_schema_decisions(draft, d) },
    'verbOfTool' => ->(schema, tool) { M.verb_of_tool(schema, tool) },
    'conformToolCall' => ->(schema, tool, args) { M.conform_tool_call(schema, tool, args) }
  }.freeze

  def test_every_function_in_the_corpus_is_replayed
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: EQ) } }

  def test_tool_call_of
    body = '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":{"a":1}}}'
    assert_equal({ 'name' => 't', 'arguments' => { 'a' => 1 } }, M.tool_call_of(body))
    assert_equal({ 'name' => 't', 'arguments' => {} }, M.tool_call_of('{"method":"tools/call","params":{"name":"t","arguments":[1]}}'))
    [nil, 5, '', '{', '[]', '{"method":"tools/list"}', '{"method":"tools/call","params":{}}', '{"method":"tools/call","params":{"name":5}}',
     '{"method":"tools/call","params":{"name":"t","arguments":NaN}}'].each { |bad| assert_nil M.tool_call_of(bad) }
  end

  def test_pca_fetch_attaches_a_proof_and_records_the_result
    action = Struct.new(:headers, :pcactn).new({ 'PCA-Action' => 'e30' }, {})
    agent = Class.new do
      attr_reader :seen

      define_method(:act) { |verb, resource, params| (@seen = [verb, resource, params]) && action }
    end.new
    sent = []
    f = M.pca_fetch(agent, ->(n, _a) { n == 't' ? { 'verb' => "v.#{n}", 'resource' => 'r' } : nil }, ->(_url, init) { sent << init && 'res' })
    assert_equal 'res', f.call('u', { 'body' => '{"method":"tools/call","params":{"name":"t","arguments":{"a":1}}}', 'headers' => { 'x' => 'y' } })
    assert_equal 'e30', sent[0]['headers']['PCA-Action']
    assert_equal 'y', sent[0]['headers']['x']
    assert_equal ['v.t', 'r', { 'a' => 1 }], agent.seen
    f.call('u', { 'body' => '{"method":"tools/call","params":{"name":"other"}}' })
    assert_nil((sent[1]['headers'] || {})['PCA-Action'])
    f.call('u', { 'body' => 'not json' })
    assert_equal 3, sent.length
  end

  def test_guard_tool_result_refuses_a_null_proof_and_result
    assert_raises(TypeError) { M.guard_tool_result(nil, { 'content' => [] }) }
    assert_raises(TypeError) { M.guard_tool_result({ 'encoded' => 'x' }, nil) }
  end

  def test_with_pca_fail_fast_refuses_an_out_of_grant_resource_the_chain_check_alone_admits
    key = AtlasPca::KeyPair.generate
    env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    agent = AtlasPca::Agent.new(key, AtlasPca.mint_grant(AtlasPca::KeyPair.generate, key.public, env, 'refund')['grant'], 'rs-test')
    ran = []
    tool = M.with_pca(agent, 'refund', ->(a) { a['res'] }, ->(_a, _e) { ran << 1 && { 'ok' => true } })
    assert_equal({ 'ok' => true }, tool.call({ 'res' => 'orders/1' }))
    refused = tool.call({ 'res' => 'users/1' })
    assert_equal true, refused['isError']
    assert_equal 1, ran.length
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 840, BY_FN.values.sum(&:length), 'mcp'
  end

end
