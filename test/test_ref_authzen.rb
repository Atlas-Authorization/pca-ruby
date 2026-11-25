# frozen_string_literal: true

# Replays the TS-reference oracle of the AuthZEN PDP, handler and search APIs (test-data/ref-authzen.json.gz). The PDP and
# provider tables mirror the ones the generator names.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefAuthzen < Minitest::Test
  A = AtlasPca::Authzen
  CASES = Ref.load('authzen')
  NOW = 1_000_000
  CLOCK = -> { NOW }
  BOOM = ->(*_) { raise 'boom' }

  CFG = {
    'none' => { 'resolve' => ->(_r) {}, 'now' => CLOCK },
    'throws' => { 'resolve' => BOOM, 'now' => CLOCK },
    'noauth' => { 'resolve' => ->(_r) { { 'grant' => {}, 'policy' => {} } }, 'now' => CLOCK },
    'auth' => { 'resolve' => ->(_r) { { 'grant' => {}, 'policy' => {} } }, 'authorizer' => ->(_i) { { 'allow' => true } }, 'now' => CLOCK },
    'max2' => { 'resolve' => ->(_r) {}, 'max_evaluations' => 2, 'now' => CLOCK },
    'toolmap' => { 'resolve' => ->(_r) {}, 'tool_capability' => ->(n) { "cap.#{n}" }, 'now' => CLOCK },
    'toolthrow' => { 'resolve' => ->(_r) {}, 'tool_capability' => ->(_n) { raise 'bad tool' }, 'now' => CLOCK }
  }.freeze

  def self.u(i) = { 'type' => 'user', 'id' => i }
  ECHO = ->(r) { { 'results' => [], 'context' => { 'saw' => r } } }

  PROV = {
    'none' => {},
    'full' => {
      'search_subject' => lambda { |_r|
        { 'results' => [u('a'), u('b'), { 'type' => 'group', 'id' => 'g' }, u('a'), { 'id' => 'a', 'type' => 'user' }],
          'page' => { 'next_token' => '', 'total' => 3, 'properties' => { 'k' => 1 } }, 'context' => { 'c' => 1 } }
      },
      'search_resource' => lambda { |_r|
        { 'results' => [{ 'type' => 'doc', 'id' => '1' }, { 'type' => 'doc', 'id' => '2' }, { 'type' => 'user', 'id' => 'x' }], 'page' => { 'next_token' => 'n1' } }
      },
      'search_action' => ->(_r) { { 'results' => [{ 'name' => 'read' }, { 'name' => 'write' }, { 'name' => 'read' }, { 'name' => 'read', 'properties' => { 'p' => 1 } }] } }
    },
    'nopage' => { 'search_subject' => ->(_r) { { 'results' => [u('a'), u('b')] } }, 'search_resource' => ->(_r) { { 'results' => [] } },
                  'search_action' => ->(_r) { { 'results' => [] } } },
    'emptyprops' => { 'search_subject' => ->(_r) { { 'results' => [u('a')], 'page' => { 'next_token' => 'z', 'properties' => {} }, 'context' => {} } } },
    'bad' => { 'search_subject' => ->(_r) { { 'results' => [nil] } }, 'search_resource' => ->(_r) { { 'results' => [5] } },
               'search_action' => ->(_r) { { 'results' => [nil, 5] } } },
    'notarray' => { 'search_subject' => ->(_r) { { 'results' => 'x' } }, 'search_resource' => ->(_r) { {} }, 'search_action' => ->(_r) { { 'results' => nil } } },
    'throws' => { 'search_subject' => BOOM, 'search_resource' => BOOM, 'search_action' => BOOM },
    'echo' => { 'search_subject' => ECHO, 'search_resource' => ECHO, 'search_action' => ECHO },
    'partial' => { 'search_resource' => ->(_r) { { 'results' => [] } } }
  }.freeze

  def self.pdp(c) = A.authzen_pdp(CFG[c])

  # the verifier's own check map / reason text is language-specific: the verify-stage cases compare decision + stage
  CMP = lambda do |g, o, c|
    if c['name'].end_with?('/pc17', '/pc18') && o.is_a?(Hash) && o.dig('context', 'reason_admin', 'stage') == 'verify'
      next g['decision'] == o['decision'] && g.dig('context', 'reason_admin', 'stage') == 'verify'
    end

    AtlasPca::Js.json(Ref.sort_keys(Ref.norm(g))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(o))) # lone-surrogate safe
  end

  FNS = {
    'isAccessEvaluationRequest' => ->(x) { A.is_access_evaluation_request(x) },
    'isAccessEvaluationsRequest' => ->(x) { A.is_access_evaluations_request(x) },
    'isCoazToolAuthorizationRequest' => ->(x) { A.is_coaz_tool_authorization_request(x) },
    'isAuthzenSubject' => ->(x) { A.is_authzen_subject(x) },
    'isAuthzenAction' => ->(x) { A.is_authzen_action(x) },
    'isAuthzenResource' => ->(x) { A.is_authzen_resource(x) },
    'isSubjectSearch' => ->(x) { A.is_subject_search(x) },
    'isResourceSearch' => ->(x) { A.is_resource_search(x) },
    'isActionSearch' => ->(x) { A.is_action_search(x) },
    'defaultToAction' => ->(x) { A.default_to_action(x) },
    'approvalOf' => ->(x) { A.approval_of(x) },
    'isApprovalRequired' => ->(x) { A.is_approval_required(x) },
    'pdp.evaluate' => ->(c, r) { pdp(c).evaluate(r) },
    'pdp.evaluations' => ->(c, r) { pdp(c).evaluations(r) },
    'pdp.evaluateTool' => ->(c, r) { pdp(c).evaluate_tool(r) },
    'authzenHandler' => ->(c, r) { A.authzen_handler(pdp(c)).call(r) },
    'authzenSearchHandler' => ->(p, r) { A.authzen_search_handler(PROV[p]).call(r) },
    'searchMetadata' => ->(base, p) { A.search_metadata(base, PROV[p]) }
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, call| define_method("test_#{fn.tr('.', '_')}") { Ref.run(self, CASES[fn], call, compare: CMP) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 3095, CASES.values.sum(&:length), 'authzen'
  end

end
