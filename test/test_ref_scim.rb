# frozen_string_literal: true

# Replays the TS-reference oracle of the SCIM 2.0 /Agents server, the passport mapping and the push adapters
# (test-data/ref-scim.json.gz). Handler cases are sessions over a named options table, push cases a named fake fetch; both
# tables mirror the generator's.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefScim < Minitest::Test
  S = AtlasPca::Scim
  CASES = Ref.load('scim')
  T0 = 1_700_000_000_000
  BASE = 'https://scim.acme.com/scim/v2'
  YES = ->(_r) { true }

  OPTS = {
    'open' => -> { { 'base_url' => BASE, 'now' => -> { T0 }, 'authenticate' => YES } },
    'slash' => -> { { 'base_url' => "#{BASE}///", 'now' => -> { T0 }, 'authenticate' => YES } },
    'nobase' => -> { { 'now' => -> { T0 }, 'allow_unauthenticated' => true } },
    'tick' => lambda {
      n = [0]
      { 'base_url' => 'https://x.example', 'now' => -> { (T0 + (1000 * n[0])).tap { n[0] += 1 } }, 'authenticate' => YES }
    },
    'deny' => -> { { 'now' => -> { T0 }, 'authenticate' => ->(_r) { false } } },
    'throwauth' => -> { { 'now' => -> { T0 }, 'authenticate' => ->(_r) { raise 'x' } } },
    'truthy' => -> { { 'now' => -> { T0 }, 'authenticate' => ->(_r) { 'yes' } } },
    'noauth' => -> { { 'now' => -> { T0 } } },
    'notfn' => -> { { 'now' => -> { T0 }, 'authenticate' => 'yes' } }
  }.freeze

  SESSION = lambda do |opts, setup, reqs|
    h = S.scim_handler(S.create_memory_store, OPTS[opts].call)
    setup.each { |r| h.call(r) }
    reqs.map { |r| h.call(r) }
  end

  REGISTRY = lambda do |ps, id|
    r = S.build_registry(ps)
    { 'all' => r.all, 'has' => r.has(id), 'get' => r.get(id) }
  end

  def self.fake_fetch(mode, calls)
    lambda do |url, init|
      calls << { 'url' => url, 'init' => init }
      next { 'ok' => true, 'status' => 204, 'json' => -> { raise 'x' } } if mode == 'badjson'

      ok, status, body = { 'ok201' => [true, 201, { 'id' => 'obj-1' }], 'err500' => [false, 500, { 'detail' => 'x' }],
                           'nullbody' => [true, 200, nil] }.fetch(mode)
      { 'ok' => ok, 'status' => status, 'json' => -> { body } }
    end
  end

  def self.push(fn, agent, mode)
    calls = []
    target = { 'endpoint' => 'https://dir.example/scim/Agents', 'token' => 'TOK', 'fetch' => fake_fetch(mode, calls) }
    { 'result' => S.public_send(fn, agent, target), 'calls' => calls }
  end

  PUSH_PROVISION = lambda do |agent, mode|
    calls = []
    r = S.push_provision(S.to_entra_agent_payload(agent), { 'endpoint' => 'e', 'token' => 't', 'fetch' => fake_fetch(mode, calls) })
    { 'result' => r, 'calls' => calls }
  end

  # the generator drives some cases through a fixed clock: [passport, proj, nowMs] instead of [passport, proj, meta]
  TO_SCIM = ->(p, pr, m) { S.passport_to_scim(p, pr, AtlasPca::Js.num?(m) ? { 'now' => -> { m } } : Ref.snake(m)) }

  FNS = {
    'scimSession' => SESSION,
    'passportFingerprint' => ->(p) { S.passport_fingerprint(p) },
    'issuePassport' => ->(i) { S.issue_passport(i) },
    'passportToScim' => TO_SCIM,
    'scimToProvisioningRequest' => ->(b) { S.scim_to_provisioning_request(b) },
    'parseFilter' => ->(f) { S.parse_filter(f) },
    'scimError' => ->(*a) { S.scim_error(*a) },
    'scimListResponse' => ->(r, t, s) { S.scim_list_response(r, t, s) },
    'registry' => REGISTRY,
    'toEntraAgentPayload' => ->(a) { S.to_entra_agent_payload(a) },
    'toOktaScimPayload' => ->(a) { S.to_okta_scim_payload(a) },
    'pushToEntra' => ->(_fn, a, m) { push(:push_to_entra, a, m) },
    'pushToOkta' => ->(_fn, a, m) { push(:push_to_okta, a, m) },
    'pushProvision' => PUSH_PROVISION
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1124, CASES.values.sum(&:length), 'scim'
  end

end
