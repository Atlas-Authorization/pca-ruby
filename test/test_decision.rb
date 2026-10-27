# frozen_string_literal: true

# Rules 20-21, the ternary decision and escalation answers: the shared vectors
# (packages/pca/conformance/decision-vectors.json) and exact-outcome authorize / Rack tests.
#   ruby -Ilib test/test_decision.rb
require_relative '../lib/atlas_pca/rack_middleware'
require 'minitest/autorun'
require 'json'
require 'stringio'

module DecisionFixtures
  CONF = File.expand_path('../conformance', __dir__)
  DOC = AtlasPca.parse_json(File.read(File.join(CONF, 'decision-vectors.json'), encoding: 'UTF-8'), loose: true)['primitives']
  KEYS = JSON.parse(File.read(File.join(CONF, 'keys.json')))
  FIX = AtlasPca.parse_json(File.read(File.expand_path('../test-data/authorize-fixtures.json', __dir__), encoding: 'UTF-8'),
                            loose: true)
  CASE = FIX['cases'].find { |c| c['steps'].length == 1 && c['steps'][0]['expect']['allow'] == true }
  NOW = FIX['now']
  AUD = FIX['audience']
  SK = OpenSSL::PKey.new_raw_private_key('ED25519', AtlasPca.b64d(KEYS['principal']['seed'], 32))
  PUB = KEYS['principal']['public']
  ROGUE = KEYS['rogue']['public']
end

class TestDecisionVectors < Minitest::Test
  D = DecisionFixtures::DOC

  def test_vector_files_are_non_empty
    assert_equal [85, 73, 25, 31, 85, 18, 11],
                 %w[intent_units intent_tighten decision_of decision_lattice escalation_answer escalation_fold escalation_truncate].map { |k| D[k].length }
  end

  # `input_text` is raw JSON text each runner parses itself: key order is part of the input
  def input_of(e) = e.key?('input_text') ? AtlasPca.parse_json(e['input_text'], loose: true) : e['input']

  # JSON.stringify of a string: a lone surrogate (kept as its three-byte form) is written as \\udXXX.
  def js_json_string(str)
    parts = str.b.split(/(\xED[\xA0-\xBF][\x80-\xBF])/n).each_with_index.map do |c, i|
      i.odd? ? format('\\u%04x', ((c.getbyte(0) & 0x0F) << 12) | ((c.getbyte(1) & 0x3F) << 6) | (c.getbyte(2) & 0x3F)) : JSON.generate(c.force_encoding('UTF-8'))[1..-2]
    end
    "\"#{parts.join}\""
  end

  def test_escalation_truncate
    D['escalation_truncate'].each do |e|
      req = AtlasPca.build_escalation_request(aud: 'a', grant: { 'id' => 'g' }, pcactn: { 'action' => { 'verb' => 'v', 'resource' => 'r' } },
                                              last_counter: nil, reasons: e['input']['reasons'], now: 1)
      wire = '[' + req['reasons'].map { |r| js_json_string(r) }.join(',') + ']'
      assert_equal e['expect']['wire'], wire, e['name']
    end
  end

  def test_units
    D['intent_units'].each do |e|
      r = AtlasPca.decide_units(input_of(e))
      assert_equal e['expect']['ok'], r['ok'], e['name']
      assert_equal e['expect']['reason'], r['reason'], e['name'] unless e['expect']['ok']
    end
  end

  def test_tighten
    D['intent_tighten'].each do |e|
      r = AtlasPca.decide_tighten(input_of(e))
      assert_equal e['expect'], r, e['name']
    end
  end

  def test_tighten_null_is_malformed_like_typescript
    r = AtlasPca.decide_tighten({ 'tighten' => nil })
    assert_equal 'deny', r['outcome']
    assert_includes r['reason'], 'tighten must be an array'
    assert_equal 'deny', AtlasPca.decide_tighten({ 'polarity' => nil })['outcome']
  end

  def test_decision_of
    D['decision_of'].each { |e| assert_equal e['expect']['decision'], AtlasPca.decision_of(e['input']), e['name'] }
  end

  def test_lattice
    D['decision_lattice'].each do |e|
      i = e['input']
      n = e['name']
      got = if n.start_with?('meet-') then AtlasPca.meet(i['a'], i['b'])
            elsif n.start_with?('pep-') then AtlasPca.pep_decision(i['decision'], i['answered'])
            else AtlasPca.tighten(i['decision'], i['signal'])
            end
      assert_equal e['expect']['decision'], got, n
    end
  end

  def test_never_widens
    order = %w[deny escalate allow]
    order.each do |d|
      ['ok', 'escalate', 'deny', nil, 'allow', 1].each do |s|
        assert_operator order.index(AtlasPca.tighten(d, s)), :<=, order.index(d)
      end
    end
    refute_equal 'allow', AtlasPca.pep_decision('deny', true)
    refute_equal 'allow', AtlasPca.pep_decision('escalate', false)
    assert_equal 'deny', AtlasPca.meet('allow', 'maybe')
  end

  def test_decision_of_considers_every_failing_check
    one = { 'allow' => false, 'checks' => { 'a' => 'fail', 'b' => 'pass' }, 'reasons' => ['a: intent_required: q'] }
    assert_equal 'escalate', AtlasPca.decision_of(one)
    two = one.merge('checks' => { 'a' => 'fail', 'b' => 'fail' }, 'reasons' => ['a: intent_required: q', 'b: bad'])
    assert_equal 'deny', AtlasPca.decision_of(two)
    assert_equal 'deny', AtlasPca.decision_of(one.merge('reasons' => []))
    assert_equal 'deny', AtlasPca.decision_of(one.merge('checks' => { 'a' => 'pass' }))
    assert_equal 'deny', AtlasPca.decision_of(nil)
  end

  def test_escalation_fold
    D['escalation_fold'].each do |e|
      i = e['input']
      assert_equal e['expect'], AtlasPca.fold_escalation(i['core_reasons'], i['v2'], i['checks']), e['name']
    end
  end

  def test_escalation_answer_vectors
    supported = AtlasPca.supported_suites
    D['escalation_answer'].each do |e|
      i = input_of(e)
      r = AtlasPca.verify_escalation_answer(i['answer'], i['principals'], i['bind'], i['now'])
      need = e['requires_suite']
      if need && !supported.include?(need)
        # a suite this runtime cannot run is refused with the distinct reason, never passed or failed silently
        refute r[:ok], e['name']
        assert_includes r[:reason], 'unsupported_suite', e['name']
        next
      end
      assert_equal e['expect']['ok'], r[:ok], e['name']
      if r[:ok]
        assert_equal [e['expect']['principal'], e['expect']['decision']], [r[:principal], r[:decision]], e['name']
      else
        assert_includes r[:reason], e['expect']['reason_contains'], e['name']
      end
    end
  end
end

class TestEscalationGuard < Minitest::Test
  F = DecisionFixtures
  STEP = F::CASE['steps'][0]
  GRANT = F::CASE['grant']

  # Make the core verifier report the given checks as failed (escalate-class or not), restoring it after.
  def with_failing(checks, reason)
    real = AtlasPca.method(:verify_pcactn)
    AtlasPca.define_singleton_method(:verify_pcactn) do |*a, **k|
      v = real.call(*a, **k)
      AtlasPca::Verdict.new(false, v.checks.merge(checks.to_h { |c| [c, false] }), reason)
    end
    yield
  ensure
    AtlasPca.define_singleton_method(:verify_pcactn, real)
  end

  def run_az(store, answer = nil, principals: [F::PUB])
    AtlasPca.authorize(STEP['pcactn'], operation: STEP['operation'], audience: F::AUD, resolve_grant: ->(_r) { GRANT },
                       state_store: store, is_revoked: ->(_p, _g) { false }, now: F::NOW, plan: 'single-step',
                       escalation_principals: principals, escalation_answer: answer)
  end

  def answer(last: nil, **o)
    body = { 'v' => 1, 'kind' => 'pca-escalation-answer', 'principal' => F::PUB,
             'policy_digest' => AtlasPca.escalation_policy_digest(GRANT),
             'action_digest' => AtlasPca.escalation_action_digest(STEP['pcactn']),
             'history_head' => AtlasPca.escalation_history_head(last), 'decision' => 'allow', 'iat' => F::NOW,
             'expires_at' => F::NOW + 600_000, 'nonce' => AtlasPca.b64e("\x09".b * 16) }.merge(o)
    sig = F::SK.sign(nil, AtlasPca::ESCALATION_ANSWER_DOMAIN.b + AtlasPca.canon_bytes(body))
    body.merge('sig' => AtlasPca.b64e(sig))
  end

  def test_baseline_is_allow
    r = run_az(AtlasPca::MemoryStateStore.new)
    assert_equal [true, 'allow', nil], [r.allow, r.decision, r.escalation]
  end

  def test_escalate_without_answer_is_refused_and_surfaced
    with_failing(['provenance'], 'provenance: intent_required: a question is required') do
      r = run_az(AtlasPca::MemoryStateStore.new)
      assert_equal [false, 'escalate', 403], [r.allow, r.decision, r.status]
      assert_equal 'pca-escalation-request', r.escalation['kind']
      assert_equal STEP['operation']['verb'], r.escalation['verb']
      assert_equal 'fail', r.checks['provenance']
    end
  end

  def test_hard_failure_is_deny_not_escalate
    with_failing(%w[provenance leaf_signature], 'provenance: intent_required: q') do
      r = run_az(AtlasPca::MemoryStateStore.new)
      assert_equal [false, 'deny', nil], [r.allow, r.decision, r.escalation]
    end
  end

  def test_valid_answer_admits_once_and_the_counter_spends_it
    with_failing(['provenance'], 'provenance: intent_required: q') do
      store = AtlasPca::MemoryStateStore.new
      r = run_az(store, answer)
      assert_equal [true, 'allow'], [r.allow, r.decision]
      assert_equal({ 'answered_by' => F::PUB }, r.escalation)
      again = run_az(store, answer(last: STEP['pcactn']['counter']))
      refute again.allow
      assert_equal 'fail', again.checks['replay']
    end
  end

  def test_bad_answers_stay_escalate
    with_failing(['provenance'], 'provenance: intent_required: q') do
      z = AtlasPca.b64e("\x00".b * 32)
      [answer(decision: 'deny'), answer(policy_digest: z), answer(action_digest: z),
       answer(history_head: AtlasPca.escalation_history_head(99)), answer(expires_at: F::NOW - 1, iat: F::NOW - 5),
       { 'junk' => 1 }].each do |ans|
        r = run_az(AtlasPca::MemoryStateStore.new, ans)
        assert_equal [false, 'escalate'], [r.allow, r.decision]
      end
      refute run_az(AtlasPca::MemoryStateStore.new, answer, principals: [F::ROGUE]).allow
      refute run_az(AtlasPca::MemoryStateStore.new, answer, principals: []).allow
    end
  end

  def test_answer_never_upgrades_a_deny
    with_failing(%w[provenance leaf_signature], 'provenance: intent_required: q') do
      r = run_az(AtlasPca::MemoryStateStore.new, answer)
      assert_equal [false, 'deny'], [r.allow, r.decision]
    end
  end

  def test_store_without_last_cannot_bind_the_history
    bare = Class.new do
      def initialize = @m = AtlasPca::MemoryStateStore.new
      def claim(key, counter) = @m.claim(key, counter)
    end
    with_failing(['provenance'], 'provenance: intent_required: q') do
      r = run_az(bare.new, answer)
      assert_equal [false, 'escalate'], [r.allow, r.decision]
    end
    assert_raises(ArgumentError) do
      AtlasPca::AuthorizeOptions.new(state_store: bare.new, escalation_principals: [F::PUB])
    end
  end

  def test_rack_surfaces_escalate_and_reads_the_answer_header_and_body
    with_failing(['provenance'], 'provenance: intent_required: q') do
      mw = lambda do
        AtlasPca::RackMiddleware.new(->(_e) { [200, {}, ['ok']] }, audience: F::AUD, resolve_grant: ->(_r) { GRANT }, now: F::NOW,
                                     authorize: AtlasPca::AuthorizeOptions.new(
                                       state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false },
                                       operation: ->(_e) { STEP['operation'] }, escalation_principals: [F::PUB]
                                     ))
      end
      hdr = AtlasPca.b64e(JSON.generate(STEP['pcactn']))
      env = ->(extra = {}, body = '') { { 'HTTP_PCA_ACTION' => hdr, 'rack.input' => StringIO.new(body) }.merge(extra) }
      status, headers, body = mw.call.call(env.call)
      b = JSON.parse(body.join)
      assert_equal [403, 'escalate', 'pca-escalation-request'], [status, b['decision'], b['escalation']['kind']]
      refute_includes headers['WWW-Authenticate'].downcase, 'escalat'
      s2, = mw.call.call(env.call({ 'HTTP_PCA_ESCALATION_ANSWER' => AtlasPca.b64e(JSON.generate(answer)) }))
      assert_equal 200, s2
      s3, = mw.call.call(env.call({}, JSON.generate({ 'escalation_answer' => answer })))
      assert_equal 200, s3
      s4, = mw.call.call(env.call({ 'HTTP_PCA_ESCALATION_ANSWER' => 'not base64!' }))
      assert_equal 403, s4
    end
  end
end
