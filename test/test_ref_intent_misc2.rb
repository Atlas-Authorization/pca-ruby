# frozen_string_literal: true

# Replays the TS-reference oracle of the leftovers of five intent modules (test-data/ref-intent-misc2.json.gz, 770 cases): the shared strict-artifact
# helpers (path segments, scalars, closed members, signed artifacts and their verification, parameter paths), the signed "ask the principal" question and
# its RFC 9457 problem, the classifier verdicts / policy / quorum decision / attestation gate, the accumulator receipts and sequencer key sets, and the
# admission / settlement through a session store. Every fn of the corpus has a handler and the totals are asserted. Encodings: {"$num": ...} a
# non-finite number; {"$bytes": {"$seed": label}} the 32-byte Ed25519 secret; a suite is {alg, pqSeed?} (the ML-DSA-65 seed; signing is
# deterministic, so signatures compare byte for byte). Cases that sign or verify with ML-DSA need a runtime that has it (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefIntentMisc2 < Minitest::Test
  A = AtlasPca
  IA = AtlasPca::IntentArtifacts
  IR = AtlasPca::IntentRequired
  BY_FN = Ref.load('intent-misc2')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PQ = A.supported_suites.include?('ml-dsa-65')

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  # {'alg', 'pq'} of a corpus suite ({alg, pqSeed?} or null)
  def self.suite(s)
    return nil unless s.is_a?(Hash)

    out = { 'alg' => s['alg'] }
    out['pq'] = A::PqKeyPair.from_seed('ML-DSA-65', s['pqSeed']) if s['pqSeed']
    out
  end

  # {alg:, pq:} keywords of a corpus suite
  def self.suite_kw(s)
    return {} unless s.is_a?(Hash)

    { alg: s['alg'], pq: s['pqSeed'] ? A::PqKeyPair.from_seed('ML-DSA-65', s['pqSeed']) : nil }
  end

  def self.key(secret) = A::KeyPair.new(secret)
  def self.bytes(b) = { '$bytes' => Ref.b64e(b) }

  def self.set_nested(a)
    root = a['root']
    ok = IA.set_nested(root, a['path'], a['value'])
    { 'ok' => ok, 'root' => root }
  end

  # the attestation gate of a verdict's measurement (a non-object verdict is refused; an unexpected error is a refusal)
  def self.classifier_attestation(v, att, approved) = A::SemanticThreshold.verify_classifier_attestation(v, att, approved)

  # The state set of a monitor. The reference's exhaustive switch yields undefined for an unknown kind; this SDK raises (asserted below).
  def self.monitor_states(m)
    A::IntentV2.monitor_states(A::V2JS.jsnorm(m))
  rescue A::IntentV2::StrictError
    raise if A::IntentV2::MONITOR_KINDS.include?(m['kind'])

    nil
  end

  # a session store held in memory (the reference's memory store): `durable` true / false / absent (nil)
  class MemStore
    attr_reader :durable, :ev

    def initialize(durable)
      @durable = durable
      @ev = {}
    end

    def with_session(session)
      list = (@ev[session] ||= [])
      yield Tx.new(list)
    end

    Tx = Struct.new(:list) do
      def events = list.map(&:dup)
      def append(e) = (list << e.dup) && nil

      def set_status(id, status)
        e = list.find { |x| x['id'] == id }
        return false if e.nil?

        e['status'] = status
        true
      end
    end
  end

  # the reference's `admit` scenario: one fresh store, one result per step (a refused step is {"$err": true})
  def self.admit(ops)
    st = MemStore.new(true)
    out = []
    ops.each do |op, a, b, c|
      case op
      when 'store'
        st = MemStore.new(a['durable'] == 'absent' ? nil : a['durable'] != false)
        out << nil
      when 'admit'
        verify = lambda do |acc|
          raise 'verify boom' if a['verifyAs'] == 'throws'

          out << { 'acc' => acc }
          { 'allow' => a['verifyAs']['allow'] }
        end
        kw = { session: a['session'], root: a['root'], event: a['event'], verify: verify }
        kw[:schema] = a['schema'] if a['schema']
        kw[:require_durable] = a['requireDurable'] if a.key?('requireDurable')
        out << { 'allow' => A.admit_intent_action(st, **kw)['allow'] }
      when 'settle' then out << A.settle_intent_event(st, a, b, c)
      when 'events' then out << (st.ev[a] || []).map(&:dup)
      else out << { '$err' => 'op' }
      end
    rescue StandardError
      out << { '$err' => true }
    end
    out
  end

  HANDLERS = {
    'isPathSegment' => ->(s) { IA.path_segment?(s) },
    'isPlainObject' => ->(v) { IA.plain_object?(v) },
    'isSafeInt' => ->(v) { IA.safe_int?(v) },
    'isScalar' => ->(v) { IA.scalar?(v) },
    'isClock' => ->(v) { IA.clock?(v) },
    'scalarEq' => ->(a, b) { IA.scalar_eq(a, b) },
    'utf8Len' => ->(s) { IA.utf8_len(s) },
    'isBoundedString' => ->(v, max) { IA.bounded_string?(v, max) },
    'isDigest' => ->(v) { IA.digest?(v) },
    'closedMembers' => ->(o, req, opt, where) { IA.closed_members(o, req, opt, where) },
    'pinPqOk' => ->(*v) { IA.pin_pq_ok?(v.empty? ? IA::UNDEF : v[0]) },
    'artifactSuiteError' => ->(a) { IA.artifact_suite_error(a) },
    'artifactMessage' => ->(dom, a) { bytes(IA.artifact_message(dom, a)) },
    'signArtifact' => ->(dom, body, sk, s) { IA.sign_artifact(dom, body, key(sk), suite(s)) },
    'verifyArtifactSig' => ->(dom, a, pin) { IA.verify_artifact_sig(dom, a, pin) },
    'artifactRef' => ->(rd, slot, a) { IA.artifact_ref(rd, slot, a) },
    'publicKeyB64u' => ->(sk) { IA.public_key_b64u(key(sk)) },
    'resolveParamPath' => ->(params, path) { IA.resolve_param_path(params, path) },
    'isParamPath' => ->(p) { IA.param_path?(p) },
    'setNested' => ->(a) { set_nested(a) },
    'ownGet' => ->(o, k) { IA.own_get(o, k) },
    'nullRecord' => -> { IA.null_record },
    'intentActionDigest' => ->(a) { A::IntentJit.intent_action_digest(a) },
    'cellCoordsError' => ->(c) { A.cell_coords_error(c) },
    'intentRequiredShapeError' => ->(b, o) { IR.intent_required_shape_error(b, !(o.is_a?(Hash) && o['signed'] == false)) },
    'signIntentRequired' => ->(body, kid, sk, s) { A.sign_intent_required(body, kid, key(sk), **suite_kw(s)) },
    'verifyIntentRequired' => ->(b, keys, now) { IR.verify_intent_required(b, keys, now) },
    'verifyIntentRequiredAt' => ->(b, keys, now) { IR.verify_intent_required_at(b, keys, now) },
    'intentProblem' => ->(kind, o) { IR.intent_problem(kind, o) },
    'classifierContentDigest' => ->(v) { A.classifier_content_digest(v) },
    'signClassifierVerdict' => ->(body, sk, s) { A.sign_classifier_verdict(body, key(sk), **suite_kw(s)) },
    'validateClassifierVerdictWire' => ->(v) { A.validate_classifier_verdict_wire(v) },
    'classifierVerdictRef' => ->(v) { A.classifier_verdict_ref(v) },
    'validateClassifierPolicy' => ->(p) { A.validate_classifier_policy(p) },
    'classifierCheckActive' => ->(i) { A.classifier_check_active(i) },
    'decideClassifierDimensions' => ->(i) { A.decide_classifier_dimensions(i) },
    'verifyClassifierAttestation' => ->(v, att, approved) { classifier_attestation(v, att, approved) },
    'constants' => -> { A::IntentConstants.view },
    'monitorStates' => ->(m) { monitor_states(m) },
    'monitorInitialState' => ->(m) { A.monitor_initial_state(m) },
    'distinctKey' => ->(x) { A.distinct_key(x) },
    'sortedDistinct' => ->(keys) { A.sorted_distinct(keys) },
    'signAccReceipt' => ->(body, sk, s) { A.sign_acc_receipt(body, key(sk), **suite_kw(s)) },
    'accReceiptDigest' => ->(r) { A.acc_receipt_digest(r) },
    'accReceiptCoreDigest' => ->(r) { A.acc_receipt_core_digest(r) },
    'verifyReceiptSignature' => ->(r, signer, pin) { A.verify_acc_receipt_signature(r, signer, pin.is_a?(Hash) ? pin['pqPins'] : nil) },
    'signSequencerKeySet' => ->(body, sk, s) { A.sign_sequencer_key_set(body, key(sk), **suite_kw(s)) },
    'sequencerKeySetDigest' => ->(k) { A.sequencer_key_set_digest(k) },
    'verifyKeySet' => ->(k, root, rpk) { A.verify_sequencer_key_set(k, root, rpk.nil? ? A::V2JS::UNDEF : rpk) },
    'accContextFor' => ->(root, history, cand, schema) { A.acc_context_for(root, history, cand, schema.nil? ? A::V2JS::UNDEF : schema) },
    'admit' => ->(ops) { admit(ops) }
  }.freeze

  TOTALS = { 'constants' => 1, 'isPathSegment' => 16, 'isPlainObject' => 8, 'isSafeInt' => 12, 'isScalar' => 16, 'isClock' => 12, 'scalarEq' => 11, 'utf8Len' => 7,
             'isBoundedString' => 12, 'isDigest' => 12, 'closedMembers' => 8, 'pinPqOk' => 6, 'artifactSuiteError' => 12, 'artifactMessage' => 10,
             'signArtifact' => 8, 'verifyArtifactSig' => 18, 'artifactRef' => 8, 'publicKeyB64u' => 2, 'resolveParamPath' => 25, 'isParamPath' => 25,
             'setNested' => 14, 'ownGet' => 11, 'nullRecord' => 1, 'intentActionDigest' => 6, 'cellCoordsError' => 26, 'intentRequiredShapeError' => 90,
             'signIntentRequired' => 8, 'verifyIntentRequired' => 26, 'verifyIntentRequiredAt' => 26, 'intentProblem' => 42, 'classifierContentDigest' => 12,
             'signClassifierVerdict' => 7, 'validateClassifierVerdictWire' => 26, 'classifierVerdictRef' => 5, 'validateClassifierPolicy' => 42,
             'classifierCheckActive' => 11, 'decideClassifierDimensions' => 44, 'verifyClassifierAttestation' => 11, 'monitorStates' => 13,
             'monitorInitialState' => 13, 'distinctKey' => 18, 'sortedDistinct' => 7, 'signAccReceipt' => 16, 'accReceiptDigest' => 4, 'accReceiptCoreDigest' => 4,
             'verifyReceiptSignature' => 8, 'signSequencerKeySet' => 15, 'sequencerKeySetDigest' => 3, 'verifyKeySet' => 8, 'accContextFor' => 13,
             'admit' => 11 }.freeze

  def self.pq_case?(c) = Ref.canon(c['args']).match?(/ml-dsa/)

  LIBRARY_TEXT = ['malformed intent_required:', 'classes: evaluation error (fail closed):', 'attestation check error (fail closed):'].freeze

  # the case the reference accepts only through allowUnboundPq (a post-quantum receipt whose signer key is not pinned)
  def self.unbound?(c) = c['fn'] == 'verifyReceiptSignature' && c['args'][2].is_a?(Hash) && c['args'][2]['allowUnboundPq'] == true && c['out'] == true

  # a reason that carries library text compares by its prefix
  def self.same?(got, out, c)
    return got == false if unbound?(c)

    if out.is_a?(Hash) && (pre = LIBRARY_TEXT.find { |p| out['reason'].to_s.start_with?(p) })
      return got.is_a?(Hash) && got['ok'] == false && got['reason'].to_s.start_with?(pre)
    end
    Ref.canon(got) == Ref.canon(out)
  end

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal TOTALS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 770, BY_FN.values.sum(&:length)
    assert_empty BY_FN.keys - HANDLERS.keys
    assert_equal 1, BY_FN.values.flatten.count { |c| self.class.unbound?(c) }, 'the cases the reference accepts only under allowUnboundPq'
  end

  def test_an_unknown_monitor_kind_has_no_value_and_the_enforcement_form_raises
    assert_nil A::IntentV2.monitor_states({ 'kind' => 'zzz' })
    assert_raises(A::IntentV2::StrictError) { A::IntentV2.monitor_states!({ 'kind' => 'zzz' }) }
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| k.dnum(a) }) }, skip: ->(c) { !PQ && k.pq_case?(c) }, compare: ->(got, out, c) { k.same?(got, out, c) })
    end
  end
end
