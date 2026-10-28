# frozen_string_literal: true

# The Intent Layer v2 state vectors (packages/pca/conformance/intent-state-vectors.json): accumulator and monitor
# declarations, values and pre-states, the session-history window and fold, sequencer key sets and reservation receipts.
# Every case is run through this verifier's implementation and compared (as canonical JSON) to the reference output.
# A case that names a post-quantum suite this runtime's OpenSSL lacks is counted as skipped, never passed or failed.
#   ruby -Ilib test/test_intent_state.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestIntentState < Minitest::Test
  DIR = File.expand_path('../conformance', __dir__)
  # the platform-JSON reading (-0 kept, a lone surrogate becomes an invalid-encoding string)
  DOC = AtlasPca::JsonParser.new(File.read(File.join(DIR, 'intent-state-vectors.json'), encoding: 'UTF-8'), true, true,
                                 json_text: true).parse_document
  PQ_RE = /ml-dsa|hybrid|slh-dsa|fn-dsa|less/

  def n(x) = AtlasPca::V2JS.jsnorm(x)
  def iv2 = AtlasPca::IntentV2
  def absent = AtlasPca::V2JS::UNDEF
  def opt(x) = x.nil? ? absent : n(x)

  def history(thunk)
    thunk.call
  rescue AtlasPca::HistoryError
    { 'throws' => true }
  end

  def run_case(c)
    a = c['args']
    case c['fn']
    when 'accumulatorDeclError' then iv2.accumulator_decl_error(n(a[0]))
    when 'monitorDeclError' then iv2.monitor_decl_error(n(a[0]))
    when 'monitorStates' then iv2.monitor_states(n(a[0]))
    when 'trackedKeySetError' then iv2.tracked_key_set_error(n(a[0]))
    when 'preStateError' then iv2.pre_state_error({ 'agg' => a[0] }, n(a[1]))
    when 'preValue' then iv2.pre_value({ 'agg' => a[0] }, n(a[1]))
    when 'combineAcc' then iv2.combine_acc({ 'agg' => a[0] }, n(a[1]), n(a[2]))
    when 'accSelects' then iv2.acc_selects(n(a[0]), a[1], opt(a[2]))
    when 'accValueOf'
      r = iv2.acc_value_of(n(a[0]), a[1], n(a[2]), opt(a[3]))
      r['ok'] ? { 'ok' => true, 'val' => r['val'], 'key' => r['key'] } : { 'ok' => false, 'reason' => r['reason'] }
    when 'receiptArithmeticOk' then iv2.receipt_arithmetic_ok({ 'agg' => a[0] }, n(a[1]), a[2])
    when 'pcactnReservationDigest' then iv2.pcactn_reservation_digest(n(a[0]))
    when 'receiptShapeError' then iv2.acc_receipt_shape_error(n(a[0]))
    when 'keySetShapeError' then iv2.sequencer_key_set_shape_error(n(a[0]))
    when 'verifyKeySet' then iv2.verify_sequencer_key_set(n(a[0]), a[1], a[3] ? a[2] : absent)
    when 'verifyReceiptSignature' then a[0].is_a?(Hash) ? iv2.verify_acc_receipt_signature(n(a[0]), a[1], a[2]) : false
    when 'verifyReceiptAgainstHolder'
      fresh = { 'max_receipt_age_ms' => a[4], 'max_keyset_age_ms' => a[5] }
      fresh['tracked'] = n(a[6]) unless a[6].nil?
      iv2.verify_receipt_against_holder(n(a[0]), n(a[1]), n(a[2]), a[3], fresh)
    when 'inWindow' then AtlasPca.in_window(n(a[0]), n(a[1]), n(a[2]))
    when 'accKeyOf' then AtlasPca.acc_key_of(n(a[0]), n(a[1]))
    when 'accPreState' then history(-> { AtlasPca.acc_pre_state(n(a[0]), n(a[1]), n(a[2]), opt(a[3])) })
    when 'accPost' then history(-> { AtlasPca.acc_post(n(a[0]), n(a[1]), n(a[2]), opt(a[3])) })
    when 'monitorStep' then AtlasPca.monitor_step(n(a[0]), a[1], n(a[2]))
    when 'monitorState' then AtlasPca.monitor_state(n(a[0]), n(a[1]))
    else raise "unknown fn #{c['fn']}"
    end
  end

  def norm(x)
    case x
    when Hash then x.each_with_object({}) { |(k, v), h| h[k] = norm(v) }
    when Array then x.map { |v| norm(v) }
    when Float then x.finite? && x == x.floor && x.abs < 1e300 ? (x.zero? && (1.0 / x).negative? ? -0.0 : x.to_i) : x
    else x
    end
  end

  def test_the_corpus_file_is_fully_run
    assert_equal ['pca-intent-state-vectors', 1], [DOC['format'], DOC['ver']]
    assert_operator DOC['cases'].length, :>, 3000
    assert_equal 22, DOC['cases'].map { |c| c['fn'] }.uniq.length
  end

  def test_matches_the_reference
    pq_ok = AtlasPca.supported_suites.include?('ml-dsa-65')
    bad = []
    skipped = 0
    DOC['cases'].each do |c|
      got = begin
        run_case(c)
      rescue StandardError, SystemStackError => e
        "THREW #{e.class}"
      end
      next if norm(got) == norm(c['out'])

      if !pq_ok && c['args'].to_s.match?(PQ_RE)
        skipped += 1
        next
      end
      bad << "#{c['name']}: want #{c['out'].inspect} got #{got.inspect}"
    end
    warn "intent-state: #{skipped} PQ case(s) skipped (suite unavailable on this runtime)" if skipped.positive?
    assert_equal [], bad.first(20)
  end
end
