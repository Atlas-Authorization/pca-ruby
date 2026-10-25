# frozen_string_literal: true
# Rule 15 (accumulators, monitors, receipts, sequencer key sets) differential kills against the TS reference
# (packages/pca/src/intent-acc.ts): test-data/k042-intentacc.json = tools/pca-audit/java-mutate/k042-intentacc-oracle.mjs
# (`[{fn, name, args, out}]`; the Java suite runs the same file). Exact reasons / verdicts / values. Only intent_v2.rb bears
# on these rules. AtlasPca is resolved at CALL time (the oracle replaces the module per mutant).
module MutationKill
  module IntentAccDiff
    module_function
    def cases = (@cases ||= DiffUtil.load('k042-intentacc.json'))
    def fns = cases.map { |c| c['fn'] }.uniq
    def n(x) = AtlasPca::V2JS.jsnorm(x)
    def iv2 = AtlasPca::IntentV2
    def absent = AtlasPca::V2JS::UNDEF

    def run(c)
      a = c['args']
      case c['fn']
      when 'accumulatorDeclError' then iv2.accumulator_decl_error(n(a[0]))
      when 'monitorDeclError' then iv2.monitor_decl_error(n(a[0]))
      when 'monitorStates' then iv2.monitor_states(n(a[0]))
      when 'trackedKeySetError' then iv2.tracked_key_set_error(n(a[0]))
      when 'preStateError' then iv2.pre_state_error({ 'agg' => a[0] }, n(a[1]))
      when 'preValue' then iv2.pre_value({ 'agg' => a[0] }, n(a[1]))
      when 'combineAcc' then iv2.combine_acc({ 'agg' => a[0] }, n(a[1]), n(a[2]))
      when 'accSelects' then iv2.acc_selects(n(a[0]), a[1], a[2].nil? ? absent : n(a[2]))
      when 'accValueOf'
        r = iv2.acc_value_of(n(a[0]), a[1], n(a[2]), a[3].nil? ? absent : n(a[3]))
        r['ok'] ? { 'ok' => true, 'val' => r['val'], 'key' => r['key'] } : { 'ok' => false, 'reason' => r['reason'] }
      when 'receiptArithmeticOk' then iv2.receipt_arithmetic_ok({ 'agg' => a[0] }, n(a[1]), a[2])
      when 'pcactnReservationDigest' then iv2.pcactn_reservation_digest(n(a[0]))
      when 'receiptShapeError' then iv2.acc_receipt_shape_error(n(a[0]))
      when 'keySetShapeError' then iv2.sequencer_key_set_shape_error(n(a[0]))
      when 'verifyKeySet' then iv2.verify_sequencer_key_set(n(a[0]), a[1], a[3] ? a[2] : absent)
      when 'verifyReceiptSignature'
        a[0].is_a?(Hash) ? iv2.verify_acc_receipt_signature(n(a[0]), a[1], a[2]) : false
      when 'verifyReceiptAgainstHolder'
        fresh = { 'max_receipt_age_ms' => a[4], 'max_keyset_age_ms' => a[5] }
        fresh['tracked'] = n(a[6]) unless a[6].nil?
        iv2.verify_receipt_against_holder(n(a[0]), n(a[1]), n(a[2]), a[3], fresh)
      else raise "unknown fn #{c['fn']}"
      end
    end

    # the first case of `fn` that differs, else nil
    def first_bad(fn)
      cases.each do |c|
        next unless c['fn'] == fn
        got = begin
          run(c)
        rescue StandardError, SystemStackError => e
          "THREW #{e.class}"
        end
        next if DiffUtil.norm(got) == DiffUtil.norm(c['out'])
        next if DiffUtil.pq_case?(c['args'])
        return "#{c['name']}: want #{c['out'].inspect} got #{got.inspect}"
      end
      nil
    end
  end

  IntentAccDiff.fns.each do |fn|
    t("intent acc differential (TS oracle): #{fn}") do
      next true if DiffUtil.skip?('intent_v2.rb')
      bad = IntentAccDiff.first_bad(fn)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
