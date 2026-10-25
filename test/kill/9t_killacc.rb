# frozen_string_literal: true
# Rule 15 (accumulators, monitors, receipts, sequencer key sets) targeted differential kills: test-data/killAcc.json.gz (gzip of the Kotlin file) =
# tools/pca-audit/kotlin-mutate/killAcc-oracle-gen.mjs (the Kotlin KillAccTest's golden file: one case per boundary / disjunct of
# the TS reference intent-acc.ts, exact reason strings). The Java/Python corpus (k042-intentacc.json) is random-ish; this one pins
# each disjunct. Only intent_v2.rb bears on it. AtlasPca is resolved at CALL time (the oracle replaces the module per mutant).
module MutationKill
  module KillAcc
    module_function
    def root = (@root ||= DiffUtil.load('killAcc.json.gz'))
    def cases = root['cases']
    def fns = cases.map { |c| c['fn'] }.uniq
    def n(x) = AtlasPca::V2JS.jsnorm(x)
    def iv2 = AtlasPca::IntentV2
    def absent = AtlasPca::V2JS::UNDEF
    def has(i, k) = i.key?(k)

    def run(c)
      i = c['in']
      case c['fn']
      when 'acc' then iv2.accumulator_decl_error(n(i))
      when 'mon' then iv2.monitor_decl_error(n(i))
      when 'states' then iv2.monitor_states(n(i))
      when 'sel' then iv2.acc_selects(n(i['a']), i['verb'], has(i, 'schema') && !i['schema'].nil? ? n(i['schema']) : absent)
      when 'dkey' then iv2.distinct_key(i['x'])
      when 'val'
        r = iv2.acc_value_of(n(i['a']), i['verb'], n(i['params']), has(i, 'schema') && !i['schema'].nil? ? n(i['schema']) : absent)
        r['ok'] ? { 'reason' => nil, 'value' => r['val'], 'key' => r['key'] } : { 'reason' => r['reason'], 'value' => 0, 'key' => nil }
      when 'pre' then iv2.pre_state_error({ 'agg' => i['agg'] }, n(i['s']))
      when 'combine' then iv2.combine_acc({ 'agg' => i['agg'] }, n(i['pre']), { 'val' => i['value'], 'key' => i['key'] })
      when 'prev' then iv2.pre_value({ 'agg' => i['agg'] }, n(i['pre']))
      when 'arith' then iv2.receipt_arithmetic_ok({ 'agg' => i['agg'] }, n(i['r']), i['value'])
      when 'resdig' then iv2.pcactn_reservation_digest(n(i['p']))
      when 'rshape' then iv2.acc_receipt_shape_error(n(i))
      when 'rsig' then iv2.verify_acc_receipt_signature(n(i['r']), i['signer'], has(i, 'pin') ? n(i['pin']) : nil)
      when 'rdig' then iv2.acc_receipt_digest(n(i['r']))
      when 'ksshape' then iv2.sequencer_key_set_shape_error(n(i))
      when 'ksverify' then iv2.verify_sequencer_key_set(n(i['k']), i['root'], has(i, 'rootPqPk') ? i['rootPqPk'] : absent)
      when 'ksdig' then iv2.sequencer_key_set_digest(n(i['k']))
      when 'tracked' then iv2.tracked_key_set_error(n(i['t']))
      when 'holder'
        f = {}
        f['max_receipt_age_ms'] = i['maxR'] if has(i, 'maxR')
        f['max_keyset_age_ms'] = i['maxK'] if has(i, 'maxK')
        f['tracked'] = n(i['tracked']) if has(i, 'tracked')
        iv2.verify_receipt_against_holder(n(i['r']), n(i['holder']), n(i['keySets']), i['now'], f)
      else raise "unknown fn #{c['fn']}"
      end
    end

    # the same case through the PUBLIC wrapper (94a_pub_twin.rb): every argument the wrapper normalizes as its twin, an
    # absent optional argument omitted (the wrapper's default)
    def tw(x) = PubTwin.twin(x)

    def pub(c)
      i = c['in']
      a = AtlasPca
      case c['fn']
      when 'acc' then a.accumulator_decl_error(tw(n(i)))
      when 'mon' then a.monitor_decl_error(tw(n(i)))
      when 'states' then a.monitor_states(n(i))
      when 'sel'
        has(i, 'schema') && !i['schema'].nil? ? a.acc_selects(n(i['a']), i['verb'], tw(n(i['schema']))) : a.acc_selects(n(i['a']), i['verb'])
      when 'dkey' then a.distinct_key(i['x'])
      when 'val'
        r = if has(i, 'schema') && !i['schema'].nil?
              a.acc_value_of(n(i['a']), i['verb'], tw(n(i['params'])), tw(n(i['schema'])))
            else
              a.acc_value_of(n(i['a']), i['verb'], tw(n(i['params'])))
            end
        r['ok'] ? { 'reason' => nil, 'value' => r['val'], 'key' => r['key'] } : { 'reason' => r['reason'], 'value' => 0, 'key' => nil }
      when 'pre' then a.pre_state_error({ 'agg' => i['agg'] }, n(i['s']))
      when 'combine' then a.combine_acc({ 'agg' => i['agg'] }, n(i['pre']), { 'val' => i['value'], 'key' => i['key'] })
      when 'prev' then a.pre_value({ 'agg' => i['agg'] }, n(i['pre']))
      when 'arith' then a.receipt_arithmetic_ok({ 'agg' => i['agg'] }, n(i['r']), i['value'])
      when 'resdig' then a.pcactn_reservation_digest(tw(n(i['p'])))
      when 'rshape' then a.acc_receipt_shape_error(n(i))
      when 'rsig'
        has(i, 'pin') ? a.verify_acc_receipt_signature(tw(n(i['r'])), i['signer'], n(i['pin'])) : a.verify_acc_receipt_signature(tw(n(i['r'])), i['signer'])
      when 'rdig' then a.acc_receipt_digest(tw(n(i['r'])))
      when 'ksshape' then a.sequencer_key_set_shape_error(n(i))
      when 'ksverify'
        has(i, 'rootPqPk') ? a.verify_sequencer_key_set(tw(n(i['k'])), i['root'], i['rootPqPk']) : a.verify_sequencer_key_set(tw(n(i['k'])), i['root'])
      when 'ksdig' then a.sequencer_key_set_digest(tw(n(i['k'])))
      when 'tracked' then a.tracked_key_set_error(tw(n(i['t'])))
      when 'holder'
        f = {}
        f['max_receipt_age_ms'] = i['maxR'] if has(i, 'maxR')
        f['max_keyset_age_ms'] = i['maxK'] if has(i, 'maxK')
        f['tracked'] = n(i['tracked']) if has(i, 'tracked')
        args = [tw(n(i['r'])), tw(n(i['holder'])), tw(n(i['keySets'])), tw(i['now'])]
        f.empty? ? a.verify_receipt_against_holder(*args) : a.verify_receipt_against_holder(*args, tw(f))
      else raise "unknown fn #{c['fn']}"
      end
    end

    def first_bad(fn)
      cases.each do |c|
        next unless c['fn'] == fn
        bad = [[:run, 'internal'], [:pub, 'public twin']].each do |m, tag|
          got = begin
            send(m, c)
          rescue StandardError, SystemStackError => e
            "THREW #{e.class}"
          end
          r = verdict(c, got)
          break "#{tag} #{r}" if r
        end
        return bad if bad.is_a?(String)
      end
      nil
    end

    def verdict(c, got)
      want = c['expect']
      # the reference returns [] for an unknown / missing monitor kind; this verifier raises (monitor_decl_error refuses the kind first)
      return nil if c['fn'] == 'states' && want == [] && got.to_s.include?('StrictError')
      return nil if DiffUtil.norm(got) == DiffUtil.norm(want)
      return nil if DiffUtil.pq_case?(c['in'])

      "#{c['name']}: want #{want.inspect} got #{got.inspect}"
    end
  end

  KillAcc.fns.each do |fn|
    t("kill acc differential (TS oracle): #{fn}") do
      next true if DiffUtil.skip?('intent_v2.rb')
      bad = KillAcc.first_bad(fn)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
