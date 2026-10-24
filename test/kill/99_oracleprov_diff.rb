# frozen_string_literal: true
# Rule 16 (facts, relational dimensions, offer sets) and rule 17 (provenance, label receipts, flows, read purpose) differential
# kills against the TS reference (oracle-facts.ts, offer-set.ts, label-receipts.ts, param-provenance.ts): test-data/
# k042-oracleprov.json.gz = tools/pca-audit/java-mutate/k042-oracleprov-oracle.mjs (the Java suite runs the same file). The FULL
# result is compared: exact reasons, world / labels / env WITH member order, friction, the read-purpose lists. Only
# intent_wb.rb bears on these rules.
module MutationKill
  module OracleProvDiff
    module_function
    def doc = (@doc ||= DiffUtil.load('k042-oracleprov.json.gz'))
    def cases = doc['cases']
    KINDS = %w[fn ratio flowRule flowAllowed active read world prov].freeze

    # JSON text keeping member ORDER, numbers by value
    def ser(v)
      case v
      when nil then 'null'
      when true then 'true'
      when false then 'false'
      when String then v.dup.force_encoding('UTF-8').inspect + (v.dup.force_encoding('UTF-8').valid_encoding? ? '' : '!')
      when Hash then '{' + v.map { |k, x| "#{ser(k)}:#{ser(x)}" }.join(',') + '}'
      when Array then '[' + v.map { |x| ser(x) }.join(',') + ']'
      when Integer then v.to_s
      when Float then v.finite? && v == v.floor && v.abs < 1e17 ? v.to_i.to_s : v.to_s
      else "<#{v.class}>"
      end
    end

    def run(c)
      case c['kind']
      when 'fn'
        m = { 'validateFactWire' => :validate_fact_wire, 'validateWorldPolicy' => :validate_world_policy,
              'validateOfferPolicy' => :validate_offer_policy, 'validateOfferSetWire' => :validate_offer_set_wire,
              'validateLabelsWire' => :validate_labels_wire, 'validateFlowRules' => :validate_flow_rules,
              'validateProvenancePolicy' => :validate_provenance_policy, 'validateProvWire' => :validate_prov_wire }.fetch(c['fn'])
        cmp(AtlasPca.send(m, c['arg']), c['want'])
      when 'ratio' then cmp(AtlasPca.ratio_ppm(c['a'], c['b']), c['want'])
      when 'flowRule' then cmp(AtlasPca.flow_rule_for(c['rules'], c['cls']), c['want'])
      when 'flowAllowed' then cmp(AtlasPca.flow_allowed(c['rules'], c['cls'], c['origin'], c['aud']), c['want'])
      when 'active' then cmp(AtlasPca.intent_world_active({ 'committed' => c['committed'], 'policy' => c['policy'] }), c['expect'])
      when 'read'
        r = AtlasPca.decide_read_purpose(c['input'])
        e = c['expect']
        cmp({ 'outcome' => r['outcome'], 'minimise' => r['minimise'], 'uncovered' => r['uncovered'] },
            { 'outcome' => e['outcome'], 'minimise' => e['minimise'], 'uncovered' => e['uncovered'] })
      when 'world'
        r = AtlasPca.decide_intent_world(c['input'])
        e = c['expect']
        got = r['ok'] ? ['ok', ser(r['world']), ser(r['single_source'])] : ['fail', r['reason']]
        want = e['ok'] == true ? ['ok', ser(e['world']), ser(e['single_source'])] : ['fail', e['reason']]
        got == want ? nil : [got, want]
      when 'prov'
        r = AtlasPca.decide_param_provenance(c['input'])
        e = c['expect']
        f = ->(x) { [x['outcome'], x['reason'], x['friction'], ser(x['labels']), ser(x['classes']), ser(x['env'])] }
        f.call(r) == f.call(e) ? nil : [f.call(r), f.call(e)]
      else raise "unknown kind #{c['kind']}"
      end
    end

    def cmp(got, want) = ser(got) == ser(want) ? nil : [ser(got), ser(want)]

    def first_bad(kind)
      cases.each do |c|
        next unless c['kind'] == kind
        r = begin
          run(c)
        rescue StandardError, SystemStackError => e
          ["THREW #{e.class}: #{e.message[0, 80]}", '']
        end
        next if r.nil? || DiffUtil.pq_case?(c['name'])
        return "#{c['name']}: got #{r[0]} want #{r[1]}"
      end
      nil
    end
  end

  OracleProvDiff::KINDS.each do |kind|
    t("oracle / provenance differential (TS oracle): #{kind}") do
      next true if DiffUtil.skip?('intent_wb.rb')
      bad = OracleProvDiff.first_bad(kind)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
