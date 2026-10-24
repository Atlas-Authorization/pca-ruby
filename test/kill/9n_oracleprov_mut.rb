# frozen_string_literal: true
# Mutation-style differential for rule 16/17 (oracle_facts / param_provenance, intent_wb.rb) and the predicate evaluator
# (predicates.rb), ported from the Java/Kotlin K042OracleProvMutTest: test-data/k042-oracleprov-mut.json.gz =
# tools/pca-audit/java-mutate/k042-oracleprov-mut-oracle.mjs replaces / deletes / extends every structural path of the
# k042-oracleprov and k042-predjs corpora and records the TS reference result. Same case formats as 99_oracleprov_diff.rb and
# 9c_predjs_diff.rb; an internal-error reason ("... evaluation error (fail closed): X") is compared up to the colon (the exception
# name is language-specific). Cut into groups by case kind; a mutant dies on the first mismatch of the first group that reaches it.
module MutationKill
  module OracleProvMut
    module_function
    CHUNK = 2500
    FILES_OP = %w[intent_wb.rb atlas_pca.rb].freeze
    FILES_PRED = %w[predicates.rb safe_regex.rb].freeze
    def doc = (@doc ||= DiffUtil.load('k042-oracleprov-mut.json.gz'))
    def cut(s) = s.to_s.gsub(/evaluation error \(fail closed\): [A-Za-z:]+/, 'evaluation error (fail closed): ')

    def op_groups
      @op_groups ||= doc['oracleprov'].group_by { |c| c['kind'] }.flat_map do |k, cs|
        cs.each_slice(CHUNK).each_with_index.map { |part, i| ["#{k}##{i + 1}", part] }
      end
    end

    def op_bad(cs)
      cs.each do |c|
        r = begin
          OracleProvDiff.run(c)
        rescue StandardError, SystemStackError => e
          ["THREW #{e.class}: #{e.message[0, 80]}", '']
        end
        next if r.nil? || DiffUtil.pq_case?(c['name'])
        next if cut(r[0]) == cut(r[1])

        return "#{c['name']}: got #{r[0]} want #{r[1]}"
      end
      nil
    end

    def pj = doc['predjs']
    def j(t) = AtlasPca.parse_json_text(t)
    def ctx(name) = j(pj['ctx'].fetch(name))

    def pred_groups
      @pred_groups ||= %w[tri preds].flat_map do |k|
        pj[k].each_slice(400).each_with_index.map { |part, i| ["#{k}##{i + 1}", k, part] }
      end
    end

    def tri_bad(cs)
      cs.each do |c|
        cond = j(c['cond'])
        got = AtlasPca.evaluate_condition_tri(cond, ctx(c['ctx']))
        return "tri #{c['name']}: want #{c['tri']} got #{got}" unless got == c['tri']
      end
      nil
    end

    def preds_bad(cs)
      cs.each do |c|
        preds = j(c['preds'])
        r = AtlasPca.evaluate_predicates(preds, ctx(c['ctx']))
        return "preds #{c['name']}: allowed want #{c['allowed']} got #{r['allowed']}" unless r['allowed'] == c['allowed']

        next unless preds.is_a?(Array)

        preds.each_with_index do |p, i|
          m = AtlasPca.predicate_matches(p, ctx(c['ctx']))
          return "preds #{c['name']}[#{i}]: want #{c['each'][i]} got #{m}" unless m == c['each'][i]
        end
      end
      nil
    end
  end

  OracleProvMut.op_groups.each do |g, cs|
    t("oracle / provenance mutation differential (TS oracle): #{g}") do
      next true if DiffUtil.skip?(*OracleProvMut::FILES_OP)
      bad = OracleProvMut.op_bad(cs)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
  OracleProvMut.pred_groups.each do |g, k, cs|
    t("predicate mutation differential (TS oracle): #{g}") do
      next true if DiffUtil.skip?(*OracleProvMut::FILES_PRED)
      bad = OracleProvMut.send(:"#{k}_bad", cs)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
