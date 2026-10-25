# frozen_string_literal: true
# The predicate evaluator (predicates.rb) differential kills against the TS reference (predicates.ts + hash.ts + JavaScript
# number semantics): test-data/k042-predjs.json = tools/pca-audit/java-mutate/k042-predjs-oracle.mjs (the Java suite runs the
# same file; every input is JSON TEXT so both sides parse the same lexemes: 1e400, -0, lone surrogates). The member_of closure
# caps (chain / fan) are rebuilt from the same recipes as the oracle. Bears on predicates.rb and the regex engine it calls.
module MutationKill
  module PredJsDiff
    module_function
    def g = (@g ||= DiffUtil.parse(DiffUtil.read('k042-predjs.json')))
    def j(t) = AtlasPca.parse_json_text(t)
    def ctx(name) = j(g['ctx'].fetch(name))
    FILES = %w[predicates.rb safe_regex.rb].freeze

    def first_bad(kind)
      send(:"check_#{kind}")
    end

    def check_tri
      g['tri'].each do |c|
        cond = j(c['cond'])
        got = AtlasPca.evaluate_condition_tri(cond, ctx(c['ctx']))
        gotb = AtlasPca.evaluate_condition(cond, ctx(c['ctx']))
        return "tri #{c['name']}: want #{c['tri']} got #{got}/#{gotb}" unless got == c['tri'] && gotb == (c['tri'] == 'true')
      end
      nil
    end

    def check_preds
      g['preds'].each do |c|
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

    def check_eq
      g['eq'].each do |c|
        got = AtlasPca::Predicates.deep_eq?(j(c['a']), j(c['b']))
        return "eq #{c['a']} == #{c['b']}: want #{c['eq']} got #{got}" unless got == c['eq']
      end
      nil
    end

    # ECMAScript Number::toString of every finite number the oracle lists (a -0 prints "0")
    def check_nums
      g['nums'].each do |c|
        next unless c['finite']
        want = c['js'] == '-0' ? '0' : c['js']
        got = AtlasPca::Predicates.js_number_string(j(c['raw']).to_f)
        return "nums #{c['raw']}: want #{want} got #{got}" unless got == want
      end
      nil
    end

    def check_cmp
      g['cmp'].each do |c|
        got = AtlasPca::Predicates.order_utf8(c['a'], c['b'])
        return "cmp #{c['a'].inspect} vs #{c['b'].inspect}: want #{c['sign']} got #{got.inspect}" unless got == c['sign']
      end
      nil
    end

    # member_of closure caps: a 10005-node chain and a 100x100 fan, as the oracle builds them
    def mo(v) = { 'field' => 'subject.id', 'op' => 'member_of', 'collection' => 'subject.g', 'value' => v }
    def check_closure
      grp = {}
      10_005.times { |i| grp["n#{i}"] = "n#{i + 1}" }
      cc = { 'action' => { 'verb' => 'v', 'resource' => 'r' }, 'subject' => { 'id' => 'n0', 'g' => grp } }
      g['chain'].each do |k, want|
        got = AtlasPca.evaluate_condition_tri(mo(k), cc)
        return "chain #{k}: want #{want} got #{got}" unless got == want
      end
      cs = Array.new(100) { |x| "c#{x}" }
      grf = { 's' => Array.new(100) { |x| "a#{x}" } }
      100.times { |i| grf["a#{i}"] = cs }
      grf['c0'] = 'e'
      grf['e'] = 't'
      fc = { 'action' => { 'verb' => 'v', 'resource' => 'r' }, 'subject' => { 'id' => 's', 'g' => grf } }
      g['fan'].each do |k, want|
        got = AtlasPca.evaluate_condition_tri(mo(k), fc)
        return "fan #{k}: want #{want} got #{got}" unless got == want
      end
      nil
    end
  end

  %w[tri preds eq nums cmp closure].each do |kind|
    t("predicate evaluator differential (TS oracle): #{kind}") do
      next true if DiffUtil.skip?(*PredJsDiff::FILES)
      bad = PredJsDiff.first_bad(kind)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
