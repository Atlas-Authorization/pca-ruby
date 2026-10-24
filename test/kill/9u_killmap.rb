# frozen_string_literal: true
# Rule 19 (the committed map) and rule 18 (the signed classifier) targeted differential kills: test-data/killMap.json.gz (gzip of the Kotlin file) =
# tools/pca-audit/kotlin-mutate/killMap-oracle-gen.mjs (the Kotlin KillMapTest's golden file: the k042-mapartcls cases plus
# boundary cases, and 465 RFC 9162 audit-path cases). Same case format / runner as 98_mapartcls_diff.rb (MapClsDiff.run).
module MutationKill
  module KillMap
    module_function
    def cases = (@cases ||= DiffUtil.load('killMap.json.gz'))
    def fns = cases.map { |c| c['fn'] }.uniq - ['sigfixture']

    def run(c)
      return MapClsDiff.run(c) unless c['fn'] == 'rootpath'

      a = c['args']
      path = a[3].map { |x| AtlasPca.b64d(x, 32) }
      r = AtlasPca::IntentV2.map_root_from_path(a[0], a[1], AtlasPca.b64d(a[2], 32), path)
      r && AtlasPca.b64e(r)
    end

    # The same case through the PUBLIC wrapper (94a_pub_twin.rb): the arguments it normalizes as their twins, an absent
    # optional argument omitted. :none for the classifier (intent_wb.rb) cases, which have no Intent Layer v2 wrapper.
    def pub(c)
      a = c['args']
      x = AtlasPca
      n = ->(v) { AtlasPca::V2JS.jsnorm(v) }
      tw = ->(v) { PubTwin.twin(n.call(v)) }
      case c['fn']
      when 'header' then x.map_header_error(tw.call(a[0]))
      when 'cell' then x.map_cell_error(tw.call(a[0]))
      when 'metrics' then x.map_metrics_error(tw.call(a[0]))
      when 'learner' then x.map_learner_error(tw.call(a[0]))
      when 'disclosure' then x.map_disclosure_error(tw.call(a[0]))
      when 'numcells' then x.map_num_cells(tw.call(a[0]))
      when 'cellof'
        r = x.map_cell_of(tw.call(a[0]), PubTwin.twin(a[1]), a.length > 2 ? tw.call(a[2]) : AtlasPca::V2JS::UNDEF)
        r.key?('error') ? nil : { 'cell' => r['cell'], 'flat' => r['flat'] }
      when 'commit' then x.map_commit_of_leaves(tw.call(a[0]))
      when 'decide'
        i = n.call(a[0])
        kw = { map_commit: i['map_commit'], action: PubTwin.twin(i['action']), disclosure: PubTwin.twin(i['disclosure']) }
        kw[:params] = PubTwin.twin(i['params']) if i.key?('params')
        kw[:max_residual_risk_ppm] = PubTwin.twin(i['max_residual_risk_ppm']) if i.key?('max_residual_risk_ppm')
        r = x.decide_map_disclosure(**kw)
        out = r['ok'] ? { 'ok' => true, 'cell' => r['cell'], 'p_ppm' => r['p_ppm'], 'residual_risk_ppm' => r['residual_risk_ppm'] } : { 'ok' => false, 'reason' => r['reason'] }
        # primitives.intent_map reads the same members (an absent / null action is {} there: those cases are not compared)
        if %w[map_commit action disclosure].all? { |k| i.key?(k) } && !i['action'].nil?
          q = x.intent_map_primitive(PubTwin.twin(i))
          q = q['ok'] ? { 'ok' => true, 'cell' => q['cell'], 'p_ppm' => q['p_ppm'], 'residual_risk_ppm' => q['residual_risk_ppm'] } : { 'ok' => false, 'reason' => q['reason'] }
          return ['primitive differs', q] unless DiffUtil.norm(q) == DiffUtil.norm(out)
        end
        out
      when 'rootpath'
        path = a[3].map { |v| AtlasPca.b64d(v, 32) }
        r = x.map_root_from_path(a[0], a[1], AtlasPca.b64d(a[2], 32), path)
        r && AtlasPca.b64e(r)
      else :none
      end
    end

    # a fail-closed reason ends with the language's own canonicalizer / encoding message: compare up to that prefix
    def fail_closed_same?(want, got)
      return false unless want.is_a?(Hash) && got.is_a?(Hash) && want['reason'].is_a?(String) && got['reason'].is_a?(String)

      i = want['reason'].index('(fail closed): ')
      !i.nil? && got['reason'].start_with?(want['reason'][0, i + 15]) && want.reject { |k, _| k == 'reason' } == got.reject { |k, _| k == 'reason' }
    end

    def first_bad(fn)
      cases.each do |c|
        next unless c['fn'] == fn
        [[:run, 'internal'], [:pub, 'public twin']].each do |m, tag|
          got = begin
            send(m, c)
          rescue StandardError, SystemStackError => e
            "THREW #{e.class}"
          end
          next if got == :none
          next if DiffUtil.norm(got) == DiffUtil.norm(c['out'])
          next if fail_closed_same?(c['out'], got)
          next if DiffUtil.pq_case?(c['args'])
          return "#{tag} #{c['name']}: want #{c['out'].inspect} got #{got.inspect}"
        end
      end
      nil
    end
  end

  KillMap.fns.each do |fn|
    t("kill map / classifier differential (TS oracle): #{fn}") do
      next true if DiffUtil.skip?('intent_v2.rb', 'intent_wb.rb')
      bad = KillMap.first_bad(fn)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
