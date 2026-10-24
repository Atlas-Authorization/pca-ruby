# frozen_string_literal: true
# Rule 19 (the committed map, intent_v2.rb) and rule 18 (the signed classifier, intent_wb.rb) differential kills against
# the TS reference: test-data/k042-mapartcls.json.gz = tools/pca-audit/java-mutate/k042-mapartcls-oracle.mjs
# (`[{fn, name, args, out}]`; the Java suite runs the same file). Exact reasons / verdicts / values.
module MutationKill
  module MapClsDiff
    module_function
    def cases = (@cases ||= DiffUtil.load('k042-mapartcls.json.gz'))
    def n(x) = AtlasPca::V2JS.jsnorm(x)
    def iv2 = AtlasPca::IntentV2
    def absent = AtlasPca::V2JS::UNDEF

    def run(c)
      a = c['args']
      case c['fn']
      when 'header' then iv2.map_header_error(n(a[0]))
      when 'cell' then iv2.map_cell_error(n(a[0]))
      when 'metrics' then iv2.map_metrics_error(n(a[0]))
      when 'learner' then iv2.map_learner_error(n(a[0]))
      when 'disclosure' then iv2.map_disclosure_error(n(a[0]))
      when 'verdictwire' then AtlasPca.validate_classifier_verdict_wire(n(a[0]))
      when 'policy' then AtlasPca.validate_classifier_policy(n(a[0]))
      when 'numcells' then iv2.map_num_cells(n(a[0]))
      when 'cellof'
        r = iv2.map_cell_of(n(a[0]), a[1], a.length > 2 ? n(a[2]) : absent)
        r.key?('error') ? nil : { 'cell' => r['cell'], 'flat' => r['flat'] }
      when 'commit' then iv2.map_commit_of_leaves(n(a[0]))
      when 'decide'
        i = n(a[0])
        r = iv2.decide_map_disclosure(i['map_commit'], i['action'], AtlasPca::V2JS.prop(i, 'params'), i['disclosure'], AtlasPca::V2JS.prop(i, 'max_residual_risk_ppm'))
        r['ok'] ? { 'ok' => true, 'cell' => r['cell'], 'p_ppm' => r['p_ppm'], 'residual_risk_ppm' => r['residual_risk_ppm'] } : { 'ok' => false, 'reason' => r['reason'] }
      when 'classify'
        r = AtlasPca.decide_classifier_dimensions(n(a[0]))
        r['ok'] ? { 'ok' => true, 'classes' => r['classes'] } : { 'ok' => false, 'reason' => r['reason'] }
      when 'sigfixture' then true
      else raise "unknown fn #{c['fn']}"
      end
    end

    def fns = cases.map { |c| c['fn'] }.uniq - ['sigfixture']

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

    # the signed verdict fixture: wb_verify_artifact_sig under the pinned key (the Java artifactSignature test)
    def sig_ok?
      f = cases.find { |c| c['fn'] == 'sigfixture' }['args']
      v = n(f[0])
      pk = f[1]
      other = f[2]
      dom = AtlasPca::INTENT_CLASSIFIER_DOMAIN
      vs = ->(d, a, k) { AtlasPca.wb_verify_artifact_sig(d, a, k) }
      return false unless vs.call(dom, v, pk) == true
      return false if vs.call(dom, v, other)
      return false if vs.call("#{dom}x", v, pk)
      return false if vs.call(dom, v.reject { |k, _| k == 'sig' }, pk)
      return false if vs.call(dom, v.merge('sig' => 5), pk)
      return false if vs.call(dom, v, nil)
      return false if vs.call(dom, v, 5)
      return false if vs.call(dom, v.merge('label' => "a\xED\xA0\x80".dup.force_encoding('UTF-8')), pk)
      return false if vs.call(dom, v.merge('v' => 1.5), pk)

      true
    end
  end

  MapClsDiff.fns.each do |fn|
    t("map / classifier differential (TS oracle): #{fn}") do
      next true if DiffUtil.skip?('intent_v2.rb', 'intent_wb.rb')
      bad = MapClsDiff.first_bad(fn)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
  t('classifier artifact signature (TS oracle fixture)') do
    next true if DiffUtil.skip?('intent_wb.rb')
    MapClsDiff.sig_ok?
  end
end
