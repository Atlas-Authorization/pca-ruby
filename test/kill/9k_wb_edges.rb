# frozen_string_literal: true
# Exact edge-input kills for intent_wb.rb helpers called directly: offer_matches, query_covers, wb_subject_of, flow_rule_for,
# flow_allowed, wb_artifact_suite_error, wb_resolve, wb_verify_artifact_sig (on the TS-signed verdict fixture of the mapartcls
# oracle). Every refusal must be the exact false / nil. AtlasPca is resolved at CALL time.
module MutationKill
  module WbEdge
    module_function
    def w = AtlasPca
    def u = AtlasPca::WB_UNDEF
    def fix = (@fix ||= begin
      f = DiffUtil.load('k042-mapartcls.json.gz').find { |c| c['fn'] == 'sigfixture' }['args']
      { v: AtlasPca::V2JS.jsnorm(f[0]), pk: f[1], other: f[2] }
    end)
    def f?(label, got) = got.equal?(false) ? nil : "#{label}: want false got #{got.inspect}"
    def n?(label, got) = got.nil? ? nil : "#{label}: want nil got #{got.inspect}"
    def t?(label, got) = got.equal?(true) ? nil : "#{label}: want true got #{got.inspect}"
    def e?(label, got, want) = got == want ? nil : "#{label}: want #{want.inspect} got #{got.inspect}"

    def run
      r = []
      # offer_matches / query_covers
      r << t?('om', w.offer_matches({ 'a' => 1, 'b' => 'x' }, { 'a' => 1 })) << t?('om empty', w.offer_matches({}, {})) << t?('om 1.0', w.offer_matches({ 'a' => 1 }, { 'a' => 1.0 }))
      r << f?('om miss', w.offer_matches({}, { 'a' => 1 })) << f?('om diff', w.offer_matches({ 'a' => 2 }, { 'a' => 1 })) << f?('om type', w.offer_matches({ 'a' => '1' }, { 'a' => 1 }))
      r << f?('om nil key', w.offer_matches({ 'a' => nil }, { 'a' => 0 })) << t?('om nil val', w.offer_matches({ 'a' => nil }, { 'a' => nil }))
      [nil, 5, 'x', []].each { |v| r << f?("om offer #{v.inspect}", w.offer_matches(v, {})) << f?("om f #{v.inspect}", w.offer_matches({}, v)) }
      r << t?('qc', w.query_covers({ 'a' => 1 }, { 'a' => 1, 'b' => 2 })) << t?('qc empty', w.query_covers({}, {})) << t?('qc empty q', w.query_covers({}, { 'a' => 1 }))
      r << f?('qc miss', w.query_covers({ 'a' => 1 }, {})) << f?('qc diff', w.query_covers({ 'a' => 1 }, { 'a' => 2 })) << f?('qc type', w.query_covers({ 'a' => 1 }, { 'a' => '1' }))
      r << f?('qc nil', w.query_covers({ 'a' => nil }, {})) << t?('qc nil=nil', w.query_covers({ 'a' => nil }, { 'a' => nil }))
      [nil, 5, 'x', []].each { |v| r << f?("qc q #{v.inspect}", w.query_covers(v, {})) << f?("qc fq #{v.inspect}", w.query_covers({}, v)) }
      # wb_subject_of
      act = { 'resource' => 'res', 'verb' => 'vrb' }
      params = { 'a' => 's', 'n' => 5, 'o' => { 'k' => 'deep' } }
      r << e?('subj resource', w.wb_subject_of(act, params, 'action.resource'), 'res') << e?('subj verb', w.wb_subject_of(act, params, 'action.verb'), 'vrb')
      r << e?('subj param', w.wb_subject_of(act, params, 'action.params.a'), 's') << e?('subj deep', w.wb_subject_of(act, params, 'action.params.o.k'), 'deep')
      r << n?('subj res nonstr', w.wb_subject_of({ 'resource' => 5 }, params, 'action.resource')) << n?('subj res absent', w.wb_subject_of({}, params, 'action.resource'))
      r << n?('subj verb nonstr', w.wb_subject_of({ 'verb' => 5 }, params, 'action.verb')) << n?('subj verb absent', w.wb_subject_of({}, params, 'action.verb'))
      r << n?('subj num', w.wb_subject_of(act, params, 'action.params.n')) << n?('subj obj', w.wb_subject_of(act, params, 'action.params.o')) << n?('subj miss', w.wb_subject_of(act, params, 'action.params.z'))
      r << n?('subj other root', w.wb_subject_of(act, params, 'subject.id')) << n?('subj proto', w.wb_subject_of(act, { '__proto__' => 's' }, 'action.params.__proto__'))
      begin
        w.wb_subject_of(nil, params, 'action.resource')
        r << 'subj nil action did not raise'
      rescue TypeError
        nil
      end
      # wb_resolve
      r << e?('res ok', w.wb_resolve(params, 'action.params.a'), [true, 's']) << e?('res deep', w.wb_resolve(params, 'action.params.o.k'), [true, 'deep'])
      r << e?('res obj', w.wb_resolve(params, 'action.params.o'), [true, { 'k' => 'deep' }]) << e?('res nilval', w.wb_resolve({ 'a' => nil }, 'action.params.a'), [true, nil])
      ['action.params', 'action.params.', 'action.resource', 'x', '', 'action.params.z', 'action.params.a.b', 'action.params.o.z', 'action.params.__proto__', 'action.params.a..b',
       'action.params.n.x', 'action.param.a'].each { |p| r << e?("res #{p}", w.wb_resolve(params, p), [false, nil]) }
      r << e?('res nonhash params', w.wb_resolve(5, 'action.params.a'), [false, nil]) << e?('res nonstr path', w.wb_resolve(params, 5), [false, nil])
      # flow rules
      rules = { 'pii.*' => ['a'], 'pii.identity.*' => ['b'], 'pii.identity' => ['c'], '*' => ['z'], 'fin.*' => 'notarray' }
      r << e?('fr exact', w.flow_rule_for(rules, 'pii.identity'), 'pii.identity') << e?('fr longest', w.flow_rule_for(rules, 'pii.identity.x'), 'pii.identity.*')
      r << e?('fr prefix', w.flow_rule_for(rules, 'pii.contact'), 'pii.*') << e?('fr star', w.flow_rule_for(rules, 'other'), '*') << e?('fr piix', w.flow_rule_for(rules, 'piix'), '*')
      r << e?('fr pii', w.flow_rule_for(rules, 'pii'), '*') << e?('fr pii.', w.flow_rule_for(rules, 'pii.'), 'pii.*')
      r << n?('fr none', w.flow_rule_for({ 'pii.*' => [] }, 'other')) << n?('fr nonhash', w.flow_rule_for(nil, 'a')) << n?('fr arr', w.flow_rule_for([], 'a')) << n?('fr cls nonstr', w.flow_rule_for(rules, 5))
      r << n?('fr cls nil', w.flow_rule_for(rules, nil)) << n?('fr empty', w.flow_rule_for({}, 'a'))
      r << e?('fr tie', w.flow_rule_for({ 'ab.*' => [], 'ab.*x' => [] }, 'ab.c'), 'ab.*')
      r << e?('fr longer wins', w.flow_rule_for({ 'a.*' => [], 'a.b.*' => [] }, 'a.b.c'), 'a.b.*') << e?('fr longer wins rev', w.flow_rule_for({ 'a.b.*' => [], 'a.*' => [] }, 'a.b.c'), 'a.b.*')
      r << e?('fr equal len keeps first', w.flow_rule_for({ 'ab.*' => [], 'ac.*' => [] }, 'ab.x'), 'ab.*')
      # flow_allowed
      r << t?('fa origin', w.flow_allowed(rules, 'pii.identity', 'o', 'o')) << t?('fa public', w.flow_allowed({}, 'public', 'o', 'x')) << t?('fa listed', w.flow_allowed(rules, 'pii.identity', 'o', 'c'))
      r << f?('fa other sink', w.flow_allowed(rules, 'pii.identity', 'o', 'a')) << t?('fa prefix', w.flow_allowed(rules, 'pii.contact', 'o', 'a')) << t?('fa star', w.flow_allowed(rules, 'zz', 'o', 'z'))
      r << f?('fa nomatch', w.flow_allowed({ 'pii.*' => ['a'] }, 'zz', 'o', 'a')) << f?('fa notarray', w.flow_allowed(rules, 'fin.card', 'o', 'notarray')) << f?('fa publicx', w.flow_allowed({}, 'publicx', 'o', 'x'))
      [[5, 'o', 'a'], ['c', 5, 'a'], ['c', 'o', 5], [nil, 'o', 'a'], ['c', nil, 'a'], ['c', 'o', nil]].each_with_index { |(c, o, a), i| r << f?("fa types #{i}", w.flow_allowed({ '*' => ['a'] }, c, o, a)) }
      r << f?('fa nonhash rules', w.flow_allowed(nil, 'c', 'o', 'a')) << f?('fa origin nonstr', w.flow_allowed({ '*' => [5] }, 'c', 'o', 5))
      # wb_artifact_suite_error
      s = ->(a) { w.wb_artifact_suite_error(a) }
      r << e?('suite nonobj', s.call(5), 'artifact must be an object') << e?('suite nil', s.call(nil), 'artifact must be an object') << e?('suite arr', s.call([]), 'artifact must be an object')
      r << e?('suite none', s.call({}), nil) << e?('suite ed', s.call({ 'alg' => 'ed25519' }), nil) << e?('suite alg num', s.call({ 'alg' => 5 }), 'alg must be a string') << e?('suite alg nil', s.call({ 'alg' => nil }), 'alg must be a string')
      r << e?('suite unsupported', s.call({ 'alg' => 'rot13' }), "#{AtlasPca::UNSUPPORTED_SUITE}: 'rot13'")
      r << e?('suite pq_pk', s.call({ 'pq_pk' => 5 }), 'pq_pk must be a string') << e?('suite pq_sig', s.call({ 'pq_sig' => 5 }), 'pq_sig must be a string') << e?('suite pq_pk nil', s.call({ 'pq_pk' => nil }), 'pq_pk must be a string')
      r << e?('suite ed pq_pk', s.call({ 'pq_pk' => 'x' }), 'an ed25519 artifact must not carry pq_pk / pq_sig') << e?('suite ed pq_sig', s.call({ 'alg' => 'ed25519', 'pq_sig' => 'x' }), 'an ed25519 artifact must not carry pq_pk / pq_sig')
      # wb_verify_artifact_sig
      v = fix[:v]
      pk = fix[:pk]
      dom = AtlasPca::INTENT_CLASSIFIER_DOMAIN
      vs = ->(d, a, p) { w.wb_verify_artifact_sig(d, a, p) }
      r << t?('sig ok', vs.call(dom, v, pk)) << t?('sig ok pin hash', vs.call(dom, v, { 'pk' => pk })) << f?('sig other key', vs.call(dom, v, fix[:other])) << f?('sig other domain', vs.call(dom + 'x', v, pk))
      r << f?('sig no sig', vs.call(dom, v.reject { |k, _| k == 'sig' }, pk)) << f?('sig sig num', vs.call(dom, v.merge('sig' => 5), pk)) << f?('sig sig nil', vs.call(dom, v.merge('sig' => nil), pk))
      r << f?('sig no pin', vs.call(dom, v, nil)) << f?('sig pin num', vs.call(dom, v, 5)) << f?('sig pin hash nopk', vs.call(dom, v, {})) << f?('sig pin pk num', vs.call(dom, v, { 'pk' => 5 }))
      r << f?('sig tampered', vs.call(dom, v.merge('label' => 'zz'), pk)) << f?('sig lone', vs.call(dom, v.merge('label' => "a\xED\xA0\x80".dup.force_encoding('UTF-8')), pk)) << f?('sig 1.5', vs.call(dom, v.merge('v' => 1.5), pk))
      r << f?('sig alg unsupported', vs.call(dom, v.merge('alg' => 'rot13'), pk)) << f?('sig alg num', vs.call(dom, v.merge('alg' => 5), pk)) << f?('sig artifact nil', vs.call(dom, nil, pk))
      r << f?('sig pq suite no pq key', vs.call(dom, v.merge('alg' => 'ml-dsa-65'), pk))
      r.compact.first
    end
  end

  t('intent_wb edge inputs: exact false / nil / values') do
    next true if DiffUtil.skip?('intent_wb.rb')
    bad = WbEdge.run
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
end
