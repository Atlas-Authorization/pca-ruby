# frozen_string_literal: true
# r11 kills for lib/atlas_pca/intent_wb.rb (survivors of mutation run 39902549441): the JS value helpers against their
# documented JavaScript semantics (String(number) from node, ===, Object.keys order, Number.isSafeInteger, startsWith on
# bytes, split('.')), the strict canonicalizer's depth model, the total helpers' exact false / nil, the policy validators'
# byte-level duplicate checks, and the decide functions' totality (a non-object input, an input that raises: the reason
# carries the exception's #message) and their deterministic (sorted) reason order. Names start with `rubywb` (MUT_QUICK).
module MutationKill
  module RubyWbWb
    module_function

    def a = AtlasPca
    def u = AtlasPca::WB_UNDEF
    D = AtlasPca.b64e("\x01".b * 32)
    D2 = AtlasPca.b64e("\x02".b * 32)

    class OddError < StandardError
      def message = 'the message'
      def to_s = 'not the message'
    end

    # A Hash whose member lookups raise OddError (the decide functions read members with key?).
    class OddHash < Hash
      def key?(_k) = raise(OddError)
    end

    # String(x) in JavaScript (node), for the Number values below
    JS_NUM = [[123, '123'], [-5, '-5'], [0, '0'], [0.0, '0'], [-0.0, '0'], [5.0, '5'], [1e20, '100000000000000000000'],
              [1e21, '1e+21'], [1.5, '1.5'], [0.1, '0.1'], [1e-7, '1e-7'], [1.5e-7, '1.5e-7'], [0.000001, '0.000001'],
              [0.0000015, '0.0000015'], [1.2345e25, '1.2345e+25'], [123.456, '123.456'], [1e300, '1e+300'],
              [-1.5e-10, '-1.5e-10'], [2.5e21, '2.5e+21'], [0.5, '0.5'], [100.5, '100.5'],
              [1.7976931348623157e308, '1.7976931348623157e+308'], [5e-324, '5e-324'],
              [123_456_789_012_345_680_000.0, '123456789012345680000'], [1.25e20, '125000000000000000000'], [-0.001, '-0.001'],
              [12.345678, '12.345678'], [0.000001234, '0.000001234'], [9.5e20, '950000000000000000000'], [1.5e21, '1.5e+21'],
              [4.35, '4.35'], [-2.5e-7, '-2.5e-7'], [1e100, '1e+100'], [3e-7, '3e-7'], [2**60, '1152921504606847000'],
              [2**53 + 1, '9007199254740992'], [2**53 - 1, '9007199254740991'], [-(2**60), '-1152921504606847000'],
              [10**21, '1e+21'], [Float::NAN, 'NaN'], [Float::INFINITY, 'Infinity'], [-Float::INFINITY, '-Infinity']].freeze

    def nums
      JS_NUM.each { |x, w| return "js_num_str(#{x.inspect}) = #{a.wb_js_num_str(x).inspect}, want #{w}" unless a.wb_js_num_str(x) == w }
      nil
    end

    def strict_eq
      h = {}
      t = [[u, u, true], [u, nil, false], [nil, u, false], [nil, nil, true], [nil, false, false], [false, nil, false],
           [true, true, true], [false, false, true], [true, false, false], [true, 1, false], [1, true, false], [1, 1.0, true],
           [1, '1', false], ['1', 1, false], ['a', 'a', true], ['a'.b, 'a', true], ["é", "é".b, true],
           ["é".b, "é", true], [{}, {}, false], [h, h, true], [Float::NAN, Float::NAN, false], [0.0, -0.0, true],
           [[1], [1], false], ['a', nil, false], [nil, 'a', false], ['x', 5, false], [5, 'x', false], [u, 1, false], [1, u, false],
           ['a', 'b', false], [false, true, false], [nil, 0, false], [0, nil, false], [true, 'true', false], ['true', true, false]]
      t.each { |x, y, w| return "strict_eq(#{x.inspect}, #{y.inspect})" unless a.wb_strict_eq?(x, y).equal?(w) }
      nil
    end

    def scalars
      return 'neg_zero' unless a.wb_neg_zero?(-0.0) == true && [0.0, -5.0, 0, nil, 'x', -1].all? { |v| a.wb_neg_zero?(v).equal?(false) }
      return 'safe_int -2^60' unless a.wb_safe_int?(-(2**60)) == false && a.wb_safe_int?(-(2**53 - 1)) == true
      return 'safe_int -2.0^60' unless a.wb_safe_int?(-(2.0**60)) == false && a.wb_safe_int?(-4.0) == true
      return 'wb_int' unless a.wb_int('x') == 'x' && a.wb_int(nil).nil? && a.wb_int(5.0).eql?(5) && a.wb_int(7).eql?(7)
      return 'present? of a Ruby class' unless a.wb_present?(Object) == true && a.wb_present?(u) == false && !u.is_a?(Module)
      bad = "1\xff".dup.force_encoding('UTF-8')
      h = { 'b' => 1, '2' => 1, '10' => 1, '1' => 1, '01' => 1, '4294967294' => 1, '4294967295' => 1, :sym => 1, bad => 1, 5 => 1, 'a' => 1 }
      want = ['1', '2', '10', '4294967294', 'b', '01', '4294967295', :sym, bad, 5, 'a']
      return "js_keys #{a.wb_js_keys(h).inspect}" unless a.wb_js_keys(h) == want
      return 'starts? bytes' unless a.wb_starts?("éx", "é") == true && a.wb_starts?("éx".b, "é") == true && a.wb_starts?(5, 'a').equal?(false)
      inv = "a\xff.b".dup.force_encoding('UTF-8')
      sp = a.wb_split_dot(inv)
      return "split_dot invalid #{sp.inspect}" unless sp.map(&:b) == ["a\xff".b, 'b'] && sp.all? { |x| x.encoding == Encoding::UTF_8 }
      sp = a.wb_split_dot("é.x.")
      return 'split_dot utf-8' unless sp == ["é", 'x', ''] && sp.all? { |x| x.encoding == Encoding::UTF_8 }
      return 'split_dot empty' unless a.wb_split_dot('') == ['']
      return 'digest? nil' unless a.wb_digest?(nil).equal?(false) && a.wb_digest?(D) == true
      return 'closed_members where' unless a.wb_closed_members({ 'x' => 1 }, []) == "unknown member 'object.x'"
      return 'suite_implemented? nil' unless a.wb_suite_implemented?(nil).equal?(false) && a.wb_suite_implemented?('ed25519') == true
      body = { 'v' => "é" }
      return 'artifact_message utf-8 domain' unless a.wb_artifact_message("dé\x00", body) == "dé\x00".b + a.wb_canon_bytes(body)
      nil
    end

    def jsnorm
      deep = ->(n, kind) { n.times.reduce(1) { |x, _| kind == :a ? [x] : { 'k' => x } } }
      m = AtlasPca::MAX_JSON_DEPTH
      %i[a h].each do |k|
        return "jsnorm #{k} at max" unless a.wb_jsnorm(deep.call(m, k)) == deep.call(m, k)
        begin
          a.wb_jsnorm(deep.call(m + 1, k))
          return "jsnorm #{k} over max accepted"
        rescue AtlasPca::Malformed => e
          return "jsnorm #{k} message #{e.message.inspect}" unless e.message == 'canonicalize: nesting too deep'
        end
      end
      return 'jsnorm -2^60' unless a.wb_jsnorm(-(2.0**60)).is_a?(Float) && a.wb_jsnorm(-5.0).eql?(-5)
      return 'jsnorm nested values' unless a.wb_jsnorm({ 'a' => [2.0, { 'b' => 3.0 }] }) == { 'a' => [2, { 'b' => 3 }] }
      nil
    end

    def paths
      return 'param_path? exact false' unless a.param_path?('x').equal?(false) && a.param_path?(5).equal?(false)
      return 'param_path? 8' unless a.param_path?('action.params.' + (['a'] * 8).join('.')) == true
      return 'param_path? 9' unless a.param_path?('action.params.' + (['a'] * 9).join('.')) == false
      r = { 'a' => 1 }
      return 'set_nested existing leaf' unless a.wb_set_nested(r, 'a', 2).equal?(false) && r == { 'a' => 1 }
      r = { 'a' => 1 }
      return 'set_nested through a leaf' unless a.wb_set_nested(r, 'a.b', 2).equal?(false) && r == { 'a' => 1 }
      r = {}
      return 'set_nested ok' unless a.wb_set_nested(r, 'a.b', 2) == true && r == { 'a' => { 'b' => 2 } }
      begin
        a.lower_median([])
        return 'lower_median empty'
      rescue ArgumentError => e
        return 'lower_median message' unless e.message == 'lowerMedian: empty'
      end
      return 'taint_level? nil' unless a.taint_level?(nil).equal?(false)
      return 'taint_rank unknown' unless a.taint_rank('bogus') == 4 && a.taint_rank('web') == 3
      return 'flow_allowed non-String class' unless a.flow_allowed({}, 5, 'x', 'x').equal?(false)
      return 'parse_label_ref' unless a.parse_label_ref("pca-labels:#{D}#f#g") == { 'receipt' => D, 'field' => 'f#g' }
      bad = "pca-labels:\xff#x".dup.force_encoding('UTF-8')
      return 'parse_label_ref invalid encoding' unless a.parse_label_ref(bad).nil?
      return 'wb_put undefined' unless a.wb_put({}, 'a', u) == {} && a.wb_put({}, 'a', nil) == { 'a' => nil }
      return 'judge_pin' unless a.wb_judge_pin({}, 'j') == { 'pk' => 'j' } && a.wb_judge_pin({ 'pq_keys' => { 'j' => 'q' } }, 'j') == { 'pk' => 'j', 'pq_pk' => 'q' }
      return 'provenance_active non-Hash' unless a.intent_provenance_active(5).equal?(false)
      nil
    end

    def labels_receipt
      { 'v' => 1, 'kind' => 'pca-labels', 'site' => 's', 'session' => D, 'response_digest' => D,
        'fields' => { 'f' => { 'class' => 'pii', 'value_digest' => D } }, 'issued_at' => 1, 'kid' => 'k', 'sig' => 'x' }
    end

    def validators
      l = labels_receipt
      return "labels wire #{a.validate_labels_wire(l).inspect}" unless a.validate_labels_wire(l).nil?
      return 'verify_labels keys' unless a.verify_labels(l, 5) == 'label keys must be an array'
      return 'verify_labels wire first' unless a.verify_labels(5, 5) == a.validate_labels_wire(5)
      # byte-level duplicate labels (a UTF-8 and a binary spelling of the same bytes)
      cl = { 'id' => 'c', 'param' => 'action.params.x', 'labels' => ["é", "é".b], 'keys' => [D], 'k' => 1 }
      got = a.validate_classifier_policy({ 'classifiers' => [cl] })
      return "classifier byte-duplicate labels #{got.inspect}" unless got == "classifier 'c': labels must be distinct non-empty strings"
      # read purpose: on_uncovered / purpose / field typing, byte-level de-duplication
      rp = ->(x) { a.decide_read_purpose(x) }
      mal = { 'outcome' => 'deny', 'minimise' => [], 'uncovered' => [] }
      f = [{ 'path' => 'p', 'class' => 'pii' }]
      return 'read purpose on_uncovered' unless rp.call({ 'fields' => f, 'purpose' => 'x', 'coverage' => {}, 'on_uncovered' => 'bogus' }) == mal
      return 'read purpose purpose' unless rp.call({ 'fields' => f, 'purpose' => 5, 'coverage' => {} }) == mal
      return 'read purpose path' unless rp.call({ 'fields' => [{ 'path' => 5, 'class' => 'pii' }], 'purpose' => 'x', 'coverage' => {} }) == mal
      return 'read purpose path (public)' unless rp.call({ 'fields' => [{ 'path' => 5, 'class' => 'public' }], 'purpose' => 'x', 'coverage' => {} }) == mal
      two = [{ 'path' => "é", 'class' => 'pii' }, { 'path' => "é".b, 'class' => 'pii' }]
      got = rp.call({ 'fields' => two, 'purpose' => 'x', 'coverage' => {} })
      return "read purpose byte dedup #{got.inspect}" unless got['outcome'] == 'question' && got['uncovered'].length == 1
      nil
    end

    def totality
      fw = ->(r) { { 'ok' => false, 'reason' => "facts: #{r}" } }
      odd = OddHash.new
      return 'offer_set non-Hash' unless a.decide_offer_set(5) == { 'ok' => false, 'reason' => 'offers: input must be an object' }
      return 'offer_set raising' unless a.decide_offer_set(odd) == { 'ok' => false, 'reason' => 'offers: evaluation error (fail closed): the message' }
      return 'world raising' unless a.decide_intent_world(odd) == fw.call('evaluation error (fail closed): the message')
      pd = a.decide_param_provenance(odd)
      return "provenance raising #{pd.inspect}" unless pd == { 'outcome' => 'deny', 'reason' => 'provenance: evaluation error (fail closed): the message', 'labels' => {}, 'classes' => {}, 'env' => {} }
      cf = ->(r) { { 'ok' => false, 'reason' => "classes: #{r}" } }
      return 'classifier non-Hash' unless a.decide_classifier_dimensions(5) == cf.call('input must be an object')
      return 'classifier raising' unless a.decide_classifier_dimensions(odd) == cf.call('evaluation error (fail closed): the message')
      return 'context error non-Hash' unless a.intent_wb_context_error(5) == 'input must be an object'
      s = OddHash.new
      got = a.decide_intent_wb({ 'intent_session' => s })
      want = { 'outcome' => 'deny', 'checks' => { 'facts' => 'fail' }, 'env' => {}, 'reason' => 'facts: evaluation error (fail closed): the message' }
      return "decide_intent_wb raising #{got.inspect}" unless got == want
      # only committed labels: rule 17 is active (and passes on an empty prov)
      got = a.decide_intent_wb({ 'intent_session' => { 'labels' => [D] }, 'action' => { 'params' => {} } })
      return "labels-only provenance #{got.inspect}" unless got['checks'] == { 'provenance' => 'pass' }
      nil
    end

    def prov_input(policy, prov, params)
      { 'policy' => policy, 'prov' => prov, 'action' => { 'params' => params }, 'aud' => 'rs', 'session' => D }
    end

    def provenance
      dp = ->(x) { a.decide_param_provenance(x) }
      # a policy parameter the action carries with a falsy value is still labelled (agent)
      got = dp.call(prov_input({ 'params' => { 'action.params.a' => 'material' } }, {}, { 'a' => false }))
      return "falsy param #{got.inspect}" unless got['outcome'] == 'question' && got['labels'] == { 'action.params.a' => 'agent' }
      # a registry with a default value vouches only for its own entries
      reg = Hash.new('trusted')
      got = dp.call(prov_input({ 'params' => { 'action.params.a' => 'material' }, 'registry' => reg }, { 'action.params.a' => ['r1'] }, { 'a' => 1 }))
      return "registry default #{got.inspect}" unless got['outcome'] == 'question' && got['labels'] == { 'action.params.a' => 'agent' }
      # the first critical violation in UTF-8 order (a prov path z is labelled before the policy-only a)
      pol = { 'params' => { 'action.params.a' => 'critical', 'action.params.z' => 'critical' }, 'critical_max' => 'trusted' }
      got = dp.call(prov_input(pol, { 'action.params.z' => ['r1'] }, { 'a' => 1, 'z' => 1 }))
      want = "provenance: critical parameter 'action.params.a' has provenance 'agent', above the policy maximum 'trusted'"
      return "critical order #{got['reason'].inspect}" unless got['outcome'] == 'deny' && got['reason'] == want
      pol = { 'params' => { 'action.params.a' => 'material', 'action.params.z' => 'material' }, 'material_tainted' => 'deny' }
      got = dp.call(prov_input(pol, { 'action.params.z' => ['r1'] }, { 'a' => 1, 'z' => 1 }))
      want = "provenance: tainted material parameter 'action.params.a' (provenance 'agent') is denied by policy"
      return "tainted order #{got['reason'].inspect}" unless got['outcome'] == 'deny' && got['reason'] == want
      nil
    end
  end

  %w[nums strict_eq scalars jsnorm paths validators totality provenance].each do |k|
    t("rubywb wb #{k}") do
      next true if DiffUtil.skip?('intent_wb.rb')

      bad = RubyWbWb.send(k)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
