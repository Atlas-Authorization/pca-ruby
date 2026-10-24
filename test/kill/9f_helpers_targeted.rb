# frozen_string_literal: true
# Exact-value kills for the small JS-semantics helpers: intent_wb.rb (wb_*) and intent_v2.rb (V2JS). Fast; each skips under the
# mutation oracle for files it does not bear on.
module MutationKill
  module HelpersT
    module_function
    # resolved at CALL time: the mutation oracle replaces the AtlasPca module per mutant
    def w = AtlasPca
    def v = AtlasPca::V2JS
    def i = AtlasPca::IntentV2
    INF = Float::INFINITY
    LONE = "\xED\xA0\x80".dup.force_encoding('UTF-8') # a lone surrogate (WTF-8), invalid UTF-8

    def chk(label, got, want) = got == want && got.class == want.class ? nil : "#{label}: want #{want.inspect} got #{got.inspect}"
    def run(rows) = rows.filter_map { |l, g, w| chk(l, g, w) }.first
    def tf(label, got, want) = got.equal?(want) ? nil : "#{label}: want #{want.inspect} got #{got.inspect}"
    def runtf(rows) = rows.filter_map { |l, g, w| tf(l, g, w) }.first

    NUMS = { 0 => '0', 5 => '5', -5 => '-5', 10**20 => '100000000000000000000', 10**21 => '1e+21', -(10**21) => '-1e+21', 10**22 => '1e+22',
             123 * 10**20 => '12300000000000000000000'.sub(/\A1230+/, '1.23e+22'), 0.0 => '0', -0.0 => '0', 1.0 => '1', -1.0 => '-1', 1.5 => '1.5',
             -1.5 => '-1.5', 123.456 => '123.456', 0.5 => '0.5', 100.0 => '100', 1e20 => '100000000000000000000', 1e21 => '1e+21',
             1.5e21 => '1.5e+21', 1.2345e25 => '1.2345e+25', 0.000001 => '0.000001', 0.0000012 => '0.0000012', 1e-7 => '1e-7', 1.5e-7 => '1.5e-7',
             1.2345e-10 => '1.2345e-10', 0.1 + 0.2 => '0.30000000000000004', 1e300 => '1e+300', 5e-324 => '5e-324',
             1.7976931348623157e308 => '1.7976931348623157e+308', 1234.5 => '1234.5', 0.1 => '0.1', 3.0e-5 => '0.00003', 2e-6 => '0.000002',
             1.0e-5 => '0.00001', 123456.789 => '123456.789', 4.35 => '4.35', 1e-10 => '1e-10',
             INF => 'Infinity', -INF => '-Infinity', Float::NAN => 'NaN', 1e22 => '1e+22', 1.1e-6 => '0.0000011', 9.5e-7 => '9.5e-7' }.freeze

    def wb_rows
      rows = []
      NUMS.each { |x, want| rows << ["wb_js_num_str #{x}", w.wb_js_num_str(x), want] }
      NUMS.each { |x, want| rows << ["wb_js_str #{x}", w.wb_js_str(x), want] }
      u = AtlasPca::WB_UNDEF
      rows += [['js_str undef', w.wb_js_str(u), 'undefined'], ['null', w.wb_js_str(nil), 'null'], ['true', w.wb_js_str(true), 'true'],
               ['false', w.wb_js_str(false), 'false'], ['str', w.wb_js_str('x'), 'x'], ['arr', w.wb_js_str([1, nil, 'a', [2, 3]]), '1,,a,2,3'],
               ['arr undef', w.wb_js_str([u, 1]), ',1'], ['obj', w.wb_js_str({}), '[object Object]'], ['empty arr', w.wb_js_str([]), '']]
      rows += [['utf16 ascii', w.wb_utf16_len('abc'), 3], ['utf16 2b', w.wb_utf16_len('é'), 1], ['utf16 3b', w.wb_utf16_len('€'), 1],
               ['utf16 4b', w.wb_utf16_len('😀'), 2], ['utf16 mix', w.wb_utf16_len('a😀é'), 4], ['utf16 empty', w.wb_utf16_len(''), 0],
               ['utf16 lone', w.wb_utf16_len(LONE), 1]]
      rows += [['split', w.wb_split_dot('a.b'), %w[a b]], ['split lead', w.wb_split_dot('.a'), ['', 'a']], ['split trail', w.wb_split_dot('a.'), ['a', '']],
               ['split empty', w.wb_split_dot(''), ['']], ['split inner', w.wb_split_dot('a..b'), ['a', '', 'b']], ['split one', w.wb_split_dot('a'), ['a']],
               ['after', w.wb_after('action.params.x', 'action.params.'), 'x'], ['after all', w.wb_after('ab', 'ab'), ''],
               ['keys', w.wb_js_keys({ 'b' => 1, '10' => 1, '2' => 1, 'a' => 1, '01' => 1 }), %w[2 10 b a 01]],
               ['keys big', w.wb_js_keys({ '4294967295' => 1, '4294967294' => 1, 'z' => 1 }), %w[4294967294 4294967295 z]],
               ['keys zero', w.wb_js_keys({ 'x' => 1, '0' => 1 }), %w[0 x]],
               ['int', w.wb_int(5.0), 5], ['int i', w.wb_int(7), 7],
               ['jsnorm f', w.wb_jsnorm(5.0), 5], ['jsnorm frac', w.wb_jsnorm(5.5), 5.5], ['jsnorm -0', w.wb_jsnorm(-0.0), -0.0],
               ['jsnorm big', w.wb_jsnorm(2.0**60), 2.0**60], ['jsnorm max', w.wb_jsnorm(9007199254740991.0), 9007199254740991],
               ['jsnorm nest', w.wb_jsnorm({ 'a' => [1.0, { 'b' => 2.0 }] }), { 'a' => [1, { 'b' => 2 }] }], ['jsnorm inf', w.wb_jsnorm(INF), INF]]
      rows
    end

    def wb_tf_rows
      u = AtlasPca::WB_UNDEF
      m = AtlasPca::MAX_SAFE
      [['strict nil nil', w.wb_strict_eq?(nil, nil), true], ['nil 0', w.wb_strict_eq?(nil, 0), false], ['0 nil', w.wb_strict_eq?(0, nil), false],
       ['nil undef', w.wb_strict_eq?(nil, u), false], ['undef nil', w.wb_strict_eq?(u, nil), false], ['undef undef', w.wb_strict_eq?(u, u), true],
       ['undef 0', w.wb_strict_eq?(u, 0), false], ['0 undef', w.wb_strict_eq?(0, u), false],
       ['t t', w.wb_strict_eq?(true, true), true], ['t f', w.wb_strict_eq?(true, false), false], ['f f', w.wb_strict_eq?(false, false), true],
       ['t 1', w.wb_strict_eq?(true, 1), false], ['1 t', w.wb_strict_eq?(1, true), false], ['f 0', w.wb_strict_eq?(false, 0), false],
       ['0 f', w.wb_strict_eq?(0, false), false], ['t "t"', w.wb_strict_eq?(true, 'true'), false], ['"t" t', w.wb_strict_eq?('true', true), false],
       ['2 2.0', w.wb_strict_eq?(2, 2.0), true], ['2 3', w.wb_strict_eq?(2, 3), false], ['2 "2"', w.wb_strict_eq?(2, '2'), false],
       ['"2" 2', w.wb_strict_eq?('2', 2), false], ['nan', w.wb_strict_eq?(Float::NAN, Float::NAN), false], ['0 -0', w.wb_strict_eq?(0, -0.0), true],
       ['s s', w.wb_strict_eq?('a', 'a'), true], ['s t', w.wb_strict_eq?('a', 'b'), false], ['s []', w.wb_strict_eq?('a', []), false],
       ['[] s', w.wb_strict_eq?([], 'a'), false], ['5 []', w.wb_strict_eq?(5, []), false], ['[] 5', w.wb_strict_eq?([], 5), false],
       ['obj id', w.wb_strict_eq?(a = {}, a), true], ['obj eq', w.wb_strict_eq?({}, {}), false], ['arr', w.wb_strict_eq?([], []), false],
       ['bytes', w.wb_strict_eq?('é'.b, 'é'), true],
       ['safe 0', w.wb_safe_int?(0), true], ['safe max', w.wb_safe_int?(m), true], ['safe max+1', w.wb_safe_int?(m + 1), false],
       ['safe -max', w.wb_safe_int?(-m), true], ['safe -max-1', w.wb_safe_int?(-m - 1), false], ['safe f', w.wb_safe_int?(3.0), true],
       ['safe frac', w.wb_safe_int?(3.5), false], ['safe -0', w.wb_safe_int?(-0.0), false], ['safe +0f', w.wb_safe_int?(0.0), true],
       ['safe inf', w.wb_safe_int?(INF), false], ['safe nan', w.wb_safe_int?(Float::NAN), false], ['safe str', w.wb_safe_int?('1'), false],
       ['safe fmax', w.wb_safe_int?(m.to_f), true], ['safe fmax+', w.wb_safe_int?((m + 1).to_f), false], ['safe -fmax', w.wb_safe_int?(-m.to_f), true],
       ['safe nil', w.wb_safe_int?(nil), false],
       ['num i', w.wb_num?(1), true], ['num f', w.wb_num?(1.5), true], ['num s', w.wb_num?('1'), false], ['num nil', w.wb_num?(nil), false],
       ['bool t', w.wb_bool?(true), true], ['bool f', w.wb_bool?(false), true], ['bool nil', w.wb_bool?(nil), false], ['bool 1', w.wb_bool?(1), false],
       ['negz', w.wb_neg_zero?(-0.0), true], ['negz +', w.wb_neg_zero?(0.0), false], ['negz i', w.wb_neg_zero?(0), false], ['negz -1', w.wb_neg_zero?(-1.0), false],
       ['present undef', w.wb_present?(u), false], ['present nil', w.wb_present?(nil), true],
       ['nea []', w.wb_non_empty_array?([]), false], ['nea [1]', w.wb_non_empty_array?([1]), true], ['nea h', w.wb_non_empty_array?({ 'a' => 1 }), false],
       ['nea s', w.wb_non_empty_array?('a'), false],
       ['re ok', w.wb_re?(/\Aa\z/, 'a'), true], ['re no', w.wb_re?(/\Aa\z/, 'b'), false], ['re bad enc', w.wb_re?(/a/, LONE), false], ['re nonstr', w.wb_re?(/a/, 1), false],
       ['starts', w.wb_starts?('abc', 'ab'), true], ['starts no', w.wb_starts?('abc', 'bc'), false], ['starts ns', w.wb_starts?(1, 'a'), false],
       ['starts empty', w.wb_starts?('', ''), true], ['ends', w.wb_ends?('abc', 'bc'), true], ['ends no', w.wb_ends?('abc', 'ab'), false],
       ['ends ns', w.wb_ends?(nil, 'a'), false], ['ends bad enc', w.wb_ends?("a#{LONE}", LONE), true],
       ['bounded', w.wb_bounded?('a', 1), true], ['bounded long', w.wb_bounded?('ab', 1), false], ['bounded empty', w.wb_bounded?('', 1), false],
       ['bounded ns', w.wb_bounded?(1, 1), false], ['bounded é', w.wb_bounded?('é', 2), true], ['bounded é1', w.wb_bounded?('é', 1), false],
       ['scalar s', w.wb_scalar?('a'), true], ['scalar b', w.wb_scalar?(false), true], ['scalar i', w.wb_scalar?(3), true], ['scalar f', w.wb_scalar?(1.5), false],
       ['scalar nil', w.wb_scalar?(nil), false], ['scalar a', w.wb_scalar?([]), false],
       ['digest', w.wb_digest?(AtlasPca.b64e("\x01".b * 32)), true], ['digest short', w.wb_digest?(AtlasPca.b64e("\x01".b * 31)), false],
       ['digest ns', w.wb_digest?(1), false],
       ['clock', w.wb_clock?(5), true], ['clock f', w.wb_clock?(5.5), false],
       ['path seg', w.wb_path_segment?('abc'), true], ['path seg proto', w.wb_path_segment?('__proto__'), false], ['path seg empty', w.wb_path_segment?(''), false],
       ['path seg dot', w.wb_path_segment?('a.b'), false]]
    end

    def v2_rows
      u = v::UNDEF
      m = v::MAX_SAFE_INT
      [['undef?', v.undef?(u), true], ['undef? nil', v.undef?(nil), false], ['nullish u', v.nullish?(u), true], ['nullish nil', v.nullish?(nil), true],
       ['nullish 0', v.nullish?(0), false], ['nullish_or u', v.nullish_or(u, 1), 1], ['nullish_or nil', v.nullish_or(nil, 1), 1], ['nullish_or 0', v.nullish_or(0, 1), 0],
       ['nullish_or false', v.nullish_or(false, 1), false],
       ['prop', v.prop({ 'a' => 1 }, 'a'), 1], ['prop miss', v.prop({ 'a' => 1 }, 'b'), u], ['prop nonhash', v.prop([1], 'a'), u], ['prop nil', v.prop(nil, 'a'), u],
       ['prop nilval', v.prop({ 'a' => nil }, 'a'), nil], ['opt', v.opt({ 'a' => 2 }, 'a'), 2], ['opt nil', v.opt(nil, 'a'), u],
       ['ustr', v.ustr?('a'), true], ['ustr lone', v.ustr?(LONE), false], ['ustr int', v.ustr?(1), false], ['ustr ''', v.ustr?(''), true],
       ['bool t', v.bool?(true), true], ['bool f', v.bool?(false), true], ['bool 0', v.bool?(0), false], ['bool nil', v.bool?(nil), false],
       ['num i', v.num?(1), true], ['num f', v.num?(1.5), true], ['num s', v.num?('1'), false],
       ['negz', v.neg_zero?(-0.0), true], ['negz +', v.neg_zero?(0.0), false], ['negz i', v.neg_zero?(0), false], ['negz -1', v.neg_zero?(-1.0), false],
       ['int 0', v.int?(0), true], ['int max', v.int?(m), true], ['int max+1', v.int?(m + 1), false], ['int -max', v.int?(-m), true], ['int -max-1', v.int?(-m - 1), false],
       ['int 3.0', v.int?(3.0), true], ['int 3.5', v.int?(3.5), false], ['int -0', v.int?(-0.0), false], ['int +0f', v.int?(0.0), true], ['int inf', v.int?(INF), false],
       ['int nan', v.int?(Float::NAN), false], ['int fmax', v.int?(m.to_f), true], ['int fmax+', v.int?((m + 1).to_f), false], ['int -fmax', v.int?(-m.to_f), true],
       ['int s', v.int?('1'), false], ['int nil', v.int?(nil), false],
       ['nonneg 0', v.nonneg?(0), true], ['nonneg -1', v.nonneg?(-1), false], ['nonneg 1.5', v.nonneg?(1.5), false], ['nonneg -0', v.nonneg?(-0.0), false],
       ['truthy nil', v.truthy?(nil), false], ['truthy u', v.truthy?(u), false], ['truthy false', v.truthy?(false), false], ['truthy true', v.truthy?(true), true],
       ['truthy 0', v.truthy?(0), false], ['truthy 0.0', v.truthy?(0.0), false], ['truthy -0', v.truthy?(-0.0), false], ['truthy 1', v.truthy?(1), true],
       ['truthy nan', v.truthy?(Float::NAN), false], ['truthy -1', v.truthy?(-1), true], ['truthy 0.1', v.truthy?(0.1), true], ['truthy ""', v.truthy?(''), false],
       ['truthy s', v.truthy?('a'), true], ['truthy []', v.truthy?([]), true], ['truthy {}', v.truthy?({}), true], ['truthy inf', v.truthy?(INF), true],
       ['se u u', v.strict_eq(u, u), true], ['se u nil', v.strict_eq(u, nil), false], ['se nil u', v.strict_eq(nil, u), false], ['se 0 u', v.strict_eq(0, u), false],
       ['se nil nil', v.strict_eq(nil, nil), true], ['se nil 0', v.strict_eq(nil, 0), false], ['se 0 nil', v.strict_eq(0, nil), false],
       ['se t t', v.strict_eq(true, true), true], ['se t f', v.strict_eq(true, false), false], ['se f f', v.strict_eq(false, false), true],
       ['se t 1', v.strict_eq(true, 1), false], ['se 1 t', v.strict_eq(1, true), false], ['se 0 f', v.strict_eq(0, false), false], ['se f 0', v.strict_eq(false, 0), false],
       ['se 2 2.0', v.strict_eq(2, 2.0), true], ['se 2 3', v.strict_eq(2, 3), false], ['se 2 "2"', v.strict_eq(2, '2'), false], ['se "2" 2', v.strict_eq('2', 2), false],
       ['se 0 -0', v.strict_eq(0, -0.0), true], ['se nan', v.strict_eq(Float::NAN, Float::NAN), false],
       ['se s s', v.strict_eq('a', 'a'), true], ['se s t', v.strict_eq('a', 'b'), false], ['se s []', v.strict_eq('a', []), false], ['se [] s', v.strict_eq([], 'a'), false],
       ['se bytes', v.strict_eq('é'.b, 'é'), true], ['se obj', v.strict_eq(o = {}, o), true], ['se obj2', v.strict_eq({}, {}), false], ['se []', v.strict_eq([], []), false],
       ['se 5 []', v.strict_eq(5, []), false],
       ['u16 a', v.u16len('abc'), 3], ['u16 é', v.u16len('é'), 1], ['u16 €', v.u16len('€'), 1], ['u16 😀', v.u16len('😀'), 2], ['u16 mix', v.u16len('a😀é€'), 5],
       ['u16 ""', v.u16len(''), 0], ['u16 lone', v.u16len(LONE), 1],
       ['js_str u', v.js_str(u), 'undefined'], ['js_str nil', v.js_str(nil), 'null'], ['js_str s', v.js_str('x'), 'x'], ['js_str 5', v.js_str(5), '5'],
       ['js_str 5.0', v.js_str(5.0), '5'], ['js_str 1.5', v.js_str(1.5), '1.5'], ['js_str 1e20', v.js_str(1e20), '100000000000000000000'],
       ['js_str t', v.js_str(true), 'true'], ['js_str -0', v.js_str(-0.0), '0'], ['js_str arr', v.js_str([1, nil, 'a']), '1,,a'], ['js_str obj', v.js_str({}), '[object Object]'],
       ['js_keys', v.js_keys({ 'b' => 1, '10' => 1, '2' => 1, 'a' => 1, '01' => 1 }), %w[2 10 b a 01]], ['js_keys big', v.js_keys({ '4294967295' => 1, '4294967294' => 1 }), %w[4294967294 4294967295]],
       ['js_keys 0', v.js_keys({ 'x' => 1, '0' => 1 }), %w[0 x]], ['js_keys empty', v.js_keys({}), []],
       ['te_bytes', v.te_bytes('a'), 'a'.b], ['te_bytes lone', v.te_bytes(LONE), "\xEF\xBF\xBD".b], ['te_bytes é', v.te_bytes('é'), "\xC3\xA9".b],
       ['te_bytes mix', v.te_bytes("a#{LONE}b"), "a\xEF\xBF\xBDb".b],
       ['cmp eq', v.compare_utf8('a', 'a'), 0], ['cmp lt', v.compare_utf8('a', 'b') <=> 0, -1], ['cmp gt', v.compare_utf8('b', 'a') <=> 0, 1],
       ['cmp astral', v.compare_utf8("￿", '😀') <=> 0, -1], ['cmp astral2', v.compare_utf8('😀', "￿") <=> 0, 1], ['cmp pre', v.compare_utf8('a', 'ab') <=> 0, -1],
       ['cmp lone', v.compare_utf8(LONE, "\xEF\xBF\xBD") <=> 0, ('b'.b <=> 'a'.b) * 0 + (LONE.b <=> "\xEF\xBF\xBD".b)],
       ['sort_utf8', v.sort_utf8(%w[b a é Z]), %w[Z a b é]], ['sorted_join', v.sorted_join({ 'b' => 1, 'a' => 2 }), 'a,b'],
       ['distinct', v.distinct_strs?(%w[a b]), true], ['distinct dup', v.distinct_strs?(%w[a a]), false], ['distinct empty', v.distinct_strs?([]), true],
       ['rx', v.rx?(/\Aa\z/, 'a'), true], ['rx no', v.rx?(/\Aa\z/, 'b'), false], ['rx lone', v.rx?(/a/, LONE), false], ['rx ns', v.rx?(/a/, 1), false],
       ['slice', v.slice_from('action.params.x', 14), 'x'], ['slice eq', v.slice_from('action.params.', 14), ''], ['slice short', v.slice_from('ab', 14), ''],
       ['jsnorm f', v.jsnorm(5.0), 5], ['jsnorm frac', v.jsnorm(5.5), 5.5], ['jsnorm big', v.jsnorm(2.0**60), 2.0**60], ['jsnorm max', v.jsnorm(m.to_f), m],
       ['jsnorm nest', v.jsnorm({ 'a' => [1.0, { 'b' => 2.0 }] }), { 'a' => [1, { 'b' => 2 }] }], ['jsnorm sym', v.jsnorm({ a: 1 }), { 'a' => 1 }],
       ['jsnorm inf', v.jsnorm(INF), INF], ['jsnorm str', v.jsnorm('x'), 'x'], ['jsnorm nil', v.jsnorm(nil), nil],
       ['ival', v.ival(5.0), 5], ['ival i', v.ival(7), 7],
       ['present', i.present?({ 'a' => nil }, 'a'), true], ['present miss', i.present?({}, 'a'), false], ['present nonh', i.present?([], 'a'), false],
       ['is_str', i.is_str?('a', 1), true], ['is_str long', i.is_str?('ab', 1), false], ['is_str empty', i.is_str?('', 5), false], ['is_str ns', i.is_str?(1), false],
       ['is_str é', i.is_str?('é', 2), true], ['is_str é1', i.is_str?('é', 1), false], ['is_str def', i.is_str?('a' * 256), true], ['is_str def+', i.is_str?('a' * 257), false],
       ['in_strs', i.in_strs?('a', %w[a b]), true], ['in_strs no', i.in_strs?('c', %w[a b]), false], ['in_strs ns', i.in_strs?(1, [1]), false],
       ['bad', i.bad('r'), { 'ok' => false, 'reason' => 'r' }], ['okv', i.okv, { 'ok' => true }], ['okv x', i.okv('v' => 1), { 'ok' => true, 'v' => 1 }]]
    end
  end

  t('wb helpers: exact values') do
    next true if DiffUtil.skip?('intent_wb.rb')
    bad = HelpersT.run(HelpersT.wb_rows)
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
  t('wb helpers: exact predicates') do
    next true if DiffUtil.skip?('intent_wb.rb')
    bad = HelpersT.runtf(HelpersT.wb_tf_rows)
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
  t('wb helpers: raises') do
    next true if DiffUtil.skip?('intent_wb.rb')
    deep = (1..40).inject(1) { |a, _| [a] }
    r = begin
      AtlasPca.wb_jsnorm(deep)
      false
    rescue AtlasPca::Malformed
      true
    end
    m = begin
      AtlasPca.wb_member(nil, 'k')
      false
    rescue TypeError => e
      e.message.include?("null") && e.message.include?("'k'")
    end
    m2 = begin
      AtlasPca.wb_member(AtlasPca::WB_UNDEF, 'k')
      false
    rescue TypeError => e
      e.message.include?('undefined')
    end
    r && m && m2 && AtlasPca.wb_member({ 'k' => 1 }, 'k') == 1 && AtlasPca.wb_dflt(nil, 2) == 2 && AtlasPca.wb_dflt(0, 2) == 0 &&
      AtlasPca.wb_absent(nil, 2).nil? && AtlasPca.wb_absent(AtlasPca::WB_UNDEF, 2) == 2
  end
  t('v2 helpers: exact values') do
    next true if DiffUtil.skip?('intent_v2.rb')
    bad = HelpersT.run(HelpersT.v2_rows)
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
  t('v2 helpers: slice_from raises on a non-string') do
    next true if DiffUtil.skip?('intent_v2.rb')
    begin
      AtlasPca::V2JS.slice_from(5, 1)
      false
    rescue AtlasPca::V2JS::StrictError
      true
    end
  end
end
