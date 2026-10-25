# frozen_string_literal: true
# AtlasPca::V2JS (intent_v2.rb): the JavaScript value semantics every Intent Layer v2 rule judges by, pinned value by value
# (the Kotlin KillSession2Test does the same for IntentJs.kt). Expectations are the JavaScript semantics the reference relies on
# (noted per case) or, for Ruby-only representation details (String encodings, Symbol keys, the depth cap of jsnorm), the
# documented contract of the helper. Only intent_v2.rb bears on it.
module MutationKill
  module V2JSUnits
    module_function

    def v = AtlasPca::V2JS
    LONE = "\xED\xA0\x80".dup.force_encoding('UTF-8') # a lone surrogate as the loose parser writes it (WTF-8)

    def nest_a(depth, leaf) = depth.zero? ? leaf : [nest_a(depth - 1, leaf)]
    def nest_h(depth, leaf) = depth.zero? ? leaf : { 'k' => nest_h(depth - 1, leaf) }
    def dig_a(x, depth) = depth.zero? ? x : dig_a(x[0], depth - 1)
    def dig_h(x, depth) = depth.zero? ? x : dig_h(x['k'], depth - 1)

    def checks
      e = 'é'
      eb = 'é'.b
      bin = "\xFF".b
      frozen_bin = "\xC3\xA9".b.freeze
      [
        # the absent marker: one distinct object, spelled `undefined`
        ['UNDEF inspect', v::UNDEF.inspect == 'undefined'],
        ['UNDEF instance', v::UNDEF.instance_of?(Object) && v::UNDEF.frozen?],
        # strict_eq (`===` on JSON values): strings by bytes whatever the encoding label
        ['=== utf8/binary', v.strict_eq(e, eb) == true],
        ['=== utf8/utf8', v.strict_eq(e, e.dup) == true],
        ['=== differ', v.strict_eq(e, 'e') == false],
        # js_keys (Object.keys order): canonical array indices (<= 2^32 - 2) ascending first, then the rest in insertion order
        ['keys index max', v.js_keys({ 'b' => 1, '4294967295' => 1, '4294967294' => 1, '10' => 1, '2' => 1 }) == %w[2 10 4294967294 b 4294967295]],
        ['keys non-string', v.js_keys({ 1 => 1, 'a' => 1, :'3' => 1 }) == [1, 'a', :'3']],
        # js_str (String(x) in a reason): JS prints an integral number below 1e21 without a fraction, larger ones in exponent form
        ['str 1e20', v.js_str(1e20) == '100000000000000000000'],
        ['str 1e21', !v.js_str(1e21).match?(/\A\d+\z/)],
        ['str -1e21', !v.js_str(-1e21).match?(/\A-\d+\z/)],
        ['str -1e20', v.js_str(-1e20) == '-100000000000000000000'],
        ['str Infinity', v.js_str(Float::INFINITY) == 'Infinity' && v.js_str(-Float::INFINITY) == '-Infinity'],
        ['str NaN', v.js_str(Float::NAN) == 'NaN'],
        ['str 2.5', v.js_str(2.5) == '2.5'],
        # slice_from refuses a non-string with its own message
        ['slice non-string', (begin; v.slice_from(5, 1); false; rescue v::StrictError => x; x.message == 'not a string'; end)],
        ['slice', v.slice_from('action.params.n', 14) == 'n' && v.slice_from('action.params.', 14) == ''],
        # u8 / ustr?: a String viewed as UTF-8 WITHOUT touching the caller's object
        ['ustr? binary invalid', v.ustr?(bin) == false && v.ustr?("\xED\xA0\x80".b) == false],
        ['ustr? binary valid', v.ustr?("\xC3\xA9".b) == true],
        ['ustr? lone', v.ustr?(LONE) == false],
        ['u8 frozen binary', (begin; v.u8(frozen_bin) == e; rescue FrozenError; false; end)],
        ['u8 leaves caller', (s = "\xC3\xA9".b; v.ustr?(s); s.encoding == Encoding::BINARY)],
        # compare_utf8 (hash.ts compareUtf8): TextEncoder bytes (lone surrogate -> U+FFFD), raw bytes only to break a tie
        ['cmp lone vs U+E000', v.compare_utf8(LONE, "\u{E000}") == 1 && v.compare_utf8("\u{E000}", LONE) == -1],
        ['cmp lone vs U+FFFD', v.compare_utf8(LONE, "\u{FFFD}") == -1 && v.compare_utf8("\u{FFFD}", LONE) == 1],
        ['cmp equal', v.compare_utf8(e, eb).zero?],
        # sorted_join / distinct_strs?: by bytes, whatever the key / element encoding or Symbol-ness
        ['sorted_join', v.sorted_join({ e => 1, 'a' => 2 }) == "a,#{e}".b && v.sorted_join({ b: 1, a: 2 }) == 'a,b'],
        ['distinct encodings', v.distinct_strs?([e, eb]) == false && v.distinct_strs?(%w[a b]) == true],
        # ival: a safe-integer Float as an Integer, anything else as it is
        ['ival', v.ival(5.0).eql?(5) && v.ival(7).eql?(7) && v.ival('5') == '5' && v.ival(nil).nil?],
        # neg_zero?: only the Float -0.0
        ['neg_zero?', v.neg_zero?(-0.0) && !v.neg_zero?(0.0) && !v.neg_zero?(0) && !v.neg_zero?('x') && !v.neg_zero?(nil)],
        # jsnorm: Symbol keys -> String keys (any other key kept), integral safe Floats -> Integer, -0.0 / fractions / unsafe kept,
        # containers below depth 64 normalized, deeper ones kept as they are
        ['jsnorm keys', v.jsnorm({ a: 1.0, 1 => 2, 'b' => -0.0 }).then { |r| r.keys == ['a', 1, 'b'] && r['a'].eql?(1) && r['b'].eql?(-0.0) }],
        ['jsnorm floats', v.jsnorm([2.0**53, -(2.0**60), 2.0**60, 1.5, -3.0]).then { |r| r[0].eql?(2.0**53) && r[1].eql?(-(2.0**60)) && r[2].eql?(2.0**60) && r[3].eql?(1.5) && r[4].eql?(-3) }],
        ['jsnorm max safe', v.jsnorm(9_007_199_254_740_991.0).eql?(9_007_199_254_740_991) && v.jsnorm(-9_007_199_254_740_991.0).eql?(-9_007_199_254_740_991)],
        ['jsnorm array depth 64', dig_a(v.jsnorm(nest_a(64, 5.0)), 64).eql?(5)],
        ['jsnorm array depth 65', dig_a(v.jsnorm(nest_a(65, 5.0)), 65).eql?(5.0)],
        ['jsnorm hash depth 64', dig_h(v.jsnorm(nest_h(64, 5.0)), 64).eql?(5)],
        ['jsnorm hash depth 65', dig_h(v.jsnorm(nest_h(65, 5.0)), 65).eql?(5.0)],
        ['jsnorm explicit depth', v.jsnorm(5.0, 65).eql?(5.0) && v.jsnorm(5.0, 64).eql?(5)]
      ]
    end

    def first_bad
      checks.each { |name, ok| return name unless ok == true }
      nil
    rescue StandardError, SystemStackError => e
      "raised #{e.class}: #{e.message[0, 120]}"
    end
  end

  t('intent v2 V2JS value semantics (units)') do
    next true if DiffUtil.skip?('intent_v2.rb')

    bad = V2JSUnits.first_bad
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
end
