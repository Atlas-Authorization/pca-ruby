# frozen_string_literal: true
# r11 targeted kills for predicates.rb (survivors of run 39902549441). The differential oracles (9c / 9d) go through the
# public, exception-swallowing entry points with JSON text, so they cannot see WHICH of "false" / "raises" a helper produced, nor
# any input JSON text cannot spell (symbols, non-string keys, Hashes with a default value, binary / broken encodings, a depth
# argument near MAX_EQ_DEPTH, objects with a lying ==). These tests call the helpers directly and compare the exact outcome
# (value, class, :nc for NotCanonical, [:raise, class] for any other exception).
module MutationKill
  module PredR11
    module_function
    def p_ = AtlasPca::Predicates
    def skip? = DiffUtil.skip?('predicates.rb', 'safe_regex.rb')
    NC = :nc

    # a value whose == always lies (a guard that merely compares a == b must not be reached by it)
    LIAR = Class.new { def ==(_o) = true }.new

    def jeq(a, b, d = 0)
      p_.jeq(a, b, d)
    rescue p_::NotCanonical
      NC
    end

    def check_jeq
      inf = Float::INFINITY
      cases = [
        # depth guard: a scalar pair at depth 10000 is read, at 10001 it is refused; containers add one level per nesting
        [1, 1, 10_000, true], [1, 1, 10_001, NC], [nil, nil, 10_001, NC], ['a', 'a', 10_001, NC],
        [[1], [1], 9_999, true], [[1], [1], 10_000, NC], [{ 'a' => 1 }, { 'a' => 1 }, 9_999, true], [{ 'a' => 1 }, { 'a' => 1 }, 10_000, NC],
        [[[]], [[]], 9_999, true], [[[]], [[]], 10_000, NC],
        # non-finite numbers refuse whatever the other side is (the check precedes every type branch)
        [inf, 1], [1, inf], [-inf, 1], [1, -inf], [Float::NAN, nil], [nil, Float::NAN], [inf, nil], [nil, inf], [inf, true], [true, inf],
        [inf, 'a'], ['a', inf], [10**400, 1], [1, 10**400], [10**400, nil], [nil, 10**400], [-(10**400), -(10**400)],
        [10**308, 10**308, 0, true], [(10**308) * 2, 1], [[inf], [inf]], [[1, inf], [1, inf]], [{ 'a' => inf }, { 'a' => inf }],
        # but lengths / key sets are compared first: no element is ever read
        [[inf], [], 0, false], [[], [inf], 0, false], [{ 'a' => inf }, { 'b' => 1 }, 0, false],
        # null
        [nil, nil, 0, true], [nil, 1, 0, false], [1, nil, 0, false], [nil, 'a', 0, false], ['a', nil, 0, false], [nil, false, 0, false],
        [false, nil, 0, false], [nil, true, 0, false], [nil, [], 0, false], [[], nil, 0, false], [nil, {}, 0, false], [{}, nil, 0, false],
        [nil, :sym, 0, false], [:sym, nil, 0, false], [nil, [1], 0, false], [[1], nil, 0, false],
        # booleans
        [true, true, 0, true], [false, false, 0, true], [true, false, 0, false], [false, true, 0, false],
        [true, 1, 0, false], [1, true, 0, false], [false, 0, 0, false], [0, false, 0, false], [true, 'true', 0, false], ['true', true, 0, false],
        [true, [], 0, false], [[], true, 0, false], [false, {}, 0, false], [{}, false, 0, false], [true, :sym, 0, false], [false, :sym, 0, false],
        [:sym, true, 0, false], [:sym, false, 0, false], [LIAR, true, 0, true], [true, LIAR, 0, false], [LIAR, 1, 0, false], [1, LIAR, 0, false],
        [LIAR, 'a', 0, false], ['a', LIAR, 0, false],
        # numbers: one JSON number type
        [1, 1, 0, true], [1, 1.0, 0, true], [1.0, 1, 0, true], [1, 2, 0, false], [2, 1, 0, false], [0.0, -0.0, 0, true], [-0.0, 0, 0, true],
        [0.1, 0.1, 0, true], [1.5, 1.25, 0, false], [(2**53) + 1, 2**53, 0, true], [10**20, 1e20, 0, true],
        [1, '1', 0, false], ['1', 1, 0, false], [1, [], 0, false], [[], 1, 0, false], [1, {}, 0, false], [{}, 1, 0, false],
        [1, [1], 0, false], [[1], 1, 0, false], [1, :sym, 0, false], [:sym, 1, 0, false], [1.5, :sym, 0, false], [:sym, 1.5, 0, false],
        # strings: same UTF-16 units
        ['a', 'a', 0, true], ['a', 'b', 0, false], ['', '', 0, true], ['a', '', 0, false], ['a', 'ab', 0, false],
        ["é", "é", 0, false], ["é", "é".encode('UTF-16LE').encode('UTF-8'), 0, true],
        ["\u{1F600}", "\xED\xA0\xBD\xED\xB8\x80".dup.force_encoding('UTF-8'), 0, true], ["\u{1F600}", "\u{1F601}", 0, false],
        ['a', [], 0, false], [[], 'a', 0, false], ['a', {}, 0, false], [{}, 'a', 0, false], ['a', ['a'], 0, false],
        ['a', :sym, 0, false], [:sym, 'a', 0, false],
        # arrays
        [[], [], 0, true], [[1], [1], 0, true], [[1], [2], 0, false], [[1], [1, 2], 0, false], [[1, 2], [1], 0, false], [[], [1], 0, false],
        [[1, [2, 'x']], [1, [2, 'x']], 0, true], [[1, [2, 'x']], [1, [2, 'y']], 0, false], [[1, 2], [2, 1], 0, false],
        [[nil], [nil], 0, true], [[nil], [false], 0, false], [[true], [true], 0, true], [[:sym], [:sym]], [[1, :sym], [2, :sym], 0, false],
        # objects: key sets by UTF-16 units, order does not matter
        [{}, {}, 0, true], [{ 'a' => 1 }, { 'a' => 1 }, 0, true], [{ 'a' => 1 }, { 'a' => 2 }, 0, false], [{ 'a' => 1 }, { 'b' => 1 }, 0, false],
        [{ 'a' => 1 }, { 'a' => 1, 'b' => 2 }, 0, false], [{ 'a' => 1, 'b' => 2 }, { 'a' => 1 }, 0, false], [{ 'a' => 1, 'b' => 2 }, { 'b' => 2, 'a' => 1 }, 0, true],
        [{ 'a' => 1, 'b' => 2 }, { 'b' => 2, 'a' => 3 }, 0, false], [{ 'a' => 1, 'b' => 2 }, { 'a' => 1, 'c' => 2 }, 0, false],
        [{ 'a' => { 'b' => [1] } }, { 'a' => { 'b' => [1] } }, 0, true], [{ 'a' => { 'b' => [1] } }, { 'a' => { 'b' => [2] } }, 0, false],
        [{ 'a' => nil }, { 'a' => nil }, 0, true], [{ 'a' => nil }, { 'b' => nil }, 0, false],
        # non-string keys refuse, wherever they sit (a's or b's) and whatever the values are
        [{ 1 => 1 }, { 1 => 1 }], [{ 'a' => 1 }, { 1 => 1 }], [{ 1 => 1 }, { 'a' => 1 }], [{ 'a' => 1, 1 => 1 }, { 'a' => 1 }], [{ 'a' => 1 }, { 'a' => 1, 1 => 1 }],
        [{ sym: 1 }, {}], [{}, { sym: 1 }], [{ 1 => 1 }, {}], [{}, { 1 => 1 }],
        # container vs other types
        [[], {}, 0, false], [{}, [], 0, false], [[1], { '0' => 1 }, 0, false], [{ '0' => 1 }, [1], 0, false], [{ 'a' => 1 }, [1], 0, false], [[1], { 'a' => 1 }, 0, false],
        [[], :sym], [:sym, []], [{}, :sym], [:sym, {}], [:sym, :sym], [:a, :b], [Object.new, Object.new], [[], Object.new], [Object.new, {}],
        [[], 'a', 0, false], [{}, 'a', 0, false],
        # two keys of one side with the same UTF-16 units (the astral char and its CESU spelling) are not a JSON object: false
        [{ "\u{1F600}" => 1, CESU => 1 }, { "\u{1F600}" => 1 }, 0, false], [{ "\u{1F600}" => 1 }, { "\u{1F600}" => 1, CESU => 1 }, 0, false],
        [{ "\u{1F600}" => 1, CESU => 1 }, { "\u{1F600}" => 1, CESU => 1 }, 0, false], [{ CESU => 1 }, { "\u{1F600}" => 1 }, 0, true]
      ]
      bad = []
      cases.each_with_index do |(a, b, d, want), i|
        d ||= 0
        want = NC if want.nil?
        got = jeq(a, b, d)
        bad << "jeq ##{i} #{a.inspect[0, 40]} vs #{b.inspect[0, 40]} @#{d}: want #{want.inspect} got #{got.inspect}" unless got == want
      end
      bad.empty? ? nil : bad.join("\n")
    end

    # deep_eq? starts the walk at depth 0 (the MAX_EQ_DEPTH budget is the whole document's): a spy on jeq records the first depth.
    # (Through deep_eq? alone the cap is not reachable: Ruby's VM stack overflows - rescued to false - a few thousand levels down.)
    def check_deep_eq_start
      sc = p_.singleton_class
      orig = sc.instance_method(:jeq)
      seen = []
      sc.send(:define_method, :jeq) do |a, b, d|
        seen << d
        orig.bind_call(self, a, b, d)
      end
      r = p_.deep_eq?([1], [1])
      r == true && seen == [0, 1] ? nil : "deep_eq? walk: #{r.inspect} depths #{seen.inspect}"
    ensure
      sc&.send(:define_method, :jeq, orig) if orig
    end

    # [:raise, ExceptionClass] instead of the exception (an exact-outcome compare)
    def out
      yield
    rescue StandardError, SystemStackError => e
      [:raise, e.class]
    end

    def u(s) = AtlasPca::SafeRegex.units(s)
    LONE = "\xED\xA0\x80".dup.force_encoding('UTF-8').freeze # WTF-8 lone high surrogate (the loose reader's form)
    CESU = "\xED\xA0\xBD\xED\xB8\x80".dup.force_encoding('UTF-8').freeze # U+1F600 as two 3-byte surrogate forms

    # compare [name, got, want] rows exactly (== and the same class: 5 != 5.0 here); one message per mismatch
    def rows(list)
      bad = list.reject { |_, got, want| got == want && got.class == want.class }
      bad.empty? ? nil : bad.map { |n, got, want| "#{n}: want #{want.inspect} got #{got.inspect}" }.join("\n")
    end

    def check_scalars
      inf = Float::INFINITY
      rows([
        # jsnum: the binary64 value (a Float, rounded as JSON.parse would)
        ['jsnum 5', out { p_.jsnum(5) }, 5.0], ['jsnum 2^53+1', out { p_.jsnum((2**53) + 1) }, 9_007_199_254_740_992.0],
        ['jsnum 1.5', out { p_.jsnum(1.5) }, 1.5], ['jsnum 10^400', out { p_.jsnum(10**400) }, inf],
        # str_eq? / plain_utf8?: the byte fast path only for valid UTF-8 / US-ASCII; a binary-tagged CESU pair is the astral char
        ['str_eq e/e', out { p_.str_eq?("é", "é") }, true], ['str_eq e/e-grave', out { p_.str_eq?("é", "è") }, false],
        ['str_eq cesu.b/astral', out { p_.str_eq?(CESU.b, "\u{1F600}") }, true], ['str_eq astral/cesu.b', out { p_.str_eq?("\u{1F600}", CESU.b) }, true],
        ['str_eq ascii.b', out { p_.str_eq?('abc'.b, 'abc') }, true], ['str_eq e.b/e', out { p_.str_eq?("é".b, "é") }, true],
        ['plain utf8', out { p_.plain_utf8?("é") }, true], ['plain ascii', out { p_.plain_utf8?('a'.encode('US-ASCII')) }, true],
        ['plain binary', out { p_.plain_utf8?('a'.b) }, false], ['plain cesu', out { p_.plain_utf8?(CESU) }, false],
        ['plain utf16', out { p_.plain_utf8?('a'.encode('UTF-16LE')) }, false], ['plain lone', out { p_.plain_utf8?(LONE) }, false],
        # ECMAScript Number::toString at the 21-digit boundary and the fixed / exponent forms
        ['num 1e20', out { p_.js_number_string(1e20) }, '100000000000000000000'], ['num 1e21', out { p_.js_number_string(1e21) }, '1e+21'],
        ['num 1.2345678901234568e20', out { p_.js_number_string(1.2345678901234568e20) }, '123456789012345680000'],
        ['num 12', out { p_.js_number_string(12.0) }, '12'], ['num 123.456', out { p_.js_number_string(123.456) }, '123.456'],
        ['num 0.001', out { p_.js_number_string(0.001) }, '0.001'], ['num 1e-7', out { p_.js_number_string(1e-7) }, '1e-7'],
        ['num 1.5e-7', out { p_.js_number_string(1.5e-7) }, '1.5e-7'], ['num -2.5', out { p_.js_number_string(-2.5) }, '-2.5'],
        ['num 1.5e300', out { p_.js_number_string(1.5e300) }, '1.5e+300'], ['num 0.000001', out { p_.js_number_string(0.000001) }, '0.000001'],
        # String(): a string comes back as UTF-8 whatever its tag; the nesting refusal carries its message
        ['js_string e.b', out { p_.js_string("é".b) }, "é"], ['js_string e.b enc', out { p_.js_string("é".b).encoding }, Encoding::UTF_8],
        ['js_string deep msg', out { p_.js_string(66.times.reduce(['x']) { |a, _| [a] }) rescue $!.message }, 'String(): nesting too deep'],
        # resolve: non-ASCII keys, broken-encoding segments (an array index segment that is not one is "not found", never a raise)
        ['resolve e', out { p_.resolve({ 'env' => { "é" => 1 } }, "env.é") }, [true, 1]],
        ['resolve lone key', out { p_.resolve({ 'env' => { LONE => 2 } }, "env.#{LONE}") }, [true, 2]],
        ['resolve lone index', out { p_.resolve({ 'env' => { 'a' => [7] } }, "env.a.#{LONE}") }, [false, nil]],
        ['resolve index', out { p_.resolve({ 'env' => { 'a' => [7, 8] } }, 'env.a.1') }, [true, 8]],
        # code points of a surrogate-pair unit view, at every surrogate boundary
        ['cp U+10000', out { p_.code_points(u("\u{10000}")) }, [0x10000]], ['cp U+103FF', out { p_.code_points(u("\u{103FF}")) }, [0x103FF]],
        ['cp U+10400', out { p_.code_points(u("\u{10400}")) }, [0x10400]], ['cp U+10FC00', out { p_.code_points(u("\u{10FC00}")) }, [0x10FC00]],
        ['cp U+10FFFF', out { p_.code_points(u("\u{10FFFF}")) }, [0x10FFFF]], ['cp U+FFFF', out { p_.code_points(u("\u{FFFF}")) }, [0xFFFF]],
        ['cp U+D7FF', out { p_.code_points(u("\u{D7FF}")) }, [0xD7FF]], ['cp U+E000', out { p_.code_points(u("\u{E000}")) }, [0xE000]],
        ['cp mixed', out { p_.code_points(u("a\u{1F600}b\u{10001}")) }, [0x61, 0x1F600, 0x62, 0x10001]],
        # order: code point order (astral above U+FFFF), nil (not false) for a lone surrogate
        ['ord FFFF<10000', out { p_.order_utf8("\u{FFFF}", "\u{10000}") }, -1], ['ord 10000>FFFF', out { p_.order_utf8("\u{10000}", "\u{FFFF}") }, 1],
        ['ord 10001<10002', out { p_.order_utf8("\u{10001}", "\u{10002}") }, -1], ['ord 103FF<10400', out { p_.order_utf8("\u{103FF}", "\u{10400}") }, -1],
        ['ord lone', out { p_.order_utf8(LONE, 'a') }, nil], ['ord lone r', out { p_.order_utf8('a', LONE) }, nil],
        ['ordered 1<2', out { p_.ordered(1, 2) }, -1], ['ordered 2>1', out { p_.ordered(2, 1) }, 1], ['ordered 1=1.0', out { p_.ordered(1, 1.0) }, 0],
        ['ordered 1/a', out { p_.ordered(1, 'a') }, nil], ['ordered a/1', out { p_.ordered('a', 1) }, nil], ['ordered a/[]', out { p_.ordered('a', []) }, nil],
        ['ordered []/a', out { p_.ordered(['a'], 'a') }, nil], ['ordered inf', out { p_.ordered(inf, 1) }, nil], ['ordered true/1', out { p_.ordered(true, 1) }, nil],
        ['ordered nil', out { p_.ordered(nil, nil) }, nil], ['ordered a<b', out { p_.ordered('a', 'b') }, -1], ['ordered sym', out { p_.ordered(:a, 'a') }, nil]
      ])
    end

    def check_glob_tags
      dflt = Hash.new('x')
      dtags = Hash.new(['x'])
      adj = Hash.new('zz')
      adj['a'] = 'b'
      rows([
        ['parse_glob dangling', out { p_.parse_glob(u('a\\')) }, nil], ['parse_glob **', out { p_.parse_glob(u('a**b')) }, [[:lit, 97], [:star], [:lit, 98]]],
        ['parse_glob *', out { p_.parse_glob(u('*')) }, [[:star]]], ['parse_glob esc', out { p_.parse_glob(u('\\*?')) }, [[:lit, 42], [:one]]],
        ['parse_glob ***', out { p_.parse_glob(u('***')) }, [[:star]]],
        ['glob dangling', out { p_.glob_match('a\\', 'a') }, nil], ['glob aa*ab/aab', out { p_.glob_match('aa*ab', 'aab') }, false],
        ['glob aa*ab/aaab', out { p_.glob_match('aa*ab', 'aaab') }, true], ['glob ab*b/abxb', out { p_.glob_match('ab*b', 'abxb') }, true],
        ['glob * empty', out { p_.glob_match('*', '') }, true], ['glob ? empty', out { p_.glob_match('?', '') }, false],
        # type / tag tests: own keys only (a Hash default value is not a member), nil when undecidable
        ['tag 5', out { p_.type_tag_match(5, 'x') }, nil], ['tag []', out { p_.type_tag_match(['x'], 'x') }, nil], ['tag nil', out { p_.type_tag_match(nil, 'x') }, nil],
        ['tag {}', out { p_.type_tag_match({}, 'x') }, nil], ['tag type', out { p_.type_tag_match({ 'type' => 'x' }, 'x') }, true],
        ['tag tags', out { p_.type_tag_match({ 'tags' => ['x'] }, 'x') }, true], ['tag type 5', out { p_.type_tag_match({ 'type' => 5 }, 'x') }, nil],
        ['tag default type', out { p_.type_tag_match(dflt, 'x') }, nil], ['tag default tags', out { p_.type_tag_match(dtags, 'x') }, nil],
        # adjacency: own String / String[] values only, a Hash default is no edge, a nil key is never a node
        ['nb default', out { p_.neighbours_of(adj, 'q') }, []], ['nb mixed', out { p_.neighbours_of({ 'a' => ['b', 5, nil, 'c'] }, 'a') }, %w[b c]],
        ['nb string', out { p_.neighbours_of({ 'a' => 'b' }, 'a') }, ['b']], ['nb forbidden', out { p_.neighbours_of({ '__proto__' => 'b' }, '__proto__') }, []],
        ['closure', out { p_.member_closure('a', { 'a' => 'b' }) }, { 'a' => true, 'b' => true }],
        ['closure nil key', out { p_.member_closure('a', { nil => 'zz', 'a' => 'b' }) }, { 'a' => true, 'b' => true }],
        ['closure default', out { p_.member_closure('a', adj) }, { 'a' => true, 'b' => true }],
        # leaf_condition? never raises
        ['leaf [1]', out { AtlasPca.leaf_condition?([1]) }, false], ['leaf str', out { AtlasPca.leaf_condition?('field') }, false],
        ['leaf 5', out { AtlasPca.leaf_condition?(5) }, false], ['leaf ok', out { AtlasPca.leaf_condition?({ 'field' => 'x' }) }, true],
        ['leaf group', out { AtlasPca.leaf_condition?({ 'field' => 'x', 'not' => {} }) }, false]
      ])
    end

    LIAR_OP = Class.new { def ==(_o) = true }.new
    CTX = { 'action' => { 'verb' => 'v', 'resource' => 'r', 'params' => {} },
            'env' => { 's' => 'abc', 'n' => 5, 'g' => { 'a' => 'b' }, 'arr' => [1], 'bad' => "\xFF".dup.force_encoding('UTF-8') } }.freeze

    # A 3904-instruction program (fixed repeats: no cost bits, every repeat <= 64) on a 512-unit subject: 3904 x 513 steps is over
    # the engine's 2,000,000 cap, so the matcher answers nil (=> unknown), although the per-document budget (5,000,000) admits it.
    BIG_RE = "#{'(?:abcdefghij){64}' * 6}(?:abcdefghi){7}"

    def check_tri_leaf
      tl = ->(c) { out { p_.tri_leaf(c, CTX) } }
      big = AtlasPca.compile_safe_regex(BIG_RE)
      return "BIG_RE precondition: #{big&.program&.length}" unless big && big.program.length == 3904 && AtlasPca.is_safe_regex_source(BIG_RE)

      rows([
        ['field 5', tl.call({ 'field' => 5, 'op' => 'eq', 'value' => 1 }), 'unknown'],
        ['field nil', tl.call({ 'op' => 'eq', 'value' => 1 }), 'unknown'],
        ['op liar', tl.call({ 'field' => 'env.s', 'op' => LIAR_OP }), 'unknown'],
        ['op 5', tl.call({ 'field' => 'env.s', 'op' => 5 }), 'unknown'],
        ['member_of array coll', tl.call({ 'field' => 'env.s', 'op' => 'member_of', 'collection' => 'env.arr', 'value' => 'x' }), 'unknown'],
        ['member_of missing coll', tl.call({ 'field' => 'env.s', 'op' => 'member_of', 'collection' => 'env.zz', 'value' => 'x' }), 'unknown'],
        ['member_of string coll', tl.call({ 'field' => 'env.s', 'op' => 'member_of', 'collection' => 'env.s', 'value' => 'x' }), 'unknown'],
        ['member_of ok', tl.call({ 'field' => 'env.s', 'op' => 'member_of', 'collection' => 'env.g', 'value' => 'abc' }), 'true'],
        ['lt mixed', tl.call({ 'field' => 'env.s', 'op' => 'lt', 'value' => 5 }), 'unknown'],
        ['gte mixed', tl.call({ 'field' => 'env.n', 'op' => 'gte', 'value' => 'a' }), 'unknown'],
        ['prefix v5', tl.call({ 'field' => 'env.n', 'op' => 'prefix', 'value' => 'a' }), 'unknown'],
        ['prefix op5', tl.call({ 'field' => 'env.s', 'op' => 'prefix', 'value' => 5 }), 'unknown'],
        ['like v5', tl.call({ 'field' => 'env.n', 'op' => 'like', 'value' => 'a' }), 'unknown'],
        ['like op5', tl.call({ 'field' => 'env.s', 'op' => 'like', 'value' => 5 }), 'unknown'],
        ['matches v5', tl.call({ 'field' => 'env.n', 'op' => 'matches', 'value' => 'a' }), 'unknown'],
        ['matches op5', tl.call({ 'field' => 'env.s', 'op' => 'matches', 'value' => 5 }), 'unknown'],
        ['is_a op5', tl.call({ 'field' => 'env.s', 'op' => 'is_a', 'value' => 5 }), 'unknown'],
        ['is_a op empty', tl.call({ 'field' => 'env.s', 'op' => 'is_a', 'value' => '' }), 'unknown'],
        ['prefix ok', tl.call({ 'field' => 'env.s', 'op' => 'prefix', 'value' => 'ab' }), 'true'],
        # the matcher's own step cap answers nil: unknown, never "false"
        ['matches over step cap', out { AtlasPca.evaluate_condition_tri({ 'field' => 'env.x', 'op' => 'matches', 'value' => BIG_RE }, { 'env' => { 'x' => 'a' * 512 } }) }, 'unknown'],
        ['matches under step cap', out { AtlasPca.evaluate_condition_tri({ 'field' => 'env.x', 'op' => 'matches', 'value' => BIG_RE }, { 'env' => { 'x' => 'a' * 511 } }) }, 'false'],
        # an exception inside a leaf (a subject that is not UTF-8) is unknown
        ['broken subject', out { AtlasPca.evaluate_condition_tri({ 'field' => 'env.bad', 'op' => 'prefix', 'value' => 'a' }, CTX) }, 'unknown']
      ])
    end

    # guard_brace at `{`: [length, lo, hi] (hi INF for `{n,}`) or nil (never false)
    def check_brace
      g = ->(s, i) { out { p_.guard_brace(u(s), i) } }
      inf = AtlasPca::SafeRegex::INF
      rows([
        ['{}', g.call('a{}', 1), nil], ['{,5}', g.call('a{,5}', 1), nil], ['{2', g.call('a{2', 1), nil], ['{2x', g.call('a{2x', 1), nil],
        ['{2,3x', g.call('a{2,3x', 1), nil], ['{2,3', g.call('a{2,3', 1), nil], ['{2,x}', g.call('a{2,x}', 1), nil], ['{', g.call('a{', 1), nil],
        ['{2}', g.call('a{2}', 1), [3, 2, 2]], ['{2,}', g.call('a{2,}', 1), [4, 2, inf]], ['{2,5}b', g.call('a{2,5}b', 1), [5, 2, 5]],
        ['{12,345}', g.call('a{12,345}', 1), [8, 12, 345]], ['{0}', g.call('{0}', 0), [3, 0, 0]], ['{10}x', g.call('a{10}x', 1), [4, 10, 10]]
      ])
    end

    # the guard itself (direct, so a raise is visible): exact verdicts at its edges
    def check_safe
      ss = ->(s) { out { p_.safe_source?(u(s), s) } }
      pub = ->(s) { out { AtlasPca.is_safe_regex_source(s) } }
      rows([
        ['a\\', ss.call('a\\'), false], ['\\', ss.call('\\'), false], ['a)', ss.call('a)'), false], [')', ss.call(')'), false], ['(a))', ss.call('(a))'), false],
        ['a{', ss.call('a{'), false], ['a{2', ss.call('a{2'), false], ['a{2,}', ss.call('a{2,}'), true],
        ['esc NUL', pub.call("\\\u0000"), true], ['esc NUL a*', pub.call("\\\u0000a*"), true],
        ['class esc ]', pub.call('[\\](a*)*]'), true], ['class esc ] tail', pub.call('[a\\]b(a*)*]'), true], ['class esc ]+', pub.call('[\\]]+'), true],
        ['((a*))*', pub.call('((a*))*'), false], ['((a|b))*', pub.call('((a|b))*'), false], ['(a|b)*', pub.call('(a|b)*'), false], ['(a*)*', pub.call('(a*)*'), false],
        ['((a)|b)*', pub.call('((a)|b)*'), false], ['((?:a*)b)+', pub.call('((?:a*)b)+'), false], ['((a))*', pub.call('((a))*'), true],
        ['(?:a)', pub.call('(?:a)'), true], ['(a?)', pub.call('(a?)'), true], ['a?(b)', pub.call('a?(b)'), true], ['(?:ab)*', pub.call('(?:ab)*'), true],
        ['a?b', pub.call('a?b'), true], ['(?:a)?', pub.call('(?:a)?'), true],
        ['not a string', pub.call(5), false], ['broken bytes', pub.call("\xFF".dup.force_encoding('UTF-8')), false], ['binary bytes', pub.call("\xFF".b), false]
      ])
    end

    def check_resource
      rm = ->(pat, res) { out { p_.resource_matches(pat, res) } }
      poisoned = AtlasPca::RegexBudget.new
      poisoned.evaluations = AtlasPca::RegexBudget::MAX_REGEX_EVALUATIONS_PER_DOCUMENT
      rows([
        ['Object pattern', rm.call(Object, 'r'), false], ['UNDEF', rm.call(p_::UNDEF, 'r'), true], ['*', rm.call('*', 'r'), true],
        ['* never reads the resource', rm.call('*', 5), true],
        ['re:a', rm.call('re:a', 'a'), true], ['re:a/b', rm.call('re:a', 'b'), false], ['re:ab', rm.call('re:ab', 'ab'), true],
        ['re: too long', rm.call("re:#{'a' * 201}", 'a'), false], ['re: 200', rm.call("re:#{'a' * 200}", 'a' * 200), true],
        ['re: subject 513', rm.call('re:a*', 'a' * 513), false], ['re: subject 512', rm.call('re:a*', 'a' * 512), true],
        ['re: unsafe', rm.call('re:(a*)*', 'aa'), false],
        ['re: over budget', out { poisoned.run { p_.resource_matches('re:a', 'a') } }, false],
        ['prefix*', rm.call("é*", "éx"), true], ['exact', rm.call("é", "é"), true]
      ])
    end

    # fault injection: the public entry points never raise even when the budget machinery itself fails
    def check_entry_faults
      deep = 66.times.reduce(['x']) { |a, _| [a] }
      raising = Class.new(Hash) { def key?(_k) = raise(ArgumentError, 'injected') }.new
      res = rows([
        ['String() refused in reason', out { AtlasPca.evaluate_predicates([{ 'verb' => 'x' }], { 'action' => { 'verb' => deep, 'resource' => 'r' } }) },
         { 'allowed' => false, 'reason' => 'predicate evaluation error (fail closed)' }],
        ['broken resource', out { AtlasPca.predicate_matches({ 'verb' => 'v', 'resource' => 'r' }, { 'action' => { 'verb' => 'v', 'resource' => "\xFF".dup.force_encoding('UTF-8') } }) }, false],
        ['resolve_path raising ctx', out { AtlasPca.resolve_path(raising, 'env.a') }, { 'found' => false }]
      ])
      return res if res

      klass = AtlasPca::RegexBudget
      orig = klass.instance_method(:run)
      return 'a regex scope is open' unless klass.current.nil?

      begin
        klass.send(:define_method, :run) { |&_blk| raise ArgumentError, 'injected' }
        rows([
          ['evaluate_condition_tri', out { AtlasPca.evaluate_condition_tri({ 'field' => 'env.a', 'op' => 'exists' }, { 'env' => { 'a' => 1 } }) }, 'unknown'],
          ['predicate_matches', out { AtlasPca.predicate_matches({ 'verb' => 'v' }, { 'action' => { 'verb' => 'v', 'resource' => 'r' } }) }, false],
          ['evaluate_predicates', out { AtlasPca.evaluate_predicates([{ 'verb' => 'v' }], { 'action' => { 'verb' => 'v', 'resource' => 'r' } }) },
           { 'allowed' => false, 'reason' => 'predicate evaluation error (fail closed)' }]
        ])
      ensure
        klass.send(:define_method, :run, orig)
      end
    end
  end

  %w[jeq deep_eq_start scalars glob_tags tri_leaf brace safe resource entry_faults].each do |kind|
    t("predicates r11: #{kind}") do
      next true if PredR11.skip?

      bad = PredR11.send(:"check_#{kind}")
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
