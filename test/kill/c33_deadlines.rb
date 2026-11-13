# frozen_string_literal: true
require 'timeout'
require 'openssl'

# c33: deadline kills (lib/atlas_pca/safe_regex.rb, lib/atlas_pca/predicates.rb, lib/atlas_pca.rb) plus the predicates.rb / atlas_pca.rb survivors.
#
# WHY c14 / c15 STILL LEFT TIMEOUTS (root cause, read before touching this file):
#  1. ORDER. The oracle runs the kill tests in load order and the first failing test decides the mutant. c14 / c15 load late (c-prefix),
#     so a mutant that loops forever hung inside an EARLIER test with no deadline (the corpus-style tests, 9m_saferegex_prog, 93_predicates...)
#     and the c14 / c15 deadline tests were never reached; mutate.rb recorded no verdict and counted it KILLED(timeout) or, when the loop
#     allocated, RUN_ERROR(NoMemoryError / exit 1). The oracle's move-to-front hint only learns from tests that KILLED a mutant, and a hang kills
#     nothing, so it could never promote them. FIX HERE: the tests of this file are moved to the FRONT of MutationKill::TESTS (bottom of the
#     file), each one gated by MUT_FILE so it costs nothing for the other files.
#  2. LOAD-TIME BINDING. c14 held `PR = AtlasPca::Predicates` / `SR = AtlasPca::SafeRegex` in constants: the oracle drops AtlasPca per mutant,
#     so every predicates.rb deadline test of c14 ran the ORIGINAL code. Everything here resolves AtlasPca at CALL time.
#  3. SWALLOWED TIMEOUT. The engine entry points (safe_regex_full_match, compile, Ed25519Strict.verify ...) `rescue StandardError`; a
#     Timeout::Error is a RuntimeError, so the one Timeout raised inside a hung call was swallowed and the call answered nil / false. `timed`
#     therefore also requires the case to FINISH inside its deadline and gives every case its own deadline.
#  4. SystemStackError. mutate.rb counts any SystemStackError RAISED during the oracle (TracePoint) as RUN_ERROR(SystemStackError), even
#     when a test rescues it and answers false. The recursion mutants of split_point / build / merkle_root are therefore caught by a call-count
#     seam (a StandardError after a few hundred calls) and by exact split_point values, never by letting the stack overflow.
module MutationKill
  @c33_first = TESTS.length # the registry position where this file's tests start (moved to the front at the bottom)

  module C33
    module_function

    # the MUT_FILE gate (AGENT-BRIEF): true when this test does not bear on the file under mutation
    def skip?(*files)
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !files.include?(f)
    end

    def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    # true only when the block answers truthy AND finishes inside `sec`: a Timeout::Error (or one swallowed by a rescue inside the library,
    # which then answers something else, or nothing wrong) fails the case.
    def timed(sec = 1.0)
      t0 = clock
      r = Timeout.timeout(sec) { yield }
      r && (clock - t0) < sec
    rescue Timeout::Error
      false
    end

    def m(src, subj) = AtlasPca.safe_regex_full_match(src, subj)

    def u(s) = AtlasPca::SafeRegex.units(s)

    # [source, subject, want] rows, each with its own deadline; want nil = refused / unsupported
    def rx(rows, sec = 1.0)
      rows.all? { |src, subj, want| timed(sec) { m(src, subj) == want } }
    end

    def malformed(text)
      AtlasPca.parse_json(text)
      nil
    rescue AtlasPca::Malformed => e
      e.message
    end

    # RFC 6962 MTH over already hashed leaves, with its own split (the largest power of two below n)
    def mth(hs)
      return hs[0] if hs.length == 1

      k = 1
      k <<= 1 while (k << 1) < hs.length
      AtlasPca.send(:node_hash, mth(hs[0, k]), mth(hs[k..]))
    end

    # runs the block with AtlasPca.build counting its calls: a runaway recursion becomes a RuntimeError (never a SystemStackError)
    def counted_build(limit = 400)
      orig = AtlasPca.method(:build)
      calls = 0
      stub = lambda do |hs|
        calls += 1
        raise 'runaway build recursion' if calls > limit

        orig.call(hs)
      end
      Seam.with(AtlasPca, { build: stub }) { yield }
    end
  end

  # ------------------------------------------------------------------------------------------------ lib/atlas_pca/safe_regex.rb

  t('deadline c33: CharSet#has? binary search terminates and answers below, on, between and above every range') do
    next true if C33.skip?('safe_regex.rb')

    ranges = [[10, 20], [30, 40], [50, 60], [70, 80]]
    cs = AtlasPca::SafeRegex::CharSet.new(ranges, false)
    ng = AtlasPca::SafeRegex::CharSet.new(ranges, true)
    ins = [10, 15, 20, 30, 35, 40, 50, 55, 60, 70, 75, 80]
    outs = [0, 5, 9, 21, 25, 29, 41, 45, 49, 61, 65, 69, 81, 100]
    one = AtlasPca::SafeRegex::CharSet.new([[7, 7]], false)
    C33.timed(1.0) { ins.all? { |c| cs.has?(c) && !ng.has?(c) } && outs.none? { |c| cs.has?(c) } && outs.all? { |c| ng.has?(c) } } &&
      C33.timed(1.0) { one.has?(7) && !one.has?(6) && !one.has?(8) && !AtlasPca::SafeRegex::CharSet.new([], false).has?(1) }
  end

  t('deadline c33: units_have_lone_surrogate? terminates on pairs, plain units, lone high, lone low and the empty view') do
    next true if C33.skip?('safe_regex.rb')

    sr = AtlasPca::SafeRegex
    C33.timed(1.0) do
      sr.units_have_lone_surrogate?([0x41, 0xd83d, 0xde00, 0x42]) == false && sr.units_have_lone_surrogate?([0x41, 0x42, 0x43]) == false &&
        sr.units_have_lone_surrogate?([0x41, 0xd83d]) == true && sr.units_have_lone_surrogate?([0xd83d, 0x41]) == true &&
        sr.units_have_lone_surrogate?([0xde00, 0x41]) == true && sr.units_have_lone_surrogate?([0xdbff, 0xdc00]) == false &&
        sr.units_have_lone_surrogate?([]) == false
    end
  end

  t('deadline c33: safe regex parser and matcher: alternation, concatenation, groups, anchors, dot') do
    next true if C33.skip?('safe_regex.rb')

    C33.rx([
             ['a|b|c', 'b', true], ['a|b|c', 'd', false], ['abc', 'abc', true], ['abc', 'abd', false], ['(ab)c', 'abc', true],
             ['(?:ab|cd)e', 'cde', true], ['(?:ab|cd)e', 'abe', true], ['(?:ab|cd)e', 'cbe', false], ['a.c', 'abc', true],
             ['.', "\n", false], ['.', 'x', true], ['^a$', 'a', true], ['^a', 'a', true], ['a^', 'a', false], ['^$', '', true],
             ['', '', true], ['a|', '', true], ['a|', 'a', true], ['|a', 'a', true], ['(|a)b', 'b', true], ['()', '', true],
             ['(a)(b)', 'ab', true], ['a]', 'a]', true]
           ])
  end

  t('deadline c33: safe regex parser and matcher: classes, ranges, class escapes, unterminated classes') do
    next true if C33.skip?('safe_regex.rb')

    C33.rx([
             ['[a-c]x', 'bx', true], ['[^a-c]x', 'bx', false], ['[^a-c]x', 'dx', true], ['[abc]x', 'cx', true], ['[abc]x', 'dx', false],
             ['[]', 'a', false], ['[]', '', false], ['[^]', 'z', true], ['[^]', "\n", true], ['[a-]', '-', true], ['[a-]', 'a', true],
             ['[a-]', 'b', false], ['[\\d-x]', '-', true], ['[\\d-x]', '5', true], ['[\\d-x]', 'x', true], ['[\\d-x]', 'y', false],
             ['[\\]]', ']', true], ['[\\w]', '_', true], ['[\\D]', '5', false], ['[\\D]', 'a', true], ['[\\S]', ' ', false],
             ['[\\b]', "\b", true], ['[b-a]', 'a', nil], ['[a', 'a', nil], ['[', 'a', nil], ['[^', 'a', nil], ['[a\\', 'a', nil]
           ])
  end

  t('deadline c33: safe regex parser and matcher: quantifiers, braces (four-digit cap), lazy modifiers, refusals') do
    next true if C33.skip?('safe_regex.rb')

    C33.rx([
             ['a{2,3}', 'aa', true], ['a{2,3}', 'a', false], ['a{2,3}', 'aaaa', false], ['a{3}', 'aaa', true], ['a{2,}', 'aaaa', true],
             ['a{2,}', 'a', false], ['a{12,34}', 'a' * 20, true], ['a{12,34}', 'a' * 35, false], ['a{2,34}b', 'aab', true],
             ['a+b*c?', 'aabbc', true], ['a+b*c?', 'b', false], ['a*', 'a' * 50, true], ['a*b', "#{'a' * 50}c", false],
             ['a+?', 'aaa', true], ['a*?b', 'aab', true], ['a??', '', true], ['a{2}?', 'aa', true], ['a{0}', '', true], ['a{0}', 'a', false],
             ['a{0001}', 'a', true], ['a{00001}', 'a', nil], ['a{1,0002}', 'aa', true], ['a{1,0002}', 'aaa', false],
             ['a{1,00002}', 'a', nil], ['a{,3}', 'a', nil], ['a{3,2}', 'aaa', nil], ['a{65}', 'a', nil], ['a{64}', 'a' * 64, true],
             ['a{', 'a', nil], ['{', 'a', nil], ['a**', 'a', nil], ['*a', 'a', nil], ['^*', '', nil], ['(?=a)', 'a', nil], ['a)', 'a', nil],
             ['(a', 'a', nil]
           ])
  end

  t('deadline c33: safe regex parser and matcher: escapes') do
    next true if C33.skip?('safe_regex.rb')

    C33.rx([
             ['x\\.y', 'x.y', true], ['x\\.y', 'xzy', false], ['\\x41b', 'Ab', true], ['\\x4', 'x', nil], ['\\x4g', 'x', nil],
             ['\\u0041b', 'Ab', true], ['\\u004', 'x', nil], ['\\cJ', "\n", true], ['\\cj', "\n", true], ['\\c1', 'x', nil],
             ['\\0', "\u0000", true], ['\\01', 'x', nil], ['\\d+', '123', true], ['\\d', 'a', false], ['\\D', 'a', true],
             ['\\w\\W', 'a-', true], ['\\s\\S', ' x', true], ['\\t\\n\\v\\f\\r', "\t\n\v\f\r", true], ['\\b', 'x', nil], ['\\q', 'q', nil],
             ['a\\', 'a', nil], ['\\_', '_', nil], ['\\-', '-', true], ['\\1', '1', nil]
           ])
  end

  t('deadline c33: safe regex matcher terminates on epsilon cycles, an empty subject and long subjects') do
    next true if C33.skip?('safe_regex.rb')

    C33.rx([
             ['(a*)*', 'aa', true], ['(a*)*', '', true], ['(a*)*b', 'aab', true], ['(a|)*b', 'aab', true], ['(a*)+b', 'b', true],
             ['()*', '', true], ['()*a', 'a', true], ['(a?){2,3}', 'aa', true], ['(a?){2,3}', 'aaaa', false],
             ['a*', '', true], ['a+', '', false], ['', 'a', false], ['^$', 'a', false], ['(ab|a)(bc|c)?', 'abc', true]
           ])
  end

  t('deadline c33: the compiled-regex cache evicts one entry at a time and terminates past its bound') do
    next true if C33.skip?('safe_regex.rb')

    s = AtlasPca::SafeRegex
    top = s::CACHE_MAX_ENTRIES + 19
    C33.timed(3.0) do
      (0...(s::CACHE_MAX_ENTRIES + 20)).all? { |i| C33.m("k#{i}", "k#{i}") == true } && s::CACHE.length == s::CACHE_MAX_ENTRIES &&
        !s::CACHE.key?('k0'.b) && s::CACHE.key?("k#{top}".b)
    end
  end

  # ------------------------------------------------------------------------------------------------ lib/atlas_pca/predicates.rb

  t('deadline c33: predicates code_points terminates and decodes pairs, BMP edges and the highest code point') do
    next true if C33.skip?('predicates.rb')

    pr = AtlasPca::Predicates
    C33.timed(1.0) do
      pr.code_points(C33.u("a\u{1F600}b")) == [0x61, 0x1F600, 0x62] && pr.code_points([]) == [] &&
        pr.code_points(C33.u("\u{1F600}\u{1F601}")) == [0x1F600, 0x1F601] && pr.code_points(C33.u("\u{10FFFF}")) == [0x10FFFF] &&
        pr.code_points([0xd7ff, 0xe000]) == [0xd7ff, 0xe000]
    end
  end

  t('deadline c33: predicates glob_match terminates and answers stars, ?, escapes, backtracking, trailing stars, a dangling backslash') do
    next true if C33.skip?('predicates.rb')

    pr = AtlasPca::Predicates
    rows = [
      ['a*c', 'abc', true], ['a*c', 'abd', false], ['a*c', 'ac', true], ['a?c', 'abc', true], ['a?c', 'ac', false],
      ['a*b*c', 'aXbYc', true], ['*b', 'aab', true], ['*b', 'aba', false], ['a*', 'a', true], ['a*', 'abcd', true], ['a**', 'a', true],
      ['*', '', true], ['*', 'xyz', true], ['abc', 'abc', true], ['abc', 'abcd', false], ['', '', true], ['a*a*a', 'aXaYa', true],
      ['a*c', "a\u{1F600}c", true], ['a?c', "a\u{1F600}c", false], ['a??c', "a\u{1F600}c", true], ['*', "\u{1F600}", true],
      ['a\\*b', 'a*b', true], ['a\\*b', 'axb', false], ['a\\?', 'a?', true], ['a\\?', 'ab', false], ['\\\\', '\\', true],
      ['??', 'ab', true], ['??', 'a', false], ['?', '', false], ['*a*', 'xax', true], ['*a*', 'xx', false], ['**', '', true],
      ['a*?', 'abc', true], ['abc\\', 'abc', nil], ['\\', '', nil]
    ]
    rows.all? { |g, s, want| C33.timed(1.0) { pr.glob_match(g, s) == want } }
  end

  t('deadline c33: predicates guard_brace terminates on every digit run and returns the exact span') do
    next true if C33.skip?('predicates.rb')

    pr = AtlasPca::Predicates
    inf = AtlasPca::SafeRegex::INF
    g = ->(src, i = 0) { pr.guard_brace(C33.u(src), i) }
    C33.timed(1.0) do
      g.call('{2,34}') == [6, 2, 34] && g.call('{12}') == [4, 12, 12] && g.call('{3,}') == [4, 3, inf] && g.call('{}').nil? &&
        g.call('{a}').nil? && g.call('{2,3').nil? && g.call('{2').nil? && g.call('x{10,20}', 1) == [7, 10, 20] &&
        g.call('{12345}') == [7, 12_345, 12_345] && g.call('{2,3x}').nil? && g.call('{,3}').nil?
    end
  end

  t('deadline c33: predicates safe_source? terminates and answers escapes, classes, groups, alternation, quantifiers and the cost budget') do
    next true if C33.skip?('predicates.rb')

    pr = AtlasPca::Predicates
    s = ->(src) { pr.safe_source?(C33.u(src), src) }
    yes = ['ab', '', '[ab]c', '\\.a', '[a\\]b]', '[^ab]c', '(?:a)b', '(a)', 'a|b|c', '(a|b)', 'a*', 'a+?', 'a{2,3}', 'a{2}?', 'a{64}', 'a?b',
           '(a)*', '\\0', 'a*b*', '(a)(b)*', '(?:a|b)', 'a*b*c?', 'a{0,64}b{0,64}c{0,64}d?', (['a'] * 23).join('|')]
    no = ['\\1', '\\9', '\\k', '[ab', '[a\\', 'a\\', '(?=a)', '(?<n>a)', '(?', '(?:a', ')', '(a', '*a', 'a**', 'a+*', '(a|b)*', '(a*)*', '((a*))*',
          '(b|(a))*', 'a{65}', 'a{1,65}', 'a{3,2}', 'a{2', 'a{2,3}{2}', 'a*b*c*', 'a{0,64}b{0,64}c{0,64}d?e?', (['a'] * 24).join('|')]
    # the guard alone: the source handed to the engine is a harmless 'a', so only safe_source?'s own scan can refuse these
    alone = ['*a', '+', '?', '(*a)', 'a|*b', 'a**', 'a{2}*', '(?=a)', '\\1']
    C33.timed(3.0) do
      yes.all? { |x| s.call(x) == true } && no.all? { |x| s.call(x) == false } && alone.all? { |x| pr.safe_source?(C33.u(x), 'a') == false }
    end
  end

  t('deadline c33: predicates safe_source? keeps the alternation flag of a group when an inner group closes') do
    next true if C33.skip?('predicates.rb')

    pr = AtlasPca::Predicates
    # parent[1] ||= f[1]: with `=`, the clean inner group (a) would clear the `|` seen before it, and (b|(a))* would pass
    src = '(b|(a))*'
    pr.safe_source?(C33.u(src), src) == false && pr.safe_source?(C33.u('((a))*'), '((a))*') == true && AtlasPca.is_safe_regex_source(src) == false
  end

  t('predicates show_value: the exact denial wording of each scalar, string and array operand (TS showValue)') do
    next true if C33.skip?('predicates.rb')

    pr = AtlasPca::Predicates
    sv = ->(v) { pr.show_value(v) }
    wtf = ->(bytes) { bytes.dup.force_encoding(Encoding::UTF_8) }
    nums = [[nil, 'null'], [true, 'true'], [false, 'false'], [0, '0'], [42, '42'], [-42, '-42'], [2.0, '2'], [-0.0, '0'], [1.5, '<number>'],
            [(2**53) - 1, '9007199254740991'], [2**53, '<number>'], [-((2**53) - 1), '-9007199254740991'], [-(2**53), '<number>'],
            [1e20, '<number>'], [-1e20, '<number>'], [10**400, '<number>'], [-(10**400), '<number>'], [Float::INFINITY, '<number>'],
            [-Float::INFINITY, '<number>'], [Float::NAN, '<number>']]
    strs = [['abc', '"abc"'], ['', '""'], [' ', '" "'], ['a b', '"a b"'], ["\u00e9", "\"\u00e9\""], ["\u{E000}", "\"\u{E000}\""],
            ["\u{D7FF}", "\"\u{D7FF}\""], ['a"b', '"..."'], ['a\\b', '"..."'], ["a\tb", '"..."'], ["a\u001fb", '"..."'], ["\u007f", "\"\u007f\""],
            ['a' * 64, "\"#{'a' * 64}\""], ['a' * 65, '"..."'], ["\u{1F600}", '"..."'], ["#{'a' * 63}\u{1F600}", '"..."'],
            [wtf.call("\xED\xA0\x80"), '"..."'], [wtf.call("\xED\xAF\xBF"), '"..."'], [wtf.call("\xED\xB0\x80"), '"..."'],
            [wtf.call("\xED\xBF\xBF"), '"..."']]
    arrs = [[[], '[]'], [[1, 'a', nil, true], '[1, "a", null, true]'], [(0..7).to_a, '[0, 1, 2, 3, 4, 5, 6, 7]'], [(0..8).to_a, '[...]'],
            [[[1]], '[<value>]'], [[{}], '[<value>]'], [{}, '<value>'], [{ 'a' => 1 }, '<value>']]
    (nums + strs + arrs).all? { |v, want| sv.call(v) == want } && pr.show_value([1], 1) == '<value>' && pr.show_value('x', 1) == '"x"' &&
      pr.show_value(nil, 3) == 'null' && pr.show_value(7, 1) == '7'
  end

  t('predicates describe_condition: the limit wording of leaves, groups, depth, the 8-item cap and malformed conditions (TS describeCondition)') do
    next true if C33.skip?('predicates.rb')

    pr = AtlasPca::Predicates
    d = ->(c) { pr.describe_condition(c) }
    leaf = { 'field' => 'action.params.n', 'op' => 'lte', 'value' => 5 }
    other = { 'field' => 'action.params.m', 'op' => 'eq', 'value' => 'x' }
    nest = ->(key, inner) { { key => [inner] } }
    nine = (0..8).map { |i| { 'field' => "action.params.p#{i}", 'op' => 'eq', 'value' => i } }
    eight = (0..7).map { |i| "p#{i} == #{i}" }.join('; ')
    rows = [
      [leaf, 'n <= 5'], [other, 'm == "x"'], [{ 'field' => 'action.subject.x', 'op' => 'ne', 'value' => 1 }, 'action.subject.x != 1'],
      [{ 'all_of' => [leaf, other] }, 'all of (n <= 5; m == "x")'], [{ 'any_of' => [leaf, other] }, 'any of (n <= 5; m == "x")'],
      [nest.call('all_of', nest.call('all_of', leaf)), 'all of (all of (n <= 5))'],
      [nest.call('any_of', nest.call('any_of', leaf)), 'any of (any of (n <= 5))'],
      [nest.call('all_of', nest.call('all_of', nest.call('all_of', leaf))), 'all of (all of ((...)))'],
      [nest.call('any_of', nest.call('any_of', nest.call('any_of', leaf))), 'any of (any of ((...)))'],
      [{ 'not' => leaf }, 'not (n <= 5)'], [{ 'not' => { 'not' => { 'not' => leaf } } }, 'not (not ((...)))'],
      [{ 'all_of' => 5 }, '<condition>'], [{ 'any_of' => 'x' }, '<condition>'], [{ 'all_of' => 5, 'any_of' => [leaf] }, 'any of (n <= 5)'],
      [{ 'all_of' => 5, 'not' => leaf }, 'not (n <= 5)'], [{ 'all_of' => [] }, 'all of ()'],
      [{ 'all_of' => nine }, "all of (#{eight})"], [{ 'any_of' => nine }, "any of (#{eight})"],
      [{ 'field' => 'action.params.a', 'op' => 'exists' }, 'a present'], [{ 'field' => 'action.params.a', 'op' => 'exists', 'value' => false }, 'a absent'],
      [{ 'field' => 'action.params.a', 'op' => 'exists', 'value' => true }, 'a present'],
      [{ 'op' => 'eq', 'value' => 1 }, '<field> == 1'], [{ 'field' => 5, 'op' => 'eq', 'value' => 1 }, '<field> == 1'],
      [{ 'field' => 'x', 'op' => 'bogus' }, 'x <condition>'], [{ 'field' => 'x', 'op' => 5 }, 'x <condition>'], [{ 'field' => 'x' }, 'x <condition>'],
      [{ 'field' => 'x', 'op' => nil, 'value' => 1 }, 'x <condition>'],
      [{ 'field' => 'x', 'op' => 'eq', 'ref' => 'y' }, 'x == y'], [{ 'field' => 'x', 'op' => 'eq', 'ref' => 5 }, 'x == <ref>'],
      [{ 'field' => 'x', 'op' => 'eq', 'ref' => nil }, 'x == <ref>'], [{ 'field' => 'x', 'op' => 'eq' }, 'x == <value>'],
      [{ 'field' => 'x', 'op' => 'eq', 'value' => nil }, 'x == null'], [{ 'field' => 'x', 'op' => 'nin', 'value' => [1, 2] }, 'x not in [1, 2]'],
      [{ 'field' => 'x', 'op' => 'prefix', 'value' => 'a' }, 'x starts with "a"'], [{ 'field' => 'x', 'op' => 'member_of', 'ref' => 'r' }, 'x member of r'],
      [[], '<field> <condition>'], [[1], '<field> <condition>'], [nil, '<condition>'], [5, '<condition>'], ['x', '<condition>'], [true, '<condition>']
    ]
    rows.all? { |c, want| d.call(c) == want }
  end

  t('predicates narrowest_unmet: the first unmet child of an all_of, recursion to depth 4, groups and a non-array all_of returned as is') do
    next true if C33.skip?('predicates.rb')

    pr = AtlasPca::Predicates
    ctx = { 'action' => { 'verb' => 'read', 'resource' => '/r', 'params' => { 'n' => 10 } } }
    met = { 'field' => 'action.params.n', 'op' => 'gte', 'value' => 1 }
    bad = { 'field' => 'action.params.n', 'op' => 'lte', 'value' => 5 }
    bad2 = { 'field' => 'action.params.n', 'op' => 'lte', 'value' => 6 }
    nu = ->(c, depth = 0) { pr.narrowest_unmet(c, ctx, depth) }
    g1 = { 'all_of' => [met, bad, bad2] }
    inner = { 'all_of' => [met, bad2] }
    g2 = { 'all_of' => [met, inner] }
    wrap = lambda { |levels|
      levels.times.reduce(bad) { |acc, _| { 'all_of' => [acc] } }
    }
    four = wrap.call(4) # g0 > g1 > g2 > g3 > leaf: depth 3 still recurses into the leaf
    five = wrap.call(5) # g0 > ... > g4 > leaf: the recursion stops at depth 4 and answers g4
    g4 = five
    4.times { g4 = g4['all_of'][0] }
    all_met = { 'all_of' => [met, met] }
    any = { 'any_of' => [bad] }
    nt = { 'not' => bad }
    non_array = { 'all_of' => 5 }
    # a group WITHOUT an all_of key whose indexer nevertheless answers an Array: only the key? test keeps it from being walked
    dflt = Hash.new([bad])
    dflt['not'] = met
    nu.call(g1).equal?(bad) && nu.call(g2).equal?(bad2) && nu.call(four).equal?(bad) && nu.call(five).equal?(g4) && nu.call(all_met).equal?(all_met) &&
      nu.call(any).equal?(any) && nu.call(nt).equal?(nt) && nu.call(bad).equal?(bad) && nu.call(non_array).equal?(non_array) &&
      nu.call(dflt).equal?(dflt) && nu.call(g1, 4).equal?(g1) && nu.call(g1, 3).equal?(bad)
  end

  t('predicates first_unmet_limit: names the first unmet where-limit in scope, and answers exactly nil when nothing is in scope (TS firstUnmetLimit)') do
    next true if C33.skip?('predicates.rb')

    pr = AtlasPca::Predicates
    bad = { 'field' => 'action.params.n', 'op' => 'lte', 'value' => 5 }
    met = { 'field' => 'action.params.n', 'op' => 'gte', 'value' => 1 }
    inner = { 'all_of' => [met, { 'field' => 'action.params.n', 'op' => 'lte', 'value' => 7 }] }
    cx = ->(action) { { 'action' => action } }
    act = { 'verb' => 'read', 'resource' => '/a/b', 'params' => { 'n' => 10 } }
    fu = ->(preds, c = cx.call(act)) { pr.first_unmet_limit(preds, c) }
    pred = ->(where, verb = 'read', resource = '/a/*') { { 'verb' => verb, 'resource' => resource, 'where' => where } }
    everything = ->(where) { { 'verb' => '*', 'resource' => '*', 'where' => where } }
    ok = fu.call([pred.call([bad])]) == 'n <= 5' && fu.call([pred.call([met, bad])]) == 'n <= 5' &&
         fu.call([pred.call([{ 'all_of' => [met, bad] }])]) == 'n <= 5' && fu.call([pred.call([inner])]) == 'n <= 7' &&
         fu.call([nil, 'x', 5, [], pred.call([bad])]) == 'n <= 5' &&
         fu.call([pred.call([met]), pred.call([bad], 'read', '/a/b')]) == 'n <= 5' &&
         fu.call([pred.call([bad], 'write'), pred.call([{ 'field' => 'action.params.n', 'op' => 'lte', 'value' => 9 }], %w[x read])]) == 'n <= 9' &&
         fu.call([pred.call([met])]).nil? && fu.call([pred.call([bad], 'write')]).nil? && fu.call([pred.call([bad], 'read', '/z/*')]).nil? &&
         fu.call([{ 'verb' => 'read', 'resource' => '/a/*', 'where' => { 'x' => 1 } }]).nil? &&
         fu.call([{ 'verb' => 'read', 'resource' => '/a/*' }]).nil? && fu.call([]).nil?
    # outside scope: the action lacks a String verb or resource (a wildcard predicate with an unmet limit must not be named)
    p_all = [everything.call([bad])]
    outside = [{ 'resource' => '/r', 'params' => { 'n' => 10 } }, { 'verb' => 5, 'resource' => '/r', 'params' => { 'n' => 10 } },
               { 'verb' => 'read', 'params' => { 'n' => 10 } }, { 'verb' => 'read', 'resource' => 5, 'params' => { 'n' => 10 } },
               { 'verb' => nil, 'resource' => '/r', 'params' => { 'n' => 10 } }, { 'verb' => 'read', 'resource' => nil, 'params' => { 'n' => 10 } }]
    ok && outside.all? { |a| fu.call(p_all, cx.call(a)).nil? } && fu.call(p_all, { 'action' => 'read' }).nil? &&
      fu.call(p_all, { 'action' => [] }).nil? && fu.call(p_all, {}).nil? && fu.call(p_all, cx.call(act)) == 'n <= 5'
  end

  t('predicates evaluate_predicates: the denial wording names the unmet limit, else the plain no-predicate reason, else allows') do
    next true if C33.skip?('predicates.rb')

    cx = ->(n) { { 'action' => { 'verb' => 'read', 'resource' => '/a/b', 'params' => { 'n' => n } } } }
    pred = { 'verb' => 'read', 'resource' => '/a/*', 'where' => [{ 'field' => 'action.params.n', 'op' => 'lte', 'value' => 5 }] }
    other = { 'verb' => 'write', 'resource' => '/a/*' }
    AtlasPca.evaluate_predicates([pred], cx.call(10)) == { 'allowed' => false, 'reason' => 'n <= 5 not satisfied for read on /a/b' } &&
      AtlasPca.evaluate_predicates([other], cx.call(10)) == { 'allowed' => false, 'reason' => 'no predicate permits read on /a/b' } &&
      AtlasPca.evaluate_predicates([pred], cx.call(3)) == { 'allowed' => true, 'matched' => pred } &&
      AtlasPca.evaluate_predicates([], cx.call(3)) == { 'allowed' => false, 'reason' => 'envelope grants no predicates' }
  end

  # ------------------------------------------------------------------------------------------------ lib/atlas_pca.rb

  t('deadline c33: skip_ws advances over every whitespace byte') do
    next true if C33.skip?('atlas_pca.rb')

    C33.timed(2.0) do
      AtlasPca.parse_json(" \n\t\r{\"a\" \n:\r 1}  ") == { 'a' => 1 } && AtlasPca.parse_json("\t{ \"a\" :\t[ 1 ,\n2 ] }") == { 'a' => [1, 2] } &&
        AtlasPca.parse_json('{ }') == {} && AtlasPca.parse_json('{"a":[ ]}') == { 'a' => [] }
    end
  end

  t('deadline c33: parse_string terminates and decodes plain runs, every escape, \\u pairs, and refuses control bytes / bad escapes / unterminated strings') do
    next true if C33.skip?('atlas_pca.rb')

    all_esc = "a\"b\\c/d\be\ff\ng\rh\ti"
    ok = C33.timed(2.0) do
      AtlasPca.parse_json('{"k":"abc"}') == { 'k' => 'abc' } && AtlasPca.parse_json('{"k":""}') == { 'k' => '' } &&
        AtlasPca.parse_json('{"k":"\\n"}') == { 'k' => "\n" } &&
        AtlasPca.parse_json('{"k":"a\\"b\\\\c\\/d\\be\\ff\\ng\\rh\\ti"}') == { 'k' => all_esc } &&
        AtlasPca.parse_json('{"k":"x\\ny z\\tw"}') == { 'k' => "x\ny z\tw" } && AtlasPca.parse_json('{"k":"\\n "}') == { 'k' => "\n " } &&
        AtlasPca.parse_json('{"k":"\\u0041\\ud83d\\ude00z"}') == { 'k' => "A\u{1F600}z" } && AtlasPca.parse_json('{"k":"\\u00e9"}') == { 'k' => "\u00e9" } &&
        AtlasPca.parse_json("{\"k\":\"\u00e9\u007f\"}") == { 'k' => "\u00e9\u007f" } && AtlasPca.parse_json('{"k":"a","j":"b"}') == { 'k' => 'a', 'j' => 'b' }
    end
    ok && C33.timed(2.0) do
      C33.malformed("{\"k\":\"x\u0001y\"}") == 'raw control character in string' && C33.malformed("{\"k\":\"\\n\u0001\"}") == 'raw control character in string' &&
        C33.malformed("{\"k\":\"\\n\u001f\"}") == 'raw control character in string' && C33.malformed('{"k":"abc') == 'unterminated string' &&
        C33.malformed('{"k":"a\\n') == 'unterminated string' && C33.malformed('{"k":"\\q"}') == 'unknown escape' &&
        C33.malformed('{"k":"a\\') == 'unknown escape' && C33.malformed('{"k":"\\ud800"}') == 'lone surrogate'
    end
  end

  t('deadline c33: merkle split_point is the largest power of two below n (n = 1..70, 1000, 1025) and terminates') do
    next true if C33.skip?('atlas_pca.rb')

    C33.timed(2.0) do
      ((1..70).to_a + [1000, 1024, 1025]).all? { |n| AtlasPca.send(:split_point, n) == (n == 1 ? 1 : 2**((n - 1).bit_length - 1)) }
    end
  end

  t('deadline c33: merkle_root of 1..17 leaves equals an independent RFC 6962 root; build never recurses without end (call-count seam)') do
    next true if C33.skip?('atlas_pca.rb')

    C33.timed(5.0) do
      C33.counted_build do
        (1..17).all? do |n|
          leaves = Array.new(n) { |i| { 'i' => i } }
          want = AtlasPca.send(:b64e, C33.mth(leaves.map { |l| AtlasPca.send(:leaf_hash, l) }))
          AtlasPca.merkle_root(leaves) == want
        end
      end
    end
  end

  t('deadline c33: merkle_root of no leaves is refused with Malformed("empty leaf set"), never a runaway recursion (call-count seam)') do
    next true if C33.skip?('atlas_pca.rb')

    C33.timed(5.0) do
      C33.counted_build do
        r = begin
          AtlasPca.merkle_root([])
          :returned
        rescue AtlasPca::Malformed => e
          e.message
        rescue RuntimeError
          :runaway
        end
        r == 'empty leaf set'
      end
    end
  end

  t('deadline c33: path_shape terminates and matches the RFC 6962 audit-path sides for 1..17 leaves') do
    next true if C33.skip?('atlas_pca.rb')

    side = lambda do |m, n|
      return [] if n == 1

      k = 1
      k <<= 1 while (k << 1) < n
      m < k ? side.call(m, k) + ['R'] : side.call(m - k, n - k) + ['L']
    end
    C33.timed(3.0) { (1..17).all? { |n| (0...n).all? { |m| AtlasPca.send(:path_shape, m, n) == side.call(m, n) } } }
  end

  t('deadline c33: Ed25519 strict verification terminates (the scalar-multiplication loop) and still verifies') do
    next true if C33.skip?('atlas_pca.rb')

    k = OpenSSL::PKey.new_raw_private_key('ED25519', "\x09".b * 32)
    msg = 'deadline'
    sig = k.sign(nil, msg)
    C33.timed(5.0) do
      AtlasPca::Ed25519Strict.verify(k.raw_public_key, msg, sig) == true && AtlasPca::Ed25519Strict.verify(k.raw_public_key, "#{msg}x", sig) == false
    end
  end

  t('suite_dispatch: a nested hybrid whose Ed25519 signature does not decode is exactly false and never reaches the concatenation (seam + spy)') do
    next true if C33.skip?('atlas_pca.rb')

    suite = 'hybrid-nested-ed25519-ml-dsa-65'
    next true unless AtlasPca.supported_suites.include?(suite)

    touched = false
    tail = Class.new do
      define_method(:+) do |_other|
        touched = true
        ''.b
      end
    end.new
    msg = Class.new { define_method(:b) { tail } }.new
    p = { 'alg' => suite, 'sig' => '!!', 'pq_sig' => 'x' }
    r = Seam.with(AtlasPca, { verify_b64u: ->(*) { true } }) { AtlasPca.suite_dispatch(p, 'k', msg, 'pk') }
    r.equal?(false) && touched == false
  end

  t('approved_goal_ref?: a closed object of exactly two members; a String/Symbol key collision cannot smuggle in a third member') do
    next true if C33.skip?('atlas_pca.rb')

    d = AtlasPca.send(:b64e, "\x01".b * 32)
    e = AtlasPca.send(:b64e, "\x02".b * 32)
    ref = AtlasPca.method(:approved_goal_ref?)
    ref.call({ 'goal_digest' => d, 'policy_digest' => e }) == true && ref.call({ goal_digest: d, policy_digest: e }) == true &&
      ref.call({ 'goal_digest' => d, 'policy_digest' => e, 'x' => 1 }) == false &&
      ref.call({ 'goal_digest' => d, :goal_digest => d, 'policy_digest' => e }) == false &&
      ref.call({ 'goal_digest' => d, :goal_digest => d }) == false && ref.call({ 'goal_digest' => d, 'policy_digest' => 'short' }) == false &&
      ref.call({ 'goal_digest' => d }) == false && ref.call({}) == false && ref.call(5) == false && ref.call(nil) == false
  end

  # Move this file's tests to the FRONT of the registry (root cause 1 in the header): a hung mutant must reach a deadline test, not an
  # earlier unbounded one. Order only; every test still has to pass on the real code.
  mine = TESTS.slice!(@c33_first..)
  TESTS.unshift(*mine)
end
