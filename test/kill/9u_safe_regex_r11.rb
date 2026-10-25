# frozen_string_literal: true
# r11 targeted kills for safe_regex.rb (survivors of run 39902549441). The killRegex oracle (9d) only sees the public verdicts
# (full match true / false / refused, program sizes), so it cannot tell WHICH refusal the parser raised (or that it raised a
# Refuse at all rather than crashing into the same nil), the UTF-16 helpers' exact outputs at the surrogate / U+10FFFF edges, the
# compiled-program cache's bound, LRU order and identity, or the regex-budget scope plumbing (join vs open, ambient, scale).
# These tests call the engine's pieces directly and compare exact outcomes.
module MutationKill
  module RegexR11
    module_function
    def s_ = AtlasPca::SafeRegex
    def skip? = DiffUtil.skip?('safe_regex.rb', 'predicates.rb')

    def out
      yield
    rescue StandardError, SystemStackError => e
      [:raise, e.class, e.message]
    end

    def rows(list)
      bad = list.reject { |_, got, want| got == want && got.class == want.class }
      bad.empty? ? nil : bad.map { |n, got, want| "#{n}: want #{want.inspect} got #{got.inspect}" }.join("\n")
    end

    def u(s) = s_.units(s)

    def check_units
      too_big = "\xF4\x90\x80\x80".dup.force_encoding('UTF-8') # 0x110000: decodable, beyond Unicode
      lone = ->(a) { out { s_.units_have_lone_surrogate?(a) } }
      rows([
        ['U+10000', out { u("\u{10000}") }, [0xD800, 0xDC00]], ['U+FFFF U+10000', out { u("\u{FFFF}\u{10000}") }, [0xFFFF, 0xD800, 0xDC00]],
        ['U+10FFFF', out { u("\u{10FFFF}") }, [0xDBFF, 0xDFFF]], ['BMP', out { u("a\u{FFFF}") }, [0x61, 0xFFFF]],
        ['0x110000', out { u(too_big) }, [:raise, ArgumentError, 'code point beyond U+10FFFF']],
        ['lone []', lone.call([]), false], ['lone a', lone.call([0x61]), false], ['pair lo', lone.call([0xD800, 0xDC00]), false],
        ['pair hi', lone.call([0xDBFF, 0xDFFF]), false], ['a pair', lone.call([0x61, 0xD800, 0xDC00]), false], ['pair a', lone.call([0xD800, 0xDC00, 0x61]), false],
        ['low low', lone.call([0xDC00, 0xDC00]), true], ['hi E000', lone.call([0xD800, 0xE000]), true], ['hi a', lone.call([0xD800, 0x61]), true],
        ['hi alone', lone.call([0xD800]), true], ['pair hi', lone.call([0xD800, 0xDC00, 0xD800]), true], ['low DFFF', lone.call([0xDFFF]), true],
        ['low DC00', lone.call([0xDC00]), true], ['hi DBFF alone', lone.call([0xDBFF]), true],
        ['E000 pair', lone.call([0xE000, 0xD800, 0xDC00]), false], ['pair E000', lone.call([0xD800, 0xDC00, 0xE000]), false],
        ['hex nil', out { s_.hex_unit?(nil) }, false], ['alpha nil', out { s_.alpha_unit?(nil) }, false],
        ['complement digits', out { s_.complement([[0x30, 0x39]]) }, [[0, 0x2F], [0x3A, 0xFFFF]]], ['complement 0-5', out { s_.complement([[0, 5]]) }, [[6, 0xFFFF]]],
        ['complement all', out { s_.complement([[0, 0xFFFF]]) }, []], ['complement to FFFE', out { s_.complement([[0, 0xFFFE]]) }, [[0xFFFF, 0xFFFF]]],
        ['complement none', out { s_.complement([]) }, [[0, 0xFFFF]]]
      ])
    end

    # AST in plain data (a CharSet as [:cs, ranges, negated])
    def plain(n)
      case n
      when s_::CharSet then [:cs, n.ranges, n.negated]
      when Array then n.map { |x| plain(x) }
      else n
      end
    end

    REFUSALS = [
      [')', 'unbalanced )'], ['a)', 'unbalanced )'], ['a{', '{ is not a well-formed quantifier'], ['a{2,x}', '{ is not a well-formed quantifier'],
      ['a{3,2}', 'quantifier range out of order'], ['^*', 'nothing to repeat (assertion)'], ['$+', 'nothing to repeat (assertion)'],
      ['a{65}', 'repeat bound too large'], ['a{1,65}', 'repeat bound too large'], ['(?=a)', 'lookaround / named groups are not supported'],
      ['(a', 'unterminated group'], ['*', 'nothing to repeat'], ['a|?', 'nothing to repeat'], ['{2}', '{ is not a well-formed quantifier'],
      ['\\', 'trailing backslash'], ['\\01', 'octal escape'], ['\\xZ1', 'bad \\x escape'], ['\\x1', 'bad \\x escape'], ['\\u12', 'bad \\u escape'],
      ['\\c1', 'bad \\c escape'], ['\\c', 'bad \\c escape'], ['\\b', 'word-boundary assertions are not supported'], ['\\q', 'escape is not supported'],
      ['[a', 'unterminated class'], ['[a-', 'unterminated class'], ['[z-a]', 'class range out of order']
    ].freeze

    def check_parser
      parse = ->(src) { out { plain(s_::Parser.new(u(src)).parse) } }
      brace = lambda do |src, i|
        out do
          pr = s_::Parser.new(u(src))
          pr.instance_variable_set(:@i, i)
          pr.brace
        end
      end
      esc = ->(src) { out { s_::Parser.new(u(src)).escape_inner(false)[2] } }
      a = [:set, [:cs, [[97, 97]], false]]
      b = [:set, [:cs, [[98, 98]], false]]
      list = REFUSALS.map { |src, msg| ["refuse #{src}", parse.call(src), [:raise, s_::Refuse, msg]] }
      list += [
        ['ast a', parse.call('a'), [:cat, [a]]], ['ast a|b', parse.call('a|b'), [:alt, [[:cat, [a]], [:cat, [b]]]]],
        ['ast (a)', parse.call('(a)'), [:cat, [[:cat, [a]]]]], ['ast empty', parse.call(''), [:cat, []]],
        ['at -1', out { s_::Parser.new([1, 2]).at(-1) }, nil], ['at 2', out { s_::Parser.new([1, 2]).at(2) }, nil], ['at 1', out { s_::Parser.new([1, 2]).at(1) }, 2],
        ['brace {}', brace.call('a{}', 1), nil], ['brace {2,x}', brace.call('a{2,x}', 1), nil], ['brace {2x', brace.call('a{2x', 1), nil],
        ['brace 5 digits hi', brace.call('a{1,12345}', 1), nil], ['brace 4 digits hi', brace.call('a{1,1234}', 1), [8, 1, 1234]],
        ['brace 5 digits lo', brace.call('a{12345}', 1), nil], ['brace {2,}', brace.call('a{2,}', 1), [4, 2, s_::INF]]
      ]
      list += %w[d D w W s S].map { |c| ["class escape \\#{c} has no char", esc.call("\\#{c}"), nil] }
      rows(list)
    end

    def check_emit
      set = [:set, s_::CharSet.new([[97, 97]], false)]
      star = [:rep, set, 0, s_::INF]
      big = [:raise, s_::Refuse, 'pattern too large']
      rows([
        ['emit over', out { s_.emit([:bol], Array.new(4097)) }, big], ['emit at cap', out { pr = Array.new(4096); s_.emit([:bol], pr); pr.length }, 4097],
        ['rep ends at cap', out { pr = Array.new(4093); s_.emit(star, pr); pr.length }, 4096], ['rep ends over cap', out { s_.emit(star, Array.new(4094)) }, big]
      ])
    end

    # The compiled-program cache: bounded at 512 entries, LRU (a hit moves to the end), one shared object per source, and the
    # caller's string is never frozen or retagged.
    def check_cache
      cache = s_::CACHE
      cc = ->(x) { s_.compile_cached(x) }
      keys = Array.new(600) { |i| "r11-cache-#{i}" }
      keys.each { |k| cc.call(k) }
      res = rows([
        ['size', cache.length, 512], ['oldest evicted', cache.key?(keys[87].b), false], ['first kept', cache.key?(keys[88].b), true],
        ['non-string', out { cc.call(5) }, nil], ['non-string 2', out { cc.call(nil) }, nil]
      ])
      return res if res

      cc.call(keys[88]) # hit: moves to the end
      cc.call('r11-cache-new')
      return 'LRU: the touched entry was evicted' unless cache.key?(keys[88].b) && !cache.key?(keys[89].b) && cache.length == 512

      src = +'r11-cache-identity'
      a = cc.call(src)
      b = cc.call(src)
      c = cc.call(src)
      return 'cache identity' unless a.equal?(b) && b.equal?(c) && !a.nil?
      return 'caller string frozen' if src.frozen?

      nil
    end

    def check_budget
      rb = AtlasPca::RegexBudget
      prov = rb.provider
      return 'a regex scope is open' unless rb.current.nil?

      rb.provider = nil
      b = rb.new
      rq = rb.request
      parent = rb.new
      rows([
        ['new document?', b.document?, true], ['request document?', rq.document?, false], ['new source', b.source, nil],
        ['parent_budget', rb.new(1, parent).parent_budget.equal?(parent), true],
        ['ambient none', out { rb.ambient }, nil], ['ambient open', b.run { rb.ambient.equal?(b) }, true],
        ['join document', b.run { AtlasPca.with_regex_budget { rb.current.equal?(b) } }, true],
        ['open under request', rq.run { AtlasPca.with_regex_budget { c = rb.current; !c.equal?(rq) && c.document? == true && c.parent_budget.equal?(rq) } }, true],
        ['nested joins', AtlasPca.with_regex_budget { o = rb.current; o.document? == true && AtlasPca.with_regex_budget { rb.current.equal?(o) } }, true],
        ['charge_regex charges the scope', rb.new.then { |x| x.run { AtlasPca.charge_regex('a', 1) } && x.evaluations }, 1],
        # a single-use budget outside any scope has the document scale: 201 x 30001 steps (6.03M) is over 5M, 201 x 20001 is not
        ['charge_regex over 5M', AtlasPca.charge_regex('a' * 200, 30_000), false], ['charge_regex under 5M', AtlasPca.charge_regex('a' * 200, 20_000), true],
        # a request budget scales every cap by 4
        ['request chars', rb.request.then { |x| Array.new(11) { x.charge('a' * 200, 1) }.all? }, true],
        ['request steps', rb.request.charge('a' * 200, 7000), true],
        # an over-budget charge inside an open scope poisons THAT scope: a later cheap pattern is refused too
        ['scope poisoned', rb.new.then { |x| x.run { [AtlasPca.charge_regex('a' * 200, 30_000), AtlasPca.charge_regex('a', 1)] } + [x.refusals] }, [false, false, 2]],
        # a provider that raises is no provider (nil, not false)
        ['ambient raising provider', (rb.provider = -> { raise ArgumentError, 'injected' }) && out { rb.ambient }, nil]
      ])
    ensure
      rb.provider = prov if rb
    end
  end

  %w[units parser emit cache budget].each do |kind|
    t("safe_regex r11: #{kind}") do
      next true if RegexR11.skip?

      bad = RegexR11.send(:"check_#{kind}")
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
