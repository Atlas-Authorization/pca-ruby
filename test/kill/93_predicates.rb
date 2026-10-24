# frozen_string_literal: true

# Intent Layer v2 V5 kill tests: the predicate evaluator (lib/atlas_pca/predicates.rb), the linear-time safe-regex engine
# and the per-document regex budget (lib/atlas_pca/safe_regex.rb) and the `layers` check (lib/atlas_pca/intent_layers.rb),
# ported from packages/pca/src/{predicates,safe-regex,regex-budget,intent-layers}.ts. Every op is pinned on its true /
# false / unknown sides, every cap at max and max+1 (UTF-16 code units, not code points), the JS-semantics traps (true /
# false are not numbers, 2 == 2.0, binary64 rounding, UTF-8 string order, lone surrogates) and the check order. Every
# AtlasPca constant / helper is resolved at CALL time (the oracle replaces the module per mutant).
module MutationKill
  module Pred
    module_function

    def astral = "\u{1F600}" # one code point, two UTF-16 units
    def hi = "\xED\xA0\xBD".dup.force_encoding(Encoding::UTF_8) # its lone high surrogate (WTF-8, as the loose reader gives)
    def lo = "\xED\xB0\x80".dup.force_encoding(Encoding::UTF_8) # a lone low surrogate U+DC00

    def ctx(params: {}, env: {}, verb: 'read', resource: '/r', subject: nil, with_params: true)
      a = { 'verb' => verb, 'resource' => resource }
      a['params'] = params if with_params
      c = { 'action' => a, 'env' => env }
      c['subject'] = subject unless subject.nil?
      c
    end

    def tri(c, cx) = AtlasPca.evaluate_condition_tri(c, cx)

    # Tri of `action.params.x <op> value`.
    def x(v, op, value, extra = {})
      tri({ 'field' => 'action.params.x', 'op' => op, 'value' => value }.merge(extra), ctx(params: { 'x' => v }))
    end

    def m(src, subject) = AtlasPca.safe_regex_full_match(src, subject)
    def safe(src) = AtlasPca.is_safe_regex_source(src)
    def compile(src) = AtlasPca.compile_safe_regex(src)

    def ct = { 'field' => 'env.t', 'op' => 'eq', 'value' => 1 }
    def cf = { 'field' => 'env.t', 'op' => 'eq', 'value' => 2 }
    def cu = { 'field' => 'env.missing', 'op' => 'eq', 'value' => 1 }
    def gctx = ctx(env: { 't' => 1 })

    def mem(user, target, groups, extra = {})
      c = { 'field' => 'env.user', 'op' => 'member_of', 'collection' => 'env.groups' }.merge(extra)
      c['value'] = target unless target.nil?
      tri(c, ctx(env: { 'user' => user, 'groups' => groups, 'tgt' => 'all' }))
    end

    # 40 x `X{64}`: 200 source chars, 40 x 64 sets + Match = 2561 instructions.
    def p40 = (('a'..'z').to_a + ('A'..'N').to_a).map { |ch| "#{ch}{64}" }.join

    def mr = { 'field' => 'action.verb', 'op' => 'matches', 'value' => 'r' }
    def where_pred(where) = [{ 'verb' => '*', 'where' => where }]
    def rctx = { 'action' => { 'verb' => 'r', 'resource' => '/', 'params' => {} }, 'env' => {} }

    def allow = { 'predicates' => [{ 'verb' => '*' }] }
    def deny = { 'predicates' => [{ 'verb' => 'write' }] }
    def lctx = { 'action' => { 'verb' => 'read', 'resource' => '/doc', 'params' => {} }, 'env' => {} }

    def fail(k)
      { 'status' => 'fail', 'layer' => k, 'reason' => "layers: the action is outside the #{k} ceiling (a ceiling is never a question)" }
    end

    def malformed(k)
      { 'status' => 'fail', 'layer' => k, 'reason' => "layers: the #{k} ceiling is malformed (null or not {predicates: [...]})" }
    end

    def rm(pattern, resource, has_pattern: true)
      p = has_pattern ? { 'verb' => '*', 'resource' => pattern } : { 'verb' => '*' }
      AtlasPca.predicate_matches(p, ctx(resource: resource))
    end
  end

  # ---- constants ---------------------------------------------------------------------------------------------------

  t('predicates: constants pinned') do
    pr = AtlasPca::Predicates
    sr = AtlasPca::SafeRegex
    rb = AtlasPca::RegexBudget
    [pr::MAX_PATTERN_SUBJECT_LEN, pr::MAX_LIKE_PATTERN_LEN, pr::MAX_MATCHES_PATTERN_LEN] == [512, 512, 200] &&
      [pr::MAX_MEMBER_CLOSURE_NODES, pr::MAX_RE_RESOURCE_LEN, pr::MAX_RE_SOURCE_LEN] == [10_000, 512, 200] &&
      [pr::MAX_REGEX_COST_BITS, pr::UNBOUNDED_QUANTIFIER_BITS, pr::MAX_BOUNDED_REPEAT] == [22, 8, 64] &&
      [sr::MAX_NFA_INSTRUCTIONS, sr::MAX_REPEAT, sr::MAX_MATCH_STEPS] == [4096, 64, 2_000_000] &&
      [rb::MAX_REGEX_EVALUATIONS_PER_DOCUMENT, rb::MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT, rb::MAX_REGEX_STEPS_PER_DOCUMENT] ==
        [64, 8192, 5_000_000] &&
      rb::REGEX_REQUEST_SCALE == 4 && AtlasPca::LAYER_CEILINGS == %w[org site std]
  end

  t('predicates: UTF-16 helpers (units, length, lone surrogates)') do
    sr = AtlasPca::SafeRegex
    sr.units(Pred.astral) == [0xd83d, 0xde00] && sr.utf16_len(Pred.astral) == 2 && sr.utf16_len('ab') == 2 &&
      sr.utf16_len('') == 0 && sr.units(Pred.hi) == [0xd83d] && sr.units_have_lone_surrogate?([0xd83d]) &&
      sr.units_have_lone_surrogate?([0xdc00]) && sr.units_have_lone_surrogate?([0xde00, 0xd83d]) &&
      !sr.units_have_lone_surrogate?([0xd83d, 0xde00]) && !sr.units_have_lone_surrogate?([0x61]) &&
      sr.units_have_lone_surrogate?([0x61, 0xd83d])
  end

  # ---- resolvePath -------------------------------------------------------------------------------------------------

  t('predicates: resolve_path (own properties, array indices, forbidden segments, roots)') do
    cx = Pred.ctx(params: { 'list' => [10, 20], 'o' => { 'toString' => 1, 'constructor' => 2 }, 'n' => nil, '' => 7 })
    r = ->(path, c = cx) { AtlasPca.resolve_path(c, path) }
    nf = { 'found' => false }
    [
      r.call('action.params.list.1') == { 'found' => true, 'value' => 20 },
      r.call('action.params.list.0') == { 'found' => true, 'value' => 10 },
      r.call('action.params.list.01') == nf, r.call('action.params.list.2') == nf, r.call('action.params.list.-1') == nf,
      r.call("action.params.list.1\n") == nf, # anchored index regex
      r.call('action.params.o.toString') == { 'found' => true, 'value' => 1 },
      r.call('action.params.o.constructor') == nf, r.call('action.params.__proto__') == nf,
      r.call('action.params.prototype') == nf,
      r.call('action.params.n') == { 'found' => true, 'value' => nil }, r.call('action.params.n.x') == nf,
      r.call('action.params.') == { 'found' => true, 'value' => 7 }, # JS split keeps the empty trailing segment
      r.call('action.verb.length') == nf,
      r.call('env') == { 'found' => true, 'value' => {} }, r.call('subject') == nf, r.call('params.x') == nf,
      r.call('') == nf, r.call(5) == nf, r.call(nil) == nf, r.call('action', 'not-a-ctx') == nf,
      r.call('env', { 'env' => nil }) == { 'found' => true, 'value' => nil },
      r.call('action.params.list.1.x') == nf
    ].all?
  end

  # ---- eq / ne / in / nin ------------------------------------------------------------------------------------------

  t('predicates: eq / ne are canonical JSON equality (type and binary64 value)') do
    x = Pred.method(:x)
    [
      x.call(2, 'eq', 2.0) == 'true', x.call(0, 'eq', -0.0) == 'true',
      x.call(true, 'eq', 1) == 'false', x.call(1, 'eq', true) == 'false', x.call(false, 'eq', 0) == 'false',
      x.call('2', 'eq', 2) == 'false',
      x.call({ 'a' => 1, 'b' => [1, 2] }, 'eq', { 'b' => [1, 2.0], 'a' => 1 }) == 'true',
      x.call({ 'a' => 1 }, 'eq', { 'a' => 1, 'b' => 2 }) == 'false',
      x.call([1], 'eq', { '0' => 1 }) == 'false', x.call([1, 2], 'eq', [2, 1]) == 'false',
      x.call(9_007_199_254_740_993, 'eq', 9_007_199_254_740_992) == 'true', # binary64 rounding, as JSON.parse
      x.call(Float::INFINITY, 'eq', Float::INFINITY) == 'false', # the canonicalizer refuses a non-finite number
      x.call(10**400, 'eq', 10**400) == 'false',
      x.call([1, Float::NAN], 'ne', [1, Float::NAN]) == 'true',
      x.call(Pred.astral, 'eq', "\u{1F600}") == 'true', x.call(Pred.hi, 'eq', Pred.hi.dup) == 'true',
      x.call(Pred.hi, 'eq', Pred.lo) == 'false',
      x.call(nil, 'eq', nil) == 'true', x.call(0, 'eq', nil) == 'false',
      x.call(2, 'ne', 2.0) == 'false', x.call(2, 'ne', 3) == 'true',
      x.call({ 'k' => :sym }, 'eq', { 'k' => :sym }) == 'false' # not a JSON value
    ].all?
  end

  t('predicates: in / nin need an array operand') do
    x = Pred.method(:x)
    [
      x.call(2, 'in', [1, 2.0]) == 'true', x.call(2, 'in', ['2', true]) == 'false', x.call(2, 'in', []) == 'false',
      x.call(2, 'in', 2) == 'unknown', x.call(2, 'in', { 'a' => 2 }) == 'unknown',
      x.call(2, 'nin', [1, 2.0]) == 'false', x.call(2, 'nin', []) == 'true', x.call(2, 'nin', '2') == 'unknown'
    ].all?
  end

  # ---- ordering ----------------------------------------------------------------------------------------------------

  t('predicates: lt / lte / gt / gte over finite numbers') do
    x = Pred.method(:x)
    ok = [%w[lt true false false], %w[lte true true false], %w[gt false false true], %w[gte false true true]].all? do |op, l, e, g|
      x.call(1, op, 2) == l && x.call(2, op, 2.0) == e && x.call(3, op, 2) == g
    end
    ok && x.call(9_007_199_254_740_993, 'lt', 9_007_199_254_740_992) == 'false' &&
      x.call(9_007_199_254_740_993, 'lte', 9_007_199_254_740_992) == 'true' &&
      x.call(-0.0, 'lt', 0) == 'false' && x.call(-0.0, 'gte', 0) == 'true' && x.call(1.5, 'gt', 1) == 'true'
  end

  t('predicates: ordering type mismatches are unknown (true/false are not numbers; non-finite)') do
    x = Pred.method(:x)
    [
      x.call(true, 'lt', 2), x.call(1, 'lt', true), x.call(1, 'lt', '2'), x.call('1', 'lt', 2), x.call(nil, 'lt', 1),
      x.call([1], 'lt', [2]), x.call(Float::INFINITY, 'gt', 1), x.call(10**400, 'gt', 1), x.call(1, 'lt', -Float::INFINITY)
    ].all? { |r| r == 'unknown' }
  end

  t('predicates: strings order by UTF-8 bytes (code points); a lone surrogate has no order') do
    x = Pred.method(:x)
    a = Pred.astral
    [
      x.call('a', 'lt', 'b') == 'true', x.call('b', 'lt', 'a') == 'false', x.call('abc', 'lte', 'abc') == 'true',
      x.call('abc', 'lt', 'abc') == 'false', x.call('', 'lt', 'a') == 'true', x.call('ab', 'lt', 'abc') == 'true',
      x.call('Z', 'lt', 'a') == 'true', x.call("a\u0000b", 'gt', 'a') == 'true',
      # U+FFFF < U+1F600 in code point order (JS `<` over UTF-16 units would say the opposite)
      x.call("￿", 'lt', a) == 'true', x.call(a, 'gt', "￿") == 'true', x.call("", 'lt', a) == 'true',
      x.call(a, 'gte', a) == 'true',
      x.call(Pred.hi, 'lt', 'a') == 'unknown', x.call('a', 'gt', Pred.lo) == 'unknown'
    ].all?
  end

  # ---- prefix / like -----------------------------------------------------------------------------------------------

  t('predicates: prefix over UTF-16 units, strings only') do
    x = Pred.method(:x)
    [
      x.call('abc', 'prefix', 'ab') == 'true', x.call('abc', 'prefix', '') == 'true', x.call('abc', 'prefix', 'b') == 'false',
      x.call('ab', 'prefix', 'abc') == 'false', x.call(1, 'prefix', '1') == 'unknown', x.call('1', 'prefix', 1) == 'unknown',
      x.call("#{Pred.astral}x", 'prefix', Pred.hi) == 'true' # UTF-16 startsWith
    ].all?
  end

  t('predicates: like glob semantics (UTF-16 units, escapes, dangling backslash)') do
    x = Pred.method(:x)
    a = Pred.astral
    [
      x.call('abc', 'like', 'a*c') == 'true', x.call('abc', 'like', 'a*') == 'true', x.call('abc', 'like', '*') == 'true',
      x.call('', 'like', '*') == 'true', x.call('', 'like', '?') == 'false', x.call('abc', 'like', 'a?c') == 'true',
      x.call('abbc', 'like', 'a?c') == 'false',
      x.call("a#{a}c", 'like', 'a?c') == 'false', x.call("a#{a}c", 'like', 'a??c') == 'true', # `?` is ONE unit
      x.call('a*', 'like', 'a\\*') == 'true', x.call('ab', 'like', 'a\\*') == 'false',
      x.call('a?', 'like', 'a\\?') == 'true', x.call('ab', 'like', 'a\\?') == 'false',
      x.call('a\\', 'like', 'a\\\\') == 'true', x.call('ab', 'like', 'ab\\') == 'unknown',
      x.call("a\nb", 'like', 'a*b') == 'true', x.call("a\nb", 'like', 'a?b') == 'true',
      x.call('aXbYc', 'like', '*b*c') == 'true', x.call('aXbYd', 'like', '*b*c') == 'false',
      x.call('abc', 'like', 'abc*') == 'true', x.call('abc', 'like', 'abcd') == 'false', x.call('abcd', 'like', 'abc') == 'false',
      x.call('a.c', 'like', 'a.c') == 'true', x.call('abc', 'like', 'a.c') == 'false', # no regex metacharacters
      x.call(1, 'like', '*') == 'unknown', x.call('1', 'like', 1) == 'unknown',
      x.call('a' * 500, 'like', '*a*a*a*a*a*a*b') == 'false' # the old exponential case is linear
    ].all?
  end

  t('predicates: like caps at 512 / 513 UTF-16 units (subject and glob)') do
    x = Pred.method(:x)
    a = Pred.astral
    [
      x.call('a' * 512, 'like', '*') == 'true', x.call('a' * 513, 'like', '*') == 'unknown',
      x.call(a * 256, 'like', '*') == 'true', x.call("#{a * 256}a", 'like', '*') == 'unknown',
      x.call('a', 'like', '*' * 512) == 'true', x.call('a', 'like', '*' * 513) == 'unknown',
      x.call('a', 'like', ('*' * 510) + a) == 'false', x.call('a', 'like', ('*' * 511) + a) == 'unknown'
    ].all?
  end

  # ---- matches -----------------------------------------------------------------------------------------------------

  t('predicates: matches (anchored, caps 200 / 512 units, unsafe and unsupported sources unknown)') do
    x = Pred.method(:x)
    a = Pred.astral
    [
      x.call('abc', 'matches', 'a.c') == 'true', x.call('abcd', 'matches', 'a.c') == 'false',
      x.call("a\n", 'matches', 'a$') == 'false', # no trailing-newline leniency
      x.call('a' * 200, 'matches', 'a' * 200) == 'true', x.call('a' * 201, 'matches', 'a' * 201) == 'unknown',
      x.call('a' * 512, 'matches', 'a*') == 'true', x.call('a' * 513, 'matches', 'a*') == 'unknown',
      x.call(a * 256, 'matches', '[^]*') == 'true', x.call("#{a * 256}a", 'matches', '[^]*') == 'unknown',
      x.call('a', 'matches', a * 100) == 'false', x.call('a', 'matches', "#{a * 100}a") == 'unknown',
      x.call('aa', 'matches', '(a+)+') == 'unknown', x.call('a', 'matches', '\\b') == 'unknown',
      x.call(1, 'matches', '.') == 'unknown', x.call('1', 'matches', 1) == 'unknown'
    ].all?
  end

  # ---- exists / params availability --------------------------------------------------------------------------------

  t('predicates: exists (only `false` means must-be-absent)') do
    cx = Pred.ctx(params: { 'x' => 0, 'n' => nil })
    e = ->(f, extra = {}) { Pred.tri({ 'field' => f, 'op' => 'exists' }.merge(extra), cx) }
    [
      e.call('action.params.x') == 'true', e.call('action.params.n') == 'true', e.call('action.params.y') == 'false',
      e.call('action.params.y', 'value' => false) == 'true', e.call('action.params.x', 'value' => false) == 'false',
      e.call('action.params.x', 'value' => 0) == 'true', e.call('action.params.y', 'value' => nil) == 'false',
      e.call('env.y', 'value' => false) == 'true', e.call('nope.y') == 'false', e.call('nope.y', 'value' => false) == 'true'
    ].all?
  end

  t('predicates: params unavailable is NOT field absent (fail closed), field and ref') do
    bad = [Pred.ctx(with_params: false), { 'action' => { 'verb' => 'r', 'resource' => '/', 'params' => nil } },
           { 'action' => { 'verb' => 'r', 'resource' => '/', 'params' => 'str' } },
           { 'action' => { 'verb' => 'r', 'resource' => '/', 'params' => 5 } }, { 'action' => 'not-an-object' },
           { 'action' => [1] }, {}]
    ok = bad.all? do |cx|
      Pred.tri({ 'field' => 'action.params.y', 'op' => 'exists', 'value' => false }, cx) == 'unknown' &&
        Pred.tri({ 'field' => 'action.params', 'op' => 'exists', 'value' => false }, cx) == 'unknown' &&
        Pred.tri({ 'field' => 'env.x', 'op' => 'nin', 'ref' => 'action.params.y' }, cx.merge('env' => { 'x' => 1 })) == 'unknown' &&
        Pred.tri({ 'field' => 'env.x', 'op' => 'exists', 'ref' => 'action.params' }, cx.merge('env' => { 'x' => 1 })) == 'unknown'
    end
    arr = { 'action' => { 'verb' => 'r', 'resource' => '/', 'params' => [] } }
    ok && Pred.tri({ 'field' => 'action.params.y', 'op' => 'exists', 'value' => false }, arr) == 'true' &&
      Pred.tri({ 'field' => 'action.paramsX', 'op' => 'exists', 'value' => false }, Pred.ctx(with_params: false)) == 'true' &&
      Pred.tri({ 'field' => 'env.x', 'op' => 'exists', 'ref' => 'action.paramsX' },
               Pred.ctx(with_params: false, env: { 'x' => 1 })) == 'true' &&
      Pred.tri({ 'field' => 'env.x', 'op' => 'eq', 'ref' => 5, 'value' => 1 }, Pred.ctx(with_params: false, env: { 'x' => 1 })) ==
        'unknown' # a non-string ref is not params-rooted, but it is present: it resolves to nothing
  end

  # ---- operand resolution ------------------------------------------------------------------------------------------

  t('predicates: ref / value operand (ref present wins, missing operand unknown)') do
    cx = Pred.ctx(params: { 'x' => 5 }, env: { 'five' => 5, 'six' => 6 })
    tr = ->(c) { Pred.tri({ 'field' => 'action.params.x' }.merge(c), cx) }
    [
      tr.call('op' => 'eq', 'ref' => 'env.five') == 'true', tr.call('op' => 'eq', 'ref' => 'env.six') == 'false',
      tr.call('op' => 'eq', 'ref' => 'env.none') == 'unknown', tr.call('op' => 'eq', 'ref' => nil, 'value' => 5) == 'unknown',
      tr.call('op' => 'eq', 'ref' => 'env.five', 'value' => 6) == 'true', tr.call('op' => 'eq') == 'unknown',
      tr.call('op' => 'eq', 'value' => nil) == 'false', # a null operand is present
      Pred.tri({ 'field' => 'action.params.missing', 'op' => 'ne', 'value' => 1 }, cx) == 'unknown'
    ].all?
  end

  t('predicates: leaf shape and group detection') do
    cx = Pred.ctx(params: { 'x' => 1 })
    [
      Pred.tri({ 'field' => '', 'op' => 'eq', 'value' => 1 }, cx) == 'unknown',
      Pred.tri({ 'field' => 5, 'op' => 'eq', 'value' => 1 }, cx) == 'unknown',
      Pred.tri({ 'field' => 'action.params.x', 'op' => 5, 'value' => 1 }, cx) == 'unknown',
      Pred.tri({ 'field' => 'action.params.x', 'op' => 'regex', 'value' => 1 }, cx) == 'unknown',
      Pred.tri({ 'field' => 'action.params.x', 'value' => 1 }, cx) == 'unknown',
      Pred.tri([{ 'field' => 'action.params.x', 'op' => 'eq', 'value' => 1 }], cx) == 'unknown',
      Pred.tri('x', cx) == 'unknown', Pred.tri(nil, cx) == 'unknown', Pred.tri(5, cx) == 'unknown',
      AtlasPca.leaf_condition?({ 'field' => 'a', 'op' => 'eq' }), !AtlasPca.leaf_condition?({ 'field' => 1 }),
      AtlasPca.group_condition?({ 'not' => nil }), AtlasPca.group_condition?({ 'all_of' => 1 }),
      AtlasPca.group_condition?({ 'any_of' => 1 }), !AtlasPca.group_condition?([{ 'not' => 1 }]),
      !AtlasPca.group_condition?({ 'field' => 'a' }), !AtlasPca.leaf_condition?({ 'field' => 'a', 'all_of' => [] }),
      AtlasPca.evaluate_condition({ 'field' => 'action.params.x', 'op' => 'eq', 'value' => 1 }, cx) == true,
      AtlasPca.evaluate_condition({ 'field' => 'action.params.x', 'op' => 'eq', 'value' => 2 }, cx) == false
    ].all?
  end

  # ---- is_a / member_of --------------------------------------------------------------------------------------------

  t('predicates: is_a (string prefix Type::, object type / tags)') do
    x = Pred.method(:x)
    [
      x.call('User::alice', 'is_a', 'User') == 'true', x.call('User', 'is_a', 'User') == 'true',
      x.call('Username', 'is_a', 'User') == 'false', x.call('User:alice', 'is_a', 'User') == 'false',
      x.call({ 'type' => 'Doc::pdf' }, 'is_a', 'Doc') == 'true', x.call({ 'type' => 'Doc' }, 'is_a', 'Doc') == 'true',
      x.call({ 'type' => 'Docs' }, 'is_a', 'Doc') == 'false',
      x.call({ 'tags' => %w[a Doc] }, 'is_a', 'Doc') == 'true', x.call({ 'tags' => ['a', 5] }, 'is_a', 'Doc') == 'false',
      x.call({ 'tags' => ['Doc::x'] }, 'is_a', 'Doc') == 'false', # tags compare exactly
      x.call({ 'type' => 5 }, 'is_a', 'Doc') == 'unknown', x.call({ 'type' => 5, 'tags' => [] }, 'is_a', 'Doc') == 'false',
      x.call({ 'type' => 'X', 'tags' => ['Doc'] }, 'is_a', 'Doc') == 'true',
      x.call({ 'type' => 'Doc', 'tags' => 5 }, 'is_a', 'Doc') == 'true',
      x.call({}, 'is_a', 'Doc') == 'unknown', x.call(5, 'is_a', 'Doc') == 'unknown', x.call(['Doc'], 'is_a', 'Doc') == 'unknown',
      x.call('Doc', 'is_a', '') == 'unknown', x.call('Doc', 'is_a', 5) == 'unknown'
    ].all?
  end

  t('predicates: member_of (reflexive bounded closure; operand and collection shapes)') do
    g = { 'alice' => ['eng', 5], 'eng' => 'staff', 'staff' => ['all'] }
    mem = Pred.method(:mem)
    [
      mem.call('alice', 'all', g) == 'true', mem.call('alice', 'alice', g) == 'true', mem.call('alice', 'ops', g) == 'false',
      mem.call('alice', %w[ops staff], g) == 'true', mem.call('alice', [5, 'ops'], g) == 'false',
      mem.call('alice', [5], g) == 'unknown', mem.call('alice', 5, g) == 'unknown', mem.call('alice', nil, g) == 'unknown',
      mem.call('alice', nil, g, 'ref' => 'env.tgt') == 'true', mem.call('alice', nil, g, 'ref' => 'env.none') == 'unknown',
      mem.call('alice', 'nope', g, 'ref' => 'env.tgt') == 'true', # ref wins over value
      mem.call(5, 'all', g) == 'unknown', mem.call('alice', 'all', ['alice']) == 'unknown',
      Pred.tri({ 'field' => 'env.user', 'op' => 'member_of', 'value' => 'all' }, Pred.ctx(env: { 'user' => 'a' })) == 'unknown',
      Pred.tri({ 'field' => 'env.user', 'op' => 'member_of', 'collection' => '', 'value' => 'a' },
               Pred.ctx(env: { 'user' => 'a' })) == 'unknown',
      Pred.tri({ 'field' => 'env.user', 'op' => 'member_of', 'collection' => 'env.no', 'value' => 'a' },
               Pred.ctx(env: { 'user' => 'a' })) == 'unknown',
      mem.call('a', 'c', { 'a' => 'b', 'b' => 'a' }) == 'false', # a cycle terminates
      mem.call('__proto__', 'x', { '__proto__' => 'x' }) == 'false', # a forbidden node has no neighbours
      mem.call('constructor', 'constructor', {}) == 'true' # reflexive still holds
    ].all?
  end

  t('predicates: member_of closure visits at most 10000 nodes') do
    n = AtlasPca::Predicates::MAX_MEMBER_CLOSURE_NODES
    chain = (0..(n + 1)).to_h { |i| ["n#{i}", "n#{i + 1}"] }
    Pred.mem('n0', "n#{n}", chain) == 'true' && Pred.mem('n0', "n#{n + 1}", chain) == 'false'
  end

  # ---- boolean groupings -------------------------------------------------------------------------------------------

  t('predicates: all_of / any_of / not three-valued logic and precedence') do
    ct = Pred.ct
    cf = Pred.cf
    cu = Pred.cu
    g = Pred.gctx
    tr = ->(c) { Pred.tri(c, g) }
    [
      tr.call('all_of' => [ct, ct]) == 'true', tr.call('all_of' => [ct, cu]) == 'unknown', tr.call('all_of' => [cu, cf]) == 'false',
      tr.call('all_of' => []) == 'unknown', tr.call('all_of' => ct) == 'unknown',
      tr.call('any_of' => [cu, ct]) == 'true', tr.call('any_of' => [cf, cu]) == 'unknown', tr.call('any_of' => [cf, cf]) == 'false',
      tr.call('any_of' => []) == 'unknown', tr.call('any_of' => 'x') == 'unknown',
      tr.call('not' => ct) == 'false', tr.call('not' => cf) == 'true', tr.call('not' => cu) == 'unknown',
      tr.call('not' => nil) == 'unknown', tr.call('not' => { 'not' => ct }) == 'true',
      tr.call('all_of' => [ct], 'any_of' => [cf]) == 'true', # all_of is checked first
      tr.call('any_of' => [ct], 'not' => ct) == 'true', # then any_of
      tr.call('all_of' => [ct], 'field' => 'env.t', 'op' => 'eq', 'value' => 2) == 'true', # a group is never a leaf
      AtlasPca.evaluate_condition({ 'not' => cu }, g) == false, AtlasPca.evaluate_condition({ 'not' => cf }, g) == true
    ].all?
  end

  t('predicates: absurd nesting fails closed (never raises)') do
    deep = Pred.ct
    20_000.times { deep = { 'not' => deep } }
    r = Pred.tri(deep, Pred.gctx)
    %w[true false unknown].include?(r) && AtlasPca.evaluate_predicates([{ 'verb' => '*', 'where' => [deep] }], Pred.gctx)
                                                  .is_a?(Hash)
  end

  # ---- safe regex: engine ------------------------------------------------------------------------------------------

  t('safe regex: full-match semantics over UTF-16 units') do
    m = Pred.method(:m)
    a = Pred.astral
    [
      m.call('a|b', 'a') == true, m.call('a|b', 'ab') == false, m.call('a|', '') == true, m.call('.', 'x') == true,
      ["\n", "\r", " ", " "].all? { |lt| m.call('.', lt) == false },
      m.call('.', a) == false, m.call('..', a) == true,
      m.call('[^]', "\n") == true, m.call('[]', '') == false, m.call('[]*', '') == true, m.call('[]', 'a') == false,
      m.call('a$', "a\n") == false, m.call('^a$', 'a') == true, m.call('a^', 'a') == false,
      m.call('\\d+', '123') == true, m.call('\\d', "٣") == false,
      m.call('\\D', 'a') == true, m.call('\\D', '1') == false,
      m.call('\\w', '_') == true, m.call('\\w', "é") == false, m.call('\\W', '-') == true,
      m.call('\\s', ' ') == true, m.call('\\s', "﻿") == true, m.call('\\s', "\u0085") == false,
      m.call('\\S', 'a') == true, m.call('\\S', ' ') == false,
      m.call('[\\b]', "\b") == true, m.call('\\cJ', "\n") == true, m.call('\\cj', "\n") == true,
      m.call('\\x41', 'A') == true, m.call('\\u00e9', "é") == true, m.call('\\0', "\u0000") == true,
      m.call('\\t\\n\\v\\f\\r', "\t\n\v\f\r") == true,
      m.call('[a-c]', 'b') == true, m.call('[a-c]', 'd') == false, m.call('[^a-c]', 'd') == true,
      m.call('[\\d-z]', '-') == true, m.call('[\\d-z]', '5') == true, m.call('[\\d-z]', 'z') == true,
      m.call('[\\d-z]', 'm') == false, # Annex B: the '-' is literal
      m.call('[a-]', '-') == true, m.call('[-a]', '-') == true,
      m.call('[\\D]', 'a') == true, m.call('[\\D]', '1') == false, m.call('[^\\D]', '1') == true,
      m.call('[\\]]', ']') == true, m.call(']', ']') == true, m.call('}', '}') == true,
      m.call('a{2,3}', 'a') == false, m.call('a{2,3}', 'aa') == true, m.call('a{2,3}', 'aaa') == true,
      m.call('a{2,3}', 'aaaa') == false,
      m.call('a{2}', 'aa') == true, m.call('a{2}', 'aaa') == false, m.call('a{2,}', 'aaaaa') == true, m.call('a{2,}', 'a') == false,
      m.call('a{0}', '') == true, m.call('a{0}', 'a') == false,
      m.call('a*?', 'aaa') == true, m.call('a+?', '') == false, m.call('a??', 'a') == true,
      m.call('(?:ab)+', 'abab') == true, m.call('(a|b)*c', 'abbac') == true, m.call('(a|b)*c', 'abbad') == false,
      m.call('\\uD83D\\uDE00', a) == true, m.call(a, a) == true,
      m.call("[#{a}]", a) == false, m.call("[#{a}]", Pred.hi) == true, # a class holds two separate units
      m.call('\\.', '.') == true, m.call('\\.', 'a') == false, m.call('\\/', '/') == true,
      m.call('a', 5).nil?, m.call(5, 'a').nil?, m.call('a', "\xFF".dup.force_encoding(Encoding::UTF_8)).nil?
    ].all?
  end

  t('safe regex: compile refusals and acceptances') do
    refused = ['\\b', '\\B', '\\1', '\\k<a>', '(?=a)', '(?!a)', '(?<=a)', '(?<n>a)', '\\p{L}', 'a**', '*', '+a', '?',
               '{', 'a{', 'a{x}', 'a{2,1}', 'a{65}', 'a{1,65}', 'a{65,}', '\\', '[a', '[', '(a', 'a)', ')', '\\00',
               '\\01', '\\xG0', '\\x4', '\\u12', '\\uZZZZ', '\\c1', '\\c', '\\_', '\\q', '\\e', '^*', '$+', '[b-a]',
               'a{1}{2}', 'a{12345}', 'a{,5}', 'a{1,23456}']
    accepted = ['', '\\.', '\\-', 'a{0,64}', 'a{64}', 'a{64,}', '\\0', '[\\]]', ']', '}', 'a{2}?', '[\\d-z]', '(?:)',
                'a{0064}', '[a-a]']
    refused.all? { |s| Pred.compile(s).nil? && Pred.m(s, 'a').nil? } && accepted.all? { |s| !Pred.compile(s).nil? } &&
      Pred.compile(5).nil? && Pred.compile(nil).nil?
  end

  t('safe regex: NFA size cap 4096 instructions') do
    Pred.compile('(?:a{64}){64}').nil? && Pred.compile('(?:a{63}){64}').program.length == 4033 &&
      Pred.compile('a').program.length == 2
  end

  t('safe regex: match-steps cap (program x (subject + 1) <= 2M)') do
    p = Pred.p40
    p.length == 200 && Pred.compile(p).program.length == 2561 &&
      Pred.m(p, 'a' * 779) == false && Pred.m(p, 'a' * 780).nil? # 2561 x 780 <= 2M < 2561 x 781
  end

  # ---- safe regex: the source guard --------------------------------------------------------------------------------

  t('safe regex guard: nested quantifiers, backreferences, lookaround, malformed') do
    unsafe = ['(a+)+', '(a*)*', '(a|aa)+', '(.*a){10}', '(?:a|b)*', '((a)+)?', '[^](a+)+]', '(a?){2}',
              '\\1', '\\9', '\\k', '(?=a)', '(?<n>a)', '*a', 'a|*', '(*)', 'a{2,1}', 'a{65}', 'a{', '(a', 'a)', '[a', '\\', '\\b',
              'a{1,65}']
    ok = ['/acct/[^/]+/items/\\d+', '(?:GET|POST) /x', '(ab)+', '(?:a)*', '[(a+)+]', '\\(a+\\)+', 'a{0,64}', '\\0']
    unsafe.all? { |s| Pred.safe(s) == false } && ok.all? { |s| Pred.safe(s) == true } &&
      Pred.safe(5) == false && Pred.safe(nil) == false
  end

  t('safe regex guard: the 22-bit backtracking-cost budget') do
    s = Pred.method(:safe)
    [
      s.call('a*b*') == true, s.call('a*b*c*') == false, s.call('a*b*c?d?e?f?g?h?') == true,
      s.call('a*b*c?d?e?f?g?h?i?') == false, s.call('a*b*a{0,63}') == true, s.call('a*b*a{0,64}') == false,
      s.call('a*b*c{0,3}d{0,3}d{0,1}') == true, s.call('a*b*c{0,4}d{0,3}d{0,1}') == true,
      s.call('a*b*c{0,4}d{0,3}d{0,2}') == false, s.call('a*b*a{5}a{5}a{5}') == true, s.call('a*b*a{2,}') == false,
      s.call(Array.new(23, 'a').join('|')) == true, s.call(Array.new(24, 'a').join('|')) == false,
      s.call('a*?b*?') == true, s.call('a+b+') == true, s.call('a+b+c+') == false
    ].all?
  end

  t('safe regex guard: the source must also compile in the engine') do
    Pred.safe('\\q') == false && Pred.safe('a{12345,}') == false && Pred.safe('\\c1') == false && Pred.safe('\\xZZ') == false
  end

  # ---- regex budget ------------------------------------------------------------------------------------------------

  t('regex budget: 64 evaluations per document, fresh per call, shared across predicates of one document') do
    mr = Pred.mr
    cx = Pred.rctx
    AtlasPca.evaluate_predicates(Pred.where_pred([mr] * 64), cx)['allowed'] == true &&
      AtlasPca.evaluate_predicates(Pred.where_pred([mr] * 65), cx) == { 'allowed' => false, 'reason' => 'no predicate permits r on /' } &&
      AtlasPca.evaluate_predicates(Pred.where_pred([mr] * 64), cx)['allowed'] == true &&
      AtlasPca.evaluate_predicates([{ 'verb' => 'x' }] + Pred.where_pred([mr] * 40) + Pred.where_pred([mr] * 30), cx)['allowed'] == true &&
      AtlasPca.evaluate_predicates(Pred.where_pred([mr] * 40 + [Pred.cf]) + Pred.where_pred([mr] * 30), cx)['allowed'] == false &&
      AtlasPca.evaluate_predicates(Pred.where_pred([mr] * 40 + [Pred.cf]) + Pred.where_pred([mr] * 24), cx)['allowed'] == true
  end

  t('regex budget: 5M steps per document, then poisoned (a cheap pattern after an over-budget one is refused)') do
    nb = { 'not' => { 'field' => 'action.params.s', 'op' => 'matches', 'value' => Pred.p40 } }
    cx = { 'action' => { 'verb' => 'r', 'resource' => '/', 'params' => { 's' => 'z' * 512 } }, 'env' => {} }
    mr = Pred.mr
    tail = { 'any_of' => [nb['not'], mr] }
    # 2561 x 513 = 1_313_793 steps per evaluation: 3 fit in 5M, the 4th does not
    AtlasPca.evaluate_predicates([{ 'verb' => '*', 'where' => [nb] * 3 }], cx)['allowed'] == true &&
      AtlasPca.evaluate_predicates([{ 'verb' => '*', 'where' => [nb] * 4 }], cx)['allowed'] == false &&
      AtlasPca.evaluate_predicates([{ 'verb' => '*', 'where' => ([nb] * 3) + [mr] }], cx)['allowed'] == true &&
      AtlasPca.evaluate_predicates([{ 'verb' => '*', 'where' => ([nb] * 3) + [tail] }], cx)['allowed'] == false
  end

  t('regex budget: the budget object (chars cap at 8192 / 8193, refusal on an uncompilable source, astral = 2)') do
    rb = AtlasPca::RegexBudget
    b = rb.new
    first = b.charge('\\b', 1) == false && b.refusals == 1 && b.evaluations.zero?
    forty = (1..40).all? { b.charge('a' * 200, 0) }
    c = rb.new
    40.times { c.charge('a' * 200, 0) }
    d = rb.new
    first && forty && b.chars == 8000 && b.charge('a' * 200, 0) == false &&
      b.evaluations == rb::MAX_REGEX_EVALUATIONS_PER_DOCUMENT + 1 && b.refusals == 2 && b.charge('a', 0) == false &&
      c.charge('a' * 192, 0) == true && c.chars == 8192 && c.steps == (40 * 201) + 193 && c.charge('a', 0) == false &&
      d.charge(Pred.astral, 0) == true && d.chars == 2 && d.steps == 3
  end

  t('regex budget: steps cap at exactly 5M / 5M + 1') do
    b = AtlasPca::RegexBudget.new
    # 'a' compiles to 2 instructions: 2 x (2_499_999 + 1) = 5_000_000 exactly
    c = AtlasPca::RegexBudget.new
    b.charge('a', 2_499_999) == true && b.steps == 5_000_000 && c.charge('a', 2_500_000) == false && c.refusals == 1
  end

  t('regex budget: request chain, scopes, nesting, explicit budget') do
    rb = AtlasPca::RegexBudget
    req = rb.request('client')
    head = !req.document? && req.source == 'client' && rb.request.source.nil?
    full = (1..4).all? do
      doc = rb.new(1, req, true)
      (1..64).all? { doc.charge('r', 1) }
    end
    over = rb.new(1, req, true).charge('r', 1) == false && req.evaluations == (4 * 64) + 1
    loose = (1..100).all? { AtlasPca.charge_regex('r', 1) } && AtlasPca.regex_refusals.zero?
    oks, refusals = AtlasPca.with_regex_budget { [(1..65).map { AtlasPca.charge_regex('r', 1) }, AtlasPca.regex_refusals] }
    nested = AtlasPca.with_regex_budget do
      64.times { AtlasPca.charge_regex('r', 1) }
      AtlasPca.with_regex_budget { AtlasPca.charge_regex('r', 1) }
    end
    mine = rb.new
    AtlasPca.with_regex_budget(mine) { AtlasPca.charge_regex('r', 4) }
    restored = AtlasPca::RegexBudget.current.nil?
    head && full && over && loose && oks == ([true] * 64) + [false] && refusals == 1 && nested == false &&
      [mine.evaluations, mine.steps, mine.chars] == [1, 10, 1] && restored
  end

  t('regex budget: an ambient request provider bounds fresh document budgets') do
    req = AtlasPca::RegexBudget.request
    AtlasPca.set_regex_budget_provider(-> { req })
    begin
      ok = (1..4).all? { AtlasPca.evaluate_predicates(Pred.where_pred([Pred.mr] * 64), Pred.rctx)['allowed'] == true } &&
           AtlasPca.evaluate_predicates(Pred.where_pred([Pred.mr]), Pred.rctx)['allowed'] == false
    ensure
      AtlasPca.set_regex_budget_provider(nil)
    end
    ok && AtlasPca.evaluate_predicates(Pred.where_pred([Pred.mr]), Pred.rctx)['allowed'] == true
  end

  t('regex budget: check order (safety and caps before charging; verb before resource before where)') do
    mr = Pred.mr
    cx = Pred.rctx
    unsafe = { 'field' => 'action.verb', 'op' => 'matches', 'value' => '(r+)+' }
    long_subject = { 'field' => 'action.params.s', 'op' => 'matches', 'value' => 'a*' }
    cxs = cx.merge('action' => cx['action'].merge('params' => { 's' => 'a' * 513 }))
    verb_first = Array.new(64) { { 'verb' => 'w', 'resource' => 're:r' } } + Pred.where_pred([mr])
    res_first = Array.new(64) { { 'verb' => '*', 'resource' => '/nope', 'where' => [mr] } } + Pred.where_pred([mr])
    AtlasPca.evaluate_predicates(Pred.where_pred([{ 'any_of' => ([unsafe] * 64) + [mr] }]), cx)['allowed'] == true &&
      AtlasPca.evaluate_predicates(Pred.where_pred([{ 'any_of' => ([long_subject] * 64) + [mr] }]), cxs)['allowed'] == true &&
      AtlasPca.evaluate_predicates(verb_first, cx)['allowed'] == true &&
      AtlasPca.evaluate_predicates(res_first, cx)['allowed'] == true &&
      # the first failing `where` condition ends the predicate: the 64 `matches` after it are never charged
      AtlasPca.evaluate_predicates(Pred.where_pred([Pred.cf] + ([mr] * 64)) + Pred.where_pred([mr]), cx)['allowed'] == true
  end

  # ---- predicates --------------------------------------------------------------------------------------------------

  t('predicates: verb matching') do
    cx = Pred.ctx(verb: 'read')
    pm = ->(p, c = cx) { AtlasPca.predicate_matches(p, c) }
    [
      pm.call({ 'verb' => 'read' }) == true, pm.call({ 'verb' => '*' }) == true, pm.call({ 'verb' => 'write' }) == false,
      pm.call({ 'verb' => %w[write read] }) == true, pm.call({ 'verb' => %w[write *] }) == true,
      pm.call({ 'verb' => [5, 'write'] }) == false, pm.call({ 'verb' => [] }) == false, pm.call({ 'verb' => 5 }) == false,
      pm.call({ 'verb' => 'READ' }) == false, pm.call({}) == false, pm.call(nil) == false, pm.call([{ 'verb' => '*' }]) == false,
      pm.call({ 'verb' => '*' }, Pred.ctx(verb: '*')) == true, pm.call({ 'verb' => 'x*' }, Pred.ctx(verb: 'xy')) == false
    ].all?
  end

  t('predicates: resource matching (exact, *, trailing-* prefix, re: with caps)') do
    rm = Pred.method(:rm)
    a = Pred.astral
    [
      rm.call(nil, '/anything', has_pattern: false) == true, rm.call('*', '/x') == true,
      rm.call(nil, '/x') == false, rm.call(5, '/x') == false,
      rm.call('/acct/*', '/acct/1') == true, rm.call('/acct/*', '/acct/') == true, rm.call('/acct/*', '/acc') == false,
      rm.call("#{Pred.hi}*", a) == true, # UTF-16 startsWith
      rm.call('/x', '/x') == true, rm.call('/x', '/x/') == false, rm.call('/a*b', '/a*b') == true, rm.call('/a*b', '/axb') == false,
      rm.call('re:/acct/[^/]+', '/acct/7') == true, rm.call('re:/acct/[^/]+', '/acct/7/x') == false,
      rm.call('re:/x', "/x\n") == false,
      rm.call("re:#{'a' * 200}", 'a' * 200) == true, rm.call("re:#{'a' * 201}", 'a' * 201) == false,
      rm.call("re:#{a * 100}", a * 100) == true, rm.call("re:#{a * 100}a", "#{a * 100}a") == false,
      rm.call('re:a*', 'a' * 512) == true, rm.call('re:a*', 'a' * 513) == false, rm.call('re:[^]*', "#{a * 256}a") == false,
      rm.call('re:(a+)+', 'aa') == false, rm.call('re:\\b', '') == false,
      rm.call('re:', '') == true, rm.call('re:', 'a') == false, rm.call('re:*', '*') == false, rm.call('RE:x', 'RE:x') == true
    ].all?
  end

  t('predicates: predicate shape and context shape') do
    cx = Pred.ctx(params: { 'x' => 1 })
    l1 = { 'field' => 'action.params.x', 'op' => 'eq', 'value' => 1 }
    l2 = { 'field' => 'action.params.x', 'op' => 'eq', 'value' => 2 }
    bad = [{}, { 'action' => nil }, { 'action' => { 'verb' => 1, 'resource' => '/' } }, { 'action' => { 'verb' => 'r' } },
           { 'action' => { 'verb' => 'r', 'resource' => 5 } }, { 'action' => [] }, 'ctx', nil]
    AtlasPca.predicate_matches({ 'verb' => '*', 'where' => [] }, cx) == true &&
      AtlasPca.predicate_matches({ 'verb' => '*', 'where' => { 'field' => 'action.params.x' } }, cx) == false &&
      AtlasPca.predicate_matches({ 'verb' => '*', 'where' => nil }, cx) == false &&
      AtlasPca.predicate_matches({ 'verb' => '*', 'where' => [l1] }, cx) == true &&
      AtlasPca.predicate_matches({ 'verb' => '*', 'where' => [l1, l2] }, cx) == false &&
      bad.all? { |c| AtlasPca.predicate_matches({ 'verb' => '*' }, c) == false } &&
      AtlasPca.predicate_matches({ 'verb' => '*' }, { 'action' => { 'verb' => 'r', 'resource' => '/' } }) == true
  end

  t('predicates: evaluate_predicates verdicts and reasons (JS String() of the action)') do
    cx = Pred.ctx(verb: 'read', resource: '/x')
    p = { 'verb' => 'read' }
    star = [{ 'verb' => '*', 'where' => [Pred.cf] }]
    no = 'envelope grants no predicates'
    ep = ->(a) { AtlasPca.evaluate_predicates(star, a)['reason'] }
    [
      AtlasPca.evaluate_predicates([], cx) == { 'allowed' => false, 'reason' => no },
      AtlasPca.evaluate_predicates('p', cx) == { 'allowed' => false, 'reason' => no },
      AtlasPca.evaluate_predicates(nil, cx) == { 'allowed' => false, 'reason' => no },
      AtlasPca.evaluate_predicates({ 'verb' => '*' }, cx) == { 'allowed' => false, 'reason' => no },
      AtlasPca.evaluate_predicates([{ 'verb' => 'w' }, p, { 'verb' => '*' }], cx) == { 'allowed' => true, 'matched' => p },
      AtlasPca.evaluate_predicates([{ 'verb' => 'w' }, p], cx)['matched'].equal?(p),
      AtlasPca.evaluate_predicates([{ 'verb' => 'w' }], cx) == { 'allowed' => false, 'reason' => 'no predicate permits read on /x' },
      ep.call({}) == 'no predicate permits undefined on undefined',
      ep.call({ 'action' => nil }) == 'no predicate permits undefined on undefined',
      ep.call({ 'action' => 'str' }) == 'no predicate permits undefined on undefined',
      ep.call({ 'action' => { 'verb' => 5 } }) == 'no predicate permits 5 on undefined',
      ep.call({ 'action' => { 'verb' => 1.5e-7, 'resource' => nil } }) == 'no predicate permits 1.5e-7 on null',
      ep.call({ 'action' => { 'verb' => 1e21, 'resource' => true } }) == 'no predicate permits 1e+21 on true',
      ep.call({ 'action' => { 'verb' => 1e20, 'resource' => false } }) == 'no predicate permits 100000000000000000000 on false',
      ep.call({ 'action' => { 'verb' => 2.0, 'resource' => 0.001 } }) == 'no predicate permits 2 on 0.001',
      ep.call({ 'action' => { 'verb' => 0.000001, 'resource' => -0.0 } }) == 'no predicate permits 0.000001 on 0',
      ep.call({ 'action' => { 'verb' => -123.456, 'resource' => 2**53 + 1 } }) == 'no predicate permits -123.456 on 9007199254740992',
      ep.call({ 'action' => { 'verb' => [1, [2, nil]], 'resource' => { 'a' => 1 } } }) == 'no predicate permits 1,2, on [object Object]'
    ].all?
  end

  # ---- layers ------------------------------------------------------------------------------------------------------

  t('layers: ceilings in the fixed order org -> site -> std; absent = no constraint') do
    al = Pred.allow
    de = Pred.deny
    c = Pred.lctx
    d = ->(l) { AtlasPca.decide_layer_ceilings(l, c) }
    [
      d.call({}) == { 'status' => 'pass' },
      d.call({ 'org' => al, 'site' => al, 'std' => al }) == { 'status' => 'pass' },
      d.call({ 'org' => de, 'site' => de, 'std' => de }) == Pred.fail('org'),
      d.call({ 'org' => al, 'site' => de, 'std' => de }) == Pred.fail('site'),
      d.call({ 'site' => al, 'std' => de }) == Pred.fail('std'),
      d.call({ 'std' => de, 'site' => al }) == Pred.fail('std'),
      d.call({ 'site' => de, 'org' => de }) == Pred.fail('org'), # order is fixed, not key order
      d.call({ 'std' => de, 'site' => de }) == Pred.fail('site'),
      d.call({ 'site' => al }) == { 'status' => 'pass' }
    ].all?
  end

  t('layers: a ceiling present with null or not {predicates: [...]} is malformed and fails as that ceiling') do
    bad = [nil, {}, { 'predicates' => 'x' }, { 'predicates' => nil }, { 'predicates' => { 'verb' => '*' } }, [Pred.allow],
           false, 0, '', 'org', { 'predicate' => [{ 'verb' => '*' }] }, { 'predicates' => [{ 'verb' => '*' }], 'note' => 1 }]
    c = Pred.lctx
    bad.all? { |b| AtlasPca.decide_layer_ceilings({ 'org' => b }, c) == Pred.malformed('org') } &&
      bad.all? { |b| AtlasPca.decide_layer_ceilings({ 'org' => Pred.allow, 'site' => b }, c) == Pred.malformed('site') } &&
      AtlasPca.decide_layer_ceilings({ 'std' => nil }, c) == Pred.malformed('std') &&
      # a malformed earlier ceiling wins over a denying later one, a denying earlier one over a malformed later one
      AtlasPca.decide_layer_ceilings({ 'org' => nil, 'site' => Pred.deny }, c) == Pred.malformed('org') &&
      AtlasPca.decide_layer_ceilings({ 'org' => Pred.deny, 'site' => nil }, c) == Pred.fail('org') &&
      # an empty predicate list is well-formed but admits nothing
      AtlasPca.decide_layer_ceilings({ 'org' => { 'predicates' => [] } }, c) == Pred.fail('org') &&
      AtlasPca.is_layer_policy(Pred.allow) && AtlasPca.is_layer_policy({ 'predicates' => [] }) &&
      !AtlasPca.is_layer_policy(nil) && !AtlasPca.is_layer_policy({}) && !AtlasPca.is_layer_policy([Pred.allow]) &&
      !AtlasPca.is_layer_policy({ 'predicates' => [], 'caveats' => [] }) && !AtlasPca.is_layer_policy({ 'predicates' => [], 1 => 2 })
  end

  t('layers: the layers object is closed to {org?, site?, std?} (an unknown member fails as org, before any ceiling)') do
    unk = { 'status' => 'fail', 'layer' => 'org', 'reason' => 'layers: unknown member (the layers object is {org?, site?, std?})' }
    c = Pred.lctx
    al = Pred.allow
    AtlasPca.decide_layer_ceilings({ 'org' => al, 'extra' => al }, c) == unk &&
      AtlasPca.decide_layer_ceilings({ 'task' => [al] }, c) == unk && AtlasPca.decide_layer_ceilings({ 'denied' => [] }, c) == unk &&
      AtlasPca.decide_layer_ceilings({ 'site' => Pred.deny, 'x' => nil }, c) == unk &&
      AtlasPca.decide_layer_ceilings({ 'org' => nil, 'x' => 1 }, c) == unk &&
      AtlasPca.decide_layer_ceilings({ 'ORG' => al }, c) == unk &&
      AtlasPca.decide_layer_ceilings({ 'org' => al, 'site' => al, 'std' => al }, c) == { 'status' => 'pass' }
  end

  t('layers: a layers value that is not an object fails as org') do
    r = { 'status' => 'fail', 'layer' => 'org', 'reason' => 'layers: the layers member is malformed (not an object)' }
    [nil, 'x', [], [Pred.allow], 5, true, false].all? { |l| AtlasPca.decide_layer_ceilings(l, Pred.lctx) == r }
  end

  t('layers: ceilings use the full predicate evaluator (verb, re: resource, where over env)') do
    org = { 'predicates' => [{ 'verb' => 'read', 'resource' => 're:/d[a-z]+',
                               'where' => [{ 'field' => 'env.canon.k', 'op' => 'eq', 'value' => 1 }] }] }
    c = Pred.lctx
    AtlasPca.decide_layer_ceilings({ 'org' => org }, c.merge('env' => { 'canon' => { 'k' => 1 } })) == { 'status' => 'pass' } &&
      AtlasPca.decide_layer_ceilings({ 'org' => org }, c.merge('env' => { 'canon' => { 'k' => 2 } })) == Pred.fail('org') &&
      AtlasPca.decide_layer_ceilings({ 'org' => org }, c.merge('env' => {})) == Pred.fail('org') &&
      AtlasPca.decide_layer_ceilings({ 'org' => org }, c.merge('action' => c['action'].merge('resource' => '/d1'),
                                                               'env' => { 'canon' => { 'k' => 1 } })) == Pred.fail('org')
  end

  t('layers: decide_layers order ceiling -> malformed -> denied -> task (by index) -> intent_required') do
    al = Pred.allow
    de = Pred.deny
    c = Pred.lctx
    d = ->(g) { AtlasPca.decide_layers(g, c) }
    den = { 'decision' => 'intent_denied' }
    [
      d.call({ 'task' => [de, al] }) == { 'decision' => 'admit', 'by' => 1 },
      d.call({ 'task' => [al] }) == { 'decision' => 'admit', 'by' => 0 },
      d.call({ 'task' => [de] }) == { 'decision' => 'intent_required' },
      d.call({ 'task' => [] }) == { 'decision' => 'intent_required' },
      d.call({ 'task' => [{ 'predicates' => [] }] }) == { 'decision' => 'intent_required' },
      d.call({ 'denied' => [], 'task' => [al] }) == { 'decision' => 'admit', 'by' => 0 },
      d.call({ 'denied' => [al], 'task' => [al] }) == den,
      d.call({ 'denied' => [de], 'task' => [al] }) == { 'decision' => 'admit', 'by' => 0 },
      d.call({ 'denied' => [de, al], 'task' => [] }) == den,
      # task is required and must be a list of layers
      d.call({}) == den, d.call({ 'task' => nil }) == den, d.call({ 'task' => 'x' }) == den, d.call({ 'task' => al }) == den,
      d.call({ 'task' => [al, nil] }) == den, d.call({ 'task' => [al.merge('caveats' => [])] }) == den,
      d.call({ 'denied' => [de.merge('note' => 'x')], 'task' => [al] }) == den,
      # the grant is closed to {org?, site?, std?, task, denied?}: an unknown member is intent_denied, before the ceilings
      d.call({ 'task' => [al], 'extra' => [] }) == den, d.call({ 'org' => de, 'task' => [al], 'extra' => 1 }) == den,
      d.call({ 'org' => nil, 'task' => [al], 'x' => nil }) == den,
      d.call({ 'org' => al, 'site' => al, 'std' => al, 'task' => [al], 'denied' => [] }) == { 'decision' => 'admit', 'by' => 0 }, d.call({ 'task' => [nil, 5, al] }) == den, d.call({ 'task' => [al, {}] }) == den,
      # denied present must be a list of layers (null is not absent; a string is never iterated)
      d.call({ 'denied' => nil, 'task' => [al] }) == den, d.call({ 'denied' => 'ab', 'task' => [al] }) == den,
      d.call({ 'denied' => 5, 'task' => [al] }) == den, d.call({ 'denied' => al, 'task' => [al] }) == den,
      d.call({ 'denied' => [de, nil], 'task' => [al] }) == den, d.call({ 'denied' => [{}], 'task' => [al] }) == den,
      # ceilings first (a malformed ceiling or layers value is a ceiling decision)
      d.call({ 'org' => de, 'denied' => [al], 'task' => [al] }) == { 'decision' => 'ceiling', 'layer' => 'org' },
      d.call({ 'org' => de, 'task' => nil }) == { 'decision' => 'ceiling', 'layer' => 'org' },
      d.call({ 'std' => de, 'task' => [al] }) == { 'decision' => 'ceiling', 'layer' => 'std' },
      d.call({ 'site' => {}, 'task' => [al] }) == { 'decision' => 'ceiling', 'layer' => 'site' },
      d.call({ 'site' => nil, 'task' => [al] }) == { 'decision' => 'ceiling', 'layer' => 'site' },
      d.call(nil) == { 'decision' => 'ceiling', 'layer' => 'org' }, d.call('x') == { 'decision' => 'ceiling', 'layer' => 'org' },
      d.call([]) == { 'decision' => 'ceiling', 'layer' => 'org' },
      d.call({ 'org' => al, 'site' => al, 'std' => al, 'task' => [al] }) == { 'decision' => 'admit', 'by' => 0 }
    ].all?
  end
end
