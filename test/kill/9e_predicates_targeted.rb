# frozen_string_literal: true
# Targeted kills for predicates.rb: deep_eq? (jeq), js_number_string, js_string, resolve. Complements the TS differential
# (9c_predjs_diff.rb) with exact boundary values. Fast; skipped under the mutation oracle for other files.
module MutationKill
  module PredTargeted
    module_function
    def p_ = AtlasPca::Predicates
    INF = Float::INFINITY
    def skip? = DiffUtil.skip?('predicates.rb', 'safe_regex.rb')
    def eq(a, b) = p_.deep_eq?(a, b)

    def eq_cases
      t = []
      f = []
      # scalars
      t.push([nil, nil], [true, true], [false, false], [1, 1], [1, 1.0], [0, -0.0], ['a', 'a'], ['', ''], [[], []], [{}, {}], [2**60, 2**60])
      f.push([nil, 0], [0, nil], [nil, false], [false, nil], [nil, ''], ['', nil], [nil, []], [{}, nil],
             [true, false], [false, true], [true, 1], [1, true], [false, 0], [0, false], [true, 'true'], ['true', true], [false, ''],
             [1, '1'], ['1', 1], [1, 2], [1.5, 1.6], [1, [1]], [[1], 1], [1, {}], [{}, 1],
             ['a', 'b'], ['a', 'ab'], ['a', []], [[], 'a'], ['a', {}], [{}, 'a'],
             [INF, INF], [-INF, -INF], [INF, 1], [1, INF], [-INF, 1.0], [1.0, -INF], [Float::NAN, Float::NAN],
             [2**1100, 2**1100], [2**1100, 1], [1, 2**1100])
      # arrays
      t.push([[1], [1]], [[1, 2, 3], [1, 2, 3]], [[[1]], [[1]]], [[nil, true], [nil, true]], [['a', [1, { 'k' => 'v' }]], ['a', [1, { 'k' => 'v' }]]])
      f.push([[1], [1, 2]], [[1, 2], [1]], [[1, 2], [1, 3]], [[1, 2], [2, 1]], [[[1]], [[2]]], [[1], [2]], [[nil], [0]], [[true], [false]],
             [[], [1]], [[1], []], [[1], { '0' => 1 }], [{ '0' => 1 }, [1]], [[], {}], [{}, []], [[INF], [INF]])
      # objects: order-insensitive, same keys, same values
      t.push([{ 'a' => 1 }, { 'a' => 1 }], [{ 'a' => 1, 'b' => 2 }, { 'b' => 2, 'a' => 1 }], [{ 'a' => { 'b' => [1] } }, { 'a' => { 'b' => [1] } }])
      f.push([{ 'a' => 1 }, { 'a' => 2 }], [{ 'a' => 1 }, { 'b' => 1 }], [{ 'a' => 1 }, { 'a' => 1, 'b' => 2 }], [{ 'a' => 1, 'b' => 2 }, { 'a' => 1 }],
             [{ 'a' => 1, 'b' => 1 }, { 'a' => 1, 'c' => 1 }], [{ 'a' => 1, 'b' => 2 }, { 'a' => 2, 'b' => 1 }],
             [{ 'a' => { 'b' => 1 } }, { 'a' => { 'b' => 2 } }], [{ :a => 1 }, { :a => 1 }], [{ 'a' => 1 }, { :a => 1 }], [{ :a => 1 }, { 'a' => 1 }],
             [{ 'a' => INF }, { 'a' => INF }], [Object.new, Object.new], [:s, :s], [1..2, 1..2])
      [t, f]
    end

    # JS Number::toString
    NUMS = { 0.0 => '0', -0.0 => '0', 1.0 => '1', -1.0 => '-1', 1.5 => '1.5', -1.5 => '-1.5', 123.456 => '123.456', 0.5 => '0.5', 
             1e20 => '100000000000000000000', 1e21 => '1e+21', 1.5e21 => '1.5e+21', 1.2345e25 => '1.2345e+25', 123456789012345680000.0 => '123456789012345680000',
             0.000001 => '0.000001', 0.0000012 => '0.0000012', 1e-7 => '1e-7', 1.5e-7 => '1.5e-7', 1.2345e-10 => '1.2345e-10', 0.1 + 0.2 => '0.30000000000000004',
             1e300 => '1e+300', 5e-324 => '5e-324', 1.7976931348623157e308 => '1.7976931348623157e+308', 9007199254740991.0 => '9007199254740991',
             1000.0 => '1000', 1234.5 => '1234.5', 0.1 => '0.1', 12.0 => '12', 120.0 => '120', 3.0e-5 => '0.00003',
             INF => 'Infinity', -INF => '-Infinity', Float::NAN => 'NaN', 4.35 => '4.35', 2e-6 => '0.000002', 1.0e-5 => '0.00001' }.freeze

    def check_eq
      t, f = eq_cases
      t.each { |a, b| return "eq true #{a.inspect}" unless eq(a, b).equal?(true) && eq(b, a).equal?(true) }
      f.each { |a, b| return "eq false #{a.inspect} #{b.inspect}" unless eq(a, b).equal?(false) && eq(b, a).equal?(false) }
      nil
    end

    def check_nums
      NUMS.each { |v, want| (got = p_.js_number_string(v)) == want or return "num #{v}: want #{want} got #{got}" }
      nil
    end

    def check_strings
      s = p_.method(:js_string)
      want = [[AtlasPca::Predicates::UNDEF, 'undefined'], [nil, 'null'], [true, 'true'], [false, 'false'], ['x', 'x'], [1, '1'], [1.5, '1.5'], [[], ''], [[1, nil, 'a'], '1,,a'],
              [[[1, 2], 3], '1,2,3'], [{}, '[object Object]'], [{ 'a' => 1 }, '[object Object]'], [-0.0, '0'], [2**70, '1.1805916207174113e+21']]
      want.each { |v, w| (g = s.call(v)) == w or return "js_string #{v.inspect}: want #{w} got #{g}" }
      deep = (1..66).inject(1) { |a, _| [a] }
      begin
        s.call(deep)
        return 'js_string depth 66 did not raise'
      rescue AtlasPca::Predicates::NotCanonical
        nil
      end
      ok = (1..64).inject(1) { |a, _| [a] }
      s.call(ok) == '1' or return 'js_string depth 64'
      nil
    end

    def check_resolve
      ctx = { 'action' => { 'verb' => 'v', 'params' => { 'n' => 5, 'l' => [10, 20], 'z' => nil, 'e' => [], 'o' => { 'k' => { 'j' => 1 } }, 'constructor' => 1, '' => 'ek' } },
              'subject' => nil, 'env' => { 'x' => 1 } }
      r = p_.method(:resolve)
      ok = { 'action.verb' => 'v', 'action.params.n' => 5, 'action.params.l.0' => 10, 'action.params.l.1' => 20, 'action.params.z' => nil,
             'action.params.o.k.j' => 1, 'env.x' => 1, 'action.params.' => 'ek' }
      ok.each { |p, v| (g = r.call(ctx, p)) == [true, v] or return "resolve #{p}: want #{[true, v].inspect} got #{g.inspect}" }
      nf = ['', 'nope.x', 'action.nope', 'action.params.nope', 'action.params.l.2', 'action.params.l.-1', 'action.params.l.01', 'action.params.l.x', 'action.params.l.0.x',
            'action.params.n.x', 'action.params.z.x', 'action.params.constructor', 'action.__proto__', 'action.prototype', 'subject.id', 'subject.x.y',
            'action.params.e.0', 'action.params.o.k.j.z', 'ACTION.verb', 'actions.verb', 'env.', 'action.params.l.1.']
      nf.each { |p| (g = r.call(ctx, p)).equal?(nil) || g == [false, nil] or return "resolve #{p}: want not found got #{g.inspect}"; g.is_a?(Array) or return "resolve #{p} not an array" }
      r.call(ctx, 'action.verb.x') == [false, nil] or return 'resolve into a string'
      [nil, 5, :action, ['action']].each { |p| r.call(ctx, p) == [false, nil] or return "resolve non-string #{p.inspect}" }
      r.call(ctx, 'subject') == [true, nil] or return 'resolve subject null'
      r.call({ 'action' => [1, 2] }, 'action.1') == [true, 2] or return 'resolve array root'
      r.call({}, 'action') == [false, nil] or return 'resolve missing root'
      nil
    end
  end

  %w[eq nums strings resolve].each do |k|
    t("predicates targeted: #{k}") do
      next true if PredTargeted.skip?
      bad = PredTargeted.send(:"check_#{k}")
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
