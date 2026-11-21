# frozen_string_literal: true

# zf: kill tests for the agent facade (facade.rb): limit parsing, the catalog lookups, compile_policy, the dollar risk claim
# (ECMAScript Number of a param) and the AgentHandle (dry_run / act / sub_agent / create_agent defaults). Expected values pin
# the reference (packages/pca/src/facade.ts: parseLimit, specFor, compilePolicy, riskFor, makeAgent, agent). AtlasPca is
# resolved at call time.

module MutationKill
  module ZF
    module_function

    def gate? = (f = ENV['MUT_FILE']).nil? || f.empty? || f == 'facade.rb'

    # type-exact (Integer 1 and Float 1.0 differ) and deep for Hash / Array
    def eq(label, got, want) = got.eql?(want) || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    def same(label, got, want) = got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    def nan(label, got) = (got.is_a?(Float) && got.nan?) || raise("#{label}: got #{got.inspect}, want NaN")

    # the block raises `klass` with exactly `msg` (a String) or a message matching it (a Regexp)
    def refuses(label, msg, klass = ArgumentError)
      yield
    rescue klass => e
      ok = msg.is_a?(Regexp) ? msg.match?(e.message) : e.message == msg
      ok || raise("#{label}: message #{e.message.inspect}, want #{msg.inspect}")
    else
      raise "#{label}: did not raise"
    end

    # swap singleton methods of AtlasPca for the block, restore afterwards
    def seam(stubs)
      orig = stubs.keys.to_h { |n| [n, AtlasPca.method(n)] }
      stubs.each { |n, impl| AtlasPca.define_singleton_method(n, &impl) }
      yield
    ensure
      orig&.each { |n, m| AtlasPca.define_singleton_method(n, m) }
    end

    NOW = 1_800_000_000_000
    DAY = 86_400_000

    def spec(verb, rev: 'reversible', br: 0.1, **extra)
      c, _, a = verb.partition('.')
      { 'connector' => c, 'action' => a, 'verb' => verb, 'reversibility' => rev, 'blastRadius' => br }.merge(extra.transform_keys(&:to_s))
    end

    # a caller's catalog: an own resource, aliases, an ambiguous alias, an empty connector, a verb with no dot, a verb ending in
    # a dot and an unknown reversibility class
    def cat
      [spec('pay.send', resource: 'acct:*', amountField: 'amount', aliases: ['transfer']),
       spec('pay.cancel', rev: 'irreversible', br: 0.6, amountField: 'amount', aliases: ['void']),
       spec('dup.one', aliases: ['twin']), spec('dup.two', aliases: ['twin']),
       { 'connector' => '', 'action' => 'anon', 'verb' => 'anon', 'reversibility' => 'reversible', 'blastRadius' => 0.1, 'aliases' => ['zz'] },
       spec('ping.'), spec('odd.x', rev: 'weird'), spec('sym.a', aliases: [:sym])]
    end

    def fallback(verb, connector, action)
      { 'connector' => connector, 'action' => action, 'verb' => verb, 'reversibility' => 'irreversible', 'blastRadius' => 0.8,
        'description' => "(uncatalogued) #{verb}" }
    end

    def builtin(verb) = AtlasPca::BUILTIN_ACTIONS.find { |a| a['verb'] == verb }

    def dollar_weights = { 'alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0 }

    # fresh per call: the mutation oracle reloads AtlasPca between mutants, so a key kept across tests is of a stale class
    def keys = [AtlasPca::KeyPair.generate, AtlasPca::KeyPair.generate]

    # a handle over a hand-written policy (dry_run reads only the policy, the catalog and the chain length)
    def handle(policy, chain: [{}], provenance: nil, grant: {}, aud: 'rs')
      pol = { 'riskPolicy' => AtlasPca::DEFAULT_RISK_POLICY, 'budgetModel' => 'risk', 'caveats' => [] }.merge(policy)
      AtlasPca::AgentHandle.new(grant: grant, chain: chain, goal_salt: 's', policy: pol, holder: keys[1], principal_public: keys[0].public,
                                catalog: AtlasPca.facade_catalog(nil), aud: aud, start_now: 0, provenance: provenance)
    end
  end

  # ---- parse_limit ------------------------------------------------------------------------------------------------------

  t('zf facade parse_limit: every period name and its length in ms, any case') do
    next true unless ZF.gate?

    want = { 's' => 1000, 'sec' => 1000, 'second' => 1000, 'seconds' => 1000,
             'm' => 60_000, 'min' => 60_000, 'minute' => 60_000, 'minutes' => 60_000,
             'h' => 3_600_000, 'hr' => 3_600_000, 'hour' => 3_600_000, 'hours' => 3_600_000,
             'd' => 86_400_000, 'day' => 86_400_000, 'days' => 86_400_000,
             'w' => 604_800_000, 'week' => 604_800_000, 'weeks' => 604_800_000,
             'mo' => 2_592_000_000, 'month' => 2_592_000_000, 'months' => 2_592_000_000 }
    want.all? { |k, ms| ZF.eq("5/#{k}", AtlasPca.parse_limit("5/#{k}"), { 'amount' => 5, 'unit' => 'count', 'periodMs' => ms }) } &&
      ZF.eq('upper case', AtlasPca.parse_limit('$2/MONTHS'), { 'amount' => 2, 'unit' => 'usd', 'periodMs' => 2_592_000_000 }) &&
      ZF.eq('table', AtlasPca::LIMIT_PERIODS, want) &&
      ZF.refuses('unknown', "parseLimit: unknown period 'yr' in '5/yr'") { AtlasPca.parse_limit('5/yr') }
  end

  t('zf facade parse_limit: an integral amount is an Integer up to 2^53 - 1, else a Float') do
    next true unless ZF.gate?

    ZF.eq('max safe', AtlasPca.parse_limit('9007199254740991')['amount'], 9_007_199_254_740_991) &&
      ZF.eq('2^53', AtlasPca.parse_limit('9007199254740992')['amount'], 9_007_199_254_740_992.0) &&
      ZF.eq('1e20', AtlasPca.parse_limit('$100000000000000000000')['amount'], 1.0e20) &&
      ZF.eq('fraction', AtlasPca.parse_limit('1.5')['amount'], 1.5) &&
      ZF.eq('x.0', AtlasPca.parse_limit('3.0')['amount'], 3) &&
      # js_decimal on its own: a non-finite value stays a Float, a negative one is judged by its magnitude
      ZF.eq('inf', AtlasPca.js_decimal('1e400'), Float::INFINITY) &&
      ZF.eq('-5', AtlasPca.js_decimal('-5'), -5) &&
      ZF.eq('-1e300', AtlasPca.js_decimal('-1e300'), -1.0e300)
  end

  t('zf facade parse_limit: a non-string, an invalid string or a blank one is an empty limit') do
    next true unless ZF.gate?

    ['', '   ', "　\t", nil, 5, ['1'], "\xff1".dup.force_encoding('UTF-8')].all? do |v|
      ZF.refuses("empty #{v.inspect}", 'parseLimit: empty limit') { AtlasPca.parse_limit(v) }
    end
  end

  t('zf facade parse_limit: the length cap counts UTF-16 units (astral characters count two)') do
    next true unless ZF.gate?

    long = 'parseLimit: limit is longer than 64 characters'
    unparsable = /\AparseLimit: cannot parse limit '/
    ZF.refuses('65 units', long) { AtlasPca.parse_limit("#{"\u{10000}" * 32}1") } &&
      ZF.refuses('44 units', unparsable) { AtlasPca.parse_limit("\u{10000}" * 22) } &&
      ZF.refuses('64 BMP units', unparsable) { AtlasPca.parse_limit("￿" * 64) } &&
      ZF.refuses('65 BMP units', long) { AtlasPca.parse_limit("￿" * 65) } &&
      ZF.eq('utf16', [AtlasPca.utf16_length("\u{10000}"), AtlasPca.utf16_length("￿"), AtlasPca.utf16_length("a\u{1F4B0}")], [2, 1, 3])
  end

  t('zf facade parse_limit: a non-finite or negative amount is refused (the guard behind the grammar)') do
    next true unless ZF.gate?

    bad = "parseLimit: bad amount in '1'"
    [Float::INFINITY, -Float::INFINITY, Float::NAN, -1, -0.5].all? { |v|
      ZF.seam(js_decimal: ->(_t) { v }) { ZF.refuses("amount #{v}", bad) { AtlasPca.parse_limit('1') } }
    } && ZF.seam(js_decimal: ->(_t) { 0 }) { ZF.eq('zero', AtlasPca.parse_limit('1'), { 'amount' => 0, 'unit' => 'count' }) } &&
      ZF.seam(js_decimal: ->(_t) { 2.5 }) { ZF.eq('float', AtlasPca.parse_limit('$1'), { 'amount' => 2.5, 'unit' => 'usd' }) }
  end

  t('zf facade constants: the whitespace class is frozen') do
    next true unless ZF.gate?

    AtlasPca::JS_WS_CLASS.frozen? || raise('JS_WS_CLASS is not frozen')
  end

  # ---- the catalog ------------------------------------------------------------------------------------------------------

  t('zf facade catalog: get, exact resolve and aliases of exactly one action of the connector') do
    next true unless ZF.gate?

    b = AtlasPca.facade_catalog(nil)
    c = AtlasPca.facade_catalog(ZF.cat)
    ZF.same('get', b.get('stripe.charge'), ZF.builtin('stripe.charge')) &&
      ZF.same('get none', b.get('stripe.bill'), nil) &&
      ZF.same('get no dot', c.get('anon')&.fetch('action'), 'anon') &&
      ZF.same('exact', b.resolve('stripe', 'charge'), ZF.builtin('stripe.charge')) &&
      ZF.same('alias', b.resolve('stripe', 'bill'), ZF.builtin('stripe.charge')) &&
      ZF.same('alias 2', b.resolve('gmail', 'send_email'), ZF.builtin('gmail.send')) &&
      ZF.same('other connector', b.resolve('gmail', 'bill'), nil) &&
      ZF.same('unknown', b.resolve('stripe', 'nope'), nil) &&
      ZF.same('own alias', c.resolve('pay', 'transfer')&.fetch('verb'), 'pay.send') &&
      ZF.same('exact own', c.resolve('dup', 'one')&.fetch('verb'), 'dup.one') &&
      (c.resolve('dup', 'twin').nil? || raise('an alias of two actions must resolve to nil, not a guess'))
  end

  t('zf facade spec_for: catalogued, via alias, and the uncatalogued fallback') do
    next true unless ZF.gate?

    b = AtlasPca.facade_catalog(nil)
    c = AtlasPca.facade_catalog(ZF.cat)
    ZF.same('catalogued', b.spec_for('stripe.charge'), ZF.builtin('stripe.charge')) &&
      ZF.same('alias', b.spec_for('stripe.bill'), ZF.builtin('stripe.charge')) &&
      ZF.same('no-dot verb', c.spec_for('anon')&.fetch('aliases'), ['zz']) &&
      ZF.eq('x.y.z', b.spec_for('x.y.z'), ZF.fallback('x.y.z', 'x', 'y.z')) &&
      ZF.eq('x.y', b.spec_for('x.y'), ZF.fallback('x.y', 'x', 'y')) &&
      ZF.eq('trailing dot', b.spec_for('x.y.'), ZF.fallback('x.y.', 'x', 'y.')) &&
      ZF.eq('x.', b.spec_for('x.'), ZF.fallback('x.', 'x', 'x.')) &&
      ZF.eq('no dot', b.spec_for('nodot'), ZF.fallback('nodot', 'nodot', 'nodot')) &&
      ZF.eq('empty', b.spec_for(''), ZF.fallback('', '', '')) &&
      ZF.eq('alias of another connector', b.spec_for('gmail.bill'), ZF.fallback('gmail.bill', 'gmail', 'bill')) &&
      # an alias needs a connector before the dot, and a verb without a dot is never looked up as `<verb>.`
      ZF.eq('leading dot', c.spec_for('.zz'), ZF.fallback('.zz', '', 'zz')) &&
      ZF.eq('no dot, not <verb>.', c.spec_for('ping'), ZF.fallback('ping', 'ping', 'ping')) &&
      ZF.same('ping.', c.spec_for('ping.')&.fetch('verb'), 'ping.')
  end

  t('zf facade reversibility_rank and now_ms') do
    next true unless ZF.gate?

    t0 = (Time.now.to_f * 1000).to_i
    v = AtlasPca.now_ms
    t1 = (Time.now.to_f * 1000).to_i
    ZF.eq('ranks', %w[reversible rate_limited irreversible weird].map { |c| AtlasPca.reversibility_rank(c) }, [0, 1, 2, -1]) &&
      (v.is_a?(Integer) && v >= t0 && v <= t1 || raise("now_ms #{v.inspect} not in #{t0}..#{t1}"))
  end
end
