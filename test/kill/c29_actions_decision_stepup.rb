# frozen_string_literal: true

# c29: mutation-kill tests for lib/atlas_pca/actions.rb, actions_registry.rb (deadlines only), decision.rb and stepup.rb.
# Expected values pin the reference (packages/pca/src/decision.ts, packages/pca-actions, the step-up client). Everything
# resolves AtlasPca at CALL time (the oracle re-evaluates AtlasPca per mutant). Exceptions whose message differs from to_s
# (MsgErr) pin `e.message` against `e`; Duck / HKey pin is_a?(String) guards that a later comparison would otherwise mask.
require 'timeout'
require 'json'
require 'socket'
require 'tmpdir'

module MutationKill
  module C29
    module_function

    # true when the mutated file (MUT_FILE basename) is none of `names`: cheap tests then pass at once
    def skip?(*names)
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !names.include?(f)
    end

    # exact equality; true / false / nil are compared by identity
    def same(label, got, want)
      ok = want == true || want == false || want.nil? ? got.equal?(want) : got == want
      raise "#{label}: got #{got.inspect}, want #{want.inspect}" unless ok

      true
    end

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    # an exception whose message differs from to_s (a mutant that interpolates the exception reads to_s)
    class MsgErr < StandardError
      def message = 'M'
      def to_s = 'S'
    end

    class NetErr < IOError
      def message = 'M'
      def to_s = 'S'
    end

    # not a String, but a String compares equal to it (String#== defers to the other side's == for a to_str object)
    class Duck
      def initialize(str)
        @str = str
      end

      def to_str = @str

      def ==(_other)
        true
      end
    end

    # not a String, but it finds a String key of a Hash (same hash, eql? to anything)
    class HKey
      def initialize(str)
        @str = str
      end

      def hash = @str.hash
      def eql?(_other) = true
    end

    # a reasons list that is not an Array but answers #select with an escalate-class reason
    class Sel
      def select = ['n: escalate: x']
    end

    def with_stubs(mod, stubs)
      orig = stubs.keys.to_h { |n| [n, mod.method(n)] }
      stubs.each { |n, impl| mod.define_singleton_method(n, &impl) }
      yield
    ensure
      orig&.each { |n, m| mod.define_singleton_method(n, m) }
    end

    def act = AtlasPca::Actions
    def svf = AtlasPca::Actions::SvfJS
    def js = AtlasPca::V2JS
    def su = AtlasPca::StepUp

    def ake
      yield
      raise 'expected an ActionKitError'
    rescue AtlasPca::Actions::ActionKitError => e
      [e.code, e.message]
    end

    # 0.5 s: the real call takes microseconds; a mutant that never advances the cursor grows an array, so stop it early
    def sl(str, len) = Timeout.timeout(0.5) { AtlasPca.utf16_slice(str, len) }

    def chain(depth, leaf)
      c = leaf
      depth.times { c = { 'all_of' => [c] } }
      c
    end

    def du(over = {})
      { 'units' => {}, 'verb' => 'v.x', 'schema_units' => {}, 'verb_params' => {}, 'predicates' => [] }.merge(over)
    end

    def base_def
      { 'v' => 1, 'kind' => 'pca-action-def', 'verb' => 'acme.invoice.pay', 'title' => 'Pay', 'effects' => ['pay'],
        'resource' => { 'type' => 'invoice', 'id' => '*', 'scope' => 'one' }, 'params' => {}, 'review' => { 'state' => 'authored' } }
    end

    # a verb whose floors are exactly the floor of every core trait, except `rev` which the caller supplies
    def floor_verb(over = {})
      reg = act::CORE_REGISTRY
      traits = act.top_traits(reg)
      floors = act.floor_of(reg, traits).merge('rev' => ['irreversible'])
      { 'verb' => 'x.y', 'kind' => 'read', 'effects' => ['read'], 'traits' => traits, 'params' => {}, 'floors' => floors }.merge(over)
    end

    # ---- a loopback HTTP server for the built-in step-up transport -----------------------------------------------------
    # each entry of `responses`: { data: raw bytes } | { raw: true, data: ... } (one readpartial, no parsing) | { hang: true }
    def http(code, reason, body, extra = '')
      "HTTP/1.1 #{code} #{reason}\r\nContent-Type: text/plain\r\n#{extra}Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
    end

    def with_server(responses)
      proxies = %w[http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY]
      saved = proxies.to_h { |k| [k, ENV.delete(k)] }
      srv = TCPServer.new('127.0.0.1', 0)
      seen = []
      th = Thread.new do
        responses.each do |r|
          c = srv.accept
          begin
            if r[:raw]
              c.readpartial(65_536)
            else
              head = +''
              while (line = c.gets)
                head << line
                break if line == "\r\n"
              end
              len = head[/^content-length:\s*(\d+)/i, 1].to_i
              seen << { head: head, body: len.positive? ? c.read(len) : '' }
            end
            sleep 30 if r[:hang]
            c.write(r[:data]) if r[:data]
          ensure
            c.close
          end
        end
      rescue StandardError
        nil
      end
      yield srv.addr[1], seen
    ensure
      th&.kill
      srv&.close
      saved&.each { |k, v| ENV[k] = v unless v.nil? }
    end

    class Fake
      attr_reader :calls

      def initialize(*answers)
        @answers = answers
        @calls = []
      end

      def call(method, url, headers, body)
        @calls << [method, url, headers, body]
        a = @answers.shift
        raise a if a.is_a?(Exception)

        a
      end
    end

    MSG = 'threshold message bytes'.b

    def client(fake, now: -> { 1_799_999_999_000 }, instance: 'ins/1')
      key = su::PrincipalDeviceKey.new(su::MemorySecretStore.new)
      key.generate
      [su::Client.new('https://dash.example/', 'https://atlas.example/', 'acct 1', instance, key, -> { 'tok' }, transport: fake, now: now), key]
    end

    def item(id = 'su_1', exp: '2099-01-01T00:00:00Z', msg: nil, **kw)
      { 'id' => id, 'grant_ref' => 'g1', 'action' => { 'verb' => 'payments.send', 'resource' => 'payments/acme' }, 'required_t' => 2,
        'threshold_message' => msg || AtlasPca.b64e(MSG), 'expires_at' => exp }.merge(kw.transform_keys(&:to_s))
    end

    def list(*items) = [200, JSON.generate({ 'stepups' => items })]

    def iso(time) = time.utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')
  end

  K29 = C29

  # ============================================================ decision.rb ============================================================

  t('c29 decision: the rank table is exactly deny 0 < escalate 1 < allow 2') do
    next true if K29.skip?('decision.rb')

    K29.same('rank', AtlasPca::DECISION_RANK, { 'deny' => 0, 'escalate' => 1, 'allow' => 2 })
  end

  t('c29 decision: utf16_key and utf16_len read the bytes as UTF-8 and scrub invalid bytes to U+FFFD') do
    next true if K29.skip?('decision.rb')

    K29.ck('key binary input', AtlasPca.utf16_key("\xC3\xA9".b), "\x00\xE9".b) &&
      K29.ck('key invalid byte', AtlasPca.utf16_key("a\xFFb"), "\x00a\xFF\xFD\x00b".b) &&
      K29.ck('key encoding', AtlasPca.utf16_key('a').encoding, Encoding::BINARY) &&
      K29.ck('len binary input', AtlasPca.utf16_len("\xC3\xA9".b), 1) &&
      K29.ck('len invalid byte', AtlasPca.utf16_len("a\xFFb"), 3) &&
      K29.ck('len astral', AtlasPca.utf16_len("\u{1F600}"), 2)
  end

  t('c29 decision: utf16_slice joins surrogate pairs, keeps a cut pair as a lone WTF-8 surrogate, and always terminates') do
    next true if K29.skip?('decision.rb')

    pairs = K29.sl("\u{10000}\u{10FFFF}x", 4)
    s = +"a\xFF"
    K29.ck('pairs', pairs, "\u{10000}\u{10FFFF}") && K29.ck('pairs encoding', pairs.encoding, Encoding::UTF_8) &&
      K29.ck('lone D83D', K29.sl("\u{1F600}", 1).b, "\xED\xA0\xBD".b) &&
      K29.ck('lone D800', K29.sl("\u{10000}", 1).b, "\xED\xA0\x80".b) &&
      K29.ck('lone DBFF', K29.sl("\u{10FFFF}", 1).b, "\xED\xAF\xBF".b) &&
      K29.ck('bmp then lone', K29.sl("é\u{1F600}", 2).b, "\xC3\xA9\xED\xA0\xBD".b) &&
      K29.ck('bmp', K29.sl('abcdef', 3), 'abc') &&
      K29.ck('invalid byte is scrubbed when cutting', K29.sl("a\xFFbc", 3).b, "a\xEF\xBF\xBDb".b) &&
      K29.ck('binary input is read as UTF-8', K29.sl("\xC3\xA9\xC3\xA9".b, 1), "é") &&
      K29.ck('integer input', K29.sl(12_345, 2), '12') && K29.ck('integer input kept whole', K29.sl(123, 5), '123') &&
      (K29.sl(s, 5).equal?(s) || raise('a short string comes back as the same object')) &&
      (K29.sl(s, 2).equal?(s) || raise('length == n comes back as the same object'))
  end

  t('c29 decision: js_keys puts canonical array indexes (< 2^32 - 1) first, ascending') do
    next true if K29.skip?('decision.rb')

    got = AtlasPca.js_keys({ 'z' => 1, '4294967295' => 2, '4294967294' => 3, '2' => 4, '10' => 5, '01' => 6 })
    K29.ck('keys', got, %w[2 10 4294967294 z 4294967295 01])
  end

  t('c29 decision: decision_safe_int? is the JS safe-integer test, exactly') do
    next true if K29.skip?('decision.rb')

    table = [[0, true], [(2**53) - 1, true], [2**53, false], [-((2**53) - 1), true], [-(2**53), false], [3.0, true], [-3.0, true], [1.5, false],
             [Float::INFINITY, false], [-Float::INFINITY, false], [Float::NAN, false], [9_007_199_254_740_991.0, true],
             [9_007_199_254_740_992.0, false], [-9_007_199_254_740_992.0, false], ['x', false], [nil, false]]
    table.all? { |v, want| K29.same("safe_int #{v.inspect}", AtlasPca.decision_safe_int?(v), want) }
  end

  t('c29 decision: meet is the minimum; a non-String decision is a deny even when it looks up as one') do
    next true if K29.skip?('decision.rb')

    a = +'deny'
    b = +'deny'
    K29.same('allow/escalate', AtlasPca.meet('allow', 'escalate'), 'escalate') &&
      K29.same('escalate/allow', AtlasPca.meet('escalate', 'allow'), 'escalate') &&
      K29.same('deny/allow', AtlasPca.meet('deny', 'allow'), 'deny') &&
      K29.same('unknown name', AtlasPca.meet('maybe', 'allow'), 'deny') &&
      K29.same('integer a', AtlasPca.meet(5, 'allow'), 'deny') &&
      K29.same('integer b', AtlasPca.meet('allow', 5), 'deny') &&
      K29.same('nil b', AtlasPca.meet('allow', nil), 'deny') &&
      K29.same('key-like a', AtlasPca.meet(K29::HKey.new('deny'), 'allow'), 'deny') &&
      K29.same('key-like b', AtlasPca.meet('allow', K29::HKey.new('deny')), 'deny') &&
      (AtlasPca.meet(a, b).equal?(a) || raise('a tie returns the first argument'))
  end

  t('c29 decision: fold_escalation lists failing v2 reasons once, copies the core list, and allows only when nothing failed') do
    next true if K29.skip?('decision.rb')

    core = ['core']
    v2 = [{ 'name' => 'a', 'ok' => true, 'reason' => 'r1' }, { 'name' => 'b', 'ok' => false }, { 'name' => 'c', 'ok' => false, 'reason' => nil },
          { 'name' => 'd', 'ok' => false, 'reason' => 'x' }, { 'name' => 'd', 'ok' => false, 'reason' => 'x' }]
    r = AtlasPca.fold_escalation(core, v2, { 'a' => 'pass' })
    e = AtlasPca.fold_escalation([], [{ 'name' => 'd', 'ok' => false, 'reason' => 'escalate: why' }], { 'd' => 'fail' })
    K29.ck('allow case', r, { 'reasons' => ['core', 'd: x'], 'decision' => 'allow' }) && K29.ck('core list untouched', core, ['core']) &&
      K29.ck('escalate case', e, { 'reasons' => ['d: escalate: why'], 'decision' => 'escalate' })
  end

  t('c29 decision: decision_of reads reasons only from an Array') do
    next true if K29.skip?('decision.rb')

    v = { 'allow' => false, 'checks' => { 'n' => 'fail' } }
    K29.same('array', AtlasPca.decision_of(v.merge('reasons' => ['n: escalate: x'])), 'escalate') &&
      K29.same('not an array', AtlasPca.decision_of(v.merge('reasons' => K29::Sel.new)), 'deny') &&
      K29.same('no reasons', AtlasPca.decision_of(v), 'deny')
  end

  t('c29 decision: model_derived_path? (env root, model roots, world single-source)') do
    next true if K29.skip?('decision.rb')

    table = [['env.class', [], true], ['env.prov', [], true], ['x.class', [], false], ['env', [], false], ['', [], false], [5, [], false],
             ['env.foo', ['x'], false], ['env.foo.bar', ['bar'], false], ['env.world', [], false], ['env.world', ['x'], true],
             ['env.world.c', ['a'], false], ['env.world.a', ['a'], true], ['env.world.', ['x'], false], ['x.world', ['a'], false]]
    table.all? { |path, single, want| K29.same("path #{path.inspect}", AtlasPca.model_derived_path?(path, single), want) }
  end

  t('c29 decision: collect_condition_paths stops at depth 64, reads only strings, and ignores non-objects') do
    next true if K29.skip?('decision.rb')

    run = lambda do |c|
      out = []
      AtlasPca.collect_condition_paths(c, out, 0)
      out
    end
    K29.ck('depth 64', run.call(K29.chain(64, { 'field' => 'f' })), ['f']) && K29.ck('depth 65', run.call(K29.chain(65, { 'field' => 'f' })), []) &&
      K29.ck('not', run.call({ 'not' => { 'field' => 'n' } }), ['n']) &&
      K29.ck('members', run.call({ 'field' => 'f', 'ref' => 'r', 'collection' => 'c' }), %w[f r c]) &&
      K29.ck('non-string members', run.call({ 'field' => 5, 'ref' => ['a'], 'collection' => nil, 'all_of' => 'x', 'any_of' => 7 }), []) &&
      K29.ck('string condition', run.call('field'), []) && K29.ck('integer condition', run.call(5), []) && K29.ck('nil condition', run.call(nil), [])
  end

  t('c29 decision: closed_member_error and tighten_list_error return nil exactly when well-formed') do
    next true if K29.skip?('decision.rb')

    K29.same('closed ok', AtlasPca.closed_member_error({ 'a' => 1 }, ['a'], [], 'w'), nil) &&
      K29.same('closed unknown', AtlasPca.closed_member_error({ 'a' => 1, 'b' => 2 }, ['a'], [], 'w'), "unknown member 'w.b'") &&
      K29.same('closed missing', AtlasPca.closed_member_error({}, ['a'], [], 'w'), "missing member 'w.a'") &&
      K29.same('tighten empty', AtlasPca.tighten_list_error([]), nil) &&
      K29.same('tighten ok', AtlasPca.tighten_list_error([{ 'id' => 'r1', 'when' => {}, 'signal' => 'deny' }]), nil)
  end

  t('c29 decision: decide_tighten fails closed with the exception class, and only String single-source entries count') do
    next true if K29.skip?('decision.rb')

    preds = [[{ 'where' => [{ 'field' => 'env.world' }] }]]
    K29.ck('fault', AtlasPca.decide_tighten(nil),
         { 'outcome' => 'deny', 'legacy' => false, 'offending' => [], 'reason' => 'evaluation error (fail closed): NoMethodError' }) &&
      K29.ck('non-string single_source entry', AtlasPca.decide_tighten({ 'single_source' => [5], 'predicates' => preds }),
           { 'outcome' => 'ok', 'legacy' => false, 'offending' => [] }) &&
      K29.ck('string single_source entry', AtlasPca.decide_tighten({ 'single_source' => ['w'], 'predicates' => preds }),
           { 'outcome' => 'deny', 'legacy' => false, 'offending' => ['env.world'],
             'reason' => "a grant's where reads model-derived path(s) env.world: a model may only tighten (move them into tighten[]) (rule 21)" })
  end

  t('c29 decision: unit_tags_error caps at 64 entries and checks currency length and type') do
    next true if K29.skip?('decision.rb')

    n64 = (0...64).to_h { |i| ["action.params.p#{i}", { 'kind' => 'k' }] }
    n65 = n64.merge('action.params.extra' => { 'kind' => 'k' })
    path = 'action.params.a'
    K29.same('64 entries', AtlasPca.unit_tags_error(n64), nil) && K29.same('65 entries', AtlasPca.unit_tags_error(n65), 'units has more than 64 entries') &&
      K29.same('one-character currency', AtlasPca.unit_tags_error({ path => { 'kind' => 'k', 'currency' => 'X' } }), nil) &&
      K29.same('empty currency', AtlasPca.unit_tags_error({ path => { 'kind' => 'k', 'currency' => '' } }),
             "units['action.params.a'].currency must be a string of 1..16 characters") &&
      K29.same('17-char currency', AtlasPca.unit_tags_error({ path => { 'kind' => 'k', 'currency' => 'X' * 17 } }),
             "units['action.params.a'].currency must be a string of 1..16 characters") &&
      K29.same('integer currency is refused, not measured', AtlasPca.unit_tags_error({ path => { 'kind' => 'k', 'currency' => 5 } }),
               "units['action.params.a'].currency must be a string of 1..16 characters")
  end

  t('c29 decision: unit_tag_text prints an absent kind as ? and renders values the JS way') do
    next true if K29.skip?('decision.rb')

    K29.same('no unit', AtlasPca.unit_tag_text(nil), 'no unit') &&
      K29.same('absent kind', AtlasPca.unit_tag_text({ 'currency' => 'USD' }), '?/USD') &&
      K29.same('numeric kind and currency', AtlasPca.unit_tag_text({ 'kind' => 1.0, 'currency' => 2.0 }), '1/2') &&
      K29.same('full', AtlasPca.unit_tag_text({ 'kind' => 'money', 'currency' => 'USD', 'exponent' => 2 }), 'money/USD/e2')
  end

  t('c29 decision: same_unit_tag? compares value and presence of each member') do
    next true if K29.skip?('decision.rb')

    K29.same('equal', AtlasPca.same_unit_tag?({ 'kind' => 'x' }, { 'kind' => 'x' }), true) &&
      K29.same('a lacks currency, b holds nil', AtlasPca.same_unit_tag?({ 'kind' => 'x' }, { 'kind' => 'x', 'currency' => nil }), false) &&
      K29.same('b lacks currency, a holds nil', AtlasPca.same_unit_tag?({ 'kind' => 'x', 'currency' => nil }, { 'kind' => 'x' }), false) &&
      K29.same('different kind', AtlasPca.same_unit_tag?({ 'kind' => 'x' }, { 'kind' => 'y' }), false)
  end

  t('c29 decision: verb_in_scope? (wildcard, equal, list; not a substring; a non-object has no verb)') do
    next true if K29.skip?('decision.rb')

    K29.same('wildcard', AtlasPca.verb_in_scope?({ 'verb' => '*' }, 'x'), true) && K29.same('equal', AtlasPca.verb_in_scope?({ 'verb' => 'x' }, 'x'), true) &&
      K29.same('in list', AtlasPca.verb_in_scope?({ 'verb' => %w[a x] }, 'x'), true) && K29.same('not in list', AtlasPca.verb_in_scope?({ 'verb' => ['a'] }, 'x'), false) &&
      K29.same('substring is not membership', AtlasPca.verb_in_scope?({ 'verb' => 'a-x-b' }, 'x'), false) &&
      K29.same('string p', AtlasPca.verb_in_scope?('verb', 'verb'), false) && K29.same('array p', AtlasPca.verb_in_scope?([], 'verb'), false) &&
      K29.same('absent verb equals an absent verb (JS undefined === undefined)', AtlasPca.verb_in_scope?(5, nil), true)
  end

  t('c29 decision: decide_units walks declarations, predicates and depth exactly') do
    next true if K29.skip?('decision.rb')

    ok = { 'ok' => true }
    tag = { 'kind' => 'k' }
    reads = lambda do |*fields|
      { 'predicates' => [[{ 'verb' => '*', 'where' => fields.map { |f| { 'field' => f } } }]] }
    end
    declared = { 'action.params.a' => { 'unit' => 'u' }, 'action.params.b' => { 'unit' => 'u' } }
    base = { 'verb_params' => declared, 'schema_units' => { 'u' => tag } }
    d = ->(over) { AtlasPca.decide_units(K29.du(over)) }
    no_tag = ->(p) { { 'ok' => false, 'reason' => "a policy term reads '#{p}' (k) without a unit tag" } }
    chain = ->(n) { { 'verb' => '*', 'where' => [K29.chain(n, { 'field' => 'action.params.a' })] } }
    K29.ck('non-object declaration is skipped', d.call('units' => { 'action.params.a' => tag }, 'verb_params' => { 'action.params.a' => 'str' }), ok) &&
      K29.ck('non-string unit id is no unit', d.call('units' => { 'action.params.a' => tag }, 'verb_params' => { 'action.params.a' => { 'unit' => 5 } }, 'schema_units' => { 5 => tag }),
           { 'ok' => false, 'reason' => "'action.params.a' is declared as no unit by the action schema but the policy term is tagged k (unit confusion)" }) &&
      K29.ck('predicates must be an array', d.call('predicates' => 'x'), ok) &&
      K29.ck('where must be an array', d.call('predicates' => [[{ 'verb' => '*', 'where' => 'x' }]]), ok) &&
      K29.ck('first sorted path is reported', d.call(base.merge(reads.call('action.params.b', 'action.params.a'))), no_tag.call('action.params.a')) &&
      K29.ck('a repeated path is reported once', d.call(base.merge(reads.call('action.params.b', 'action.params.b'))), no_tag.call('action.params.b')) &&
      K29.ck('only action.params paths are checked', d.call({ 'verb_params' => { 'env.x' => { 'unit' => 'u' } }, 'schema_units' => { 'u' => tag } }.merge(reads.call('env.x'))), ok) &&
      K29.ck('depth 64 is read', d.call(base.merge('predicates' => [[chain.call(64)]])), no_tag.call('action.params.a')) &&
      K29.ck('depth 65 is not', d.call(base.merge('predicates' => [[chain.call(65)]])), ok) &&
      K29.ck('out-of-scope verb is not read', d.call(base.merge('predicates' => [[{ 'verb' => 'other.v', 'where' => [{ 'field' => 'action.params.a' }] }]])), ok) &&
      K29.ck('a fault fails closed with the class', AtlasPca.decide_units(nil), { 'ok' => false, 'reason' => 'evaluation error (fail closed): NoMethodError' })
  end

  # ============================================================ actions.rb ============================================================

  t('c29 actions: constants the mutants edit without changing behaviour (rank, id classes, impersonation row)') do
    next true if K29.skip?('actions.rb')

    digits = '0123456789'
    lower = ('a'..'z').to_a.join
    row = K29.act::TABLE.find { |r| r[0] == 'impersonation' }
    K29.ck('sensitivity rank', K29.act::SENSITIVITY_RANK, { 'free' => 0, 'material' => 1, 'critical' => 2 }) &&
      K29.ck('id classes', K29.act::ID_CLASS_CHARS,
           { 'digits' => digits, 'hex' => "#{digits}abcdef", 'alnum' => digits + lower + lower.upcase, 'slug' => "#{digits}#{lower}-_",
             'uuid' => "#{digits}abcdef-", 'any_safe' => "#{digits}#{lower}#{lower.upcase}._-:/" }) &&
      K29.ck('impersonation row', row, ['impersonation', ['external_communication'], { 'risk' => 2, 'esc' => 1 }, 'acts as a person'])
  end

  t('c29 actions: in?, role? and format? refuse a non-String that merely compares equal') do
    next true if K29.skip?('actions.rb')

    K29.same('in?', K29.act.in?(K29::Duck.new('free'), ['free']), false) && K29.same('in? string', K29.act.in?('free', ['free']), true) &&
      K29.same('role?', K29.act.role?(K29::Duck.new('money.amount')), false) && K29.same('role? string', K29.act.role?('money.amount'), true) &&
      K29.same('format?', K29.act.format?(K29::Duck.new('email')), false) && K29.same('format? string', K29.act.format?('email'), true)
  end

  t('c29 actions: str_list? needs real strings without lone surrogates and distinct members') do
    next true if K29.skip?('actions.rb')

    bad = +"\xED\xA0\x80"
    yes = ->(*) { true }
    K29.same('lone surrogate', !!K29.act.str_list?([bad], 5, &yes), false) && K29.same('non-string member', !!K29.act.str_list?([5], 5, &yes), false) &&
      K29.same('duplicates', !!K29.act.str_list?(%w[a a], 5, &yes), false) && K29.same('ok', !!K29.act.str_list?(%w[a b], 5, &yes), true) &&
      K29.same('ok callback decides', !!K29.act.str_list?(%w[a b], 5) { |s| s == 'a' }, false) && K29.same('too long', !!K29.act.str_list?(%w[a b], 1, &yes), false)
  end

  t('c29 actions: u16key is the UTF-16BE bytes as a binary string') do
    next true if K29.skip?('actions.rb')

    K29.ck('bytes', K29.act.u16key('a'), "\x00a".b) && K29.ck('encoding', K29.act.u16key('a').encoding, Encoding::BINARY)
  end

  t('c29 actions: param_error refuses a unit.ccy.from that is not a String even when a declared name compares equal to it') do
    next true if K29.skip?('actions.rb')

    p = { 'type' => 'integer', 'unit' => { 'kind' => 'money', 'exp' => 2, 'ccy' => { 'from' => K29::Duck.new('cur') } } }
    ok = { 'type' => 'integer', 'unit' => { 'kind' => 'money', 'exp' => 2, 'ccy' => { 'from' => 'cur' } } }
    K29.same('duck', K29.act.param_error('a', p, ['cur']), 'a: unit.ccy.from must name a declared parameter') && K29.same('string', K29.act.param_error('a', ok, ['cur']), nil)
  end

  t('c29 actions: max_sens, max_rev and join return the first argument on a tie') do
    next true if K29.skip?('actions.rb')

    a = +'free'
    b = +'free'
    r = +'reversible'
    p = K29.act.profile('rev' => +'rate_limited')
    q = K29.act.profile('rev' => +'rate_limited')
    (K29.act.max_sens(a, b).equal?(a) || raise('max_sens tie')) && (!K29.act.max_rev([r]).equal?(r) || raise('max_rev keeps the initial class on a tie')) &&
      (K29.act.join(p, q)['rev'].equal?(p['rev']) || raise('join tie'))
  end

  t('c29 actions: normalize sorts the parameter names') do
    next true if K29.skip?('actions.rb')

    d = K29.base_def.merge('params' => { 'b' => { 'type' => 'string' }, 'a' => { 'type' => 'string' } })
    K29.ck('keys', K29.act.normalize(d)['params'].keys, %w[a b])
  end

  t('c29 actions: extend_registry names a non-object custom trait the JS way; closure refuses a non-String id') do
    next true if K29.skip?('actions.rb')

    reg = K29.act::CORE_REGISTRY
    K29.ck('nil custom', K29.ake { K29.act.extend_registry(reg, [nil]) }, ['bad_registry', "custom trait 'null' may not redefine a core trait"]) &&
      K29.ck('lone key-like id', K29.ake { K29.act.closure(reg, [K29::HKey.new('pca.bulk')]) }.first, 'unknown_trait') &&
      K29.ck('key-like id after a seen id', K29.ake { K29.act.closure(reg, [K29::HKey.new('pca.bulk'), 'pca.bulk']) }.first, 'unknown_trait') &&
      K29.ck('closure', K29.act.closure(reg, ['pca.impersonation']), %w[pca.external_communication pca.impersonation])
  end

  t('c29 actions: traits_digest sorts each implies list') do
    next true if K29.skip?('actions.rb')

    mk = ->(imp) { { 'x.a' => { 'id' => 'x.a', 'implies' => imp, 'floor' => K29.act::BOTTOM, 'card_phrase' => 'p' } } }
    K29.ck('order does not matter', K29.act.traits_digest(mk.call(%w[x.z x.b])), K29.act.traits_digest(mk.call(%w[x.b x.z])))
  end

  t('c29 actions: pack_proof terminates and has the RFC 6962 path shape for the first, middle and last leaf') do
    next true if K29.skip?('actions.rb')

    ds = %w[aaa bbb ccc ddd eee]
    root = K29.act.pack_root(ds)
    [[0, 3], [2, 3], [4, 1]].all? do |i, len|
      proof = Timeout.timeout(2) { K29.act.pack_proof(ds, ds[i]) }
      K29.ck("proof #{i}", [proof['index'], proof['size'], proof['path'].length], [i, 5, len]) && K29.act.verify_pack_proof(root, proof, ds[i])
    end
  end

  t('c29 actions: SvfJS.own?, includes? and worst read JS semantics') do
    next true if K29.skip?('actions.rb')

    s = K29.svf
    by = ->(d) { { 'p' => d } }
    K29.same('own? of a number', s.own?(5, 'length'), false) && K29.same('own? of a number 2', s.own?(true, '0'), false) &&
      K29.same('own? array length', s.own?([1], 'length'), true) && K29.same('own? array index', s.own?([1], '0'), true) &&
      K29.same('own? array out of range', s.own?([1], '1'), false) &&
      K29.same('includes? compares bytes', s.includes?(['é'], 'é'), true) &&
      K29.same('worst: numeric domain value keys the map by its JS string',
             s.worst({ 'by' => 'p', 'map' => { '5' => 'reversible' } }, by.call({ 'type' => 'string', 'values' => [5] })), 'reversible') &&
      K29.same('worst: an array decl covers values whose JS string is length or name',
             s.worst([], { 'undefined' => { 'type' => 'string', 'values' => [['length'], ['name']] } }), 'reversible') &&
      K29.same('worst: uncovered adds the default', s.worst({ 'by' => 'p', 'map' => { '5' => 'reversible' } }, by.call({ 'type' => 'string', 'values' => [6] })), 'irreversible')
  end

  t('c29 actions: SvfJS.num reads JS number syntax; a fault in the string scan is NaN') do
    next true if K29.skip?('actions.rb')

    s = K29.svf
    boom = Class.new(String) { def gsub(*) = raise(ArgumentError, 'seam') }.new('5')
    K29.ck('.5', s.num('.5'), 0.5) && K29.ck('-.5', s.num('-.5'), -0.5) && K29.ck('+.5', s.num('+.5'), 0.5) && K29.ck('+5', s.num('+5'), 5.0) &&
      K29.ck('5.', s.num('5.'), 5.0) && K29.ck('1.e2', s.num('1.e2'), 100.0) && K29.ck('0x1f', s.num('0x1f'), 31.0) && K29.ck('0b101', s.num('0b101'), 5.0) &&
      K29.ck('0o17', s.num('0o17'), 15.0) && K29.ck('0B11', s.num('0B11'), 3.0) && s.num('0b12').nan? && s.num('abc').nan? && s.num(Object.new).nan? &&
      (s.num(boom).nan? || raise('a fault in the scan is NaN'))
  end

  t('c29 actions: schema_verb_floor_error compares floors.rev with the declared reversibility (kind read, unknown class)') do
    next true if K29.skip?('actions.rb')

    forged = 'schema_floor_forged: floors.rev is below the declared reversibility'
    K29.same('kind read declares reversible', K29.act.schema_verb_floor_error(K29.floor_verb), forged) &&
      K29.same('an unknown declared class has no rank', K29.act.schema_verb_floor_error(K29.floor_verb('reversibility' => 'bogus')), nil)
  end

  t('c29 actions: rescue arms report the exception message, not the exception object (seams)') do
    next true if K29.skip?('actions.rb')

    reg = K29.act::CORE_REGISTRY
    ake = Class.new(K29.act::ActionKitError) do
      def message = 'M'
      def to_s = 'S'
    end
    boom = ->(*) { raise K29::MsgErr }
    kit = ->(*) { raise ake.new('c0de', 'x') }
    v = K29.floor_verb
    K29.same('validate_def', K29.with_stubs(K29.js, { jsnorm: boom }) { K29.act.validate_def({}) }, 'malformed def: M') &&
      K29.same('attestation_error', K29.with_stubs(K29.act, { reviewer_pins_error: boom }) { K29.act.attestation_error({}, 'dd', reg, {}) }, 'malformed attestation: M') &&
      K29.same('def_confirmation_error', K29.with_stubs(K29.act, { def_digest: boom }) { K29.act.def_confirmation_error({ 'review' => { 'state' => 'confirmed' } }, reg, nil) }, 'malformed def: M') &&
      K29.same('verb_confirmation_error', K29.with_stubs(K29.act, { facts_digest: boom }) { K29.act.verb_confirmation_error({ 'traits' => [] }, reg, nil) }, 'malformed confirmation: M') &&
      K29.same('schema_verb_floor_error StandardError', K29.with_stubs(K29.act, { floor_of: boom }) { K29.act.schema_verb_floor_error(v) }, 'schema_floor_forged: M') &&
      K29.same('schema_verb_floor_error ActionKitError', K29.with_stubs(K29.act, { floor_of: kit }) { K29.act.schema_verb_floor_error(v) }, 'c0de: M') &&
      K29.same('schema_floor_error ActionKitError', K29.with_stubs(K29.act, { registry_of_schema: kit }) { K29.act.schema_floor_error({ 'verbs' => [] }) }, 'c0de: M') &&
      K29.same('schema_floor_error StandardError', K29.with_stubs(K29.act, { registry_of_schema: boom }) { K29.act.schema_floor_error({ 'verbs' => [] }) }, 'bad_registry: M')
  end

  t('c29 registry: decide_pin terminates when no evolution chain reaches the presented digest (deadline)') do
    next true if K29.skip?('actions_registry.rb')

    k = MutationKill::C02RegUndo
    ar = AtlasPca::ActionsRegistry
    wide = k.evo({ 'class' => 'widen' })
    d = ->(i) { Timeout.timeout(2) { ar.decide_pin(i) } }
    K29.ck('no records', d.call(k.dp), k.dn('def_changed', k::NONE)) &&
      K29.ck('widened chain', d.call(k.dp('records' => [wide])), k.dn('def_changed', k::WIDE, false, ar.evolution_diff_digest(wide)))
  end

  # ============================================================ stepup.rb ============================================================

  t('c29 stepup: the abstract store raises NotImplementedError; the stores call super; the alias is exported') do
    next true if K29.skip?('stepup.rb')

    su = K29.su
    abstract = lambda do |meth, *args|
      su::SecretStore.new.public_send(meth, *args)
      false
    rescue NotImplementedError
      true
    end
    calls = []
    su::SecretStore.send(:define_method, :initialize) { |*a| calls << a }
    begin
      su::MemorySecretStore.new
      su::FileSecretStore.new('p')
    ensure
      su::SecretStore.send(:remove_method, :initialize)
    end
    K29.same('load', abstract.call(:load), true) && K29.same('save', abstract.call(:save, 'x'), true) && K29.same('delete', abstract.call(:delete), true) &&
      K29.ck('super calls', calls, [[], []]) && (AtlasPca::SecretStore.equal?(su::SecretStore) || raise('SecretStore alias'))
  end

  t('c29 stepup: MemorySecretStore keeps a binary copy and hands out copies') do
    next true if K29.skip?('stepup.rb')

    st = K29.su::MemorySecretStore.new
    K29.same('empty', st.load, nil)
    seed = +"\xFF#{'a' * 31}"
    st.save(seed)
    got = st.load
    got.setbyte(0, 0)
    K29.ck('binary', st.load.encoding, Encoding::BINARY) && K29.ck('copy on load', st.load, "\xFF#{'a' * 31}".b) && K29.same('delete', st.delete, nil) && K29.same('deleted', st.load, nil)
  end

  t('c29 stepup: FileSecretStore creates the file mode 0600, narrows an existing file, and delete of a missing file is nil') do
    next true if K29.skip?('stepup.rb') || Gem.win_platform? # Windows has no POSIX file modes

    su = K29.su
    Dir.mktmpdir do |dir|
      old = File.umask(0)
      begin
        fresh = File.join(dir, 'fresh')
        K29.with_stubs(File, { chmod: ->(*) { 0 } }) { su::FileSecretStore.new(fresh).save('x' * 32) }
        K29.ck('creation mode', File.stat(fresh).mode & 0o777, 0o600)
        wide = File.join(dir, 'wide')
        File.write(wide, 'old')
        File.chmod(0o644, wide)
        s = su::FileSecretStore.new(wide)
        s.save('y' * 32)
        mode = File.stat(wide).mode & 0o777
        loaded = s.load
        s.delete
        K29.ck('existing file narrowed', mode, 0o600) && K29.ck('roundtrip', loaded, 'y' * 32) && K29.same('delete of a missing file', s.delete, nil) &&
          K29.same('load missing', s.load, nil)
      ensure
        File.umask(old)
      end
    end
  end

  t('c29 stepup: the device key reports its failures with the documented messages') do
    next true if K29.skip?('stepup.rb')

    su = K29.su
    err = lambda do |cls, &blk|
      blk.call
      raise 'expected an error'
    rescue cls => e
      e.message
    end
    mem = -> { su::PrincipalDeviceKey.new(su::MemorySecretStore.new) }
    short = mem.call
    short.instance_variable_get(:@store).save('a' * 31)
    broken = Class.new(su::SecretStore) { def load = raise(ArgumentError, 'x') }
    K29.ck('import', err.call(su::InvalidSecret) { mem.call.import_secret('x') }, 'The secret must be a base64url 32-byte Ed25519 seed.') &&
      K29.ck('no key', err.call(su::NoDeviceKey) { mem.call.sign('m') }, 'No principal device key is stored.') &&
      K29.ck('short seed', err.call(su::InvalidSecret) { short.sign('m') }, 'The stored secret is not a 32-byte seed.') &&
      K29.same('exists? of a failing store', su::PrincipalDeviceKey.new(broken.new).exists?, false)
  end

  t('c29 stepup: parse_iso reads seconds and fractions; base refuses non-http URLs with the quoted URL; seg escapes bytes') do
    next true if K29.skip?('stepup.rb')

    su = K29.su
    err = lambda do |arg|
      su.base(arg)
      raise 'expected an ArgumentError'
    rescue ArgumentError => e
      e.message
    end
    badiso = begin
      su.parse_iso('x')
    rescue ArgumentError => e
      e.message
    end
    stringish = Object.new
    def stringish.to_s = 'http://e.example/x/'
    def stringish.sub(*) = 'RES'
    K29.ck('seconds', su.parse_iso('2027-01-15T08:00:07Z'), 1_800_000_007_000) && K29.ck('fraction', su.parse_iso('2027-01-15T08:00:07.5Z'), 1_800_000_007_500) &&
      K29.ck('bad timestamp', badiso, 'bad timestamp') &&
      K29.ck('ftp', err.call('ftp://x'), 'a step-up URL must be an http(s) URL: "ftp://x"') &&
      K29.ck('invalid URI', err.call('http://exa mple'), 'a step-up URL must be an http(s) URL: "http://exa mple"') &&
      %w[http: http:// http:///x https://].all? { |u| K29.ck(u, err.call(u), "a step-up URL must be an http(s) URL: #{u.inspect}") } &&
      K29.ck('trailing slashes', su.base('https://a.example//'), 'https://a.example') && K29.ck('to_s is what is parsed', su.base(stringish), 'RES') &&
      K29.ck('seg bytes', su.seg('é'), '%C3%A9') && K29.ck('seg reserved', su.seg('a b/c'), 'a%20b%2Fc') && K29.ck('seg unreserved', su.seg('A-z_0.9~'), 'A-z_0.9~') &&
      K29.ck('seg integer', su.seg(5), '5') && K29.ck('seg nil', su.seg(nil), '')
  end

  t('c29 stepup: the client sends exact headers and URLs, refuses unreadable entries, and maps statuses at 200 and 300') do
    next true if K29.skip?('stepup.rb')

    su = K29.su
    fake = K29::Fake.new(K29.list(K29.item), K29.list(K29.item('s1', exp: '2027-01-14T23:59:59.999Z')), K29.list(K29.item('s2', exp: '2027-01-15T08:00:00Z')))
    c, key = K29.client(fake, now: -> { 1_800_000_000_000 })
    first = c.pending
    c.pending
    third = c.pending
    _m, url, headers, _b = fake.calls[0]
    errs = lambda do |answer|
      cc, = K29.client(K29::Fake.new(answer))
      cc.pending
      :returned
    rescue su::TransportError, su::ApiError, su::PrincipalMismatch => e
      [e.class.name.split('::').last, e.message, (e.status if e.respond_to?(:status))]
    end
    K29.ck('url', url, 'https://dash.example/v1/dashboard/accounts/acct%201/instances/ins%2F1/pca/stepups?status=pending') &&
      K29.ck('headers', headers, { 'Authorization' => 'Bearer tok', 'Accept' => 'application/json' }) &&
      K29.ck('only the live one', [first.length, third.length], [1, 0]) && (c.key.equal?(key) || raise('key reader')) &&
      K29.ck('unreadable list', errs.call([200, 'not json']), ['TransportError', 'Unreadable step-up list.', nil]) &&
      K29.ck('unreadable entry', errs.call(K29.list(K29.item(required_t: true))), ['TransportError', 'Unreadable step-up entry.', nil]) &&
      K29.ck('non-string id', errs.call(K29.list(K29.item(5))), ['TransportError', 'Unreadable step-up entry.', nil]) &&
      K29.ck('status 199', errs.call([199, '{}']), ['ApiError', 'The request failed.', 199]) && K29.ck('status 100', errs.call([100, '{}']), ['ApiError', 'The request failed.', 100]) &&
      K29.ck('status 300', errs.call([300, '{}']), ['ApiError', 'The request failed.', 300]) && K29.ck('status 403', errs.call([403, '{}'])[0], 'PrincipalMismatch') &&
      K29.ck('status 299', errs.call([299, JSON.generate({ 'stepups' => [] })]), :returned) && K29.ck('status 200', errs.call(K29.list), :returned)
  end

  t('c29 stepup: approve and deny send exact headers, escaped ids and bodies; approve reads only an object answer') do
    next true if K29.skip?('stepup.rb')

    su = K29.su
    json = { 'Content-Type' => 'application/json', 'Accept' => 'application/json' }
    pend = su::PendingStepUp.new(id: 'su 1/x', grant_ref: 'g', action_verb: 'v.a', action_resource: 'r', required_t: 2, threshold_message: AtlasPca.b64e(K29::MSG), expires_at: 1)
    answers = [[200, '[]'], [200, 'null'], [200, '"str"'], [200, JSON.generate({ 'status' => 5, 'allow' => true })], [202, JSON.generate({ 'status' => 'pending', 'allow' => false })]]
    fake = K29::Fake.new(*answers, [200, '{}'], [200, '{}'])
    c, = K29.client(fake)
    results = answers.map { c.approve(pend).to_a }
    denied = [c.deny(pend, 'no'), c.deny(pend)]
    bad = begin
      c.approve(pend.dup.tap { |p| p.threshold_message = 'AAAA=' })
    rescue su::InvalidThresholdMessage => e
      e.message
    end
    _m, url, headers, body = fake.calls[0]
    _m2, durl, dheaders, dbody = fake.calls[answers.length]
    K29.ck('cosign url', url, 'https://atlas.example/v1/pca/stepups/su%201%2Fx/cosign') && K29.ck('approve headers', headers, json) &&
      K29.ck('approve body', JSON.parse(body).keys.sort, %w[publicKey role sig]) &&
      K29.ck('results', results, [['', false, 200], ['', false, 200], ['', false, 200], ['', true, 200], ['pending', false, 202]]) &&
      K29.ck('deny url', durl, 'https://dash.example/v1/dashboard/accounts/acct%201/instances/ins%2F1/pca/stepups/su%201%2Fx/deny') &&
      K29.ck('deny headers', dheaders, { 'Authorization' => 'Bearer tok', 'Accept' => 'application/json', 'Content-Type' => 'application/json' }) &&
      K29.ck('deny body', [JSON.parse(dbody), JSON.parse(fake.calls[answers.length + 1][3])], [{ 'reason' => 'no' }, {}]) && K29.same('deny returns nil', denied, [nil, nil]) &&
      K29.ck('threshold message', bad, "The step-up's threshold message is not canonical base64url.")
  end

  t('c29 stepup: the default clock is epoch milliseconds and the given clock wins') do
    next true if K29.skip?('stepup.rb')

    su = K29.su
    key = su::PrincipalDeviceKey.new(su::MemorySecretStore.new)
    key.generate
    mk = ->(**kw) { su::Client.new('https://d.example', 'https://a.example', 'a', 'i', key, -> { 't' }, **kw) }
    clock = mk.call(transport: K29::Fake.new).instance_variable_get(:@now).call
    far = K29::Fake.new(K29.list(K29.item))
    given, = K29.client(far, now: -> { 9_999_999_999_999 })
    now = Time.now
    soon = K29.iso(now + (10 * 86_400))
    ago = K29.iso(now - (10 * 86_400))
    live = mk.call(transport: K29::Fake.new(K29.list(K29.item('fut10', exp: soon), K29.item('fut2099'), K29.item('past10', exp: ago), K29.item('past2020', exp: '2020-01-01T00:00:00Z'))))
    (clock.is_a?(Integer) && (clock - (now.to_f * 1000)).abs < 5000 || raise("default clock #{clock.inspect}")) &&
      K29.ck('given clock is used', given.pending.length, 0) && K29.ck('default clock filters by real time', live.pending.map(&:id), %w[fut10 fut2099])
  end

  t('c29 stepup: the built-in transport speaks HTTP over a socket (status, UTF-8 body, request line, headers, body)') do
    next true if K29.skip?('stepup.rb')

    su = K29.su
    t5 = su.net_transport(5)
    K29.with_server([{ data: K29.http(201, 'Created', "café") }, { data: K29.http(200, 'OK', 'hello') }, { data: "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n" }]) do |port, seen|
      base = "http://127.0.0.1:#{port}"
      post = t5.call('POST', "#{base}/p/q?x=1", { 'X-Test' => 'v', 'Content-Type' => 'application/json' }, '{"a":1}')
      get = t5.call('GET', "#{base}/g", {}, nil)
      none = t5.call('GET', "#{base}/n", {}, nil)
      K29.ck('post answer', post, [201, "café"]) && K29.ck('post encoding', post[1].encoding, Encoding::UTF_8) && K29.ck('status is an Integer', post[0].class, Integer) &&
        K29.ck('request line', seen[0][:head].lines.first, "POST /p/q?x=1 HTTP/1.1\r\n") && (seen[0][:head] =~ /^x-test: v\r$/i || raise('header not sent')) &&
        K29.ck('request body', seen[0][:body], '{"a":1}') && K29.ck('get answer', get, [200, 'hello']) && K29.ck('get request line', seen[1][:head].lines.first, "GET /g HTTP/1.1\r\n") &&
        (seen[1][:head] !~ /^content-length:/i || raise('a body-less GET has no Content-Length')) && K29.ck('no content', none, [204, '']) &&
        K29.ck('no content encoding', none[1].encoding, Encoding::UTF_8)
    end
  end

  t('c29 stepup: an https URL is spoken to with TLS; a stalled server hits the timeout; a network fault keeps its message') do
    next true if K29.skip?('stepup.rb')

    su = K29.su
    tls = begin
      K29.with_server([{ raw: true, data: K29.http(200, 'OK', 'plain') }]) { |port, _| su.net_transport(5).call('GET', "https://127.0.0.1:#{port}/", {}, nil) }
      :plain
    rescue su::TransportError
      :tls
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    stalled = begin
      K29.with_server([{ hang: true }]) { |port, _| Timeout.timeout(6) { su.net_transport(0.3).call('GET', "http://127.0.0.1:#{port}/", {}, nil) } }
      :returned
    rescue su::TransportError
      :transport_error
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    msg = K29.with_stubs(Net::HTTP, { new: ->(*) { raise K29::NetErr } }) do
      su.net_transport(1).call('GET', 'http://127.0.0.1:1/', {}, nil)
      nil
    rescue su::TransportError => e
      e.message
    end
    K29.ck('https', tls, :tls) && K29.ck('stalled', stalled, :transport_error) && (elapsed < 3 || raise("the timeout is not applied (#{elapsed}s)")) && K29.ck('message', msg, 'M')
  end

  t('c29 stepup: a client without a transport talks HTTP through the built-in one') do
    next true if K29.skip?('stepup.rb')

    su = K29.su
    key = su::PrincipalDeviceKey.new(su::MemorySecretStore.new)
    key.generate
    body = JSON.generate({ 'stepups' => [K29.item('live')] })
    K29.with_server([{ data: K29.http(200, 'OK', body) }]) do |port, seen|
      c = su::Client.new("http://127.0.0.1:#{port}", "http://127.0.0.1:#{port}", 'a', 'i', key, -> { 'tok' })
      K29.ck('ids', c.pending.map(&:id), ['live']) && (seen[0][:head] =~ %r{\AGET /v1/dashboard/accounts/a/instances/i/pca/stepups\?status=pending HTTP/1\.1} || raise('request line')) &&
        (seen[0][:head] =~ /^authorization: Bearer tok\r$/i || raise('bearer token'))
    end
  end
end
