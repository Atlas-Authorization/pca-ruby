# frozen_string_literal: true
# c27: exact-outcome kill tests for mesh.rb, a2a.rb and passport.rb (round 2 survivors). Every AtlasPca constant, class and
# function is resolved at CALL time inside each test block (the oracle re-evaluates AtlasPca per mutant). Fixtures are built
# with throwaway Ed25519 keys derived at load; nothing here is a real key. Each test is gated on MUT_FILE so a mutant of an
# unrelated file never pays for it.
require 'openssl'
require 'digest'
require 'timeout'

module MutationKill
  module C27
    # An object that answers like a Hash but is not one (is_a?(Hash) is false).
    class Duck
      def initialize(h)
        @h = h
      end

      def method_missing(name, *args, &blk)
        @h.__send__(name, *args, &blk)
      end

      def respond_to_missing?(name, priv = false)
        @h.respond_to?(name, priv)
      end
    end

    module_function

    def only?(file)
      m = ENV['MUT_FILE']
      m.nil? || m.empty? || m == file
    end

    # exact comparison: true/false/nil by identity, everything else by value and class
    def ck(got, want)
      ok = want.nil? || want == true || want == false ? got.equal?(want) : (got == want && got.class == want.class)
      warn "c27: got #{got.inspect[0, 400]} want #{want.inspect[0, 400]}" if !ok && ENV['MUT_FILE'].to_s.empty?
      ok
    end

    def key(label)
      @keys ||= {}
      @keys[label] ||= OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest("c27/#{label}"))
    end

    def pub(label) = AtlasPca.b64e(key(label).raw_public_key)
    def sgn(label, msg) = AtlasPca.b64e(key(label).sign(nil, msg))
  end

  # ---- Merkle helpers (RFC 6962 / 9162), built from the library's own node and leaf hashes --------------------------------
  module C27T
    module_function

    def lh(ids) = ids.map { |i| AtlasPca.leaf_hash(i) }
    def mth(hs) = AtlasPca.build(hs)

    def audit(hs, m)
      return [] if hs.length == 1

      k = AtlasPca.split_point(hs.length)
      if m < k
        audit(hs[0, k], m) + [['R', mth(hs[k..])]]
      else
        audit(hs[k..], m - k) + [['L', mth(hs[0, k])]]
      end
    end

    def incl(hs, i)
      { 'size' => hs.length, 'index' => i, 'path' => audit(hs, i).map { |s, h| { 'side' => s, 'hash' => AtlasPca.b64e(h) } } }
    end

    def sub(m, hs, b)
      n = hs.length
      return(b ? [] : [mth(hs)]) if m == n

      k = AtlasPca.split_point(n)
      if m <= k
        sub(m, hs[0, k], b) + [mth(hs[k..])]
      else
        sub(m - k, hs[k..], false) + [mth(hs[0, k])]
      end
    end

    def cproof(hs, m) = sub(m, hs, true).map { |h| AtlasPca.b64e(h) }
  end

  # ================================================== a2a.rb ================================================================
  module C27A
    module_function

    def need(extra = {}) = { 'v' => 1, 'kind' => 'scope', 'verb' => 'v', 'resource' => 'r' }.merge(extra)
    def signer = C27.pub('a2a')
    def chain = AtlasPca.pca_grant_chain_digest(['c1'])

    def rec(over = {})
      r = { 'v' => 1, 'task_id' => 't', 'state' => 'TASK_STATE_WORKING', 'seq' => 0, 'prev' => nil, 'chain' => chain,
            'issued_at' => 1, 'signer' => signer }.merge(over)
      body = %w[v task_id state seq prev chain issued_at signer].each_with_object({}) { |k, h| h[k] = r[k] }
      r.merge('sig' => C27.sgn('a2a', AtlasPca::A2A_RECEIPT_DOMAIN.b + AtlasPca.canon_bytes(body)))
    end
  end

  t('c27 a2a: need member limits and codes are exact (every boundary both sides)') do
    next true unless C27.only?('a2a.rb')

    n = C27A.method(:need)
    a = ->(k) { 'a' * k }
    lim = ->(k) { (1..k).to_h { |i| ["k#{i}", 1] } }
    dis = { 'issuer' => 'i', 'claim' => 'c' }
    rows = [
      [n.(), nil], [5, 'bad_shape'], [n.('zz' => 1), 'unknown_member'], [n.('v' => 2), 'bad_version'], [n.('kind' => 'x'), 'bad_kind'],
      [n.('verb' => a.(128)), nil], [n.('verb' => a.(129)), 'bad_field'], [n.('verb' => ''), 'bad_field'],
      [n.('resource' => a.(512)), nil], [n.('resource' => a.(513)), 'bad_field'], [n.('resource' => ''), 'bad_field'],
      [n.('scopes' => []), nil], [n.('scopes' => ['x'] * 16), nil], [n.('scopes' => ['x'] * 17), 'bad_field'],
      [n.('scopes' => [a.(128)]), nil], [n.('scopes' => [a.(129)]), 'bad_field'], [n.('scopes' => ['a b']), 'bad_field'],
      [n.('scopes' => {}), 'bad_field'], [n.('scopes' => 'ab'), 'bad_field'], [n.('scopes' => nil), 'bad_field'],
      [n.('scopes' => ['']), 'bad_field'],
      [n.('grant_ref' => a.(128)), nil], [n.('grant_ref' => a.(129)), 'bad_field'], [n.('grant_ref' => ''), 'bad_field'],
      [n.('grant_ref' => 5), 'bad_field'], [n.('grant_ref' => nil), 'bad_field'],
      [n.('policy_digest' => a.(128)), nil], [n.('policy_digest' => a.(129)), 'bad_field'], [n.('policy_digest' => ''), 'bad_field'],
      [n.('policy_digest' => 5), 'bad_field'], [n.('policy_digest' => nil), 'bad_field'],
      [n.('kind' => 'escalate', 'tier' => 2), nil], [n.('kind' => 'escalate', 'tier' => 3), nil],
      [n.('kind' => 'escalate', 'tier' => 1), 'bad_field'], [n.('kind' => 'escalate', 'tier' => 4), 'bad_field'],
      [n.('kind' => 'escalate', 'tier' => 0), 'bad_field'], [n.('tier' => 2), 'bad_field'], [n.('kind' => 'escalate'), 'bad_field'],
      [n.('limits' => {}), nil], [n.('limits' => { 'a' => 0 }), nil], [n.('limits' => { 'a' => 1.5 }), nil],
      [n.('limits' => lim.(16)), nil], [n.('limits' => lim.(17)), 'bad_field'],
      [n.('limits' => { a.(64) => 1 }), nil], [n.('limits' => { a.(65) => 1 }), 'bad_field'], [n.('limits' => { '' => 1 }), 'bad_field'],
      [n.('limits' => { 'a' => -1 }), 'bad_field'], [n.('limits' => { 'a' => '1' }), 'bad_field'], [n.('limits' => { 'a' => nil }), 'bad_field'],
      [n.('limits' => []), 'bad_field'], [n.('limits' => 'str'), 'bad_field'], [n.('limits' => nil), 'bad_field'],
      [n.('discharges' => []), nil], [n.('discharges' => [dis]), nil], [n.('discharges' => [dis] * 16), nil],
      [n.('discharges' => [dis] * 17), 'bad_field'], [n.('discharges' => [{ 'issuer' => a.(512), 'claim' => 'c' }]), nil],
      [n.('discharges' => [{ 'issuer' => a.(513), 'claim' => 'c' }]), 'bad_field'],
      [n.('discharges' => [{ 'issuer' => 'i', 'claim' => a.(256) }]), nil],
      [n.('discharges' => [{ 'issuer' => 'i', 'claim' => a.(257) }]), 'bad_field'],
      [n.('discharges' => [dis.merge('x' => 1)]), 'bad_field'], [n.('discharges' => [{ 'issuer' => 'i' }]), 'bad_field'],
      [n.('discharges' => [5]), 'bad_field'], [n.('discharges' => [[]]), 'bad_field'], [n.('discharges' => {}), 'bad_field'],
      [n.('discharges' => 'x'), 'bad_field'], [n.('discharges' => nil), 'bad_field']
    ]
    rows.all? { |x, want| C27.ck(AtlasPca.a2a_need_error(x), want) }
  end

  t('c27 a2a: decode_a2a_need returns [need, nil] or [nil, code] exactly (length 2048 vs 2049, utf8, json, shape)') do
    next true unless C27.only?('a2a.rb')

    enc = ->(s) { AtlasPca.b64e(s.b) }
    nd = C27A.need
    [
      [nil, [nil, 'bad_base64']], ['', [nil, 'bad_base64']], [5, [nil, 'bad_base64']], ['!!!!', [nil, 'bad_base64']],
      ['A' * 2049, [nil, 'too_long']], ['A' * 2048, [nil, 'bad_json']],
      [enc.("\xff"), [nil, 'bad_utf8']], [enc.('{'), [nil, 'bad_json']], [enc.('[]'), [nil, 'bad_shape']],
      [enc.('{"v":1,"kind":"scope","verb":"v","resource":"r"}'), [nd, nil]],
      [enc.('{"v":2,"kind":"scope","verb":"v","resource":"r"}'), [nil, 'bad_version']]
    ].all? { |input, want| C27.ck(AtlasPca.decode_a2a_need(input), want) }
  end

  t('c27 a2a: chain extension names the hop and reason (non-array and empty hops are no_chain)') do
    next true unless C27.only?('a2a.rb')

    nc = ->(i) { { 'ok' => false, 'failedHop' => i, 'reason' => 'no_chain' } }
    ne = ->(i) { { 'ok' => false, 'failedHop' => i, 'reason' => 'chain_does_not_extend_previous_hop' } }
    [
      [[], { 'ok' => true }], [[['a'], %w[a b]], { 'ok' => true }], [[['a'], ['a']], { 'ok' => true }],
      [[[]], nc.(0)], [[nil], nc.(0)], [['ab'], nc.(0)], [[{ 'a' => 1 }], nc.(0)], [[['a'], []], nc.(1)],
      [[['a'], ['b']], ne.(1)], [[%w[a b], ['a']], ne.(1)], [[['a'], %w[b a]], ne.(1)]
    ].all? { |input, want| C27.ck(AtlasPca.check_a2a_chain_extension(input), want) }
  end

  t('c27 a2a: resume gate refuses in order and a nil need is no_valid_need') do
    next true unless C27.only?('a2a.rb')

    nd = C27A.need
    enc = AtlasPca.b64e(AtlasPca.canon_bytes(nd))
    dig = AtlasPca.a2a_need_digest(nd)
    pa = { 'verb' => 'v', 'resource' => 'r' }
    st = 'TASK_STATE_AUTH_REQUIRED'
    g = ->(*args) { AtlasPca.a2a_resume_gate(*args) }
    [
      g.(st, enc, dig, pa), g.('auth-required', enc, dig, pa), g.('TASK_STATE_WORKING', enc, dig, pa), g.(st, nil, dig, pa),
      g.(st, 'zz', dig, pa), g.(st, enc, 'wrong', pa), g.(st, enc, dig, nil), g.(st, enc, dig, { 'verb' => 'x', 'resource' => 'r' }),
      g.(st, enc, dig, { 'verb' => 'v', 'resource' => 'x' })
    ].zip([nil, nil, 'task_not_auth_required', 'no_valid_need', 'no_valid_need', 'answer_not_bound_to_need', 'no_proof',
           'action_mismatch', 'action_mismatch']).all? { |got, want| C27.ck(got, want) }
  end

  t('c27 a2a: push token needs a String salt of at least 16 characters') do
    next true unless C27.only?('a2a.rb')

    f = ->(salt) { AtlasPca.a2a_push_token('t1', ['c1'], salt) }
    want = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/a2a-push/v1', 'task_id' => 't1', 'chain' => AtlasPca.pca_grant_chain_digest(['c1']), 'salt' => 's' * 16 })
    C27.ck(f.('s' * 16), want) && C27.ck(f.('s' * 15), nil) && C27.ck(f.('s' * 40).class, String) && C27.ck(f.(nil), nil) &&
      C27.ck(f.(12_345_678_901_234_567), nil) && C27.ck(f.(['s'] * 16), nil) && C27.ck(f.({}), nil)
  end

  t('c27 a2a: push check refuses a missing token, a wrong token and a payload without the task') do
    next true unless C27.only?('a2a.rb')

    salt = 's' * 16
    tk = ->(task) { AtlasPca.a2a_push_token(task, ['c1'], salt) }
    chk = ->(task, token, payload) { AtlasPca.check_a2a_push(task, ['c1'], salt, token, payload) }
    ok = { 'ok' => true }
    no = ->(r) { { 'ok' => false, 'reason' => r } }
    [
      [chk.('t1', tk.('t1'), { 'task' => { 'id' => 't1' } }), ok],
      [chk.('t1', tk.('t1'), { 'statusUpdate' => { 'taskId' => 't1' } }), ok],
      [chk.('t1', tk.('t1'), { 'artifactUpdate' => { 'taskId' => 't1' } }), ok],
      [chk.('t1', tk.('t1'), { 'task' => { 'id' => 'zz' } }), no.('task_mismatch')],
      [chk.('t1', tk.('t1'), nil), no.('task_mismatch')], [chk.('t1', tk.('t1'), []), no.('task_mismatch')],
      [chk.('t1', tk.('t1'), {}), no.('task_mismatch')],
      [chk.('id', tk.('id'), { 'task' => 'xid' }), no.('task_mismatch')],
      [chk.('taskId', tk.('taskId'), { 'statusUpdate' => 'taskId' }), no.('task_mismatch')],
      [chk.('t1', nil, {}), no.('no_token')], [chk.('t1', '', {}), no.('no_token')], [chk.('t1', 5, {}), no.('no_token')],
      [chk.('t1', 'bogus', {}), no.('token_mismatch')], [chk.('t1', tk.('t2'), {}), no.('token_mismatch')],
      [AtlasPca.check_a2a_push('t1', ['c1'], 'short', 'bogus', {}), no.('token_mismatch')]
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 a2a: receipt domain is bytes (binary encoding)') do
    next true unless C27.only?('a2a.rb')

    AtlasPca::A2A_RECEIPT_DOMAIN.encoding == Encoding::BINARY && AtlasPca::A2A_RECEIPT_DOMAIN == "atlas-pca/a2a-receipt/v1\x00".b
  end

  t('c27 a2a: verify_a2a_receipt judges each field on a validly signed record') do
    next true unless C27.only?('a2a.rb')

    r = C27A.method(:rec)
    s = C27A.signer
    ver = ->(x) { AtlasPca.verify_a2a_receipt(x, s) }
    ch = C27A.chain
    [
      [ver.(r.()), true], [ver.(nil), false], [ver.([]), false], [ver.('x'), false], [ver.(r.('v' => 2)), false],
      # signed by the right key but the record names another signer
      [ver.(r.('signer' => 'not-the-signer')), false],
      [ver.(r.('task_id' => 'a' * 4096)), true], [ver.(r.('task_id' => 'a' * 4097)), false], [ver.(r.('task_id' => '')), false],
      [ver.(r.('state' => 'TASK_STATE_FAILED')), true], [ver.(r.('state' => 'nope')), false],
      [ver.(r.('seq' => -1, 'prev' => ch)), false], [ver.(r.('seq' => 1, 'prev' => ch)), true],
      [ver.(r.('issued_at' => -1)), false], [ver.(r.('issued_at' => 'x')), false],
      [ver.(r.('chain' => nil)), false], [ver.(r.('chain' => 'AAAA')), false],
      [ver.(r.('seq' => 1, 'prev' => 'AAAA')), false], [ver.(r.('seq' => 1, 'prev' => 5)), false],
      [ver.(r.('seq' => 0, 'prev' => ch)), false], [ver.(r.('seq' => 1, 'prev' => nil)), false],
      [ver.(r.().merge('sig' => 'AAAA')), false], [ver.(r.().merge('sig' => nil)), false]
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 a2a: receipt chain names the code and the index') do
    next true unless C27.only?('a2a.rb')

    s = C27A.signer
    r = C27A.method(:rec)
    ids = ['c1']
    run = ->(list, task = 't') { AtlasPca.check_a2a_receipt_chain(list, s, task, ids) }
    r0 = r.()
    r1 = r.('seq' => 1, 'prev' => AtlasPca.a2a_receipt_digest(r0), 'state' => 'TASK_STATE_WORKING')
    r2 = r.('seq' => 2, 'prev' => AtlasPca.a2a_receipt_digest(r1), 'state' => 'TASK_STATE_COMPLETED')
    r3 = r.('seq' => 3, 'prev' => AtlasPca.a2a_receipt_digest(r2), 'state' => 'TASK_STATE_WORKING')
    bad_prev = r.('seq' => 1, 'prev' => C27A.chain)
    bad_seq = r.('seq' => 5, 'prev' => AtlasPca.a2a_receipt_digest(r0))
    other_chain = r.('chain' => AtlasPca.pca_grant_chain_digest(['zz']))
    start1 = r.('seq' => 1, 'prev' => C27A.chain)
    [
      [run.([r0, r1, r2]), { 'ok' => true, 'terminal' => true, 'last_state' => 'TASK_STATE_COMPLETED' }],
      [run.([r0]), { 'ok' => true, 'terminal' => false, 'last_state' => 'TASK_STATE_WORKING' }],
      [run.(nil), { 'ok' => false, 'code' => 'empty' }], [run.([]), { 'ok' => false, 'code' => 'empty' }],
      [run.({ 'a' => 1 }), { 'ok' => false, 'code' => 'empty' }],
      [run.([r0, nil]), { 'ok' => false, 'code' => 'bad_receipt', 'at' => 1 }],
      [run.([r0], 'other'), { 'ok' => false, 'code' => 'wrong_task', 'at' => 0 }],
      [run.([other_chain]), { 'ok' => false, 'code' => 'wrong_chain', 'at' => 0 }],
      [run.([start1]), { 'ok' => false, 'code' => 'bad_start', 'at' => 0 }],
      [run.([r0, r1, r2, r3]), { 'ok' => false, 'code' => 'after_terminal', 'at' => 3 }],
      [run.([r0, bad_prev]), { 'ok' => false, 'code' => 'broken_link', 'at' => 1 }],
      [run.([r0, bad_seq]), { 'ok' => false, 'code' => 'broken_link', 'at' => 1 }]
    ].all? { |got, want| C27.ck(got, want) } &&
      C27.ck(AtlasPca.a2a_may_trigger_next?([r0, r1, r2], s, 't', ids), true) && C27.ck(AtlasPca.a2a_may_trigger_next?([r0], s, 't', ids), false)
  end

  # ================================================ passport.rb =============================================================
  module C27P
    module_function

    NOW = 500_000_000

    def iss = C27.pub('pp-iss')
    def sub = C27.pub('pp-sub')

    def mk(p_over = {}, expv: 1000, pre: nil, sign: true)
      p = { 'model_id' => 'm', 'operator' => 'o', 'hardware_rooted' => false }.merge(p_over)
      fp = { 'd' => 'atlas-pca/passport/v1', 'hardware_rooted' => p['hardware_rooted'], 'operator' => p['operator'] }
      %w[model_id weights_digest system_prompt_digest tool_manifest_digest runtime_measurement].each { |k| fp[k] = p[k] }
      p['id'] = AtlasPca.hash_canonical(fp)
      sp = { 'typ' => 'atlas-pca/passport', 'ver' => 1, 'iss' => iss, 'sub' => sub, 'iat' => 100, 'nbf' => 100, 'exp' => expv, 'passport' => p }
      pre&.call(sp)
      if sign
        body = sp.reject { |k, _| %w[sig pq_sig].include?(k) }
        sp['sig'] = C27.sgn('pp-iss', AtlasPca::PASSPORT_SIG_DOMAIN.b + AtlasPca.canon_bytes(body))
      end
      sp
    end

    def vp(sp, now = 500, trusted = nil, **kw)
      kw = { revoked: ->(*) { false } }.merge(kw)
      AtlasPca.verify_passport(sp, trusted || [iss], now, **kw)
    end

    # a hardware-rooted passport; `ev` is the evidence value (:none = no evidence member)
    def hw(at = NOW, doc = { 'nonce' => 'n1', 'q' => 1 }, ev: nil, p_over: {})
      mk({ 'hardware_rooted' => true }.merge(p_over), expv: 10**12,
         pre: lambda { |sp|
           sp['evidence'] = (ev.nil? ? { 'document' => doc, 'at' => at } : ev) unless ev == :none
         })
    end

    OK_RES = { 'ok' => true, 'bound' => true, 'measured' => { 'model_id' => 'm', 'operator' => 'o' } }.freeze

    def att(res = OK_RES, log = nil)
      lambda do |d, e|
        log << [d, e] if log
        raise 'down' if res == :raise

        res
      end
    end

    class DV
      attr_reader :calls

      def initialize(res)
        @res = res
        @calls = []
      end

      def verify(doc, expected, now)
        @calls << [doc, expected, now]
        @res
      end
    end
  end

  t('c27 passport: passport_int is a safe integer as an Integer, anything else nil') do
    next true unless C27.only?('passport.rb')

    [[5, 5], [2.0, 2], [0, 0], [-3, -3], ['5', nil], [nil, nil], [1.5, nil], [2**60, nil], [Float::NAN, nil], [[], nil], [true, nil]]
      .all? { |input, want| C27.ck(AtlasPca.passport_int(input), want) }
  end

  t('c27 passport: passport_str is the string itself when non-empty, else nil') do
    next true unless C27.only?('passport.rb')

    [['a', 'a'], ['', nil], [nil, nil], [5, nil], [[1], nil], [{}, nil], [:sym, nil], [false, nil], [true, nil]]
      .all? { |input, want| C27.ck(AtlasPca.passport_str(input), want) }
  end

  t('c27 passport: a signed baseline verifies and the shape checks before the signature are exact malformed') do
    next true unless C27.only?('passport.rb')

    mk = C27P.method(:mk)
    vp = C27P.method(:vp)
    pre = ->(&blk) { mk.({}, pre: blk) }
    nosig = mk.().tap { |sp| sp.delete('sig') }
    rows = [
      [mk.(), nil],
      [pre.() { |sp| sp.delete('iss') }, 'malformed'], [pre.() { |sp| sp['iss'] = '' }, 'malformed'],
      [pre.() { |sp| sp.delete('sub') }, 'malformed'], [pre.() { |sp| sp['sub'] = 5 }, 'malformed'],
      [nosig, 'malformed'],
      [pre.() { |sp| sp['passport'].delete('id') }, 'malformed'],
      [pre.() { |sp| sp['passport'].delete('model_id') }, 'malformed'], [pre.() { |sp| sp['passport']['model_id'] = '' }, 'malformed'],
      [pre.() { |sp| sp['passport'].delete('operator') }, 'malformed'],
      [mk.({ 'hardware_rooted' => 'yes' }), 'malformed'], [mk.({ 'hardware_rooted' => nil }), 'malformed'],
      [pre.() { |sp| sp['passport'].delete('hardware_rooted') }, 'malformed'],
      [pre.() { |sp| sp.delete('iat') }, 'malformed'], [pre.() { |sp| sp['iat'] = 'x' }, 'malformed'],
      [pre.() { |sp| sp.delete('nbf') }, 'malformed'], [pre.() { |sp| sp.delete('exp') }, 'malformed'],
      [mk.({}, expv: 100), 'malformed'], [mk.({}, expv: 99), 'malformed'], [mk.({}, expv: 101), 'expired'],
      [pre.() { |sp| sp['typ'] = 'other' }, 'malformed'], [pre.() { |sp| sp['passport'] = [] }, 'malformed'],
      [pre.() { |sp| sp['passport'] = 'x' }, 'malformed'],
      [pre.() { |sp| sp['ver'] = 2 }, 'unsupported_version'], [pre.() { |sp| sp.delete('ver') }, 'unsupported_version'],
      [pre.() { |sp| sp['alg'] = 'nope' }, 'unsupported_suite'],
      [5, 'malformed'], [nil, 'malformed'], [[], 'malformed'], ['x', 'malformed']
    ]
    rows.all? { |sp, want| C27.ck(vp.(sp), want) } &&
      # now_ms must be a safe integer by value
      [nil, 1.5, 2**60, 'x', Float::NAN].all? { |now| C27.ck(vp.(mk.(), now), 'malformed') }
  end

  t('c27 passport: a duck-typed (non-Hash) passport is malformed') do
    next true unless C27.only?('passport.rb')

    good = C27P.mk
    wrong_typ = C27P.mk({}, pre: ->(sp) { sp['typ'] = 'other' })
    C27.ck(C27P.vp(C27::Duck.new(good)), 'malformed') && C27.ck(C27P.vp(wrong_typ), 'malformed') &&
      C27.ck(C27P.vp(C27P.mk({}, pre: ->(sp) { sp['passport'] = C27::Duck.new(sp['passport']) }, sign: false)), 'malformed')
  end

  t('c27 passport: only an Array of issuers can trust') do
    next true unless C27.only?('passport.rb')

    sp = C27P.mk
    iss = C27P.iss
    [[iss, 'unknown_issuer'], [[], 'unknown_issuer'], [{ iss => 1 }, 'unknown_issuer'], [['x', iss], nil]]
      .all? { |trusted, want| C27.ck(C27P.vp(sp, 500, trusted), want) } && C27.ck(AtlasPca.verify_passport(sp, nil, 500, revoked: ->(*) { false }), 'unknown_issuer')
  end

  t('c27 passport: the signed message is the domain bytes plus the canonical body (binary)') do
    next true unless C27.only?('passport.rb')

    seen = []
    sp = C27P.mk
    r = MutationKill::Seam.with(AtlasPca, { verify_suite: ->(*a) { seen << a; false } }) { C27P.vp(sp) }
    body = AtlasPca.canon_bytes(sp.reject { |k, _| %w[sig pq_sig].include?(k) })
    C27.ck(r, 'bad_signature') && seen.length == 1 && seen[0][2].encoding == Encoding::BINARY &&
      seen[0][2] == "atlas-pca/passport-sig/v1\x00".b + body && seen[0][1] == C27P.iss
  end

  t('c27 passport: a canonical-form failure is malformed and a tampered body is a bad signature') do
    next true unless C27.only?('passport.rb')

    weird = C27P.mk({}, pre: ->(sp) { sp['x'] = Object.new }, sign: false).merge('sig' => 'AAAA')
    tampered = C27P.mk.merge('nbf' => 101)
    C27.ck(C27P.vp(weird), 'malformed') && C27.ck(C27P.vp(tampered), 'bad_signature')
  end

  t('c27 passport: an id that cannot be hashed is id_mismatch, a wrong id is id_mismatch') do
    next true unless C27.only?('passport.rb')

    sp = C27P.mk
    wrong = C27P.mk({}, pre: ->(sp2) { sp2['passport']['id'] = 'x' * 43 })
    r = MutationKill::Seam.with(AtlasPca, { hash_canonical: ->(*) { raise 'boom' } }) { C27P.vp(sp) }
    C27.ck(r, 'id_mismatch') && C27.ck(C27P.vp(wrong), 'id_mismatch')
  end

  t('c27 passport: validity window, skew default 0, skew clamped to 60000, subject and revocation') do
    next true unless C27.only?('passport.rb')

    sp = C27P.mk
    vp = C27P.method(:vp)
    sub = C27P.sub
    seen = []
    spy = ->(i, a, b) { seen << [i, a, b]; false }
    [
      [vp.(sp, 99), 'not_yet_valid'], [vp.(sp, 100), nil], [vp.(sp, 999), nil], [vp.(sp, 1000), 'expired'], [vp.(sp, 1001), 'expired'],
      # explicit skew 1000: now + skew < nbf, now - skew >= exp
      [vp.(sp, -900, clock_skew_ms: 1000), nil], [vp.(sp, -901, clock_skew_ms: 1000), 'not_yet_valid'],
      [vp.(sp, 0, clock_skew_ms: 1000), nil], [vp.(sp, 1999, clock_skew_ms: 1000), nil], [vp.(sp, 2000, clock_skew_ms: 1000), 'expired'],
      [vp.(sp, 0, clock_skew_ms: -5), 'not_yet_valid'], [vp.(sp, 99, clock_skew_ms: -5), 'not_yet_valid'], [vp.(sp, 1000, clock_skew_ms: -5), 'expired'],
      # clamp to PASSPORT_MAX_SKEW_MS = 60000
      [vp.(sp, -59_900, clock_skew_ms: 10**9), nil], [vp.(sp, -59_901, clock_skew_ms: 10**9), 'not_yet_valid'],
      [vp.(sp, 60_999, clock_skew_ms: 10**9), nil], [vp.(sp, 61_000, clock_skew_ms: 10**9), 'expired'],
      [vp.(sp, 500, clock_skew_ms: 'x'), 'malformed'],
      [vp.(sp, 500, subject: sub), nil], [vp.(sp, 500, subject: 'someone-else'), 'subject_mismatch'], [vp.(sp, 500), nil],
      [vp.(sp, 500, revoked: nil), 'revocation_unavailable'], [vp.(sp, 500, revoked: ->(*) { raise 'store down' }), 'revocation_unavailable'],
      [vp.(sp, 500, revoked: ->(*) { true }), 'revoked'], [vp.(sp, 500, revoked: ->(*) { 1 }), nil], [vp.(sp, 500, revoked: spy), nil]
    ].all? { |got, want| C27.ck(got, want) } && seen == [[sp['passport']['id'], C27P.iss, sub]]
  end

  t('c27 passport: hardware evidence shape, freshness boundaries and the evidence age default of 24h') do
    next true unless C27.only?('passport.rb')

    n = C27P::NOW
    hw = C27P.method(:hw)
    run = ->(sp, **kw) { C27P.vp(sp, n, attest: C27P.att, **kw) }
    miss = 'hardware_evidence_missing'
    stale = 'hardware_evidence_stale'
    day = 86_400_000
    [
      [run.(hw.()), nil],
      [run.(hw.(ev: :none)), miss], [run.(hw.(ev: [])), miss], [run.(hw.(ev: 'x')), miss], [run.(hw.(ev: {})), miss],
      [run.(hw.(ev: { 'document' => [], 'at' => n })), miss], [run.(hw.(ev: { 'document' => 'str', 'at' => n })), miss],
      [run.(hw.(ev: { 'document' => 5, 'at' => n })), miss], [run.(hw.(ev: { 'document' => nil, 'at' => n })), miss],
      [run.(hw.(ev: { 'document' => { 'nonce' => '' }, 'at' => n })), miss], [run.(hw.(ev: { 'document' => {}, 'at' => n })), miss],
      [run.(hw.(ev: { 'document' => { 'nonce' => 5 }, 'at' => n })), miss],
      [run.(hw.(ev: { 'document' => { 'nonce' => 'n1' } })), miss], [run.(hw.(ev: { 'document' => { 'nonce' => 'n1' }, 'at' => 'x' })), miss],
      [run.(hw.(n - day)), nil], [run.(hw.(n - day - 1)), stale], [run.(hw.(n - day + 1)), nil],
      [run.(hw.(n - 1000), max_evidence_age_ms: 1000), nil], [run.(hw.(n - 1001), max_evidence_age_ms: 1000), stale],
      [run.(hw.(n), max_evidence_age_ms: 0), nil], [run.(hw.(n - 1), max_evidence_age_ms: 0), stale],
      [run.(hw.(n + 5), max_evidence_age_ms: -1, clock_skew_ms: 10), stale],
      [run.(hw.(n + 1)), stale], [run.(hw.(n)), nil],
      [run.(hw.(n + 10), clock_skew_ms: 10), nil], [run.(hw.(n + 11), clock_skew_ms: 10), stale]
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 passport: the vendor verifier is handed the binding and its answer is judged exactly') do
    next true unless C27.only?('passport.rb')

    n = C27P::NOW
    sp = C27P.hw
    pid = sp['passport']['id']
    doc = sp['evidence']['document']
    want_b = { 'holder_pub' => C27P.sub, 'grant_ref' => "passport:#{pid}", 'epoch' => 0, 'nonce' => 'n1' }
    log = []
    ok1 = C27.ck(C27P.vp(sp, n, attest: C27P.att(C27P::OK_RES, log)), nil) && log == [[doc, want_b]]
    sym = { ok: true, bound: true, measured: { model_id: 'm', operator: 'o' } }
    run = ->(res) { C27P.vp(sp, n, attest: C27P.att(res)) }
    fail_ = 'hardware_attestation_failed'
    ident = 'hardware_identity_mismatch'
    base = C27P::OK_RES
    ok2 = [
      [run.(sym), nil], [run.(nil), fail_], [run.(true), fail_], [run.([]), fail_], [run.('x'), fail_], [run.(:raise), fail_],
      [run.(base.merge('bound' => false)), fail_], [run.(base.merge('ok' => false)), fail_], [run.(base.merge('ok' => 'yes')), fail_],
      [run.(base.merge('bound' => 1)), fail_], [run.(base.reject { |k, _| k == 'bound' }), fail_],
      [run.(base.merge('measured' => { 'model_id' => 'z', 'operator' => 'o' })), ident], [run.(base.merge('measured' => [])), ident],
      [run.(base.merge('measured' => 'x')), ident], [run.(base.merge('measured' => nil)), ident]
    ].all? { |got, want| C27.ck(got, want) }
    # default verifier: used when no attest is given, with (document, binding, now_ms); an explicit attest wins
    dv = C27P::DV.new(base)
    r_dv = C27P.vp(sp, n, default_verifier: dv)
    dv2 = C27P::DV.new({})
    r_both = C27P.vp(sp, n, attest: C27P.att, default_verifier: dv2)
    r_none = C27P.vp(sp, n)
    r_bad_dv = C27P.vp(sp, n, default_verifier: C27P::DV.new({ 'ok' => false }))
    ok1 && ok2 && C27.ck(r_dv, nil) && dv.calls == [[doc, want_b, n]] && C27.ck(r_both, nil) && dv2.calls.empty? &&
      C27.ck(r_none, 'hardware_verifier_missing') && C27.ck(r_bad_dv, fail_)
  end

  t('c27 passport: identity_matches compares the claims with the measurement (direct)') do
    next true unless C27.only?('passport.rb')

    f = ->(p, m) { AtlasPca.passport_identity_matches?(p, m) }
    pc = { 'model_id' => 'm', 'operator' => 'o' }
    mc = { 'model_id' => 'm', 'operator' => 'o' }
    [
      [f.(pc, mc), true], [f.(pc, { model_id: 'm', operator: 'o' }), true], [f.(pc, nil), false], [f.(pc, []), false], [f.(pc, 'x'), false],
      [f.({ 'operator' => 'o' }, { 'operator' => 'o' }), false], [f.({ 'model_id' => nil, 'operator' => 'o' }, { 'model_id' => nil, 'operator' => 'o' }), false],
      [f.({ 'model_id' => 'm' }, { 'model_id' => 'm' }), false], [f.(pc, mc.merge('model_id' => 'x')), false],
      [f.(pc, mc.merge('operator' => 'x')), false], [f.({ 'model_id' => 5, 'operator' => 'o' }, { 'model_id' => 5, 'operator' => 'o' }), false],
      [f.(pc.merge('weights_digest' => 'w'), mc), false], [f.(pc.merge('weights_digest' => 'w'), mc.merge('weights_digest' => 'w')), true],
      [f.(pc.merge('weights_digest' => 'w'), mc.merge('weights_digest' => 'x')), false],
      [f.(pc.merge('runtime_measurement' => 'r'), mc), false], [f.(pc.merge('system_prompt_digest' => 's'), mc), false],
      [f.(pc.merge('tool_manifest_digest' => 't'), mc), false], [f.(pc.merge('weights_digest' => nil), mc.merge('weights_digest' => nil)), false],
      [f.(pc, mc.merge('weights_digest' => 'ignored')), true],
      [f.(pc.merge('weights_measured' => true), mc), false], [f.(pc.merge('weights_measured' => true), mc.merge('weights_measured' => true)), true],
      [f.(pc.merge('weights_measured' => true), mc.merge('weights_measured' => 'yes')), false],
      [f.(pc.merge('weights_measured' => false), mc), true], [f.(pc, mc.merge('weights_measured' => true)), true]
    ].all? { |got, want| C27.ck(got, want) }
  end

  # ================================================== mesh.rb ===============================================================
  module C27M
    module_function

    NOW = 1_000_000
    ACTION = { 'type' => 'read', 'resource' => 'doc/1', 'service_domain' => 'svc', 'nonce' => 'n1', 'at' => NOW }.freeze
    CHAIN_OK = ->(*) { [nil, true] }

    def dom = C27.pub('m-dom')
    def rev_root = AtlasPca::IntentV2.bind_root(0, AtlasPca::IntentV2.empty_tree)

    def trust(extra = {})
      { 'humanPrincipal' => 'human', 'witnesses' => [C27.pub('m-w1')], 'threshold' => 1, 'now' => NOW,
        'allowedDomains' => [dom], 'rootDomain' => dom }.merge(extra)
    end

    def head(size, root, over = {})
      { 'domain' => dom, 'root' => root, 'rev_root' => rev_root, 'size' => size, 'rev_size' => 0, 'timestamp' => NOW }.merge(over)
    end

    def cosig(h) = { 'witness' => C27.pub('m-w1'), 'sig' => C27.sgn('m-w1', AtlasPca.mesh_msg(AtlasPca::MESH_COSIG_DOMAIN, h)) }

    def cosigned(h, cosigs = nil)
      { 'head' => h, 'sig' => C27.sgn('m-dom', AtlasPca.mesh_msg(AtlasPca::MESH_HEAD_DOMAIN, h)), 'cosigs' => cosigs || [cosig(h)] }
    end

    def cap(i, over = {})
      { 'id' => "cap#{i}", 'issuer' => C27.pub("m-iss#{i}"), 'holder' => C27.pub("m-h#{i}"), 'caveats' => [],
        'parent' => i.zero? ? nil : "cap#{i - 1}" }.merge(over)
    end

    def bind(c)
      body = { 'agent' => c['issuer'], 'domain' => dom, 'role' => 'r' }
      body.merge('sig' => C27.sgn('m-dom', AtlasPca.mesh_msg(AtlasPca::MESH_BINDING_DOMAIN, body)))
    end

    # A proof of caps issued under one domain, one head covering all of them, an empty revocation set, signed by the tip holder.
    # heads: a lambda ch -> heads array; hop_head: the head index each hop names.
    def proof(caps, head_over: {}, heads: nil, hop_head: nil)
      lhs = caps.map { |c| AtlasPca.leaf_hash(AtlasPca.cap_hash(c)) }
      ch = cosigned(head(caps.length, AtlasPca.b64e(AtlasPca.build(lhs)), head_over))
      hops = caps.each_with_index.map do |c, i|
        h = { 'domain' => dom, 'head' => (hop_head ? hop_head[i] : 0), 'inclusion' => C27T.incl(lhs, i),
              'revocation' => { 'cap' => { 'size' => 0 }, 'issuer_key' => { 'size' => 0 } } }
        h['binding'] = bind(c) if i.positive?
        h
      end
      tip = caps[-1]
      am = AtlasPca.mesh_msg(AtlasPca::MESH_ACTION_DOMAIN, { 'action' => ACTION, 'tip' => AtlasPca.cap_hash(tip) })
      { 'chain' => caps, 'hops' => hops, 'heads' => (heads ? heads.call(ch) : [ch]), 'rev_leaves' => [], 'action' => ACTION,
        'action_sig' => C27.sgn("m-h#{caps.length - 1}", am) }
    end

    def vd(v) = v.respond_to?(:ok) ? [v.ok, v.reason, v.hop] : v
    def run(pf, tr = trust) = AtlasPca.verify_mesh_proof(pf, tr)

    def with_chain(extra = {}, &blk)
      MutationKill::Seam.with(AtlasPca, { :verify_chain => CHAIN_OK }.merge(extra), &blk)
    end

    def ea(over = {})
      { 'actions' => nil, 'prefixes' => [], 'max_amount' => nil, 'expires_at' => nil, 'audience' => nil, 'max_hops' => nil }.merge(over)
    end
  end

  t('c27 mesh: mesh_num? is a finite JSON number') do
    next true unless C27.only?('mesh.rb')

    [[1, true], [1.5, true], [0, true], [-1, true], [-0.5, true], [Float::NAN, false], [Float::INFINITY, false], [-Float::INFINITY, false],
     ['1', false], [nil, false], [true, false], [[], false]].all? { |x, want| C27.ck(AtlasPca.mesh_num?(x), want) }
  end

  t('c27 mesh: mesh_truthy? follows JS truthiness exactly') do
    next true unless C27.only?('mesh.rb')

    [[nil, false], [false, false], [0, false], [0.0, false], [-0.0, false], [Float::NAN, false], [1, true], [-1, true], [0.5, true],
     ['', false], ['a', true], [[], true], [{}, true], [true, true]].all? { |x, want| C27.ck(AtlasPca.mesh_truthy?(x), want) }
  end

  t('c27 mesh: validators (consistency, inclusion) enforce shape and the 128 path bound') do
    next true unless C27.only?('mesh.rb')

    okc = { 'oldSize' => 1, 'newSize' => 2, 'path' => [] }
    oki = { 'index' => 0, 'size' => 1, 'path' => [] }
    vc = ->(x) { AtlasPca.mesh_valid_consistency(x) }
    vi = ->(x) { AtlasPca.mesh_valid_inclusion(x) }
    [
      [vc.(okc), okc], [vc.(nil), nil], [vc.([]), nil], [vc.(okc.merge('oldSize' => -1)), nil], [vc.(okc.merge('oldSize' => 'x')), nil],
      [vc.(okc.merge('newSize' => 'x')), nil], [vc.(okc.merge('newSize' => 1.5)), nil], [vc.({ 'oldSize' => 1, 'newSize' => 2 }), nil],
      [vc.(okc.merge('path' => {})), nil], [vc.(okc.merge('path' => 'ab')), nil], [vc.(okc.merge('path' => nil)), nil],
      [vc.(okc.merge('path' => [5])), nil], [vc.(okc.merge('path' => ['a'] * 128)), okc.merge('path' => ['a'] * 128)],
      [vc.(okc.merge('path' => ['a'] * 129)), nil],
      [vi.(oki), oki], [vi.(nil), nil], [vi.(oki.merge('index' => -1)), nil], [vi.(oki.merge('size' => 'x')), nil], [vi.(oki.merge('path' => nil)), nil],
      [vi.(oki.merge('path' => 'ab')), nil], [vi.(oki.merge('path' => [1] * 128)), oki.merge('path' => [1] * 128)],
      [vi.(oki.merge('path' => [1] * 129)), nil]
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 mesh: mesh_effective returns the full authority hash or the exact refusal') do
    next true unless C27.only?('mesh.rb')

    e = C27M.method(:ea)
    f = ->(c) { AtlasPca.mesh_effective(c) }
    mp = [nil, 'malformed proof']
    [
      [f.([]), [e.(), nil]],
      [f.([{ 'type' => 'scope', 'actions' => %w[b a] }, { 'type' => 'audience', 'domains' => ['d'] }, { 'type' => 'max_hops', 'n' => 3 },
           { 'type' => 'max_amount', 'max' => 5 }, { 'type' => 'expires', 'at' => 9 }, { 'type' => 'resource', 'prefix' => 'p' }]),
       [e.('actions' => %w[a b], 'audience' => ['d'], 'max_hops' => 3, 'max_amount' => 5, 'expires_at' => 9, 'prefixes' => ['p']), nil]],
      [f.(nil), mp], [f.({}), mp], [f.('x'), mp], [f.(5), mp],
      [f.([5]), mp], [f.(['x']), mp], [f.([nil]), mp], [f.([[]]), mp],
      [f.([{}]), [nil, 'unknown caveat type "undefined" (fail closed)']], [f.([{ 'type' => 'zz' }]), [nil, 'unknown caveat type "zz" (fail closed)']],
      [f.([{ 'type' => nil }]), [nil, 'unknown caveat type "null" (fail closed)']],
      [f.([{ 'type' => 'scope', 'actions' => 'a' }]), [nil, 'malformed scope caveat']],
      [f.([{ 'type' => 'audience', 'domains' => [1] }]), [nil, 'malformed audience caveat']],
      [f.([{ 'type' => 'max_hops', 'n' => 'x' }]), [nil, 'malformed max_hops caveat']],
      [f.([{ 'type' => 'max_amount', 'max' => 'x' }]), [nil, 'malformed max_amount caveat']]
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 mesh: mesh_narrows? decides each dimension, false exactly') do
    next true unless C27.only?('mesh.rb')

    e = C27M.method(:ea)
    nar = ->(c, p) { AtlasPca.mesh_narrows?(c, p) }
    num = lambda do |k|
      [[nar.(e.(), e.(k => 10)), false], [nar.(e.(k => 11), e.(k => 10)), false], [nar.(e.(k => 10), e.(k => 10)), true],
       [nar.(e.(k => 9), e.(k => 10)), true], [nar.(e.(k => 1), e.()), true]]
    end
    rows = [
      [nar.(e.(), e.('actions' => %w[a b])), false], [nar.(e.('actions' => ['a']), e.('actions' => %w[a b])), true],
      [nar.(e.('actions' => ['c']), e.('actions' => %w[a b])), false], [nar.(e.('actions' => %w[a b]), e.('actions' => %w[a b])), true],
      [nar.(e.(), e.('audience' => %w[d e])), false], [nar.(e.('audience' => ['d']), e.('audience' => %w[d e])), true],
      [nar.(e.('audience' => ['z']), e.('audience' => %w[d e])), false],
      [nar.(e.(), e.()), true], [nar.(e.('prefixes' => %w[p q]), e.('prefixes' => ['p'])), true], [nar.(e.('prefixes' => []), e.('prefixes' => ['p'])), false]
    ] + num.('max_amount') + num.('expires_at') + num.('max_hops')
    rows.all? { |got, want| C27.ck(got, want) }
  end

  t('c27 mesh: mesh_admits compares prefixes as bytes (non-ASCII) and reports the exact reason') do
    next true unless C27.only?('mesh.rb')

    e = C27M.method(:ea)
    act = { 'type' => 't', 'resource' => "é/x", 'service_domain' => 's' }
    adm = ->(ea, a = act, now = 5, len = 1) { AtlasPca.mesh_admits(ea, a, now, len) }
    [
      [adm.(e.('prefixes' => ['é'])), nil], [adm.(e.('prefixes' => ['q'])), "resource \"é/x\" outside prefix \"q\""],
      [adm.(e.('actions' => ['u'])), 'action "t" not in scope'], [adm.(e.('max_amount' => 3)), 'amount exceeds ceiling 3'],
      [adm.(e.('max_amount' => 3), act.merge('amount' => 4)), 'amount exceeds ceiling 3'], [adm.(e.('max_amount' => 3), act.merge('amount' => 3)), nil],
      [adm.(e.('expires_at' => 4)), 'capability expired'], [adm.(e.('expires_at' => 5)), nil],
      [adm.(e.('audience' => ['x'])), 'service domain not in audience'], [adm.(e.('max_hops' => 1), act, 5, 2), 'chain exceeds max_hops 1']
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 mesh: mesh_valid_trust keeps string pq pins only and the defaults') do
    next true unless C27.only?('mesh.rb')

    v = ->(extra) { AtlasPca.mesh_valid_trust(C27M.trust(extra)) }
    base = v.({})
    C27.ck(v.('pqPins' => { 'a' => 'x', 'b' => 5 })['pq_pins'], { 'a' => 'x' }) && !base.key?('pq_pins') &&
      !v.('pqPins' => []).key?('pq_pins') && !v.('pqPins' => 'zz').key?('pq_pins') && !v.('pqPins' => nil).key?('pq_pins') &&
      C27.ck(base['max_head_age'], 300_000) && C27.ck(base['max_skew'], 60_000) && C27.ck(base['max_chain'], 64) &&
      C27.ck(v.('maxActionAgeMs' => 7)['max_action_age'], 7) &&
      C27.ck(v.('maxActionAgeMs' => -1), 'invalid trust configuration: maxActionAgeMs')
  end

  t('c27 mesh: expand_nm only takes natural sizes and in-range leaf indexes') do
    next true unless C27.only?('mesh.rb')

    lv = %w[L0 L1]
    x = ->(c) { AtlasPca.mesh_expand_nm(c, lv) }
    [
      [x.({ 'size' => 0 }), { 'size' => 0 }], [x.({ 'size' => 2, 'lo' => 0 }), { 'size' => 2, 'lo' => 'L0' }],
      [x.({ 'size' => 2, 'lo' => 0, 'hi' => 1 }), { 'size' => 2, 'lo' => 'L0', 'hi' => 'L1' }],
      [x.({ 'size' => -1 }), nil], [x.({ 'size' => 'x' }), nil], [x.(nil), nil], [x.([]), nil], [x.({}), nil],
      [x.({ 'size' => 2, 'lo' => 2 }), nil], [x.({ 'size' => 2, 'hi' => 2 }), nil], [x.({ 'size' => 2, 'lo' => -1 }), nil],
      [x.({ 'size' => 2, 'lo' => 'x' }), nil], [x.({ 'size' => 2, 'lo' => 1.5 }), nil]
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 mesh: leaf proofs are bound to size, index and side (direct)') do
    next true unless C27.only?('mesh.rb')

    ids = %w[a b c]
    lhs = C27T.lh(ids)
    ib = AtlasPca::IntentV2
    root = ib.bind_root(3, AtlasPca.b64e(AtlasPca.build(lhs)))
    lo = ->(root_, size, id, pf) { AtlasPca.mesh_leaf_ok?(root_, size, id, pf) }
    pf = ->(i) { C27T.incl(lhs, i) }
    good = (0..2).all? { |i| C27.ck(lo.(root, 3, ids[i], pf.(i)), true) }
    p1 = pf.(1)
    step0 = p1['path'][0]
    swapped = p1.merge('path' => [step0.merge('side' => step0['side'] == 'L' ? 'R' : 'L')] + p1['path'][1..])
    sib = AtlasPca.sha('sib')
    forged_root = ib.bind_root(3, AtlasPca.b64e(AtlasPca.node_hash(sib, AtlasPca.leaf_hash('c'))))
    forged = { 'size' => 3, 'index' => 3, 'path' => [{ 'side' => 'L', 'hash' => AtlasPca.b64e(sib) }] }
    one = C27T.lh(['a'])
    root1 = ib.bind_root(1, AtlasPca.b64e(one[0]))
    root2_leaf_only = ib.bind_root(2, AtlasPca.b64e(AtlasPca.leaf_hash('a')))
    float_ok = C27.ck(lo.(root, 3.0, 'b', p1.merge('size' => 3.0)), true)
    good && float_ok && [
      [lo.(root, 3, 'b', p1.merge('size' => 4)), false], [lo.(root, 3, 'b', p1.merge('size' => '3')), false],
      [lo.(root, 3, 'b', p1.merge('index' => -1)), false], [lo.(root, 3, 'b', p1.merge('index' => 1.5)), false],
      [lo.(root, 3, 'b', p1.merge('index' => 3)), false], [lo.(root, 3, 'b', p1.merge('index' => 2)), false],
      [lo.(root, 'x', 'b', { 'size' => 'x', 'index' => 0, 'path' => [] }), false],
      [lo.(root, 3, 'b', p1.merge('index' => 'x')), false], [lo.(root, 3, 'b', p1.merge('index' => nil)), false],
      [lo.(forged_root, 3, 'c', forged), false],
      [lo.(root1, 1, 'a', { 'size' => 1, 'index' => 0, 'path' => {} }), false], [lo.(root1, 1, 'a', { 'size' => 1, 'index' => 0, 'path' => [] }), true],
      [lo.(root2_leaf_only, 2, 'a', { 'size' => 2, 'index' => 0, 'path' => [] }), false],
      [lo.(root, 3, 'b', p1.merge('path' => [])), false], [lo.(root, 3, 'b', p1.merge('path' => nil)), false],
      [lo.(root, 3, 'b', p1.merge('path' => [nil] * p1['path'].length)), false], [lo.(root, 3, 'b', swapped), false],
      [lo.(root, 3, 'b', p1.merge('path' => [[1]] * p1['path'].length)), false],
      [lo.(root, 3, 'b', p1.merge('path' => [step0.merge('hash' => 5)] + p1['path'][1..])), false],
      [lo.(root, 3, 'b', p1.merge('path' => [step0.merge('hash' => nil)] + p1['path'][1..])), false],
      [lo.(root, 3, 'b', p1.merge('path' => [step0.merge('hash' => 'AAAA')] + p1['path'][1..])), false],
      [lo.(root, 3, 'z', p1), false], [lo.('wrong', 3, 'b', p1), false],
      [lo.(root, 3, 'b', p1.merge('path' => p1['path'] + p1['path'])), false]
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 mesh: non-membership needs adjacent neighbours, a zero size only for the empty set') do
    next true unless C27.only?('mesh.rb')

    ib = AtlasPca::IntentV2
    ids = %w[b d f]
    lhs = C27T.lh(ids)
    root = ib.bind_root(3, AtlasPca.b64e(AtlasPca.build(lhs)))
    ent = ->(i) { { 'id' => ids[i], 'proof' => C27T.incl(lhs, i) } }
    nm = ->(r, x, id) { AtlasPca.mesh_non_membership?(r, x, id) }
    r0 = ib.bind_root(0, ib.empty_tree)
    lhs2 = C27T.lh([''])
    root2 = ib.bind_root(1, AtlasPca.b64e(AtlasPca.build(lhs2)))
    pf2 = C27T.incl(lhs2, 0)
    [
      [nm.(root, { 'size' => 3, 'lo' => ent.(0), 'hi' => ent.(1) }, 'c'), true], [nm.(root, { 'size' => 3, 'hi' => ent.(0) }, 'a'), true],
      [nm.(root, { 'size' => 3, 'lo' => ent.(2) }, 'z'), true],
      [nm.(root, { 'size' => 3, 'lo' => ent.(0), 'hi' => ent.(2) }, 'c'), false], [nm.(root, { 'size' => 3, 'lo' => ent.(0) }, 'c'), false],
      [nm.(root, { 'size' => 3, 'hi' => ent.(1) }, 'a'), false], [nm.(root, { 'size' => 3, 'lo' => ent.(1) }, 'c'), false],
      [nm.(root, { 'size' => 3, 'lo' => ent.(0) }, 'b'), false], [nm.('wrong', { 'size' => 3, 'lo' => ent.(2) }, 'z'), false],
      [nm.(root, { 'size' => 3 }, 'c'), false], [nm.(root, { 'size' => -1, 'lo' => ent.(2) }, 'z'), false],
      [nm.(root, { 'size' => 'x', 'lo' => ent.(2) }, 'z'), false], [nm.(root, { 'size' => 3, 'lo' => { 'id' => 'b', 'proof' => nil } }, 'c'), false],
      [nm.(root, { 'size' => 3, 'lo' => 5 }, 'c'), false],
      [nm.(r0, { 'size' => 0 }, 'x'), true], [nm.(r0, { 'size' => -0.0 }, 'x'), false], [nm.('wrong', { 'size' => 0 }, 'x'), false],
      [nm.(r0, { 'size' => 0, 'lo' => ent.(0) }, 'x'), false], [nm.(r0, { 'size' => 0, 'hi' => ent.(0) }, 'x'), false],
      [nm.(r0, { 'size' => 0, 'lo' => ent.(0), 'hi' => ent.(1) }, 'x'), false],
      # a leaf id that is not a String is read as '' (the empty id), exactly
      [nm.(root2, { 'size' => 1, 'lo' => { 'id' => 5, 'proof' => pf2 } }, 'a'), true],
      [nm.(root2, { 'size' => 1, 'lo' => { 'proof' => pf2 } }, 'a'), true],
      [nm.(root2, { 'size' => 1, 'hi' => { 'id' => 5, 'proof' => pf2 } }, 'a'), false]
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 mesh: consistency proofs verify for every (old,new) up to 12 leaves, bounded by a deadline') do
    next true unless C27.only?('mesh.rb')

    Timeout.timeout(2) do
      hs = (0...12).map { |i| AtlasPca.leaf_hash("c27-leaf-#{i}") }
      ok = true
      (1..12).each do |n|
        (1..n).each do |m|
          pf = { 'oldSize' => m, 'newSize' => n, 'path' => C27T.cproof(hs[0, n], m) }
          old = AtlasPca.b64e(AtlasPca.build(hs[0, m]))
          nw = AtlasPca.b64e(AtlasPca.build(hs[0, n]))
          ok &&= C27.ck(AtlasPca.mesh_consistency?(old, nw, pf), true)
          ok &&= C27.ck(AtlasPca.mesh_consistency?(nw, old, pf), false) if m < n
        end
      end
      ok
    end
  end

  t('c27 mesh: consistency refusals are exact (sizes, empty tree, extra and missing path steps)') do
    next true unless C27.only?('mesh.rb')

    Timeout.timeout(2) do
      ib = AtlasPca::IntentV2
      empty = ib.empty_tree
      hs = (0...4).map { |i| AtlasPca.leaf_hash("c27-leaf-#{i}") }
      mc = ->(o, n, pf) { AtlasPca.mesh_consistency?(o, n, pf) }
      pfz = ->(a, b, path = []) { { 'oldSize' => a, 'newSize' => b, 'path' => path } }
      x = AtlasPca.b64e(AtlasPca.sha('x'))
      r3 = AtlasPca.b64e(AtlasPca.build(hs[0, 3]))
      r4 = AtlasPca.b64e(AtlasPca.build(hs[0, 4]))
      cp = C27T.cproof(hs, 3)
      sb = C27T.sub(3, hs, true)
      d = AtlasPca.sha('d')
      extra_old = AtlasPca.b64e(AtlasPca.node_hash(d, AtlasPca.build(hs[0, 3])))
      extra_new = AtlasPca.b64e(AtlasPca.node_hash(d, AtlasPca.build(hs)))
      trunc_old = AtlasPca.b64e(sb[0])
      trunc_new = AtlasPca.b64e(AtlasPca.node_hash(sb[0], sb[1]))
      [
        [mc.(empty, empty, pfz.(0, 0)), true], [mc.(empty, r4, pfz.(0, 4)), true], [mc.(empty, x, pfz.(0, 0)), false],
        [mc.('zzz', r4, pfz.(0, 3)), false], [mc.(empty, r4, pfz.(0, 3, [x])), false], [mc.('zzz', empty, pfz.(0, 0)), false],
        [mc.(x, x, pfz.(3, 3)), true], [mc.(x, x, { 'oldSize' => 3, 'newSize' => 3 }), true], [mc.(x, x, pfz.(3, 3, 'abc')), true],
        [mc.(x, x, pfz.(3, 3, [x])), false], [mc.(x, r4, pfz.(3, 3)), false],
        [mc.(x, x, pfz.(-1, 1, [x])), false], [mc.(x, x, pfz.(2, 1)), false], [mc.(x, x, pfz.(3, 2)), false],
        [mc.(r3, r4, pfz.(1.5, 4, cp)), false], [mc.(r3, r4, pfz.(3, 'x', cp)), false], [mc.(r3, r4, pfz.('3', 4, cp)), false],
        [mc.(r3, r4, pfz.(3, '4', cp)), false], [mc.(r3, r4, pfz.(nil, 4, cp)), false],
        [mc.(r3, r4, pfz.(3.0, 4, cp)), true], [mc.(r3, r4, pfz.(3, 4.0, cp)), true], [mc.(r3, r4, pfz.(3, 4, cp)), true],
        [mc.(r3, r4, pfz.(3, 4, [])), false], [mc.(r3, r4, pfz.(3, 4, cp + [AtlasPca.b64e(d)])), false],
        [mc.(extra_old, extra_new, pfz.(3, 4, cp + [AtlasPca.b64e(d)])), false],
        [mc.(trunc_old, trunc_new, pfz.(3, 4, cp[0, 2])), false],
        [mc.(x, r4, pfz.(3, 4, cp)), false], [mc.(r3, x, pfz.(3, 4, cp)), false],
        [mc.(r3, r4, pfz.(3, 4, [5] + cp[1..])), false], [mc.(r3, r4, pfz.(3, 4, ['AAAA'] + cp[1..])), false],
        [mc.(5, r4, pfz.(2, 3, [AtlasPca.b64e(sb[0])])), false], [mc.(nil, r4, pfz.(2, 3, [x])), false],
        [mc.(r3, r4, pfz.(3, 4, [x] * 129)), false], [mc.(r3, r4, pfz.(3, 4, [x] * 128)), false]
      ].all? { |got, want| C27.ck(got, want) }
    end
  end

  t('c27 mesh: a cosigned head is judged against its domain, signatures, witnesses and the 256 cosig bound') do
    next true unless C27.only?('mesh.rb')

    tr = AtlasPca.mesh_valid_trust(C27M.trust)
    dom = C27M.dom
    h = C27M.head(1, AtlasPca.b64e(AtlasPca.sha('r')))
    ch = ->(cosigs = nil) { C27M.cosigned(h, cosigs) }
    f = ->(c, d = dom) { AtlasPca.mesh_check_cosigned_head(c, d, tr, nil) }
    diff = 'head is for a different domain'
    cs = C27M.cosig(h)
    none = 'head has 0/1 trusted witness cosignatures'
    [
      [f.(ch.()), nil], [f.(ch.(), 'other'), diff], [f.({}), diff], [f.(nil), diff], [f.({ 'head' => 5 }), diff], [f.({ 'head' => h }), 'malformed head'],
      [f.(ch.().merge('sig' => 5)), 'malformed head'], [f.(ch.().merge('sig' => 'AAAA')), 'head not signed by its domain key'],
      [f.(ch.().merge('cosigs' => 'x')), 'malformed head'], [f.(ch.().merge('cosigs' => nil)), 'malformed head'],
      [f.(ch.([cs] + [nil] * 255)), nil], [f.(ch.([cs] + [nil] * 256)), 'malformed head'],
      [f.(ch.([])), none], [f.(ch.([{ 'witness' => 5, 'sig' => cs['sig'] }])), none],
      [f.(ch.([{ 'witness' => cs['witness'], 'sig' => 'AAAA' }])), none],
      [f.(ch.([cs, cs])), nil]
    ].all? { |got, want| C27.ck(got, want) }
  end

  t('c27 mesh: a duplicate cosignature is verified once (the second copy is skipped)') do
    next true unless C27.only?('mesh.rb')

    tr = AtlasPca.mesh_valid_trust(C27M.trust)
    h = C27M.head(1, AtlasPca.b64e(AtlasPca.sha('r')))
    cs = C27M.cosig(h)
    orig = AtlasPca.method(:verify_b64u)
    count = 0
    spy = ->(*a) { count += 1; orig.call(*a) }
    r = MutationKill::Seam.with(AtlasPca, { verify_b64u: spy }) do
      AtlasPca.mesh_check_cosigned_head(C27M.cosigned(h, [cs, cs]), C27M.dom, tr, nil)
    end
    C27.ck(r, nil) && count == 2
  end

  t('c27 mesh: pin proofs, chain bounds and a non-Hash proof are exact refusals') do
    next true unless C27.only?('mesh.rb')

    pp = { 'domain' => 'd', 'proof' => { 'oldSize' => 0, 'newSize' => 0, 'path' => [] } }
    base = { 'chain' => [], 'hops' => [], 'heads' => [], 'rev_leaves' => [], 'action' => C27M::ACTION, 'action_sig' => 's' }
    r = ->(extra) { C27M.vd(C27M.run(base.merge(extra))) }
    bounds = [false, 'chain length out of bounds', -1]
    bad_pin = [false, 'malformed pin proofs', -1]
    mal = [false, 'malformed proof', -1]
    rows = [
      [r.('pin_proofs' => [pp] * 256), bounds], [r.('pin_proofs' => [pp] * 257), bad_pin], [r.('pin_proofs' => []), bounds],
      [r.('pin_proofs' => {}), bad_pin], [r.('pin_proofs' => nil), bad_pin], [r.('pin_proofs' => [nil]), bad_pin], [r.('pin_proofs' => [5]), bad_pin],
      [r.('pin_proofs' => [[]]), bad_pin], [r.('pin_proofs' => [pp.merge('domain' => 5)]), bad_pin],
      [r.('pin_proofs' => [pp.reject { |k, _| k == 'domain' }]), bad_pin],
      [r.('pin_proofs' => [pp.merge('proof' => {})]), bad_pin], [r.('pin_proofs' => [pp.merge('proof' => nil)]), bad_pin],
      [r.({}), bounds], [r.('chain' => [{}] * 65), bounds],
      # the proof must be a Hash (a look-alike is refused)
      [C27M.vd(C27M.run(C27::Duck.new(base))), mal],
      [C27M.vd(C27M.run(nil)), mal], [C27M.vd(C27M.run([])), mal], [C27M.vd(C27M.run('x')), mal],
      [C27M.vd(C27M.run(base.merge('chain' => nil))), mal],
      [C27M.vd(C27M.run(base.merge('action_sig' => 5))), [false, 'malformed action', -1]],
      [C27M.vd(C27M.run(base, nil)), [false, 'invalid trust configuration', -1]]
    ]
    chain64 = C27M.with_chain({ :verify_chain => ->(*) { ['why', false] } }) { C27M.vd(C27M.run(base.merge('chain' => [{}] * 64))) }
    rows.all? { |got, want| C27.ck(got, want) } && C27.ck(chain64, [false, 'chain: why', -1])
  end

  t('c27 mesh: the chain verifier is handed the human principal, the issuer flag and the string pq pins only') do
    next true unless C27.only?('mesh.rb')

    seen = []
    base = { 'chain' => [{}], 'hops' => [], 'heads' => [], 'rev_leaves' => [], 'action' => C27M::ACTION, 'action_sig' => 's' }
    stub = ->(*a) { seen << a; ['why', false] }
    v = C27M.with_chain({ :verify_chain => stub }) { C27M.vd(C27M.run(base, C27M.trust('pqPins' => { 'a' => 'x', 'b' => 5 }))) }
    C27.ck(v, [false, 'chain: why', -1]) && seen.length == 1 && seen[0][0] == base['chain'] && C27.ck(seen[0][1], 'human') &&
      C27.ck(seen[0][2], true) && C27.ck(seen[0][3], nil) && C27.ck(seen[0][4], { 'a' => 'x' }) && C27.ck(seen[0][5], nil)
  end

  t('c27 mesh: a two-hop proof verifies; the head is checked once per distinct index; no pin proof is passed as nil') do
    next true unless C27.only?('mesh.rb')

    orig = AtlasPca.method(:mesh_check_cosigned_head)
    caps = [C27M.cap(0), C27M.cap(1)]
    calls = []
    spy = ->(*a) { calls << a; orig.call(*a) }
    v = C27M.with_chain({ :mesh_check_cosigned_head => spy }) { C27M.vd(C27M.run(C27M.proof(caps))) }
    ok1 = C27.ck(v, [true, nil, -1]) && calls.length == 1 && calls[0][3].equal?(nil) && calls[0][1] == C27M.dom
    calls2 = []
    spy2 = ->(*a) { calls2 << a; orig.call(*a) }
    v2 = C27M.with_chain({ :mesh_check_cosigned_head => spy2 }) do
      C27M.vd(C27M.run(C27M.proof(caps, heads: ->(ch) { [ch, ch] }, hop_head: [0, 0.0])))
    end
    ok1 && C27.ck(v2, [true, nil, -1]) && calls2.length == 1
  end

  t('c27 mesh: a hop that widens authority, a head of another size, and an unknown head shape are refused exactly') do
    next true unless C27.only?('mesh.rb')

    widen = [C27M.cap(0, 'caveats' => [{ 'type' => 'scope', 'actions' => ['a'] }]), C27M.cap(1)]
    w = C27M.with_chain { C27M.vd(C27M.run(C27M.proof(widen))) }
    narrow = [C27M.cap(0, 'caveats' => [{ 'type' => 'scope', 'actions' => %w[a read] }]),
              C27M.cap(1, 'caveats' => [{ 'type' => 'scope', 'actions' => ['read'] }])]
    n = C27M.with_chain { C27M.vd(C27M.run(C27M.proof(narrow))) }
    sized = C27M.with_chain { C27M.vd(C27M.run(C27M.proof([C27M.cap(0)], head_over: { 'size' => 2 }))) }
    strange = C27M.with_chain { C27M.vd(C27M.run(C27M.proof([C27M.cap(0)], heads: ->(_ch) { ['xheadx'] }))) }
    nohead = C27M.with_chain { C27M.vd(C27M.run(C27M.proof([C27M.cap(0)], heads: ->(_ch) { [{}] }))) }
    C27.ck(w, [false, 'hop widens authority', 1]) && C27.ck(n, [true, nil, -1]) &&
      C27.ck(sized, [false, 'hop not included in the issuing domain log', 0]) &&
      C27.ck(strange, [false, 'malformed proof', -1]) && C27.ck(nohead, [false, 'malformed proof', -1])
  end

  t('c27 mesh: a non-String id or issuer is read as the empty string for the revocation checks') do
    next true unless C27.only?('mesh.rb')

    ids = []
    stub = ->(_root, _nm, id) { ids << id; true }
    cap = C27M.cap(0, 'id' => 5, 'issuer' => 7)
    v = C27M.with_chain({ :mesh_non_membership? => stub }) { C27M.vd(C27M.run(C27M.proof([cap]))) }
    ids2 = []
    stub2 = ->(_root, _nm, id) { ids2 << id; true }
    v2 = C27M.with_chain({ :mesh_non_membership? => stub2 }) { C27M.vd(C27M.run(C27M.proof([C27M.cap(0)]))) }
    C27.ck(v, [true, nil, -1]) && ids == ['', 'key:'] && C27.ck(v2, [true, nil, -1]) && ids2 == ['cap0', "key:#{C27M.cap(0)['issuer']}"]
  end
end
