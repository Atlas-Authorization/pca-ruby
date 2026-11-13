# frozen_string_literal: true

# c31: exact-outcome kill tests for lib/atlas_pca/{ledger,revocation_staleness,obligations,fresh_at,provenance_gate}.rb.
# Every AtlasPca constant / function is resolved at CALL time inside each test block (the oracle re-evaluates AtlasPca per
# mutant). Seams (Seam.with) pin guards that a later check or rescue would otherwise mask. Merkle trees are built here
# from RFC 9162 (independent of the code under test) and the verifiers are swept over every small (old, new) / (index, size).
require 'timeout'
require 'digest'
require 'openssl'

module MutationKill
  module C31Kill
    module_function

    # A test of this file costs little, but under the mutation oracle it only matters while one of ITS lib files is mutated.
    def skip?(*files)
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !files.include?(f)
    end

    class Duck # answers [] like a Hash but is not one
      def initialize(hash)
        @h = hash
      end

      def [](key)
        @h[key]
      end
    end

    class Chain # Enumerable that is not an Array
      include Enumerable
      def initialize(items)
        @a = items
      end

      def each(&blk)
        @a.each(&blk)
      end

      def empty?
        false
      end
    end

    # ---------------------------------------------------------------- crypto / tokens
    def key(seed)
      OpenSSL::PKey.new_raw_private_key('ED25519', [seed].pack('C') * 32)
    end

    def ka
      @ka ||= key(0x31)
    end

    def kb
      @kb ||= key(0x32)
    end

    def pub(k)
      AtlasPca.b64e(k.raw_public_key)
    end

    FA_DOMAIN = "atlas-pca/fresh-at/v1\x00".b

    # A fresh_at token signed over DOMAIN || canonical(body); `over` replaces members BEFORE signing.
    def fa_token(over = {}, signing = nil)
      body = { 'v' => 1, 'scope' => 'scope-1', 'policy_digest' => 'pd-1', 'issued_at' => 1_000_000, 'signer' => pub(ka),
               'revocation_epoch' => 5, 'ledger_tree_size' => 6, 'budget_version' => 7, 'policy_revision' => 8 }.merge(over)
      body.merge('sig' => AtlasPca.b64e((signing || ka).sign(nil, FA_DOMAIN + AtlasPca.canon_bytes(body))))
    end

    def fa_local(over = {})
      { 'revocation_epoch' => 5, 'ledger_tree_size' => 6, 'budget_version' => 7, 'policy_revision' => 8, 'policy_digest' => 'pd-1' }.merge(over)
    end

    def fa_wire(over = {})
      { 'v' => 1, 'scope' => 's', 'policy_digest' => 'd', 'issued_at' => 1, 'revocation_epoch' => 0, 'ledger_tree_size' => 0,
        'budget_version' => 0, 'policy_revision' => 0, 'signer' => pub(ka), 'sig' => 'A' * 86 }.merge(over)
    end

    # ---------------------------------------------------------------- RFC 9162 trees over leaves "leaf-0", "leaf-1", ...
    def sha(bin)
      Digest::SHA256.digest(bin)
    end

    def lh(i)
      (@lh ||= {})[i] ||= sha("\x00".b + "leaf-#{i}".b)
    end

    def nh(l, r)
      sha("\x01".b + l + r)
    end

    def split(n) # the largest power of two strictly below n
      k = 1
      k <<= 1 while (k << 1) < n
      k
    end

    def mth(a, b) # MTH over leaves a...b
      @mc ||= {}
      @mc[[a, b]] ||= if b - a == 1
                        lh(a)
                      else
                        k = split(b - a)
                        nh(mth(a, a + k), mth(a + k, b))
                      end
    end

    def incl(i, a, b) # PATH(i, D[a:b]), leaf level first
      return [] if b - a == 1

      k = split(b - a)
      if i < k
        incl(i, a, a + k) + [mth(a + k, b)]
      else
        incl(i - k, a + k, b) + [mth(a, a + k)]
      end
    end

    def sub(m, a, b, flag) # SUBPROOF(m, D[a:b], flag)
      n = b - a
      return(flag ? [] : [mth(a, b)]) if m == n

      k = split(n)
      if m <= k
        sub(m, a, a + k, flag) + [mth(a + k, b)]
      else
        sub(m - k, a + k, b, false) + [mth(a, a + k)]
      end
    end

    def empty_root
      AtlasPca.b64e(sha(''))
    end

    def root_b64(n)
      n.zero? ? empty_root : AtlasPca.b64e(mth(0, n))
    end

    # [old_root, new_root, proof] for the consistency of the first m leaves with the first n.
    def cons_case(m, n)
      path = m.zero? || m == n ? [] : sub(m, 0, n, true)
      [root_b64(m), root_b64(n), { 'oldSize' => m, 'newSize' => n, 'path' => path.map { |x| AtlasPca.b64e(x) } }]
    end

    def cons_cases
      @cons_cases ||= (0..9).flat_map { |n| (0..n).map { |m| [m, n] + cons_case(m, n) } }
    end

    def incl_cases
      @incl_cases ||= (1..9).flat_map { |n| (0...n).map { |i| [i, n, lh(i), incl(i, 0, n), mth(0, n)] } }
    end

    def utf8(s)
      s.dup.force_encoding(Encoding::UTF_8)
    end
  end

  # ======================================================================================================================
  # fresh_at.rb
  # ======================================================================================================================
  t('c31 fresh_at: FRESH_AT_DOMAIN is the exact frozen binary string') do
    next true if C31Kill.skip?('fresh_at.rb')

    d = AtlasPca::FRESH_AT_DOMAIN
    d.frozen? && d.encoding == Encoding::BINARY && d == C31Kill::FA_DOMAIN && d.bytesize == 22
  end

  t('c31 fresh_at: k3_str? defaults to 512 UTF-16 units; k3_int? is a non-negative safe Integer') do
    next true if C31Kill.skip?('fresh_at.rb')

    m = AtlasPca
    m.k3_str?('a' * 512) == true && m.k3_str?('a' * 513) == false && m.k3_str?('') == false && m.k3_str?(nil) == false &&
      m.k3_str?(5) == false && m.k3_str?('a' * 256, 256) == true && m.k3_str?('a' * 257, 256) == false &&
      m.k3_str?("\u{1F600}" * 256) == true && m.k3_str?("\u{1F600}" * 257) == false &&
      m.k3_int?(0) == true && m.k3_int?(m::MAX_SAFE) == true && m.k3_int?(m::MAX_SAFE + 1) == false && m.k3_int?(-1) == false &&
      m.k3_int?(1.0) == false && m.k3_int?('1') == false && m.k3_int?(nil) == false
  end

  t('c31 fresh_at: k3_verify_body reaches verify_b64u only for a canonical 64-byte signature, with domain.b || canonical body') do
    next true if C31Kill.skip?('fresh_at.rb')

    m = AtlasPca
    calls = []
    dom = "é\x00"
    body = { 'k' => "é" }
    good = 'A' * 86
    want = dom.b + m.canon_bytes(body)
    ok = Seam.with(m, { verify_b64u: ->(*a) { calls << a; true } }) do
      nonstr = nil
      # b64d answering non-nil for anything: only the is_a?(String) guard can refuse a non-String signature
      Seam.with(m, { b64d: ->(*_a) { 'x' * 64 } }) { nonstr = [nil, 5, 5.5, :s, ['A'], {}].map { |s| m.k3_verify_body(dom, body, 'S', s) } }
      badstr = ['', 'AA', 'A' * 85, 'A' * 87, ('A' * 85) + 'B', '!' * 86, "#{'A' * 86}="].map { |s| m.k3_verify_body(dom, body, 'S', s) }
      r = m.k3_verify_body(dom, body, 'S', good)
      nonstr.all? { |x| x.equal?(false) } && badstr.all? { |x| x.equal?(false) } && r == true && calls == [['S', want, good]]
    end
    ok && Seam.with(m, { verify_b64u: ->(*) { true }, canon_bytes: ->(*) { raise 'boom' } }) { m.k3_verify_body(dom, body, 'S', good).equal?(false) }
  end

  t('c31 fresh_at: verify_fresh_at accepts the signed token and refuses every single broken condition') do
    next true if C31Kill.skip?('fresh_at.rb')

    m = AtlasPca
    c = C31Kill
    a = c.pub(c.ka)
    good = c.fa_token
    bad = [c.fa_token('v' => 2), c.fa_token('v' => nil), c.fa_token('scope' => ''), c.fa_token('scope' => 5), c.fa_token('scope' => 'a' * 257),
           c.fa_token('policy_digest' => ''), c.fa_token('policy_digest' => nil), c.fa_token('policy_digest' => 'a' * 129),
           c.fa_token('issued_at' => -1), c.fa_token('issued_at' => nil), c.fa_token('issued_at' => '1')]
    %w[revocation_epoch ledger_tree_size budget_version policy_revision].each do |k|
      [nil, -1, '5'].each { |v| bad << c.fa_token(k => v) }
    end
    tampered = good.merge('scope' => 'scope-2')
    wrong_key = c.fa_token({}, c.kb) # field says A, signed by B
    edge = c.fa_token('scope' => 'a' * 256, 'policy_digest' => 'b' * 128, 'issued_at' => 0, 'revocation_epoch' => 0)
    m.verify_fresh_at(good, a) == true && m.verify_fresh_at(edge, a) == true &&
      bad.all? { |t| m.verify_fresh_at(t, a).equal?(false) } &&
      m.verify_fresh_at(tampered, a).equal?(false) && m.verify_fresh_at(wrong_key, a).equal?(false) &&
      # token body names signer A but is signed by B and checked against B: only the t['signer'] == signer operand refuses it
      m.verify_fresh_at(wrong_key, c.pub(c.kb)).equal?(false) &&
      [nil, 5, 'x', [], good.to_a].all? { |t| m.verify_fresh_at(t, a).equal?(false) } &&
      # not a Hash but answers [] like the good token: only is_a?(Hash) refuses it
      m.verify_fresh_at(C31Kill::Duck.new(good), a).equal?(false)
  end

  t('c31 fresh_at: verify_fresh_at is exactly false when a step raises') do
    next true if C31Kill.skip?('fresh_at.rb')

    m = AtlasPca
    good = C31Kill.fa_token
    a = C31Kill.pub(C31Kill.ka)
    Seam.with(m, { k3_verify_body: ->(*) { raise 'boom' } }) { m.verify_fresh_at(good, a).equal?(false) } &&
      Seam.with(m, { fresh_at_body: ->(*) { raise 'boom' } }) { m.verify_fresh_at(good, a).equal?(false) }
  end

  t('c31 fresh_at: fresh_at_digest is the content address, nil when hashing raises') do
    next true if C31Kill.skip?('fresh_at.rb')

    m = AtlasPca
    tok = C31Kill.fa_token
    want = m.b64e(Digest::SHA256.digest(m.canon_bytes({ 'd' => 'atlas-pca/fresh-at-ref/v1', 't' => tok })))
    m.fresh_at_digest(tok) == want && Seam.with(m, { hash_canonical: ->(*) { raise 'boom' } }) { m.fresh_at_digest(tok).nil? }
  end

  t('c31 fresh_at: check_fresh_at verdicts, default max age, counters behind, malformed local, rescue') do
    next true if C31Kill.skip?('fresh_at.rb')

    m = AtlasPca
    c = C31Kill
    a = c.pub(c.ka)
    tok = c.fa_token
    call = ->(local, **kw) { m.check_fresh_at(tok, local, signer: a, scope: 'scope-1', now: 1_000_100, **kw) }
    names = %w[revocation_epoch ledger_tree_size budget_version policy_revision]
    stale = { 'decision' => 'escalate', 'code' => 'stale_state', 'behind' => names }
    bt = { 'decision' => 'deny', 'code' => 'bad_token' }
    call.call(c.fa_local) == { 'decision' => 'ok' } &&
      call.call(c.fa_local('revocation_epoch' => 9, 'ledger_tree_size' => 600)) == { 'decision' => 'ok' } &&
      call.call(c.fa_local('budget_version' => 7.0)) == { 'decision' => 'ok' } &&
      # a malformed `local` is the empty local: every counter is behind (never a bad_token)
      call.call(nil) == stale && call.call(Object.new) == stale && call.call([]) == stale &&
      call.call(c.fa_local('ledger_tree_size' => 5)) == { 'decision' => 'escalate', 'code' => 'stale_state', 'behind' => ['ledger_tree_size'] } &&
      call.call(c.fa_local('budget_version' => nil)) == { 'decision' => 'escalate', 'code' => 'stale_state', 'behind' => ['budget_version'] } &&
      call.call(c.fa_local('budget_version' => 'x')) == { 'decision' => 'escalate', 'code' => 'stale_state', 'behind' => ['budget_version'] } &&
      call.call(c.fa_local('policy_digest' => 'other')) == { 'decision' => 'deny', 'code' => 'policy_fork' } &&
      call.call(c.fa_local, max_token_age_ms: 99) == { 'decision' => 'deny', 'code' => 'token_too_old' } &&
      call.call(c.fa_local, max_token_age_ms: 100) == { 'decision' => 'ok' } &&
      m.check_fresh_at(tok, c.fa_local, signer: a, scope: 'other', now: 1_000_100) == { 'decision' => 'deny', 'code' => 'wrong_scope' } &&
      m.check_fresh_at(tok, c.fa_local, signer: a, scope: 'scope-1', now: 939_999) == { 'decision' => 'deny', 'code' => 'token_from_the_future' } &&
      m.check_fresh_at(tok, c.fa_local, signer: a, scope: 'scope-1', now: 940_000) == { 'decision' => 'ok' } &&
      m.check_fresh_at(c.fa_token('v' => 2), c.fa_local, signer: a, scope: 'scope-1', now: 1_000_100) == bt &&
      Seam.with(m, { verify_fresh_at: ->(*) { raise 'boom' } }) { call.call(c.fa_local) == bt }
  end

  t('c31 fresh_at: validate_fresh_at_wire gives each exact problem text, nil for a well-formed member') do
    next true if C31Kill.skip?('fresh_at.rb')

    m = AtlasPca
    c = C31Kill
    w = ->(over) { m.validate_fresh_at_wire(c.fa_wire(over)) }
    sd = "'fresh_at' scope and policy_digest must be non-empty strings"
    ok = w.call({}).nil? && w.call('scope' => 'a' * 256, 'policy_digest' => 'b' * 128).nil? &&
         m.validate_fresh_at_wire(5) == "'fresh_at' must be an object" && m.validate_fresh_at_wire(nil) == "'fresh_at' must be an object" &&
         m.validate_fresh_at_wire([]) == "'fresh_at' must be an object" &&
         w.call('x' => 1) == "'fresh_at' has an unknown field 'x'" &&
         w.call('v' => 2) == "'fresh_at.v' must be 1" && w.call('v' => nil) == "'fresh_at.v' must be 1" &&
         w.call('scope' => '') == sd && w.call('scope' => 'a' * 257) == sd && w.call('scope' => 5) == sd &&
         w.call('policy_digest' => '') == sd && w.call('policy_digest' => 'a' * 129) == sd && w.call('policy_digest' => nil) == sd &&
         w.call('signer' => 'AA') == "'fresh_at.signer' is not canonical base64url (32 bytes)" &&
         w.call('signer' => nil) == "'fresh_at.signer' is not canonical base64url (32 bytes)" &&
         w.call('sig' => 'AA') == "'fresh_at.sig' is not canonical base64url (64 bytes)" &&
         w.call('sig' => nil) == "'fresh_at.sig' is not canonical base64url (64 bytes)"
    ok && %w[revocation_epoch ledger_tree_size budget_version policy_revision issued_at].all? { |k|
      [-1, nil, '1', 1.5].all? { |v| w.call(k => v) == "'fresh_at.#{k}' must be a non-negative safe integer" }
    }
  end

  t('c31 fresh_at: decide_fresh_at check hashes, exact reasons, side-carried token, rescue') do
    next true if C31Kill.skip?('fresh_at.rb')

    m = AtlasPca
    c = C31Kill
    a = c.pub(c.ka)
    tok = c.fa_token
    now = 1_000_100
    pol = { 'signer' => a, 'scope' => 'scope-1', 'local' => c.fa_local }
    fail_with = ->(why) { { 'name' => 'fresh_at', 'ok' => false, 'reason' => why } }
    okh = { 'name' => 'fresh_at', 'ok' => true }
    m.decide_fresh_at({ 'fresh_at' => tok }, pol, now) == okh &&
      m.decide_fresh_at(nil, nil, now).nil? && m.decide_fresh_at(5, nil, now).nil? && m.decide_fresh_at({}, nil, now).nil? &&
      m.decide_fresh_at({ 'fresh_at' => tok }, nil, now) ==
        fail_with.call('the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)') &&
      m.decide_fresh_at({}, 5, now) == fail_with.call('fresh_at policy is malformed (fail closed)') &&
      m.decide_fresh_at({ 'fresh_at' => tok }, [], now) == fail_with.call('fresh_at policy is malformed (fail closed)') &&
      m.decide_fresh_at({}, pol, now).nil? &&
      m.decide_fresh_at({}, pol.merge('require' => true), now) ==
        fail_with.call('escalate: a consistency token is required (refresh and retry with the token of your latest write)') &&
      m.decide_fresh_at({}, pol.merge('require' => 'yes'), now).nil? &&
      m.decide_fresh_at({}, pol.merge('side_carried' => tok), now) == okh &&
      m.decide_fresh_at({}, pol.merge('side_carried' => nil), now) == fail_with.call('bad_token') &&
      m.decide_fresh_at({ 'fresh_at' => nil }, pol.merge('side_carried' => tok), now) == fail_with.call('bad_token') &&
      m.decide_fresh_at({ 'fresh_at' => tok }, pol.merge('local' => c.fa_local('budget_version' => 1)), now) ==
        fail_with.call('escalate: stale_state (verifier state is behind the token on budget_version)') &&
      m.decide_fresh_at({ 'fresh_at' => tok }, pol.merge('scope' => 'other'), now) == fail_with.call('wrong_scope') &&
      Seam.with(m, { check_fresh_at: ->(*_a, **_k) { raise 'boom' } }) do
        m.decide_fresh_at({ 'fresh_at' => tok }, pol, now) == fail_with.call('fresh_at check error (fail closed)')
      end
  end

  # ======================================================================================================================
  # obligations.rb
  # ======================================================================================================================
  t('c31 obligations: obligation_error gives each exact message') do
    next true if C31Kill.skip?('obligations.rb')

    m = AtlasPca
    e = ->(o) { m.obligation_error(o) }
    log_msg = 'log.sink must be a non-empty string of at most 128 characters'
    notify_msg = 'notify.to is required (a non-empty string of at most 256 characters)'
    wm_msg = 'watermark.id is required (a non-empty string of at most 128 characters)'
    undo_msg = 'undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)'
    red_msg = 'redact.fields must be 1..32 dotted field paths'
    mk = ->(kind, params) { { 'kind' => kind, 'params' => params } }
    fake = Class.new do
      def to_str
        'log'
      end

      def ==(_other)
        true
      end

      def to_s
        'fake'
      end
    end.new
    ok = [{ 'kind' => 'log' }, mk.call('log', {}), mk.call('log', { 'sink' => 's' }), mk.call('log', { 'sink' => 'a' * 128 }),
          mk.call('notify', { 'to' => 'a' * 256 }), mk.call('notify', { 'to' => 'a' }), mk.call('watermark', { 'id' => 'a' * 128 }),
          mk.call('require_receipt', {}), mk.call('undo_window', { 'id' => 'u', 'window_end' => 5 }),
          mk.call('redact', { 'fields' => ['a'] }), mk.call('redact', { 'fields' => ['a.b', 'c_1.d'] }),
          mk.call('redact', { 'fields' => (0...32).map { |i| "f#{i}" } }), { 'kind' => 'log', 'due' => 0 }, { 'kind' => 'log', 'due' => 5 }].all? { |o| e.call(o).nil? }
    ok &&
      e.call(mk.call('log', { 'sink' => 'a' * 129 })) == log_msg && e.call(mk.call('log', { 'sink' => '' })) == log_msg &&
      e.call(mk.call('log', { 'sink' => nil })) == log_msg && e.call(mk.call('log', { 'sink' => 5 })) == log_msg &&
      e.call({ 'kind' => 'notify' }) == notify_msg && e.call(mk.call('notify', { 'to' => 'a' * 257 })) == notify_msg &&
      e.call(mk.call('notify', { 'to' => '' })) == notify_msg &&
      e.call({ 'kind' => 'watermark' }) == wm_msg && e.call(mk.call('watermark', { 'id' => 'a' * 129 })) == wm_msg &&
      e.call(mk.call('watermark', { 'id' => '' })) == wm_msg &&
      e.call({ 'kind' => 'undo_window' }) == undo_msg && e.call(mk.call('undo_window', { 'id' => 'u', 'window_end' => -1 })) == undo_msg &&
      e.call(mk.call('redact', { 'fields' => (0...33).map { |i| "f#{i}" } })) == red_msg && e.call({ 'kind' => 'redact' }) == red_msg &&
      e.call(mk.call('redact', { 'fields' => [] })) == red_msg && e.call(mk.call('redact', { 'fields' => 'a' })) == red_msg &&
      e.call(mk.call('redact', { 'fields' => [5] })) == red_msg && e.call(mk.call('redact', { 'fields' => ['1a'] })) == red_msg &&
      e.call(mk.call('redact', { 'fields' => nil })) == red_msg &&
      e.call(mk.call('redact', { 'fields' => %w[a a] })) == 'redact.fields has a duplicate' &&
      e.call(mk.call('log', { 'zz' => 1 })) == "unknown parameter 'zz' for 'log'" &&
      [5, nil, 'x', []].all? { |o| e.call(o) == 'an obligation must be an object' } &&
      e.call({ 'kind' => 'zzz' }) == "unknown obligation kind 'zzz'" && e.call({}) == "unknown obligation kind ''" &&
      e.call({ 'kind' => 5 }) == "unknown obligation kind '5'" && e.call({ 'kind' => 'log', 'x' => 1 }) == "unknown member 'x'" &&
      # an object that Array#include? treats as 'log' is still not a String kind
      e.call({ 'kind' => fake }) == "unknown obligation kind 'fake'" &&
      [-1, nil, 1.5, '1'].all? { |d| e.call({ 'kind' => 'log', 'due' => d }) == 'due must be a non-negative safe integer' } &&
      [5, nil, [], 'x'].all? { |p| e.call({ 'kind' => 'log', 'params' => p }) == 'params must be an object' }
  end

  t('c31 obligations: obligations_error, obligation_key and merge_obligations') do
    next true if C31Kill.skip?('obligations.rb')

    m = AtlasPca
    lg = ->(s) { { 'kind' => 'log', 'params' => { 'sink' => s } } }
    many = ->(from, to) { (from..to).map { |i| lg.call("s#{i}") } }
    ok = m.obligations_error.nil? && m.obligations_error(nil) == 'obligations must be an array' && m.obligations_error([]).nil? && m.obligations_error(many.call(1, 16)).nil? &&
         m.obligations_error('x') == 'obligations must be an array' && m.obligations_error({}) == 'obligations must be an array' &&
         m.obligations_error(5) == 'obligations must be an array' &&
         m.obligations_error(many.call(1, 17)) == 'more than 16 obligations' &&
         m.obligations_error([lg.call('a'), 5]) == 'obligations[1]: an obligation must be an object' &&
         m.obligations_error([{ 'kind' => 'zzz' }]) == "obligations[0]: unknown obligation kind 'zzz'" &&
         m.obligations_error([{ 'kind' => 'log' }, { 'kind' => 'log', 'params' => {} }]) == 'obligations[1] duplicates an earlier obligation' &&
         m.obligations_error([{ 'kind' => 'log' }, { 'kind' => 'log', 'due' => 1 }]).nil?
    ok &&
      m.obligation_key({ 'kind' => 'log' }) == '{"kind":"log","params":{}}' &&
      m.obligation_key({ 'kind' => 'log', 'due' => 5 }) == '{"due":5,"kind":"log","params":{}}' &&
      m.obligation_key({ 'kind' => 'log', 'due' => 0 }) == '{"due":0,"kind":"log","params":{}}' &&
      m.obligation_key(lg.call('s')) == '{"kind":"log","params":{"sink":"s"}}' &&
      m.merge_obligations(nil, []) == { 'ok' => true, 'obligations' => [] } &&
      m.merge_obligations(nil, [{ 'kind' => 'notify', 'params' => { 'to' => 'b' } }, { 'kind' => 'log' }]) ==
        { 'ok' => true, 'obligations' => [{ 'kind' => 'log' }, { 'kind' => 'notify', 'params' => { 'to' => 'b' } }] } &&
      m.merge_obligations([{ 'kind' => 'log' }], [{ 'kind' => 'log', 'params' => {} }]) ==
        { 'ok' => true, 'obligations' => [{ 'kind' => 'log', 'params' => {} }] } &&
      m.merge_obligations(many.call(1, 8), many.call(9, 16))['obligations'].length == 16 &&
      m.merge_obligations(many.call(1, 8), many.call(9, 17)) == { 'ok' => false, 'reason' => 'more than 16 obligations after merging' } &&
      m.merge_obligations([5]) == { 'ok' => false, 'reason' => 'obligations[0]: an obligation must be an object' } &&
      m.merge_obligations([], 'x') == { 'ok' => false, 'reason' => 'obligations must be an array' } &&
      Seam.with(m, { obligations_error: ->(*) { raise 'boom' } }) do
        m.merge_obligations([]) == { 'ok' => false, 'reason' => 'evaluation error (fail closed)' }
      end
  end

  t('c31 obligations: pep_obligation_gate exact verdicts and reasons') do
    next true if C31Kill.skip?('obligations.rb')

    m = AtlasPca
    g = ->(d, ans, obl, sup) { m.pep_obligation_gate(d, ans, obl, sup) }
    deny = ->(unsup, why) { { 'decision' => 'deny', 'perform' => [], 'unsupported' => unsup, 'reason' => why } }
    lg = { 'kind' => 'log' }
    nt = { 'kind' => 'notify', 'params' => { 'to' => 'x' } }
    g.call('deny', false, nil, []) == { 'decision' => 'deny', 'perform' => [], 'unsupported' => [] } &&
      g.call('escalate', false, nil, []) == { 'decision' => 'escalate', 'perform' => [], 'unsupported' => [] } &&
      g.call('escalate', true, [], []) == { 'decision' => 'allow', 'perform' => [], 'unsupported' => [] } &&
      g.call('allow', false, m::NO_OBLIGATIONS, []) == { 'decision' => 'allow', 'perform' => [], 'unsupported' => [] } &&
      g.call('allow', false, [lg], ['log']) == { 'decision' => 'allow', 'perform' => [lg], 'unsupported' => [] } &&
      g.call('allow', false, [5], []) == deny.call([], 'malformed obligations: obligations[0]: an obligation must be an object') &&
      [nil, 'log', 5, [1], {}].all? { |s| g.call('allow', false, [lg], s) == deny.call([], 'the supported obligation kinds are malformed') } &&
      g.call('allow', false, [nt, lg, { 'kind' => 'log', 'due' => 1 }], ['redact']) ==
        deny.call(%w[log notify], 'the enforcement point does not support obligation(s) log, notify') &&
      g.call('allow', false, [nt], []) == deny.call(['notify'], 'the enforcement point does not support obligation(s) notify') &&
      Seam.with(m, { pep_decision: ->(*) { raise 'boom' } }) { g.call('allow', false, [lg], ['log']) == deny.call([], 'evaluation error (fail closed)') }
  end

  t('c31 obligations: obligation_outcome overdue indices, malformed inputs, rescue') do
    next true if C31Kill.skip?('obligations.rb')

    m = AtlasPca
    o = ->(obl, ful, now) { m.obligation_outcome(obl, ful, now) }
    unmet = ->(overdue) { { 'outcome' => 'escalate', 'overdue' => overdue, 'status' => 'obligation_unmet' } }
    list = [{ 'kind' => 'log', 'due' => 10 }, { 'kind' => 'log', 'due' => 20, 'params' => { 'sink' => 's' } }, { 'kind' => 'log' }]
    each_index_only = Class.new do
      def each_index
        [0, 1].each
      end
    end.new
    o.call(m::NO_OBLIGATIONS, [], 0) == { 'outcome' => 'ok', 'overdue' => [] } &&
      o.call(list, [], 9) == { 'outcome' => 'ok', 'overdue' => [] } &&
      o.call(list, [], 10) == unmet.call([0]) && o.call(list, [], 15) == unmet.call([0]) && o.call(list, [], 20) == unmet.call([0, 1]) &&
      o.call(list, [0], 20) == unmet.call([1]) && o.call(list, [0, 1], 99) == { 'outcome' => 'ok', 'overdue' => [] } &&
      o.call([{ 'kind' => 'zzz' }], [], 5) == unmet.call([0]) && o.call(list, 'x', 5) == unmet.call([0, 1, 2]) &&
      o.call(list, [-1], 5) == unmet.call([0, 1, 2]) && o.call(list, [], -1) == unmet.call([0, 1, 2]) && o.call(list, [], nil) == unmet.call([0, 1, 2]) &&
      o.call('x', [], 5) == unmet.call([]) && o.call(each_index_only, [], 5) == unmet.call([]) &&
      Seam.with(m, { obligations_error: ->(*) { raise 'boom' } }) { o.call(list, [], 5) == unmet.call([]) }
  end

  # ======================================================================================================================
  # revocation_staleness.rb
  # ======================================================================================================================
  t('c31 revocation: RevocationStaleness defaults are exactly nil/false and every bad option raises its exact message') do
    next true if C31Kill.skip?('revocation_staleness.rb')

    rs = AtlasPca::RevocationStaleness
    err = lambda do |**kw|
      rs.new(**kw)
      nil
    rescue ArgumentError => e
      e.message
    end
    cb = ->(*) {}
    full = rs.new(max_revocation_age_ms: 5, staleness: { irreversible: 7, 'rate_limited' => 9.5 }, allow_unsigned_root_for_irreversible: true,
                  guardian_public: 'G', pq_pins: { 'G' => 'P' }, on_epoch_accepted: cb, ids: cb, proofs: { 'a' => {} })
    d = rs.new
    d.to_a == [nil, nil, false, nil, nil, nil, nil, nil] &&
      full.max_revocation_age_ms == 5 && full.staleness == { 'irreversible' => 7, 'rate_limited' => 9.5 } &&
      full.allow_unsigned_root_for_irreversible == true && full.guardian_public == 'G' && full.pq_pins == { 'G' => 'P' } &&
      full.on_epoch_accepted.equal?(cb) && full.ids.equal?(cb) && full.proofs == { 'a' => {} } &&
      rs.new(allow_unsigned_root_for_irreversible: 'yes').allow_unsigned_root_for_irreversible == false &&
      rs.new(proofs: cb).proofs.equal?(cb) && rs.new(max_revocation_age_ms: 0.5).max_revocation_age_ms == 0.5 &&
      [0, -1, '5', Float::NAN, Float::INFINITY, true].all? { |v| err.call(max_revocation_age_ms: v) == 'max_revocation_age_ms must be a positive number of milliseconds' } &&
      [[], 5, 'x'].all? { |v| err.call(staleness: v) == 'staleness must be a Hash' } &&
      err.call(staleness: { 'irreversible' => 0 }) == 'staleness.irreversible must be a positive number of milliseconds' &&
      err.call(staleness: { irreversible: -1 }) == 'staleness.irreversible must be a positive number of milliseconds' &&
      err.call(staleness: { rate_limited: 0 }) == 'staleness.rate_limited must be a positive number of milliseconds' &&
      err.call(staleness: { 'costly' => '1' }) == 'staleness.costly must be a positive number of milliseconds' &&
      err.call(ids: 5) == 'ids must be callable' && err.call(proofs: 5) == 'proofs must be callable or a Hash' &&
      err.call(proofs: []) == 'proofs must be callable or a Hash'
  end

  t('c31 revocation: positive_ms?, class_rank, effective_reversibility exact tables') do
    next true if C31Kill.skip?('revocation_staleness.rb')

    m = AtlasPca
    pm = [[1, true], [0.5, true], [0, false], [-1, false], [nil, false], ['1', false], [Float::INFINITY, false], [Float::NAN, false],
          [10**400, false], [true, false]]
    cr = [['reversible', 0], ['rate_limited', 1], ['costly', 1], ['irreversible', 2], ['bogus', 2], [nil, 2], [5, 2], [:reversible, 2]]
    er = [[nil, 'reversible', 'reversible'], [nil, nil, 'irreversible'], ['reversible', 'reversible', 'reversible'],
          ['reversible', 'costly', 'rate_limited'], ['rate_limited', 'reversible', 'rate_limited'], ['irreversible', 'reversible', 'irreversible'],
          ['bogus', 'reversible', 'irreversible'], ['reversible', nil, 'irreversible'], ['reversible', 'bogus', 'irreversible'],
          ['costly', 'costly', 'rate_limited']]
    # a non-String that Hash#fetch would match to 'reversible' (same #hash, eql? true): only the is_a?(String) test makes it rank 2
    lookalike = Class.new do
      def hash
        'reversible'.hash
      end

      def eql?(_other)
        true
      end
    end.new
    pm.all? { |v, want| m.positive_ms?(v) == want } && cr.all? { |v, want| m.class_rank(v) == want } && m.class_rank(lookalike) == 2 &&
      er.all? { |s, g, want| m.effective_reversibility(s, g) == want } &&
      m::REVOCATION_IRREVERSIBLE_MAX_AGE_MS == 120_000 && m::REVOCATION_EPOCH_VALIDITY_MS == 300_000 && m::REVOCATION_EPOCH_REFRESH_MS == 60_000
  end

  t('c31 revocation: revocation_max_age_ms for every class, with defaults, Hash policies and the legacy costly name') do
    next true if C31Kill.skip?('revocation_staleness.rb')

    m = AtlasPca
    rs = AtlasPca::RevocationStaleness
    a = ->(pol, cls) { m.revocation_max_age_ms(pol, cls) }
    str = { 'max_revocation_age_ms' => 1000 }
    sym = { max_revocation_age_ms: 500_000, staleness: { 'irreversible' => 200_000, 'rate_limited' => 100_000 } }
    legacy = { staleness: { 'costly' => 77 } }
    a.call(nil, 'irreversible') == 120_000 && a.call(nil, 'reversible') == 300_000 && a.call(nil, 'rate_limited') == 300_000 &&
      a.call(nil, 'costly') == 300_000 && a.call(nil, 'zzz') == 300_000 && a.call(nil, nil) == 300_000 &&
      a.call(str, 'reversible') == 1000 && a.call(str, 'irreversible') == 1000 && a.call(str, 'costly') == 1000 &&
      a.call(sym, 'reversible') == 500_000 && a.call(sym, 'irreversible') == 200_000 && a.call(sym, 'rate_limited') == 100_000 &&
      a.call(sym, 'costly') == 100_000 && a.call(legacy, 'rate_limited') == 77 && a.call(legacy, 'costly') == 77 &&
      a.call(legacy, 'irreversible') == 120_000 && a.call({ staleness: { 'rate_limited' => 9, 'costly' => 5 } }, 'costly') == 9 &&
      a.call({ max_revocation_age_ms: 50, staleness: { 'irreversible' => 400 } }, 'irreversible') == 50 &&
      a.call(rs.new(max_revocation_age_ms: 9000), 'reversible') == 9000 && a.call(rs.new(staleness: { irreversible: 70 }), 'irreversible') == 70 &&
      a.call(rs.new(staleness: { 'rate_limited' => 33 }), 'costly') == 33
  end

  t('c31 revocation: verify_non_membership refuses a non-String root or id and a non-Hash proof before the proof check') do
    next true if C31Kill.skip?('revocation_staleness.rb')

    m = AtlasPca
    Seam.with(m, { :mesh_non_membership? => ->(*) { true } }) do
      m.verify_non_membership('r', {}, 'i').equal?(true) && m.verify_non_membership('r', { 'size' => 0 }, 'i').equal?(true) &&
        [[5, 'i', {}], ['r', 5, {}], ['r', 'i', []], [nil, 'i', {}], ['r', nil, {}], ['r', 'i', nil], ['r', 'i', 'x']].all? do |r, i, p|
          m.verify_non_membership(r, p, i).equal?(false)
        end
    end && Seam.with(m, { :mesh_non_membership? => ->(*) { raise 'boom' } }) { m.verify_non_membership('r', {}, 'i').equal?(false) }
  end

  t('c31 revocation: check_revocation_state passes the exact arguments to check_revocation_epoch and returns the accepted epoch') do
    next true if C31Kill.skip?('revocation_staleness.rb')

    m = AtlasPca
    rs = AtlasPca::RevocationStaleness
    undef_v = AtlasPca::IntentV2::UNDEF
    calls = []
    spy = ->(*a, **k) { calls << [a, k]; { 'ok' => true } }
    ep = { 'root' => 'R' }
    Seam.with(m, { check_revocation_epoch: spy }) do
      pol = rs.new(guardian_public: 'G', pq_pins: { 'G' => 'PQ' }, max_revocation_age_ms: 5000)
      st = { 'kind' => 'epoch', 'epoch' => ep, 'last_accepted_epoch' => 3 }
      r1 = m.check_revocation_state(pol, st, now: 100, grant_ref: 'GR', signed_class: 'reversible', server_class: 'reversible', pcactn_epoch: 7)
      # no policy: no max age, no pins, the caller's guardian key, every optional member at its default
      r2 = m.check_revocation_state(nil, { 'kind' => 'epoch', 'epoch' => ep }, now: 100, guardian_public: 'G2')
      # the guardian key comes from the policy when the caller gives none; an empty pin set is no pin set
      r3 = m.check_revocation_state(rs.new(guardian_public: 'G', pq_pins: {}), { kind: 'epoch', epoch: ep }, now: 100)
      # the smaller of the policy maximum and the class window wins (5000 ms here; 120 s irreversible by default)
      r4 = m.check_revocation_state(pol, { 'kind' => 'epoch', 'epoch' => ep }, now: 100, signed_class: 'reversible')
      r5 = m.check_revocation_state(pol, { 'kind' => 'epoch', 'epoch' => ep }, now: 100, signed_class: 'irreversible')
      r1 == { 'ok' => true, 'epoch' => ep } && r2 == { 'ok' => true, 'epoch' => ep } && r3 == { 'ok' => true, 'epoch' => ep } &&
        r4 == r1 && r5 == r1 &&
        calls[0] == [[ep, 'G', 100, 'GR', { 'G' => 'PQ' }], { pcactn_epoch: 7, last_accepted_epoch: 3, max_age_ms: 5000 }] &&
        calls[1] == [[ep, 'G2', 100, undef_v, nil], { pcactn_epoch: undef_v }] &&
        calls[2] == [[ep, 'G', 100, undef_v, nil], { pcactn_epoch: undef_v, max_age_ms: 120_000 }] &&
        calls[3] == [[ep, 'G', 100, undef_v, { 'G' => 'PQ' }], { pcactn_epoch: undef_v, max_age_ms: 5000 }] &&
        calls[4] == [[ep, 'G', 100, undef_v, { 'G' => 'PQ' }], { pcactn_epoch: undef_v, max_age_ms: 5000 }]
    end
  end

  t('c31 revocation: check_revocation_state refusals are exact hashes') do
    next true if C31Kill.skip?('revocation_staleness.rb')

    m = AtlasPca
    rs = AtlasPca::RevocationStaleness
    no_epoch = { 'ok' => false, 'reason' => 'no signed revocation epoch' }
    no_root = { 'ok' => false, 'reason' => 'no revocation root' }
    ep = { 'root' => 'R' }
    seen = []
    Seam.with(m, { check_revocation_epoch: ->(*a, **_k) { seen << a; { 'ok' => true } } }) do
      c = ->(pol, st, **kw) { m.check_revocation_state(pol, st, now: 10, **kw) }
      ok = c.call(nil, { 'kind' => 'epoch', 'epoch' => ep }) == no_epoch && # no guardian key anywhere
           c.call(rs.new, { 'kind' => 'epoch', 'epoch' => ep }) == no_epoch &&
           c.call(nil, { 'kind' => 'epoch', 'epoch' => 5 }, guardian_public: 'G') == no_epoch &&
           c.call(nil, { 'kind' => 'epoch', 'epoch' => nil }, guardian_public: 'G') == no_epoch &&
           c.call(nil, { 'kind' => 'epoch', 'epoch' => [] }, guardian_public: 'G') == no_epoch &&
           c.call(nil, { 'kind' => 'epoch', 'epoch' => ep }, guardian_public: '') == no_epoch &&
           c.call(nil, { 'kind' => 'epoch', 'epoch' => ep }, guardian_public: 5) == no_epoch &&
           c.call(nil, { 'kind' => 'epoch' }, guardian_public: 'G') == no_epoch &&
           [nil, 5, 'x', [], {}, { 'kind' => 'zzz' }, { 'kind' => nil }].all? { |s| c.call(nil, s, guardian_public: 'G') == no_epoch } &&
           seen.empty? &&
           c.call(nil, { kind: 'root', root: 'R' }) == { 'ok' => true } &&
           c.call(nil, { 'kind' => 'root', 'root' => nil }) == no_root && c.call(nil, { 'kind' => 'root', 'root' => '' }) == no_root &&
           c.call(nil, { 'kind' => 'root' }) == no_root &&
           c.call(nil, { 'kind' => 'epoch', 'epoch' => {} }, guardian_public: 'G') == no_root &&
           c.call(nil, { 'kind' => 'epoch', 'epoch' => { 'root' => '' } }, guardian_public: 'G') == no_root &&
           c.call(nil, { 'kind' => 'epoch', 'epoch' => ep, 'root' => 'R2' }, guardian_public: 'G') ==
             { 'ok' => false, 'reason' => 'revocation root does not match the signed epoch' } &&
           c.call(nil, { 'kind' => 'epoch', 'epoch' => ep, 'root' => 'R' }, guardian_public: 'G') == { 'ok' => true, 'epoch' => ep }
      ok && Seam.with(m, { check_revocation_epoch: ->(*, **) { { 'ok' => false, 'reason' => 'bad epoch' } } }) do
        c.call(nil, { 'kind' => 'epoch', 'epoch' => ep }, guardian_public: 'G') == { 'ok' => false, 'reason' => 'bad epoch' }
      end
    end
  end

  t('c31 revocation: unsigned root, the class of the action and the default server class') do
    next true if C31Kill.skip?('revocation_staleness.rb')

    m = AtlasPca
    rs = AtlasPca::RevocationStaleness
    refuse = { 'ok' => false, 'reason' => 'unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)' }
    st = { 'kind' => 'root', 'root' => 'R', 'issued_at' => 5 }
    c = ->(pol, state, **kw) { m.check_revocation_state(pol, state, now: 10, **kw) }
    c.call(rs.new, st) == refuse && c.call(rs.new, st, signed_class: 'irreversible', server_class: 'reversible') == refuse &&
      c.call(rs.new, st, signed_class: 'reversible') == { 'ok' => true } && # server class absent = no server opinion
      c.call(rs.new, st, signed_class: 'reversible', server_class: 'reversible') == { 'ok' => true } &&
      c.call(rs.new, st, signed_class: 'reversible', server_class: 'irreversible') == refuse &&
      c.call(rs.new, st, server_class: 'reversible') == refuse && # a missing signed class is irreversible
      c.call(rs.new(allow_unsigned_root_for_irreversible: true), st) == { 'ok' => true } &&
      c.call(rs.new(allow_unsigned_root_for_irreversible: true), { 'kind' => 'root', 'root' => 'R' }) ==
        { 'ok' => false, 'reason' => 'revocation root age is unknown (unverifiable revocation state)' } &&
      c.call(rs.new(max_revocation_age_ms: 4), st, signed_class: 'reversible')['ok'] == false &&
      c.call(rs.new(max_revocation_age_ms: 5), st, signed_class: 'reversible') == { 'ok' => true }
  end

  t('c31 revocation: non-membership proofs per id, in order, exact reasons and the rescue') do
    next true if C31Kill.skip?('revocation_staleness.rb')

    m = AtlasPca
    seen = []
    nm = ->(root, proof, id) { seen << [root, proof, id]; id != 'revoked' }
    st = { 'kind' => 'root', 'root' => 'R' }
    c = ->(**kw) { m.check_revocation_state(nil, st, now: 10, **kw) }
    Seam.with(m, { verify_non_membership: nm }) do
      ok = c.call == { 'ok' => true } && c.call(ids: []) == { 'ok' => true } && c.call(ids: nil, proofs: {}) == { 'ok' => true } &&
           seen.empty? &&
           c.call(ids: %w[a b], proofs: { 'a' => { 'p' => 1 }, 'b' => { 'p' => 2 } }) == { 'ok' => true } &&
           seen == [['R', { 'p' => 1 }, 'a'], ['R', { 'p' => 2 }, 'b']] &&
           c.call(ids: %w[a b], proofs: ->(id) { { 'id' => id } }) == { 'ok' => true } &&
           c.call(ids: %w[a], proofs: nil) == { 'ok' => false, 'reason' => 'no non-membership proof for a' } &&
           c.call(ids: %w[a]) == { 'ok' => false, 'reason' => 'no non-membership proof for a' } &&
           c.call(ids: %w[a], proofs: []) == { 'ok' => false, 'reason' => 'no non-membership proof for a' } &&
           c.call(ids: %w[a], proofs: 5) == { 'ok' => false, 'reason' => 'no non-membership proof for a' } &&
           c.call(ids: %w[a b], proofs: { 'a' => {} }) == { 'ok' => false, 'reason' => 'no non-membership proof for b' } &&
           c.call(ids: %w[a revoked], proofs: { 'a' => {}, 'revoked' => {} }) ==
             { 'ok' => false, 'reason' => 'capability revoked is revoked or proof invalid' }
      ok && Seam.with(m, { verify_non_membership: ->(*) { raise 'boom' } }) do
        c.call(ids: %w[a], proofs: { 'a' => {} }) == { 'ok' => false, 'reason' => 'revocation state check error (fail closed)' }
      end
    end
  end

  # ======================================================================================================================
  # provenance_gate.rb
  # ======================================================================================================================
  t('c31 provenance: prov_b32?, rfc9162_leaf_hash, prov_level?') do
    next true if C31Kill.skip?('provenance_gate.rb')

    m = AtlasPca
    thirty_two = Class.new do
      def bytesize
        32
      end
    end.new
    like_one = Class.new do
      def ==(_other)
        true
      end
    end.new
    only_b = Class.new do
      def b
        'abc'.b
      end
    end.new
    m.prov_b32?('a' * 32) == true && m.prov_b32?("é" * 16) == true && m.prov_b32?('a' * 31) == false && m.prov_b32?('a' * 33) == false &&
      m.prov_b32?(nil) == false && m.prov_b32?(5) == false && m.prov_b32?(thirty_two) == false && m.prov_b32?('a' * 5) == false &&
      m.rfc9162_leaf_hash('abc') == Digest::SHA256.digest("\x00abc") && m.rfc9162_leaf_hash("é") == Digest::SHA256.digest("\x00\xC3\xA9".b) &&
      m.rfc9162_leaf_hash(only_b) == Digest::SHA256.digest("\x00abc") &&
      [[1, true], [2, true], [3, true], [1.0, true], [0, false], [4, false], ['1', false], [nil, false], [1.5, false], [like_one, false]].all? do |v, want|
        m.prov_level?(v) == want
      end
  end

  t('c31 provenance: verify_rfc9162_inclusion over every (index, size) up to 9, with tampering, never hanging') do
    next true if C31Kill.skip?('provenance_gate.rb')

    m = AtlasPca
    c = C31Kill
    cases = c.incl_cases
    flip = ->(h) { h.dup.tap { |x| x.setbyte(0, x.getbyte(0) ^ 1) } }
    Timeout.timeout(2) do
      cases.all? { |i, n, leaf, proof, root| m.verify_rfc9162_inclusion(leaf, i, n, proof, root) == true } &&
        # every input as a UTF-8-tagged string: the verifier must work on the bytes (.b everywhere)
        cases.all? { |i, n, leaf, proof, root| m.verify_rfc9162_inclusion(c.utf8(leaf), i, n, proof.map { |p| c.utf8(p) }, c.utf8(root)) == true } &&
        # a float that is an integer is an integer; a fraction is not an index or a size
        m.verify_rfc9162_inclusion(c.lh(1), 1.0, 4.0, c.incl(1, 0, 4), c.mth(0, 4)) == true &&
        m.verify_rfc9162_inclusion(c.lh(1), 1.5, 4, c.incl(1, 0, 4), c.mth(0, 4)) == false &&
        m.verify_rfc9162_inclusion(c.lh(1), 1, 4.5, c.incl(1, 0, 4), c.mth(0, 4)) == false &&
        m.verify_rfc9162_inclusion(c.lh(1), 1, 4, c.incl(1, 0, 4), c.mth(0, 4)) == true &&
        cases.all? do |i, n, leaf, proof, root|
          [m.verify_rfc9162_inclusion(flip.call(leaf), i, n, proof, root), m.verify_rfc9162_inclusion(leaf, i, n, proof, flip.call(root)),
           m.verify_rfc9162_inclusion(leaf, i, n, proof + [c.lh(98)], root), m.verify_rfc9162_inclusion(leaf, i, n, proof, c.mth(0, n + 1)),
           m.verify_rfc9162_inclusion(leaf, -1, n, proof, root),
           m.verify_rfc9162_inclusion(leaf, i, 0, proof, root), m.verify_rfc9162_inclusion(leaf, n, n, proof, root),
           m.verify_rfc9162_inclusion(leaf, nil, n, proof, root), m.verify_rfc9162_inclusion(leaf, i, nil, proof, root),
           m.verify_rfc9162_inclusion(leaf, i, n, nil, root), m.verify_rfc9162_inclusion(leaf, i, n, 'x', root)].all? { |r| r.equal?(false) } &&
            (proof.empty? || (m.verify_rfc9162_inclusion(leaf, i, n, proof[0...-1], root).equal?(false) &&
                              m.verify_rfc9162_inclusion(leaf, i, n, proof.map { |p| flip.call(p) }, root).equal?(false)))
        end
    end
  end

  t('c31 provenance: verify_rfc9162_inclusion refuses a wrong-length leaf, a non-Array proof and a proof longer than the tree') do
    next true if C31Kill.skip?('provenance_gate.rb')

    m = AtlasPca
    c = C31Kill
    sib = c.lh(5)
    leaf31 = 'x' * 31
    root_for_31 = c.nh(leaf31.b, sib) # size 2, index 0: the root commits a 31-byte "leaf hash"
    over = c.nh(sib, c.lh(0)) # size 1, index 0, one superfluous proof element
    m.verify_rfc9162_inclusion(leaf31, 0, 2, [sib], root_for_31).equal?(false) &&
      m.verify_rfc9162_inclusion(c.lh(0), 0, 1, {}, c.lh(0)).equal?(false) && m.verify_rfc9162_inclusion(c.lh(0), 0, 1, [], c.lh(0)) == true &&
      m.verify_rfc9162_inclusion(c.lh(0), 0, 1, [sib], over).equal?(false) &&
      m.verify_rfc9162_inclusion(c.lh(0), 0, 1, [], 'y' * 31).equal?(false) && m.verify_rfc9162_inclusion(c.lh(0), 0, 1, [], 5).equal?(false) &&
      m.verify_rfc9162_inclusion(5, 0, 1, [], c.lh(0)).equal?(false) && m.verify_rfc9162_inclusion(c.lh(0), 0, 2, [sib, 'z' * 31], c.lh(0)).equal?(false) &&
      Seam.with(m, { :wb_safe_int? => ->(*) { raise 'boom' } }) { m.verify_rfc9162_inclusion(c.lh(0), 0, 1, [], c.lh(0)).equal?(false) }
  end

  t('c31 provenance: provenance_facts_error needs a safe integer v equal to 1') do
    next true if C31Kill.skip?('provenance_gate.rb')

    m = AtlasPca
    like_one = Class.new do
      def ==(_other)
        true
      end
    end.new
    facts = { 'v' => 1, 'predicate_type' => 'https://slsa.dev/provenance/v1', 'build_type' => 'bt', 'builder_id' => 'b',
              'subjects' => [{ 'alg' => 'sha256', 'digest' => 'a' * 64 }], 'identity' => 'https://id.example/x', 'oidc_issuer' => 'https://iss',
              'integrated_time' => 100, 'rekor_log_index' => 1 }
    m.provenance_facts_error(facts).nil? && m.provenance_facts_error(facts.merge('v' => 2)) == 'facts.v must be 1' &&
      m.provenance_facts_error(facts.merge('v' => like_one)) == 'facts.v must be 1' &&
      m.provenance_facts_error(facts.merge('v' => '1')) == 'facts.v must be 1' && m.provenance_facts_error(5) == 'facts must be an object'
  end

  t('c31 provenance: provenance_gate is exactly {ok: false, code: malformed_facts} when a step raises') do
    next true if C31Kill.skip?('provenance_gate.rb')

    m = AtlasPca
    Seam.with(m, { provenance_policy_error: ->(*) { raise 'boom' } }) do
      m.provenance_gate({ 'facts' => {}, 'policy' => {}, 'now' => 1 }) == { ok: false, code: 'malformed_facts' }
    end
  end

  t('c31 provenance: provenance_caveat defaults add no optional claim and use the documented id, bind and ttl') do
    next true if C31Kill.skip?('provenance_gate.rb')

    m = AtlasPca
    base = [{ 'claim' => 'slsa_level', 'op' => 'gte', 'value' => 2 }]
    rt = { 'claim' => 'runtime_bound', 'op' => 'eq', 'value' => true }
    m.provenance_caveat(issuer: 'iss', min_level: 2) ==
      { 'type' => 'needs_discharge', 'id' => 'provenance', 'issuer' => 'iss', 'issuer_class' => 'artifact', 'bind' => 'action', 'ttl_ms' => 300_000,
        'require' => base + [rt] } &&
      m.provenance_caveat(issuer: 'iss', min_level: 2, require_runtime: false)['require'] == base &&
      m.provenance_caveat(issuer: 'iss', min_level: 3, id: 'x', source_repo: 'r', builder_ids: ['b'], oidc_issuer: 'o', bind: 'chain_hop', ttl_ms: 5) ==
        { 'type' => 'needs_discharge', 'id' => 'x', 'issuer' => 'iss', 'issuer_class' => 'artifact', 'bind' => 'chain_hop', 'ttl_ms' => 5,
          'require' => [{ 'claim' => 'slsa_level', 'op' => 'gte', 'value' => 3 }, { 'claim' => 'source_repo', 'op' => 'eq', 'value' => 'r' },
                        { 'claim' => 'builder_id', 'op' => 'in', 'value' => ['b'] }, { 'claim' => 'oidc_issuer', 'op' => 'eq', 'value' => 'o' }, rt] }
  end

  # ======================================================================================================================
  # ledger.rb
  # ======================================================================================================================
  t('c31 ledger: ledger_signed? signs domain.b || canonical body (non-ASCII domain and body)') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    got = []
    dom = "é\x00"
    body = { 'k' => "é" }
    Seam.with(m::IntentV2, { verify_pinned_suite: ->(*a) { got << a; :verdict } }) do
      r = m.ledger_signed?('id', dom, body, { 'sig' => 's', 'pq_sig' => 'q' }, { 'p' => 1 })
      r == :verdict && got.length == 1 && got[0][0].equal?(m::IntentV2::UNDEF) && got[0][1] == 'id' && got[0][2].equal?(m::IntentV2::UNDEF) &&
        got[0][3] == dom.b + m.canon_bytes(body) && got[0][4] == 's' && got[0][5] == 'q' && got[0][6] == { 'p' => 1 }
    end
  end

  t('c31 ledger: verify_ledger_consistency accepts every valid (old, new) up to 9 and refuses tampering, never hanging') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    c = C31Kill
    cases = c.cons_cases
    proofs_w = ->(proof, path) { proof.merge('path' => path) }
    Timeout.timeout(2) do
      cases.all? { |_m, _n, o, nw, pr| m.verify_ledger_consistency(o, nw, pr) == true } &&
        # path elements as long as the tree needs (a 4-element path exists in the sweep)
        cases.any? { |_m, _n, _o, _nw, pr| pr['path'].length >= 4 } &&
        cases.all? do |m0, n, o, nw, pr|
          next true unless m0.positive? && m0 < n

          path = pr['path']
          other = AtlasPca.b64e(c.lh(97))
          [m.verify_ledger_consistency(o, c.root_b64(n + 1), pr), m.verify_ledger_consistency(c.root_b64(m0 + 1), nw, pr),
           m.verify_ledger_consistency(o, nw, proofs_w.call(pr, [other] + path[1..])), m.verify_ledger_consistency(o, nw, proofs_w.call(pr, path + [other])),
           m.verify_ledger_consistency(o, nw, proofs_w.call(pr, path[0...-1])), m.verify_ledger_consistency(o, nw, proofs_w.call(pr, [])),
           m.verify_ledger_consistency(o, nw, proofs_w.call(pr, path.map { |x| x[0...-1] }))].all? { |r| r.equal?(false) }
        end
    end
  end

  t('c31 ledger: verify_ledger_consistency takes integral Float sizes as Integers') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    c = C31Kill
    [[4, 8], [3, 7], [1, 2], [2, 9], [5, 6]].all? do |a, b|
      o, nw, pr = c.cons_case(a, b)
      [[a.to_f, b], [a, b.to_f], [a.to_f, b.to_f]].all? { |x, y| m.verify_ledger_consistency(o, nw, pr.merge('oldSize' => x, 'newSize' => y)) == true }
    end
  end

  t('c31 ledger: verify_ledger_consistency input guards (types, sizes, -0, path container, undecodable old root)') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    c = C31Kill
    e = c.empty_root
    v = ->(o, n, p) { m.verify_ledger_consistency(o, n, p) }
    pr = ->(a, b, path = []) { { 'oldSize' => a, 'newSize' => b, 'path' => path } }
    o8, n8, p48 = c.cons_case(4, 8)
    like_hash = C31Kill::Duck.new(pr.call(3, 3))
    calls = []
    neg = nil
    Seam.with(m, { node_hash: ->(_l, _r) { calls << 1; 'x' * 32 } }) do
      b = AtlasPca.b64e('y' * 32)
      neg = v.call(b, b, pr.call(-1, 5, [b, b, b]))
    end
    v.call(e, 'x', pr.call(0, 3)) == true && v.call(e, e, pr.call(0, 0)) == true && v.call(e, 'x', pr.call(0, 0)) == false &&
      v.call(e, nil, pr.call(0, 3)).equal?(false) && v.call(e, 5, pr.call(0, 3)).equal?(false) && v.call(nil, nil, pr.call(3, 3)).equal?(false) &&
      v.call(5, 5, pr.call(3, 3)).equal?(false) && v.call('x', 'x', pr.call(3, 3)) == true && v.call('a', 'b', pr.call(3, 3)) == false &&
      v.call('x', 'x', pr.call(3, 3, ['x'])) == false && v.call(e, 'x', pr.call(0, 3, ['x'])) == false && v.call('x', 'x', like_hash).equal?(false) &&
      v.call('x', 'x', [pr.call(3, 3)]).equal?(false) && v.call('x', 'x', nil).equal?(false) &&
      v.call(e, 'x', pr.call(0, 3, {})).equal?(false) && v.call(e, 'x', pr.call(0, 3, nil)).equal?(false) && v.call('x', 'x', pr.call(3, 3, {})).equal?(false) &&
      v.call(e, 'x', pr.call(3, 2)) == false && v.call(e, 'x', pr.call(nil, 3)).equal?(false) && v.call(e, 'x', pr.call(0, nil)).equal?(false) &&
      v.call(e, 'x', pr.call(0, 1.5)).equal?(false) && v.call(e, 'x', pr.call('0', 3)).equal?(false) &&
      v.call(e, e, pr.call(-0.0, 0)).equal?(false) && v.call(e, 'x', pr.call(0, -0.0)).equal?(false) && v.call(e, e, pr.call(0.0, 0)) == true &&
      v.call(e, 'x', pr.call(0, 3, [])) == true && v.call('!!!!', n8, p48).equal?(false) && v.call(o8, n8, p48) == true &&
      v.call('!!!!', n8, pr.call(4, 8, p48['path'])).equal?(false) && v.call(nil, n8, p48).equal?(false) &&
      neg.equal?(false) && calls.empty? &&
      Seam.with(m, { node_hash: ->(*) { raise 'boom' } }) { v.call(*c.cons_case(3, 7)).equal?(false) }
  end

  t('c31 ledger: verify_witness_cosignature checks the key, the String sig and signs the exact head body') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    seen = []
    sth = { 'instance_id' => 'i', 'principal' => 'p', 'size' => 3, 'root' => 'r', 'prev_root' => 'q', 'guardian_epoch' => nil }
    body = { 'instance_id' => 'i', 'principal' => 'p', 'size' => 3, 'root' => 'r', 'prev_root' => 'q', 'guardian_epoch' => 0 }
    cos = { 'key' => 'W', 'sig' => 's' }
    Seam.with(m, { :ledger_signed? => ->(*a) { seen << a; true } }) do
      r1 = m.verify_witness_cosignature(sth, cos, 'W')
      r2 = m.verify_witness_cosignature(sth.merge('guardian_epoch' => 4), cos, 'W', { 'x' => 1 })
      ok = r1 == true && r2 == true && seen[0] == ['W', m::STH_WITNESS_DOMAIN, body, cos, nil] &&
           seen[1] == ['W', m::STH_WITNESS_DOMAIN, body.merge('guardian_epoch' => 4), cos, { 'x' => 1 }]
      n = seen.length
      ok && [nil, 5, 'x', [], { 'key' => 'X', 'sig' => 's' }, { 'sig' => 's' }, { 'key' => 'W' }, { 'key' => 'W', 'sig' => 5 },
             { 'key' => 'W', 'sig' => nil }, C31Kill::Duck.new(cos)].all? { |c| m.verify_witness_cosignature(sth, c, 'W').equal?(false) } &&
        seen.length == n
    end && Seam.with(m, { :ledger_signed? => ->(*) { raise 'boom' } }) { m.verify_witness_cosignature(sth, cos, 'W').equal?(false) }
  end

  t('c31 ledger: verify_witness_cosignatures counts distinct trusted valid witnesses, falls back to the policy pins') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    seen = []
    w = ->(k, s = 'ok') { { 'key' => k, 'sig' => s } }
    pol = ->(th, keys, pins = nil) { { 'threshold' => th, 'witnessKeys' => keys, 'pqPins' => pins } }
    st = ->(*ws) { { 'witnesses' => ws } }
    ok = Seam.with(m, { verify_witness_cosignature: ->(_s, cs, key, pins) { seen << [key, pins]; cs['sig'] != 'bad' } }) do
      vc = ->(s, p, *rest) { m.verify_witness_cosignatures(s, p, *rest) }
      r = vc.call({}, pol.call(0, nil)) == true && vc.call({ 'witnesses' => nil }, pol.call(0, [])) == true && seen.empty? &&
          vc.call(st.call(w.call('k1')), pol.call(1, ['k1'])) == true &&
          # a repeated witness is skipped before it is verified again (the counted set cannot show it, a spy can)
          (seen.clear; vc.call(st.call(w.call('k1'), w.call('k1')), pol.call(2, ['k1'])) == false && seen.length == 1) &&
          vc.call(st.call(w.call('k1'), w.call('k2')), pol.call(2, %w[k1 k2])) == true &&
          vc.call(st.call(w.call('k1'), w.call('k2', 'bad')), pol.call(2, %w[k1 k2])) == false &&
          vc.call(st.call(w.call('zz')), pol.call(1, ['k1'])) == false &&
          [-1, 1.5, '1', nil, true].all? { |t| vc.call(st.call(w.call('k1'), w.call('k2')), pol.call(t, %w[k1 k2])) == false } &&
          vc.call(st.call(w.call('k1')), { 'threshold' => 1 }) == false && vc.call(st.call(w.call('k1')), pol.call(1, [])) == false &&
          [nil, 'x', {}, 5].all? { |ws| vc.call({ 'witnesses' => ws }, pol.call(1, ['k1'])) == false } &&
          vc.call(C31Kill::Chain.new([w.call('k1')]).then { |ch| { 'witnesses' => ch } }, pol.call(1, ['k1'])) == false &&
          vc.call(st.call(C31Kill::Duck.new(w.call('k1'))), pol.call(1, ['k1'])) == false &&
          vc.call(st.call(w.call(:k1)), pol.call(1, [:k1])) == false &&
          vc.call(st.call(w.call('k1', nil)), pol.call(1, ['k1'])) == false && vc.call(st.call(w.call('k1', 5)), pol.call(1, ['k1'])) == false &&
          vc.call(st.call(5, nil, w.call('k1')), pol.call(1, ['k1'])) == true
      seen.clear
      vc.call(st.call(w.call('k1')), pol.call(1, ['k1'], { 'p' => 'q' }))
      vc.call(st.call(w.call('k1')), pol.call(1, ['k1'], { 'p' => 'q' }), {})
      vc.call(st.call(w.call('k1')), pol.call(1, ['k1'], { 'p' => 'q' }), { 'x' => 1 })
      vc.call(st.call(w.call('k1')), pol.call(1, ['k1']))
      r && seen == [['k1', { 'p' => 'q' }], ['k1', {}], ['k1', { 'x' => 1 }], ['k1', nil]]
    end
    # reaching the threshold ends the walk: a later witness is never asked
    ok && Seam.with(m, { verify_witness_cosignature: ->(_s, _c, key, _p) { raise 'late' if key == 'k2'; true } }) do
      m.verify_witness_cosignatures(st.call(w.call('k1'), w.call('k2')), pol.call(1, %w[k1 k2])) == true
    end && m.verify_witness_cosignatures({}, nil).equal?(false)
  end

  t('c31 ledger: verify_tree_head signs the exact head body, then asks for the witness threshold with the same pins') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    sth = { 'guardian' => 'G', 'size' => 3, 'instance_id' => 'i', 'principal' => 'p', 'root' => 'r', 'prev_root' => 'q', 'timestamp' => 9,
            'witnesses' => [] }
    body = { 'instance_id' => 'i', 'principal' => 'p', 'size' => 3, 'root' => 'r', 'prev_root' => 'q', 'timestamp' => 9 }
    signed = []
    wit = []
    st = { :ledger_signed? => ->(*a) { signed << a; true }, verify_witness_cosignatures: ->(*a) { wit << a; :cosigned } }
    Seam.with(m, st) do
      r1 = m.verify_tree_head(sth, 'G')
      r2 = m.verify_tree_head(sth, 'G', { 'threshold' => 1 })
      r3 = m.verify_tree_head(sth, 'G', { 'threshold' => 1 }, { 'a' => 'b' })
      r1 == true && r2 == :cosigned && r3 == :cosigned && signed.length == 3 && signed[0] == ['G', m::STH_DOMAIN, body, sth, nil] &&
        signed[2] == ['G', m::STH_DOMAIN, body, sth, { 'a' => 'b' }] && wit == [[sth, { 'threshold' => 1 }, nil], [sth, { 'threshold' => 1 }, { 'a' => 'b' }]] &&
        [nil, 'x', 5, [], C31Kill::Duck.new(sth), sth.merge('guardian' => 'H'), sth.merge('size' => -1), sth.merge('size' => 1.5),
         sth.merge('size' => nil), sth.merge('size' => '3')].all? { |s| m.verify_tree_head(s, 'G').equal?(false) } &&
        m.verify_tree_head(sth.merge('size' => 0), 'G') == true
    end && Seam.with(m, { :ledger_signed? => ->(*) { false } }) { m.verify_tree_head(sth, 'G').equal?(false) } &&
      Seam.with(m, { :ledger_signed? => ->(*) { raise 'boom' } }) { m.verify_tree_head(sth, 'G').equal?(false) }
  end

  t('c31 ledger: verify_head_consistency needs both heads, one log, matching sizes, linked adjacent heads') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    heads = []
    older = { 'instance_id' => 'i', 'principal' => 'p', 'size' => 3, 'root' => 'R3', 'prev_root' => 'x' }
    newer = { 'instance_id' => 'i', 'principal' => 'p', 'size' => 5, 'root' => 'R5', 'prev_root' => 'y' }
    adj = newer.merge('size' => 4, 'prev_root' => 'R3')
    cons = []
    pr = ->(a, b) { { 'oldSize' => a, 'newSize' => b, 'path' => [] } }
    Seam.with(m, { verify_tree_head: ->(*a) { heads << a; a[0]['size'] != 99 }, verify_ledger_consistency: ->(*a) { cons << a; :cons } }) do
      ok = m.verify_head_consistency(older, newer, pr.call(3, 5), 'G') == :cons &&
           heads == [[older, 'G', nil, nil], [newer, 'G', nil, nil]] && cons == [['R3', 'R5', pr.call(3, 5)]] &&
           m.verify_head_consistency(older, newer, pr.call(3, 5), 'G', { 'w' => 1 }, { 'p' => 2 }) == :cons &&
           heads[2..] == [[older, 'G', { 'w' => 1 }, { 'p' => 2 }], [newer, 'G', { 'w' => 1 }, { 'p' => 2 }]] &&
           m.verify_head_consistency(older, adj, pr.call(3, 4), 'G') == :cons &&
           m.verify_head_consistency(older, adj.merge('prev_root' => 'other'), pr.call(3, 4), 'G') == false &&
           m.verify_head_consistency(older, newer.merge('prev_root' => 'other'), pr.call(3, 5), 'G') == :cons
      ok && m.verify_head_consistency(older, newer.merge('instance_id' => 'j'), pr.call(3, 5), 'G') == false &&
        m.verify_head_consistency(older, newer.merge('principal' => 'q'), pr.call(3, 5), 'G') == false &&
        m.verify_head_consistency(older, newer, pr.call(4, 5), 'G') == false && m.verify_head_consistency(older, newer, pr.call(99, 5), 'G') == false &&
        m.verify_head_consistency(older, newer, pr.call(3, 6), 'G') == false && m.verify_head_consistency(older, newer, pr.call(3, 99), 'G') == false &&
        m.verify_head_consistency(older, newer, pr.call(nil, 5), 'G') == false && m.verify_head_consistency(older, newer, pr.call(3, nil), 'G') == false &&
        m.verify_head_consistency(older, newer, pr.call(3.5, 5), 'G') == false && m.verify_head_consistency(older, newer, pr.call(3, 5.5), 'G') == false &&
        m.verify_head_consistency(older.merge('size' => 99), newer, pr.call(99, 5), 'G') == false &&
        m.verify_head_consistency(older, newer.merge('size' => 99), pr.call(3, 99), 'G') == false &&
        m.verify_head_consistency(older, newer, nil, 'G').equal?(false)
    end
  end

  t('c31 ledger: verify_checkpoint_chain reports the index of the first bad checkpoint, exactly') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    th = []
    hc = []
    s0 = { 'n' => 0 }
    s1 = { 'n' => 1 }
    s2 = { 'n' => 2 }
    c0 = { 'sth' => s0 }
    c1 = { 'sth' => s1, 'proof' => { 'p' => 1 } }
    c2 = { 'sth' => s2, 'proof' => { 'p' => 2 } }
    bad = { 'ok' => false, 'at' => 0 }
    ok = Seam.with(m, { verify_tree_head: ->(*a) { th << a; a[0]['n'] != 9 }, verify_head_consistency: ->(*a) { hc << a; a[2]['p'] != 9 } }) do
      r = m.verify_checkpoint_chain([c0, c1, c2], 'G') == { 'ok' => true } && th.map(&:first) == [s0, s1, s2] && th.all? { |a| a[1..] == ['G', nil, nil] } &&
          hc == [[s0, s1, { 'p' => 1 }, 'G', nil, nil], [s1, s2, { 'p' => 2 }, 'G', nil, nil]] &&
          m.verify_checkpoint_chain([c0], 'G', { 'w' => 1 }, { 'q' => 2 }) == { 'ok' => true } && th.last == [s0, 'G', { 'w' => 1 }, { 'q' => 2 }] &&
          [nil, [], 'abc', 5, {}].all? { |ch| m.verify_checkpoint_chain(ch, 'G') == bad } &&
          m.verify_checkpoint_chain(C31Kill::Chain.new([c0]), 'G') == bad &&
          m.verify_checkpoint_chain([{ 'sth' => { 'n' => 9 } }], 'G') == bad && m.verify_checkpoint_chain([5], 'G') == bad &&
          m.verify_checkpoint_chain([c0, 5], 'G') == { 'ok' => false, 'at' => 1 } && m.verify_checkpoint_chain([c0, c1, nil], 'G') == { 'ok' => false, 'at' => 2 } &&
          m.verify_checkpoint_chain([c0, { 'sth' => s1 }], 'G') == { 'ok' => false, 'at' => 1 } &&
          m.verify_checkpoint_chain([c0, { 'sth' => { 'n' => 9 }, 'proof' => { 'p' => 1 } }], 'G') == { 'ok' => false, 'at' => 1 } &&
          m.verify_checkpoint_chain([c0, c1, { 'sth' => { 'n' => 9 }, 'proof' => { 'p' => 1 } }], 'G') == { 'ok' => false, 'at' => 2 } &&
          m.verify_checkpoint_chain([c0, { 'sth' => s1, 'proof' => { 'p' => 9 } }], 'G') == { 'ok' => false, 'at' => 1 } &&
          m.verify_checkpoint_chain([c0, c1, { 'sth' => s2, 'proof' => { 'p' => 9 } }], 'G') == { 'ok' => false, 'at' => 2 }
      r
    end
    ok && Seam.with(m, { verify_tree_head: ->(*) { raise 'boom' } }) { m.verify_checkpoint_chain([c0, c1], 'G') == { 'ok' => false, 'at' => 0 } }
  end

  t('c31 ledger: verify_witnessed_head and detect_equivocation') do
    next true if C31Kill.skip?('ledger.rb')

    m = AtlasPca
    seen = []
    wh = { 'witness' => 'W', 'principal' => 'p', 'size' => 1, 'root' => 'r' }
    body = { 'principal' => 'p', 'size' => 1, 'root' => 'r' }
    ok = Seam.with(m, { :ledger_signed? => ->(*a) { seen << a; true } }) do
      r = m.verify_witnessed_head(wh, 'W') == true && m.verify_witnessed_head(wh, 'W', { 'x' => 1 }) == true &&
          seen == [['W', m::LEDGER_HEAD_DOMAIN, body, wh, nil], ['W', m::LEDGER_HEAD_DOMAIN, body, wh, { 'x' => 1 }]]
      n = seen.length
      r && [nil, 5, 'x', [], wh.merge('witness' => 'X'), C31Kill::Duck.new(wh)].all? { |h| m.verify_witnessed_head(h, 'W').equal?(false) } && seen.length == n
    end
    ok && Seam.with(m, { :ledger_signed? => ->(*) { raise 'boom' } }) { m.verify_witnessed_head(wh, 'W').equal?(false) } &&
      begin
        seen = []
        a = wh.merge('root' => 'r1')
        b = wh.merge('root' => 'r2')
        Seam.with(m, { verify_witnessed_head: ->(*x) { seen << x; x[0]['root'] != 'bad' } }) do
          m.detect_equivocation(a, b, 'W') == true && seen == [[a, 'W', nil], [b, 'W', nil]] &&
            m.detect_equivocation(a, b, 'W', { 'x' => 1 }) == true && seen[2..] == [[a, 'W', { 'x' => 1 }], [b, 'W', { 'x' => 1 }]] &&
            m.detect_equivocation(a, a, 'W') == false && m.detect_equivocation(a, b.merge('size' => 2), 'W') == false &&
            m.detect_equivocation(a, b.merge('principal' => 'q'), 'W') == false && m.detect_equivocation(a.merge('root' => 'bad'), b, 'W') == false &&
            m.detect_equivocation(a, b.merge('root' => 'bad'), 'W') == false
        end
      end && Seam.with(m, { verify_witnessed_head: ->(*) { raise 'boom' } }) { m.detect_equivocation(wh, wh, 'W').equal?(false) }
  end
end
