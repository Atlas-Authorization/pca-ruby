# frozen_string_literal: true

# c02: kill tests for lib/atlas_pca/actions_registry.rb and lib/atlas_pca/undo.rb (PCA 0.5 mutation kill). Registry signatures and
# packs are signed here with throwaway keys generated at load; expected values follow action-pin.ts / action registry and undo.ts.
# Spies (Seam.with) pin guards that a later check or a method-level rescue would otherwise mask.
require 'json'
require 'timeout'

module MutationKill
  module C02RegUndo
    KP = AtlasPca::KeyPair.new('r' * 32)
    KPU = AtlasPca::KeyPair.new('u' * 32)
    KEYS = [{ 'kid' => 'k1', 'pk' => KP.public }].freeze
    VERB = 'stripe.payout'
    D1 = 'A' * 43
    D2 = 'B' * 43
    D3 = 'C' * 43
    D4 = 'E' * 43
    R = 'R' * 43
    DEFS_JSON = <<~'JSON'
      [{"v":1,"kind":"pca-action-def","verb":"stripe.create_customer","title":"Create a customer record","description":"Creates a customer record.","effects":["create"],"resource":{"type":"stripe.customer","id":{"prefix":"cus_","class":"any_safe","len":[8,64]},"scope":"one"},"params":{"email":{"type":"string","role":"contact.email","format":"email","max_len":254,"tags":["pii"],"required":false},"name":{"type":"string","max_len":200,"role":"person.name","required":false,"tags":["pii"]}},"reversibility":"rate_limited","blast":{"radius":"one","ppm":200000},"review":{"state":"authored"},"since":"0.5.0"},{"v":1,"kind":"pca-action-def","verb":"stripe.payout","aliases":["payout","pay_out"],"title":"Pay out funds to a bank account","description":"Moves funds from a Stripe balance to a bank account.","effects":["pay"],"resource":{"type":"stripe.account","id":{"prefix":"acct_","class":"any_safe","len":[8,64]},"scope":"one"},"params":{"amount":{"type":"integer","role":"money.amount","min":1,"max":10000000000,"unit":{"kind":"money","ccy":"USD","exp":2},"provenance_min":"first_party"},"account":{"type":"string","max_len":128,"role":"id.stripe.account"},"idempotency_key":{"type":"string","max_len":128}},"reversibility":"irreversible","blast":{"radius":"tenant","ppm":900000},"idempotency":{"mode":"key_param","param":"idempotency_key"},"examples":[{"params":{"account":"acct_12345678","amount":100000,"idempotency_key":"k_1"},"expect":"escalate"}],"review":{"state":"authored"},"since":"0.5.0"}]
    JSON
    MEMO = {}

    # exceptions with a message that differs from to_s (a mutant that interpolates the exception reads to_s)
    class MsgErr < StandardError
      def message
        'M'
      end

      def to_s
        'S'
      end
    end

    # not a String, but a String compares equal to it (String#== defers to the other side's == for a to_str object)
    class Duck
      def initialize(str)
        @str = str
      end

      def to_str
        @str
      end

      def ==(_other)
        true
      end
    end

    # a String that claims equality to anything when it is the receiver
    class Evil < String
      def ==(_other)
        true
      end
    end

    class HashLike
      def initialize(hash)
        @h = hash
      end

      def length
        @h.length
      end

      def key?(key)
        @h.key?(key)
      end

      def [](key)
        @h[key]
      end

      def reject(&blk)
        @h.reject(&blk)
      end
    end

    class Big
      def initialize(len, empty = false)
        @len = len
        @empty = empty
      end

      def empty?
        @empty
      end

      def length
        @len
      end

      def map
        raise MsgErr
      end
    end

    class SignOnly
      def sign(_msg)
        'x'
      end
    end

    class PublicOnly
      def public
        'p'
      end
    end

    class Sized
      def empty?
        false
      end

      def length
        3
      end
    end

    class Bytes32
      def bytesize
        32
      end
    end

    module_function

    # resolved at call time: the oracle re-evaluates AtlasPca for every mutant
    def ar = AtlasPca::ActionsRegistry
    def a = AtlasPca::Actions
    def iv = AtlasPca::IntentV2
    def undef_v = AtlasPca::V2JS::UNDEF

    def on?(*files)
      f = ENV['MUT_FILE']
      f.nil? || f.empty? || files.include?(f)
    end

    def memo(key)
      MEMO[key] ||= yield
    end

    def defs = memo(:defs) { JSON.parse(DEFS_JSON) }

    def kit_err
      yield
      nil
    rescue AtlasPca::Actions::ActionKitError => e
      [e.code, e.message]
    end

    def sig(domain, body, kid = 'k1')
      { 'alg' => 'ed25519', 'kid' => kid, 'value' => AtlasPca.b64e(KP.sign(iv.send(:dmsg, domain, body))) }
    end

    def evo(over = {}, signed: true)
      r = { 'v' => 1, 'kind' => 'pca-evolution-record', 'ns' => 'stripe', 'verb' => VERB, 'from' => D1, 'to' => D2, 'class' => 'narrow',
            'reasons' => ['r'] }.merge(over)
      signed ? r.merge('sig' => sig(ar::EVOLUTION_DOMAIN, r)) : r
    end

    def reapp(diff)
      r = { 'v' => 1, 'kind' => 'pca-reapproval', 'grant' => 'g1', 'verb' => VERB, 'diff' => diff }
      yield r if block_given?
      r.merge('sig' => { 'alg' => 'ed25519', 'value' => AtlasPca.b64e(KP.sign(iv.send(:dmsg, ar::REAPPROVAL_DOMAIN, r))) })
    end

    def dn(code, reason, esc = false, needs = nil)
      out = { 'ok' => false, 'code' => code, 'escalate' => esc, 'reason' => reason }
      out['needs_reapproval'] = needs unless needs.nil?
      out
    end

    NONE = 'the definition differs from the pinned digest and no signed evolution record chains to it'
    WIDE = 'the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve'

    def pin_base = { 'pack' => { 'ns' => 'stripe', 'root' => R }, 'defs' => { VERB => D1 }, 'on_new_action' => 'deny' }
    def doc_base(digest = D2) = { 'verbs' => [{ 'verb' => VERB, 'def' => digest }], 'pack' => { 'ns' => 'stripe', 'root' => R } }

    def dp(over = {})
      { 'pin' => pin_base, 'doc' => doc_base, 'verb' => VERB, 'keys' => KEYS, 'records' => [], 'reapprovals' => [],
        'grant' => { 'id' => 'g1', 'issuer' => KP.public } }.merge(over)
    end

    def pack_body(ver: '1.0.0', prev: nil, uri: 'https://example.test/spec')
      ds = defs
      { 'v' => 1, 'kind' => 'pca-action-pack', 'ns' => 'stripe', 'version' => ver, 'stability' => 'stable',
        'traits_digest' => a.traits_digest(a::CORE_REGISTRY), 'roles_digest' => a.tables_digest, 'rules_digest' => ar.rules_digest,
        'root' => a.pack_root(ds.map { |d| a.def_digest(d) }), 'defs' => ds,
        'source' => { 'kind' => 'hand', 'uri' => uri, 'spec_digest' => D1, 'licence' => 'MIT', 'licence_notes' => '' },
        'prev' => prev, 'evolution' => [] }
    end

    def pack(**kw)
      b = pack_body(**kw)
      b.merge('sig' => sig(ar::PACK_SIG_DOMAIN, b))
    end

    def shard_pack(over = {})
      pack_body.merge('defs' => { 'shards' => [{ 'name' => 's1', 'digest' => D1, 'uri' => 'https://example.test/s1' }.merge(over)] })
    end

    # ---- undo fixtures ----
    def urec(over = {})
      { 'id' => 'rec1', 'aud' => 'aud1', 'principal' => 'p1', 'compensation_digest' => 'cd1', 'render_digest' => 'rd1', 'window_end' => 2000 }.merge(over)
    end

    def utoken = memo(:utoken) { AtlasPca.sign_undo_token(urec, KPU) }
    def ureceipt = memo(:ureceipt) { AtlasPca.sign_undo_receipt({ 'record' => 'rec1', 'event' => 'opened', 'state' => 'open', 'at' => 1000, 'compensation_digest' => 'cd1', 'prev' => '', 'note' => '' }, KPU) }

    def raised(klass)
      yield
      nil
    rescue klass => e
      e
    end
  end

  K02 = C02RegUndo
  RG02 = 'actions_registry.rb'
  UN02 = 'undo.rb'

  # ======================================================= actions_registry.rb =======================================================

  t('c02 registry: u16key is the UTF-16BE byte string, binary, ordered by code unit') do
    next true unless K02.on?(RG02)

    r = K02.ar
    r.u16key('a') == "\x00a".b && r.u16key('a').encoding == Encoding::BINARY && r.u16key("\u{1F600}") < r.u16key("\uFF21") &&
      r.u16key("\u{1F600}") == "\xD8\x3D\xDE\x00".b
  end

  t('c02 registry: is1? is the Integer one only') do
    next true unless K02.on?(RG02)

    [[1, true], [1.0, false], [2, false], ['1', false], [nil, false], [true, false]].all? { |v, want| K02.ar.is1?(v).equal?(want) }
  end

  t('c02 registry: cat is the String itself or its to_s') do
    next true unless K02.on?(RG02)

    K02.ar.cat('a') == 'a' && K02.ar.cat(5) == '5' && K02.ar.cat(:s) == 's' && K02.ar.cat(nil) == ''
  end

  t('c02 registry: closed names the first unknown member and is exactly nil otherwise') do
    next true unless K02.on?(RG02)

    K02.ar.closed({ 'a' => 1 }, ['a']).nil? && K02.ar.closed({}, []).nil? && K02.ar.closed({ 'b' => 1 }, ['a']) == "unknown member 'b'"
  end

  t('c02 registry: an evolution class that only compares equal to a class name is refused (is_a?(String) guard)') do
    next true unless K02.on?(RG02)

    r = K02.evo({ 'class' => K02::Duck.new('narrow') }, signed: false)
    K02.ar.evolution_record_error(r, false) == 'evolution record: bad class' && K02.ar.evolution_record_error(K02.evo, true).nil?
  end

  t('c02 registry: a fault while canonicalizing an evolution record is reported with the exception message') do
    next true unless K02.on?(RG02)

    rec = K02.evo
    got = MutationKill::Seam.with(AtlasPca, { :canon_bytes => ->(*) { raise K02::MsgErr } }) { K02.ar.evolution_record_error(rec, true) }
    got == 'evolution record: M'
  end

  t('c02 registry: a fault in evolution_record_error is a refusal carrying the exception message') do
    next true unless K02.on?(RG02)

    rec = K02.evo
    got = MutationKill::Seam.with(K02.ar, { :obj? => ->(*) { raise K02::MsgErr } }) { K02.ar.evolution_record_error(rec, true) }
    got == 'evolution record: M'
  end

  t('c02 registry: verify_registry_sig refusals are exact hashes') do
    next true unless K02.on?(RG02)

    dom = K02.ar::EVOLUTION_DOMAIN
    body = { 'a' => 1 }
    s = K02.sig(dom, body)
    v = ->(sg, keys) { K02.ar.verify_registry_sig(dom, body, sg, keys) }
    bad = ->(reason) { { 'ok' => false, 'reason' => reason } }
    key = K02::KEYS[0]
    v.call(s, 'x') == bad.call('the registry keys must be an array') &&
      v.call(s.merge('kid' => 'zz'), K02::KEYS) == bad.call("no registry key with kid 'zz'") &&
      v.call(s, [key.merge('pq_pk' => 5)]) == bad.call('the registry key pq_pk must be a string') &&
      v.call(s, [key.merge('pk' => 'abc')]) == bad.call('registry key pk is not canonical base64url (32 bytes)') &&
      v.call(s.merge('alg' => 'bogus-alg'), [key.merge('alg' => 'ed25519')]) == bad.call('sig.alg does not match the pinned key suite') &&
      v.call(s.merge('alg' => 'bogus-alg'), [key.merge('alg' => 'bogus-alg')]) == bad.call('sig.alg does not match the pinned key suite') &&
      v.call(K02.sig(dom, { 'a' => 2 }), K02::KEYS) == bad.call('signature invalid') && v.call(s, K02::KEYS) == { 'ok' => true }
  end

  t('c02 registry: verify_registry_sig hands the pinned PQ key (or nil) to the suite verifier') do
    next true unless K02.on?(RG02)

    dom = K02.ar::EVOLUTION_DOMAIN
    s = K02.sig(dom, { 'a' => 1 })
    calls = []
    MutationKill::Seam.with(K02.iv, { :verify_pinned_suite => ->(*a) { calls << a; true } }) do
      K02.ar.verify_registry_sig(dom, { 'a' => 1 }, s, K02::KEYS)
      K02.ar.verify_registry_sig(dom, { 'a' => 1 }, s, [K02::KEYS[0].merge('pq_pk' => 'PQ')])
    end
    calls.length == 2 && calls[0][6].nil? && calls[0][2].equal?(K02.undef_v) && calls[1][6] == { K02::KP.public => 'PQ' } && calls[1][2] == 'PQ'
  end

  t('c02 registry: a fault while verifying a registry signature is a refusal with the exception message') do
    next true unless K02.on?(RG02)

    dom = K02.ar::EVOLUTION_DOMAIN
    s = K02.sig(dom, { 'a' => 1 })
    got = MutationKill::Seam.with(K02.iv, { :strict_eq => ->(*) { raise K02::MsgErr } }) { K02.ar.verify_registry_sig(dom, { 'a' => 1 }, s, K02::KEYS) }
    got == { 'ok' => false, 'reason' => 'verification error: M' }
  end

  t('c02 registry: reapproval_valid? refuses every single flaw of an otherwise signed reapproval') do
    next true unless K02.on?(RG02)

    diff = 'F' * 43
    ok = ->(r, grant = 'g1') { K02.ar.reapproval_valid?(r, grant, K02::KP.public, K02::VERB, diff) }
    resig = ->(**kw) { K02.reapp(diff) { |r| kw.each { |k, v| r[k.to_s] = v } } }
    cases = [
      [resig.call(v: 2), 'g1'], [resig.call(kind: 'x'), 'g1'], [K02.reapp(diff) { |r| r.delete('grant') }, nil], [resig.call(grant: 'g2'), 'g1'],
      [resig.call(verb: 'stripe.other'), 'g1'], [resig.call(diff: 'G' * 43), 'g1'], [resig.call(extra: 1), 'g1'],
      [K02.reapp(diff).tap { |r| r['sig'] = r['sig'].merge('alg' => 'ml-dsa-65') }, 'g1'],
      [K02.reapp(diff).tap { |r| r['sig'] = r['sig'].merge('zz' => 1) }, 'g1']
    ]
    ok.call(K02.reapp(diff)).equal?(true) && cases.all? { |r, g| ok.call(r, g).equal?(false) } && ok.call('str').equal?(false) && ok.call(nil).equal?(false)
  end

  t('c02 registry: reapproval_valid? does not look inside a non-object record or signature (closed is not reached)') do
    next true unless K02.on?(RG02)

    diff = 'F' * 43
    calls = []
    strsig = K02.reapp(diff).merge('sig' => 'str')
    got = MutationKill::Seam.with(K02.ar, { :closed => ->(*a) { calls << a; nil } }) do
      [K02.ar.reapproval_valid?('str', 'g1', K02::KP.public, K02::VERB, diff), K02.ar.reapproval_valid?(strsig, 'g1', K02::KP.public, K02::VERB, diff)]
    end
    got == [false, false] && calls.length == 1
  end

  t('c02 registry: reapproval_valid? reaches the suite verifier only for a string signature value; a fault in it is false') do
    next true unless K02.on?(RG02)

    diff = 'F' * 43
    good = K02.reapp(diff)
    nonstr = good.merge('sig' => good['sig'].merge('value' => 123))
    calls = []
    got = MutationKill::Seam.with(K02.iv, { :verify_pinned_suite => ->(*a) { calls << a; true } }) do
      [K02.ar.reapproval_valid?(good, 'g1', K02::KP.public, K02::VERB, diff), K02.ar.reapproval_valid?(nonstr, 'g1', K02::KP.public, K02::VERB, diff)]
    end
    boom = MutationKill::Seam.with(K02.iv, { :verify_pinned_suite => ->(*) { raise K02::MsgErr } }) do
      K02.ar.reapproval_valid?(good, 'g1', K02::KP.public, K02::VERB, diff)
    end
    got == [true, false] && calls.length == 1 && boom.equal?(false)
  end

  t('c02 registry: action_pin_error refuses a name or caveat that only compares equal to a valid one (is_a?(String) guards)') do
    next true unless K02.on?(RG02)

    base = { 'pack' => { 'ns' => 'stripe', 'root' => K02::R }, 'on_new_action' => 'deny' }
    K02.ar.action_pin_error(base).nil? &&
      K02.ar.action_pin_error(base.merge('on_new_action' => K02::Duck.new('deny'))) == "actions.on_new_action must be 'deny' or 'escalate'" &&
      K02.ar.action_pin_error(base.merge('caveats' => [K02::Duck.new('amount_cap')])) == 'actions.caveats must be distinct caveat kinds'
  end

  t('c02 registry: decide_pin exact, chain (free and approved), no chain and widened, each within a deadline') do
    next true unless K02.on?(RG02)

    d = ->(i) { Timeout.timeout(2) { K02.ar.decide_pin(i) } }
    narrow = K02.evo
    wide = K02.evo({ 'class' => 'widen' })
    approval = K02.reapp(K02.ar.evolution_diff_digest(wide))
    d.call(K02.dp('doc' => K02.doc_base(K02::D1))) == { 'ok' => true, 'via' => 'exact' } &&
      d.call(K02.dp('records' => [narrow])) == { 'ok' => true, 'via' => 'chain' } &&
      d.call(K02.dp('records' => [narrow], 'reapprovals' => 5)) == { 'ok' => true, 'via' => 'chain' } &&
      d.call(K02.dp('records' => [wide], 'reapprovals' => [approval])) == { 'ok' => true, 'via' => 'chain' } &&
      d.call(K02.dp) == K02.dn('def_changed', K02::NONE) &&
      d.call(K02.dp('records' => [wide])) == K02.dn('def_changed', K02::WIDE, false, K02.ar.evolution_diff_digest(wide))
  end

  t('c02 registry: decide_pin reports the first blocked edge of the breadth-first path (a node is reached once)') do
    next true unless K02.on?(RG02)

    pa = K02.evo({ 'class' => 'widen', 'from' => K02::D1, 'to' => K02::D3 })
    pb = K02.evo({ 'class' => 'widen', 'from' => K02::D1, 'to' => K02::D4 })
    ap = K02.evo({ 'class' => 'widen', 'from' => K02::D3, 'to' => K02::D2 })
    bp = K02.evo({ 'class' => 'widen', 'from' => K02::D4, 'to' => K02::D2 })
    got = Timeout.timeout(2) { K02.ar.decide_pin(K02.dp('records' => [pa, pb, ap, bp])) }
    got == K02.dn('def_changed', K02::WIDE, false, K02.ar.evolution_diff_digest(pa))
  end

  t('c02 registry: decide_pin skips verified records of another ns or verb and added/removed ones without touching reapprovals') do
    next true unless K02.on?(RG02)

    recs = [K02.evo({ 'ns' => 'other', 'class' => 'widen' }), K02.evo({ 'verb' => 'stripe.other', 'class' => 'widen' }),
            K02.evo({ 'from' => nil, 'class' => 'added' }), K02.evo({ 'to' => nil, 'class' => 'removed' })]
    recs.all? { |r| Timeout.timeout(2) { K02.ar.decide_pin(K02.dp('records' => [r], 'reapprovals' => 5)) } == K02.dn('def_changed', K02::NONE) }
  end

  t('c02 registry: decide_pin on a non-iterable records or reapprovals value fails closed with the reference text') do
    next true unless K02.on?(RG02)

    wide = K02.evo({ 'class' => 'widen' })
    d = ->(i) { Timeout.timeout(2) { K02.ar.decide_pin(i) } }
    d.call(K02.dp('records' => 5)) == K02.dn('bad_pin', 'pin evaluation error (fail closed): object is not iterable (cannot read property Symbol(Symbol.iterator))') &&
      d.call(K02.dp('records' => [wide], 'reapprovals' => 5)) == K02.dn('bad_pin', 'pin evaluation error (fail closed): (i.reapprovals ?? []).some is not a function') &&
      d.call(K02.dp('records' => 'abc', 'reapprovals' => 5)) == K02.dn('def_changed', K02::NONE) && d.call(K02.dp('records' => nil)) == K02.dn('def_changed', K02::NONE)
  end

  t('c02 registry: decide_pin passes an empty key list to record verification when none is given') do
    next true unless K02.on?(RG02)

    seen = []
    MutationKill::Seam.with(K02.ar, { :verify_evolution_record => ->(_r, k) { seen << k; { 'ok' => false } } }) do
      K02.ar.decide_pin(K02.dp('records' => [{ 'x' => 1 }]).reject { |k, _| k == 'keys' })
      K02.ar.decide_pin(K02.dp('records' => [{ 'x' => 1 }]))
    end
    seen == [[], K02::KEYS]
  end

  t('c02 registry: decide_pin reads the schema document strictly (verbs list, verb member, pack ns and root)') do
    next true unless K02.on?(RG02)

    d = ->(i) { K02.ar.decide_pin(i) }
    unknown = ->(v) { K02.dn('unknown_verb', "the accepted schema does not declare '#{v}'") }
    mism = "the schema does not come from the pinned pack 'stripe'"
    rootbad = 'the pack root differs from the pinned root (the grant pins the pack as a whole)'
    nodefs = { 'pack' => { 'ns' => 'stripe', 'root' => K02::R }, 'on_new_action' => 'deny' }
    d.call(K02.dp('doc' => { 'verbs' => 'abc' })) == unknown.call(K02::VERB) && d.call(K02.dp('verb' => nil, 'doc' => { 'verbs' => [{}] })) == unknown.call('') &&
      d.call(K02.dp('doc' => { 'verbs' => [{ 'verb' => K02::VERB, 'def' => K02::D2 }], 'pack' => { 'root' => K02::R } })) == K02.dn('pack_mismatch', mism) &&
      d.call(K02.dp('doc' => { 'verbs' => [{ 'verb' => K02::VERB, 'def' => K02::D2 }], 'pack' => 5 })) == K02.dn('pack_mismatch', mism) &&
      d.call(K02.dp('pin' => nodefs)) == { 'ok' => true, 'via' => 'pack' } &&
      d.call(K02.dp('pin' => nodefs.merge('pack' => { 'ns' => 'stripe', 'root' => 'Z' * 43 }))) == K02.dn('pack_mismatch', rootbad) &&
      d.call(K02.dp('pin' => nodefs, 'doc' => { 'verbs' => [{ 'verb' => K02::VERB, 'def' => K02::D2 }], 'pack' => { 'ns' => 'stripe' } })) == K02.dn('pack_mismatch', rootbad) &&
      d.call(K02.dp('pin' => K02.pin_base.merge('defs' => { 'stripe.refund' => K02::D1 }))) ==
        K02.dn('new_action', "the grant does not name '#{K02::VERB}' (on_new_action: deny)") &&
      d.call(K02.dp('pin' => K02.pin_base.merge('defs' => { 'stripe.refund' => K02::D1 }, 'on_new_action' => 'escalate'))) ==
        K02.dn('new_action', "the grant does not name '#{K02::VERB}' (on_new_action: escalate)", true) &&
      d.call(K02.dp('doc' => K02.doc_base(5))) == K02.dn('def_changed', 'the schema verb carries no definition digest') &&
      d.call(K02.dp('pin' => {})) == K02.dn('bad_pin', 'actions.pack must be {ns, root}')
  end

  t('c02 registry: a fault in decide_pin is a bad_pin refusal with the exception message') do
    next true unless K02.on?(RG02)

    got = MutationKill::Seam.with(K02.ar, { :action_pin_error => ->(*) { raise K02::MsgErr } }) { K02.ar.decide_pin(K02.dp) }
    got == K02.dn('bad_pin', 'pin evaluation error (fail closed): M')
  end

  t('c02 registry: compare_versions orders MAJOR.MINOR.PATCH and names the offending argument') do
    next true unless K02.on?(RG02)

    c = K02.ar
    bad = ->(x) { ['bad_version', "'#{x}' is not MAJOR.MINOR.PATCH"] }
    c.compare_versions('1.2.3', '1.2.4') == -1 && c.compare_versions('2.0.0', '1.9.9') == 1 && c.compare_versions('1.0.0', '1.0.0').zero? &&
      c.compare_versions('10.0.0', '9.0.0').positive? && c.compare_versions('1.3.0', '1.2.9') == 1 &&
      K02.kit_err { c.compare_versions('1.0.0', 'bad') } == bad.call('bad') && K02.kit_err { c.compare_versions('bad', '1.0.0') } == bad.call('bad') &&
      K02.kit_err { c.compare_versions('x', 'y') } == bad.call('x')
  end

  t('c02 registry: sorted_unique_defs_error is exactly nil for a sorted list') do
    next true unless K02.on?(RG02)

    K02.ar.sorted_unique_defs_error(K02.defs).nil? && K02.ar.sorted_unique_defs_error(K02.defs.reverse).to_s.start_with?('defs must be sorted by verb and unique')
  end

  t('c02 registry: pack_shape_error stability, shard refs and fault text') do
    next true unless K02.on?(RG02)

    s = ->(b) { K02.ar.pack_shape_error(b, false) }
    sh = ->(over) { s.call(K02.shard_pack(over)) }
    snames = 'pack: shard names must be distinct simple names'
    sref = 'pack: bad shard digest or uri'
    orig = AtlasPca::V2JS.method(:rx?)
    names_ok = nil
    MutationKill::Seam.with(K02.ar, { :rx? => ->(re, str) { re.equal?(K02.ar::SHARD_NAME_RE) ? true : orig.call(re, str) } }) do
      names_ok = sh.call('name' => 5)
    end
    boom = MutationKill::Seam.with(K02.ar, { :obj? => ->(*) { raise K02::MsgErr } }) { K02.ar.pack_shape_error(K02.pack_body, false) }
    s.call(K02.pack_body).nil? && s.call(K02.shard_pack).nil? && s.call(K02.pack_body.merge('stability' => K02::Duck.new('stable'))) == 'pack: bad stability' &&
      names_ok == snames && sh.call('name' => 'Bad Name') == snames && sh.call('digest' => 'bad') == sref && sh.call('uri' => 5) == sref &&
      sh.call('uri' => '') == sref && sh.call('uri' => 'u' * 2049) == sref && sh.call('uri' => 'u' * 2048).nil? && sh.call('digest' => 5) == sref &&
      boom == 'pack: M'
  end

  t('c02 registry: pack_defs copies inline defs, merges shards in verb order and names every shard failure') do
    next true unless K02.on?(RG02)

    ds = K02.defs
    inline = { 'defs' => ds }
    got = K02.ar.pack_defs(inline)
    shard = { 'v' => 1, 'kind' => 'pca-action-pack-shard', 'ns' => 'stripe', 'version' => '1.0.0', 'name' => 's1', 'defs' => ds.reverse }
    pk = ->(digest) { { 'ns' => 'stripe', 'version' => '1.0.0', 'defs' => { 'shards' => [{ 'name' => 's1', 'digest' => digest, 'uri' => 'u' }] } } }
    bad = "shard 's1' is not a shard of this pack"
    got == ds && !got.equal?(ds) && K02.ar.pack_defs(pk.call(K02.ar.shard_digest(shard)), { 's1' => shard }).map { |d| d['verb'] } == ds.map { |d| d['verb'] } &&
      K02.kit_err { K02.ar.pack_defs(pk.call(K02::D1)) } == ['missing_shard', "shard 's1' was not supplied"] &&
      K02.kit_err { K02.ar.pack_defs(pk.call(K02::D1), { 's1' => shard }) } == ['shard_digest_mismatch', "shard 's1' does not match its digest"] &&
      K02.kit_err { K02.ar.pack_defs(pk.call(K02.ar.shard_digest([])), { 's1' => [] }) } == ['bad_shard', bad] &&
      K02.kit_err { K02.ar.pack_defs(pk.call(K02.ar.shard_digest(shard.merge('v' => 2))), { 's1' => shard.merge('v' => 2) }) } == ['bad_shard', bad]
  end

  t('c02 registry: verify_pack passes nil shards by default, bounds the def count and reports a fault with the exception message') do
    next true unless K02.on?(RG02)

    pk = K02.memo(:pack1) { K02.pack }
    full = K02.ar.verify_pack(pk, K02::KEYS)
    seen = []
    miss = MutationKill::Seam.with(K02.ar, { :pack_defs => ->(_p, s) { seen << s; raise AtlasPca::Actions::ActionKitError.new('missing_shard', 'm') } }) do
      K02.ar.verify_pack(pk, K02::KEYS)
    end
    big = lambda do |n, empty = false|
      MutationKill::Seam.with(K02.ar, { :pack_defs => ->(*) { K02::Big.new(n, empty) }, :sorted_unique_defs_error => ->(_d) {} }) { K02.ar.verify_pack(pk, K02::KEYS) }
    end
    boom = MutationKill::Seam.with(K02.ar, { :pack_shape_error => ->(*) { raise K02::MsgErr } }) { K02.ar.verify_pack(pk, K02::KEYS) }
    many = { 'ok' => false, 'reason' => 'the pack lists no defs or too many' }
    full['ok'] == true && full['digest'] == K02.ar.pack_digest(pk) && full['defs'] == K02.defs && miss == { 'ok' => false, 'reason' => 'm' } && seen == [nil] &&
      big.call(1, true) == many && big.call(1_000_001) == many && big.call(1_000_000) == { 'ok' => false, 'reason' => 'pack verification error: M' } &&
      boom == { 'ok' => false, 'reason' => 'pack verification error: M' }
  end

  t('c02 registry: PackTracker answers first, same, fork, rollback, chain_gap and upgrade with exact reasons') do
    next true unless K02.on?(RG02)

    p1 = K02.memo(:pack1) { K02.pack }
    fork = K02.pack(uri: 'https://example.test/other')
    old = K02.pack(ver: '0.9.0')
    gap = K02.pack(ver: '1.1.0', prev: K02::D1)
    up = K02.pack(ver: '1.1.0', prev: K02.ar.pack_digest(p1))
    t1 = K02.ar::PackTracker.new(K02::KEYS)
    got = [p1, p1, fork, old, gap, up].map { |x| t1.accept(x) }
    bad = K02.ar::PackTracker.new(K02::KEYS).accept(p1.merge('ns' => 'BAD'))
    got == [{ 'ok' => true, 'status' => 'first' }, { 'ok' => true, 'status' => 'same' },
            { 'ok' => false, 'code' => 'fork', 'reason' => 'two different packs claim one version' },
            { 'ok' => false, 'code' => 'rollback', 'reason' => 'older than the accepted version' },
            { 'ok' => false, 'code' => 'chain_gap', 'reason' => 'prev does not name the accepted pack' },
            { 'ok' => true, 'status' => 'upgrade' }] && bad['ok'] == false && bad['code'] == 'bad_pack' && bad['reason'] == 'pack: bad ns'
  end

  t('c02 registry: PackTracker#accept passes nil shards to verify_pack by default') do
    next true unless K02.on?(RG02)

    seen = []
    got = MutationKill::Seam.with(K02.ar, { :verify_pack => ->(_p, _k, s) { seen << s; { 'ok' => false, 'reason' => 'x' } } }) do
      K02.ar::PackTracker.new(K02::KEYS).accept({})
    end
    got == { 'ok' => false, 'code' => 'bad_pack', 'reason' => 'x' } && seen == [nil]
  end

  t('c02 registry: code_of names the rule 22 code or unknown; rule22_integrity passes nil pins by default') do
    next true unless K02.on?(RG02)

    seen = []
    ok = MutationKill::Seam.with(K02.a, { :schema_floor_error => ->(d, p) { seen << [d, p]; nil } }) { K02.ar.rule22_integrity({ 'doc' => 1 }) }
    K02.ar.code_of(nil) == { 'ok' => true } && K02.ar.code_of('x: unknown_trait y') == { 'ok' => false, 'code' => 'unknown_trait' } &&
      K02.ar.code_of('zzz') == { 'ok' => false, 'code' => 'unknown' } && ok == { 'ok' => true } && seen == [[{ 'doc' => 1 }, nil]] && seen[0][1].nil?
  end

  t('c02 registry: rule22_decide filters the grant caveats and the call context to known kinds and needs two arrays') do
    next true unless K02.on?(RG02)

    floors = { 'risk' => 0, 'rev' => 'reversible', 'blast_ppm' => 0, 'esc' => 0, 'caveats' => ['amount_cap'], 'context' => ['idempotency'], 'prules' => [] }
    doc = { 'verbs' => [{ 'verb' => K02::VERB, 'floors' => floors }] }
    free = { 'verbs' => [{ 'verb' => K02::VERB, 'floors' => floors.merge('caveats' => [], 'context' => []) }] }
    g = ->(cav) { { 'caveats' => cav, 'max_esc' => 3, 'preauth_esc' => 3 } }
    d = ->(dc, grant, ctx) { K02.ar.rule22_decide(dc, K02::VERB, grant, ctx) }
    d.call(doc, g.call(['amount_cap']), ['idempotency']) == 'allow' && d.call(doc, g.call([]), ['idempotency']) == 'escalate' &&
      d.call(doc, g.call(['amount_cap']), []) == 'escalate' &&
      d.call(doc, g.call([K02::Evil.new('bogus')]), ['idempotency']) == 'escalate' && d.call(doc, g.call([K02::Duck.new('amount_cap')]), ['idempotency']) == 'escalate' &&
      d.call(doc, g.call(['amount_cap']), [K02::Evil.new('bogus')]) == 'escalate' && d.call(doc, g.call(['amount_cap', 7]), ['idempotency']) == 'allow' &&
      d.call(free, g.call([]), {}) == 'deny' && d.call(free, g.call([]), nil) == 'deny' && d.call(free, g.call(nil), []) == 'deny' &&
      d.call(free, g.call([]), []) == 'allow' && K02.ar.rule22_decide(free, 'stripe.unknown', g.call([]), []) == 'deny' &&
      d.call({ 'verbs' => [{ 'verb' => K02::VERB, 'floors' => {} }] }, g.call([]), []) == 'deny'
  end

  # ============================================================ undo.rb ============================================================

  t('c02 undo: UndoError keeps its message and code; undo_get refuses null; undo_defined! refuses an undefined member') do
    next true unless K02.on?(UN02)

    e = AtlasPca::UndoError.new('c1', 'm1')
    h = { 'a' => 1 }
    e.message == 'm1' && e.code == 'c1' && AtlasPca::MAX_UNDO_TOKEN_TEXT == 4096 &&
      K02.raised(TypeError) { AtlasPca.undo_get(nil, 'k') }&.message == "Cannot read properties of null (reading 'k')" &&
      AtlasPca.undo_get(h, 'a') == 1 && AtlasPca.undo_get(h, 'b').equal?(K02.undef_v) &&
      K02.raised(ArgumentError) { AtlasPca.undo_defined!({ 'a' => K02.undef_v }) }&.message == 'canonicalize: unsupported type undefined' &&
      AtlasPca.undo_defined!(h).equal?(h)
  end

  t('c02 undo: undo_key takes a signer object or a 32-byte seed and refuses everything else with signer_missing') do
    next true unless K02.on?(UN02)

    err = lambda do |k|
      e = K02.raised(AtlasPca::UndoError) { AtlasPca.undo_key(k) }
      e && [e.code, e.message]
    end
    want = ['signer_missing', 'the undo service key must be a 32-byte Ed25519 secret']
    [K02::SignOnly.new, K02::PublicOnly.new, K02::Bytes32.new, 'x' * 31, 'x' * 33, nil, 5].all? { |k| err.call(k) == want } &&
      AtlasPca.undo_key(K02::KPU).equal?(K02::KPU) && AtlasPca.undo_key('u' * 32).public == K02::KPU.public
  end

  t('c02 undo: undo_id_ok? is a string of 1..256 UTF-16 units without control characters (and reads lone surrogates as bytes)') do
    next true unless K02.on?(UN02)

    cases = [['a', true], ['a' * 256, true], ['a' * 257, false], ["\u{1F600}" * 128, true], ["\u{1F600}" * 128 + 'a', false], ['', false], [nil, false],
             [5, false], ["a\x1fb", false], ["a\x00b", false], ['a b', true], ["ab\xED\xA0\x80", true]]
    cases.all? { |s, want| AtlasPca.undo_id_ok?(s).equal?(want) }
  end

  t('c02 undo: undo_message is the binary domain followed by the strict canonical body') do
    next true unless K02.on?(UN02)

    m = AtlasPca.undo_message(AtlasPca::UNDO_TOKEN_DOMAIN, { 'a' => 1 })
    m == AtlasPca::UNDO_TOKEN_DOMAIN.b + AtlasPca.wb_canon_bytes({ 'a' => 1 }) && m.encoding == Encoding::BINARY
  end

  t('c02 undo: undo_token_check takes a plain object only, reports a verifier fault as signature and a null record as malformed') do
    next true unless K02.on?(UN02)

    tok = K02.utoken
    rec = K02.urec
    pub = K02::KPU.public
    chk = ->(t, r = rec, now = 1000) { AtlasPca.undo_token_check(t, pub, r, now) }
    boom = MutationKill::Seam.with(AtlasPca, { :verify_b64u => ->(*) { raise K02::MsgErr } }) { chk.call(tok) }
    chk.call(tok) == 'ok' && chk.call(tok, rec, 2000) == 'ok' && chk.call(tok, rec, 2001) == 'expired' && chk.call(K02::HashLike.new(tok)) == 'malformed' &&
      chk.call(tok.merge('zz' => 1)) == 'malformed' && chk.call('str') == 'malformed' && chk.call(tok, nil) == 'malformed' && boom == 'signature' &&
      AtlasPca.undo_token_check(tok, 'other', rec, 1000) == 'signer' && chk.call(tok.merge('aud' => 'x')) == 'signature' &&
      chk.call(tok, rec.merge('id' => 'other')) == 'record' && chk.call(tok, rec.merge('aud' => 'zz')) == 'binding' && chk.call(tok, 5) == 'record'
  end

  t('c02 undo: decode_undo_token looks at the text only when it is a non-empty string of at most 4096 characters') do
    next true unless K02.on?(UN02)

    tok = K02.utoken
    calls = []
    outs = nil
    MutationKill::Seam.with(AtlasPca, { :b64d => ->(*a) { calls << a; nil } }) do
      outs = [K02::Sized.new, '', 'A' * 4097, nil, 5].map { |s| AtlasPca.decode_undo_token(s) }
      before = calls.length
      outs << before
      AtlasPca.decode_undo_token('A' * 4096)
    end
    enc = AtlasPca.encode_undo_token(tok)
    outs == [nil, nil, nil, nil, nil, 0] && calls.length == 1 && AtlasPca.decode_undo_token(enc) == tok &&
      [AtlasPca.b64e('[1]'), AtlasPca.b64e("\xFF{}".b), AtlasPca.b64e('{"a":1,"a":2}'), AtlasPca.b64e("\xEF\xBB\xBF{}".b), 'a%', ''].all? { |s| AtlasPca.decode_undo_token(s).nil? }
  end

  t('c02 undo: verify_undo_receipt checks every member, the length and the signer (signature check spied)') do
    next true unless K02.on?(UN02)

    base = K02.ureceipt
    pub = K02::KPU.public
    flaws = [->(r) { r['v'] = 2 }, ->(r) { r['kind'] = 'x' }, ->(r) { r['record'] = '' }, ->(r) { r['event'] = 'bogus' }, ->(r) { r['state'] = 'bogus' },
             ->(r) { r['at'] = 'x' }, ->(r) { r['compensation_digest'] = 5 }, ->(r) { r['prev'] = 5 }, ->(r) { r['note'] = 5 },
             ->(r) { r['signer'] = 'other' }, ->(r) { r['sig'] = 'xx' }, ->(r) { r['zz'] = 1 }, ->(r) { r.delete('note') }]
    stubbed = MutationKill::Seam.with(AtlasPca, { :undo_signed_ok? => ->(*) { true } }) do
      v = ->(r, sg = pub) { AtlasPca.verify_undo_receipt(r, sg) }
      v.call(base).equal?(true) && flaws.all? { |f| r = base.dup; f.call(r); v.call(r).equal?(false) } && v.call(base.merge('signer' => 5), 5).equal?(false) &&
        v.call(K02::HashLike.new(base)).equal?(false) && v.call('str').equal?(false) && v.call(nil).equal?(false)
    end
    boom = MutationKill::Seam.with(AtlasPca, { :undo_signed_ok? => ->(*) { raise K02::MsgErr } }) { AtlasPca.verify_undo_receipt(base, pub) }
    stubbed && boom.equal?(false) && AtlasPca.verify_undo_receipt(base, pub) && !AtlasPca.verify_undo_receipt(base.merge('note' => 'zz'), pub) &&
      !AtlasPca.verify_undo_receipt(base, K02::KP.public)
  end

  t('c02 undo: undo_receipt_chain_error and undo_with_receipt link each receipt to the digest of the previous one') do
    next true unless K02.on?(UN02)

    pub = K02::KPU.public
    k = K02::KPU
    rec0 = { 'id' => 'rec1', 'compensation_digest' => 'cd1', 'state' => 'open', 'receipts' => [] }
    rec1 = AtlasPca.undo_with_receipt(rec0, { 'event' => 'opened', 'note' => '' }, 1000, k)
    rec2 = AtlasPca.undo_with_receipt(rec1, { 'event' => 'effect', 'note' => '' }, 1001, k)
    rec3 = AtlasPca.undo_with_receipt(rec2, { 'event' => 'effect', 'note' => '' }, 1002, k)
    r = rec3['receipts']
    odd = AtlasPca.undo_with_receipt(rec0.merge('receipts' => 'abc'), { 'event' => 'opened', 'note' => '' }, 1000, k)
    boom = MutationKill::Seam.with(AtlasPca, { :verify_undo_receipt => ->(*) { raise K02::MsgErr } }) { AtlasPca.undo_receipt_chain_error(rec1, pub) }
    err = ->(x) { AtlasPca.undo_receipt_chain_error(x, pub) }
    rec1['receipts'][0]['prev'] == '' && r[1]['prev'] == AtlasPca.undo_receipt_digest(r[0]) && r[2]['prev'] == AtlasPca.undo_receipt_digest(r[1]) &&
      r[2]['prev'] != AtlasPca.undo_receipt_digest(r[0]) && odd['receipts'].length == 1 && odd['receipts'][0]['prev'] == '' &&
      err.call(rec1).nil? && err.call(rec3).nil? && err.call(nil) == 'no receipts' && err.call(rec0) == 'no receipts' &&
      err.call(rec1.merge('receipts' => 'abc')) == 'no receipts' && err.call(rec1.merge('receipts' => { 'a' => 1 })) == 'no receipts' &&
      boom == 'evaluation error (fail closed)'
  end

  t('c02 undo: undo_transition copies the veto, clips reasons by UTF-16 units and reports a fault exactly') do
    next true unless K02.on?(UN02)

    orec = { 'state' => 'open', 'window_end' => 2000, 'ver' => 3 }
    tr = ->(rec, ev, now = 1000) { AtlasPca.undo_transition(rec, ev, now) }
    veto = { 'at' => 1000, 'via' => 'token', 'by' => 'p1' }
    vr = tr.call(orec, { 'kind' => 'veto', 'veto' => veto })
    ab = lambda do |s|
      r = tr.call(orec, { 'kind' => 'abort', 'reason' => s })
      [r['receipt']['note'].b, r['record']['outcome']['reason'].b]
    end
    a127 = 'a' * 127
    s1 = a127 + "\u{1F600}" + 'b'
    s2 = a127 + "\u{10000}" + 'b'
    s3 = a127 + "\u{1F600}"
    s4 = ('a' * 126) + "\u{1F600}" + 'bb'
    s5 = ('a' * 511) + "\u{10000}" + 'b'
    s7 = ('a' * 126) + "\xC3" + "\u{1F600}" + 'z'
    s8 = 'ab' + "\xC3"
    cf = tr.call({ 'state' => 'vetoed', 'window_end' => 2000, 'ver' => 3 }, { 'kind' => 'compensation_failed', 'reason' => s1 })
    fin = { 'state' => 'finalized', 'window_end' => 2000, 'ver' => 1, 'outcome' => [] }
    boom = MutationKill::Seam.with(AtlasPca, { :wb_safe_int? => ->(*) { raise K02::MsgErr } }) { tr.call(orec, { 'kind' => 'finalize' }) }
    vr['outcome'] == 'applied' && vr['record']['veto'] == veto && !vr['record']['veto'].equal?(veto) && vr['record']['ver'] == 4 &&
      vr['receipt'] == { 'event' => 'vetoed', 'note' => 'token' } &&
      ab.call(s1) == [a127.b, s1.b] && ab.call(s2) == [a127.b, s2.b] && ab.call(s3) == [a127.b, s3.b] &&
      ab.call(s4) == [(('a' * 126) + "\u{1F600}").b, s4.b] && ab.call(s5) == [('a' * 128).b, ('a' * 511).b] &&
      ab.call(s7) == [(('a' * 126) + "�").b, s7.b] && ab.call(s8) == [s8.b, s8.b] && ab.call("é".b) == ["é".b, "é".b] &&
      cf['record']['outcome'] == { 'at' => 1000, 'status' => 'compensation_failed', 'reason' => s1 } && cf['receipt'] == { 'event' => 'compensation_failed', 'note' => a127 } &&
      tr.call(fin, { 'kind' => 'abort', 'reason' => 'x' }) == { 'outcome' => 'refused', 'code' => 'finalized', 'reason' => 'a finalized record cannot be aborted' } &&
      tr.call(fin.merge('outcome' => { 'status' => 'aborted' }), { 'kind' => 'abort', 'reason' => 'x' }) ==
        { 'outcome' => 'replayed', 'record' => fin.merge('outcome' => { 'status' => 'aborted' }) } &&
      boom == { 'outcome' => 'refused', 'code' => 'invalid', 'reason' => 'evaluation error (fail closed)' }
  end

  t('c02 undo: undo_policy reads own non-nil members (string or symbol key) and is exactly nil otherwise') do
    next true unless K02.on?(UN02)

    up = ->(pol) { AtlasPca.undo_policy(pol, 'minMs', 'min_ms') }
    up.call(nil).nil? && up.call(5).nil? && up.call('x').nil? && up.call({}).nil? && up.call(Hash.new(7)).nil? && up.call({ 'minMs' => nil, 'min_ms' => 5 }) == 5 &&
      up.call({ minMs: 3 }) == 3 && up.call({ 'minMs' => 1, 'min_ms' => 2 }) == 1 && up.call({ 'min_ms' => 2 }) == 2 && up.call({ 'minMs' => nil }).nil?
  end

  t('c02 undo: resolve_undo_window clamps into [min, max], floors, and takes the default for anything but a finite number') do
    next true unless K02.on?(UN02)

    w = ->(*a) { AtlasPca.resolve_undo_window(*a) }
    w.call(40_000, { 'min_ms' => 60_000 }) == 60_000 && w.call(40_000, { 'minMs' => 60_000 }) == 60_000 && w.call('abc') == 900_000 && w.call(nil) == 900_000 &&
      w.call(10**400) == 900_000 && w.call(Float::NAN) == 900_000 && w.call(Float::INFINITY) == 900_000 && w.call(45_000.5) == 45_000 &&
      w.call(10**12) == 86_400_000 && w.call(1) == 30_000 && w.call(nil, { 'default_ms' => 50_000 }) == 50_000 && w.call(nil, { 'defaultMs' => 50_000 }) == 50_000 &&
      w.call(10**9, { 'max_ms' => 100_000 }) == 100_000 && w.call(10**9, { 'maxMs' => 100_000 }) == 100_000 && w.call(100_000_000) == 86_400_000
  end
end
