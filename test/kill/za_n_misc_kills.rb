# frozen_string_literal: true

# Exact kills for small survivors in atlas_pca.rb (the pq_pin rule of verify_pcactn, the beacons require), rack_middleware.rb (the
# authorize option keys), atomic_kv.rb, blueprint.rb, predicates.rb (js_number_string), sigstore_bundle.rb / attest/{common,cert,der,
# nvidia}.rb (OID arc limits, JSON depth counter, RSA key rule). AtlasPca is resolved at CALL time (the mutation oracle re-evaluates
# the library per mutant). Helpers come from c06 / c30 (loaded earlier: alphabetical order).
require 'openssl'
require 'atlas_pca/attest'
require 'atlas_pca/sigstore_bundle'

module MutationKill
  module ZaN
    module_function

    def on?(*files) = (f = ENV['MUT_FILE']).nil? || f.empty? || files.include?(f)

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end

    def err
      yield
      nil
    rescue Exception => e # rubocop:disable Lint/RescueException
      [e.class, e.message]
    end

    def com = AtlasPca::Attest::Common

    # a key object that is none of EC / RSA, whose SPKI carries a usable RSA key and whose verify always says yes
    class Duck
      def initialize(der) = @der = der
      def oid = 'duck'
      def public_to_der = @der
      def verify(*) = true
    end

    def rsa_spki = (@rsa_spki ||= OpenSSL::PKey::RSA.generate(2048).public_to_der)

    def pin_verify(pins, grant = MutationKill::C06.base['grant'])
      AtlasPca.verify_pcactn(MutationKill::C06.fixture_pcactn, grant, now: MutationKill::C06::NOW, audience: MutationKill::C06.aud,
                                                                      insecure_skip_plan_root_check: true, pq_pins: pins)
    end
  end

  t('za_n verify_pcactn pq_pin rule: only a pinned issuer of a classical Hash grant is refused') do
    next true unless ZaN.on?('atlas_pca.rb')

    g = MutationKill::C06.base['grant']
    iss = g['issuer']
    pinned = ZaN.pin_verify({ iss => 'pinned-pk' })
    ZaN.ck('pinned classical root', [pinned.allow, pinned.checks['pq_pin']], [false, false]) &&
      ZaN.ck('an unpinned issuer', ZaN.pin_verify({ 'another-issuer' => 'pk' }).checks.key?('pq_pin'), false) &&
      ZaN.ck('a post-quantum grant', ZaN.pin_verify({ iss => 'pinned-pk' }, g.merge('alg' => 'ml-dsa-65')).checks.key?('pq_pin'), false) &&
      ZaN.ck('a non-Hash grant', ZaN.pin_verify({ 'issuer' => 'pk' }, 'issuer').checks.key?('pq_pin'), false) &&
      ZaN.ck('pins that are not a Hash', ZaN.pin_verify([]).checks, MutationKill::C06.honest.checks) &&
      ZaN.ck('no pins', ZaN.pin_verify(nil).checks, MutationKill::C06.honest.checks)
  end

  t('za_n beacons: the extension is loaded with the library') do
    next true unless ZaN.on?('atlas_pca.rb', 'beacons.rb')

    b = { 'a' => 1 }
    ZaN.ck('beacon_ref', AtlasPca.beacon_ref(b), AtlasPca.hash_canonical(b)) &&
      ZaN.ck('acceptor class', AtlasPca::BeaconAcceptor.is_a?(Class), true)
  end

  t('za_n rack middleware: every authorize option key is accepted and stored') do
    next true unless ZaN.on?('rack_middleware.rb')

    keys = %i[require_risk_inputs passport enforce_taint contracts resolve_principal enforce_freshness beacon threshold_hook
              require_verified_principal adaptive require_linked_template pq_pins require_passport seed_budget forbid]
    store = AtlasPca::MemoryStateStore.new
    keys.each do |k|
      v = Object.new
      m = AtlasPca::RackMiddleware.new(nil, audience: 'a', resolve_grant: ->(_r) {}, authorize: { state_store: store, k => v })
      ZaN.ck("authorize key #{k}", m.instance_variable_get(:@authorize).public_send(k).equal?(v), true)
    end
    true
  end

  t('za_n atomic kv: shard_of takes any id by its text, pin_shards refuses a non-Hash answer') do
    next true unless ZaN.on?('atomic_kv.rb')

    pin = ->(ans) { AtlasPca.kv_pin_shards(Class.new { define_method(:update) { |_k, &_b| ans } }.new, 'm', 16) }
    ZaN.ck('integer id', AtlasPca.kv_shard_of(5, 16), AtlasPca.kv_shard_of('5', 16)) &&
      ZaN.ck('symbol id', AtlasPca.kv_shard_of(:abc, 4096), AtlasPca.kv_shard_of('abc', 4096)) &&
      ZaN.ck('nil answer', pin.call(nil), false) &&
      ZaN.ck('array answer', pin.call(['shards']), false) &&
      ZaN.ck('matching answer', pin.call({ 'shards' => 16 }), true) &&
      ZaN.ck('other count', pin.call({ 'shards' => 4 }), false)
  end

  t('za_n blueprint: an accepted epoch equal to the stored maximum leaves the epoch record untouched') do
    next true unless ZaN.on?('blueprint.rb')

    c = MutationKill::C30
    k1 = c.pk('op1')
    kv = AtlasPca::MemoryBlueprintKv.new
    reg = AtlasPca::BlueprintRegistry.new([k1], kv)
    kv.set('blueprint/epoch', { 'v' => 1, 'max' => 1, 'extra' => true })
    r1 = c.sign_bp(c.bp('operator' => k1, 'epoch' => 1), 'op1')
    r2 = c.sign_bp(c.bp('operator' => k1, 'epoch' => 2), 'op1')
    ZaN.ck('accept at the maximum', reg.accept(r1), { 'ok' => true, 'replaced' => true }) &&
      ZaN.ck('record untouched', kv.get('blueprint/epoch'), { 'v' => 1, 'max' => 1, 'extra' => true }) &&
      ZaN.ck('accept above', reg.accept(r2), { 'ok' => true, 'replaced' => true }) &&
      ZaN.ck('record raised', kv.get('blueprint/epoch'), { 'v' => 1, 'max' => 2 })
  end

  t('za_n predicates js_number_string: an Integer prints as the double, a non-number is refused') do
    next true unless ZaN.on?('predicates.rb')

    pr = AtlasPca::Predicates
    ZaN.ck('integers', [12, 0, -7, 10**20, 10**21, 2**53].map { |i| pr.js_number_string(i) },
           ['12', '0', '-7', '100000000000000000000', '1e+21', '9007199254740992']) &&
      ZaN.ck('nil', ZaN.err { pr.js_number_string(nil) }&.first, NoMethodError) &&
      ZaN.ck('string', ZaN.err { pr.js_number_string('5') }&.first, NoMethodError)
  end

  t('za_n sigstore oid: the first arc may use 64 groups') do
    next true unless ZaN.on?('sigstore_bundle.rb')

    big = (0...64).sum { |k| 128**k }
    content = ("\x81".b * 63) + "\x01".b
    der = [6, content.bytesize].pack('CC') + content
    s = AtlasPca::SigstoreBundle
    ZaN.ck('64-group first arc', s.oid(der, s.tlv(der, 0)), "2.#{big - 80}")
  end

  t('za_n attest der oid_to_dotted: the group count restarts for the second arc') do
    next true unless ZaN.on?('der.rb')

    big = (0...64).sum { |k| 128**k }
    bytes = "\x2a".b + ("\x81".b * 63) + "\x01".b
    d = AtlasPca::Attest::Der
    ZaN.ck('64-group second arc', d.oid_to_dotted(bytes, d::Tlv.new(0x06, 0, bytes.bytesize)), "1.2.#{big}")
  end

  t('za_n attest json: the depth counter restores after each container; a stack overflow is a JsError') do
    next true unless ZaN.on?('common.rb')

    c = ZaN.com
    js = AtlasPca::Attest::JsError
    stack = [js, 'Maximum call stack size exceeded']
    siblings = c.js_json_loads("[#{(['[]'] * 600).join(',')}]")
    objects = c.js_json_loads("[#{(['{}'] * 600).join(',')}]")
    after_leaf = "[[],#{'[' * 512}#{']' * 512}]"
    orig = JSON.method(:parse)
    JSON.define_singleton_method(:parse) { |*_a, **_k| raise SystemStackError }
    overflow = begin
      ZaN.err { c.js_json_loads('[1]') }
    ensure
      JSON.define_singleton_method(:parse, orig)
    end
    ZaN.ck('600 sibling arrays', siblings.length, 600) && ZaN.ck('600 sibling objects', objects.length, 600) &&
      ZaN.ck('513 deep after a closed sibling', ZaN.err { c.js_json_loads(after_leaf) }, stack) &&
      ZaN.ck('a stack overflow of the parser', overflow, stack)
  end

  t('za_n attest rsa key rule: only RSA keys qualify, whatever the key object claims') do
    next true unless ZaN.on?('common.rb', 'cert.rb')

    c = ZaN.com
    n = OpenSSL::BN.new(((2**2047) + 1).to_s)
    ints = OpenSSL::ASN1::Integer(n).to_der + OpenSSL::ASN1::Integer(65_537).to_der
    ctx = "\xA0".b + [0x82, ints.bytesize].pack('Cn') + ints # a [0] constructed value in place of the RSAPublicKey SEQUENCE
    algid = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('rsaEncryption'), OpenSSL::ASN1::Null.new(nil)])
    ctx_spki = OpenSSL::ASN1::Sequence([algid, OpenSSL::ASN1::BitString(ctx)]).to_der
    duck = ZaN::Duck.new(ZaN.rsa_spki)
    pss_alg = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('1.2.840.113549.1.1.10')]).to_der
    ZaN.ck('an EC key', c.rsa_key_ok?(OpenSSL::PKey::EC.generate('prime256v1')), false) &&
      ZaN.ck('a non-key', c.rsa_key_ok?(Object.new), false) &&
      ZaN.ck('a [0] wrapped key is read from its value', c.rsa_key_ok?(ZaN::Duck.new(ctx_spki)), true) &&
      ZaN.ck('pkcs1: a key of another type', c.rsa_pkcs1_verify(duck, 'sig'.b, 'data'.b, 'sha256'), false) &&
      ZaN.ck('pss: a key of another type', AtlasPca::Attest::Cert.verify_signature(pss_alg, 'msg'.b, 'sig'.b, duck), false)
  end

  t('za_n attest nvidia: the CRL distribution point OID constant is a frozen binary string') do
    next true unless ZaN.on?('nvidia.rb')

    v = AtlasPca::Attest::Nvidia::CDP_OID_DER
    ZaN.ck('value', v, "\x06\x03\x55\x1d\x1f".b) && ZaN.ck('frozen', v.frozen?, true) && ZaN.ck('binary', v.encoding, Encoding::BINARY)
  end
end
