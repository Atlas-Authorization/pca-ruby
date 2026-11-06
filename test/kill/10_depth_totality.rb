# frozen_string_literal: true

# Depth caps (MAX_JSON_DEPTH = 32, counted like the TypeScript reference: the outermost container is depth 1) on EVERY
# recursive walk over untrusted JSON, and totality (R6-05) of the public verify entry points: a hostile value of any
# depth is a clean refusal, never an escaping exception (SystemStackError is not a StandardError, so an uncapped
# recursion escaped the `rescue StandardError` totality wrappers).
require 'openssl'
require 'stringio'

module MutationKill
  module Depth
    module_function

    def nested(n)
      v = []
      (n - 1).times { v = [v] }
      v
    end

    def nested_text(n) = ('[' * n) + (']' * n)

    def malformed?
      yield
      false
    rescue AtlasPca::Malformed
      true
    end

    def key(label)
      OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest("ruby-kill/#{label}"))
    end

    def pub(k) = AtlasPca.b64e(k.raw_public_key)

    # A correctly SIGNED root whose single caveat carries `n` nested arrays: the hop body is depth n + 3
    # (body 1, caveats 2, caveat 3, arrays 4..n+3). The digest is computed from the canonical text built here (no cap),
    # so the signature is genuine at any depth and only the depth cap can refuse it.
    def deep_root(n)
      p = key('principal')
      a = key('agent')
      canon = "{\"caveats\":[{\"type\":\"deep\",\"v\":#{nested_text(n)}}],\"holder\":\"#{pub(a)}\"," \
              "\"issuer\":\"#{pub(p)}\",\"parent\":null}"
      d = Digest::SHA256.digest(canon.b)
      sig = p.sign(nil, AtlasPca::CAP_DOMAIN + d)
      id = AtlasPca.b64e(d)
      [{ 'id' => id, 'issuer' => pub(p), 'holder' => pub(a), 'caveats' => [{ 'type' => 'deep', 'v' => nested(n) }],
         'body_digest' => id, 'sig' => AtlasPca.b64e(sig) }, pub(p)]
    end

    def chain_ok(n)
      root, iss = deep_root(n)
      AtlasPca.verify_chain([root], iss, true)
    end
  end

  # canonicalize / hash_canonical: the strict canonical form refuses depth > 32 (reference canonicalizeStrict).
  t('canonicalize depth 31/32 ok') { AtlasPca.canonicalize(Depth.nested(31)) == Depth.nested_text(31) && AtlasPca.canonicalize(Depth.nested(32)) == Depth.nested_text(32) }
  t('canonicalize depth 33 refused') { Depth.malformed? { AtlasPca.canonicalize(Depth.nested(33)) } }
  t('canonicalize object depth 33 refused') do
    o = 1
    33.times { o = { 'a' => o } }
    Depth.malformed? { AtlasPca.canonicalize(o) }
  end
  t('canonicalize object depth 32 ok') do
    o = 1
    32.times { o = { 'a' => o } }
    AtlasPca.canonicalize(o) == ('{"a":' * 32) + '1' + ('}' * 32)
  end
  t('hash_canonical depth 100000 refused cleanly') { Depth.malformed? { AtlasPca.hash_canonical(Depth.nested(100_000)) } }

  # strict parser: 31/32 accepted, 33 and 100000 refused with Malformed (never SystemStackError)
  t('parse_json strict depth 31/32/33/100000') do
    AtlasPca.parse_json(Depth.nested_text(31), any_top: true) == Depth.nested(31) &&
      AtlasPca.parse_json(Depth.nested_text(32), any_top: true) == Depth.nested(32) &&
      Depth.malformed? { AtlasPca.parse_json(Depth.nested_text(33), any_top: true) } &&
      Depth.malformed? { AtlasPca.parse_json(Depth.nested_text(100_000), any_top: true) }
  end
  # loose mode (reading the conformance file) has no depth cap, but running out of stack is a Malformed, not a crash
  t('parse_json loose depth 100000 never raises SystemStackError') do
    begin
      AtlasPca.parse_json(Depth.nested_text(100_000), loose: true, any_top: true).is_a?(Array)
    rescue AtlasPca::Malformed
      true
    end
  end

  # verify_chain over a genuinely signed root: body depth 31/32 verifies, 33 is refused (reference: capHash is strict),
  # 100000 is a clean refusal.
  t('verify_chain hop depth 31 ok') { Depth.chain_ok(28) == ['', true] }
  t('verify_chain hop depth 32 ok') { Depth.chain_ok(29) == ['', true] }
  t('verify_chain hop depth 33 refused') { Depth.chain_ok(30).last == false }
  t('verify_chain hop depth 100000 refused, no raise') { Depth.chain_ok(100_000).last == false }

  # verify_pcactn: a hostile (deep) grant or pcactn is a verdict, never an exception
  t('verify_pcactn deep grant is a verdict') do
    v = Corpus.core['vectors'].find { |x| x['expect']['allow'] == true && x['pcactn'].is_a?(Hash) && x['requires'].nil? }
    g = v['grant'].merge('deep' => Depth.nested(100_000))
    r = AtlasPca.verify_pcactn(v['pcactn'], g, now: v['context']['now'], audience: v['context']['aud'])
    r.is_a?(AtlasPca::Verdict) && r.allow == false && r.checks['chain'] == false
  end
  t('verify_pcactn deep pcactn hash is a wire refusal') do
    v = Corpus.core['vectors'].find { |x| x['expect']['allow'] == true && x['pcactn'].is_a?(Hash) && x['requires'].nil? }
    p = v['pcactn'].merge('risk_claim' => v['pcactn']['risk_claim'].merge('inputs' => { 'x' => Depth.nested(100_000) }))
    r = AtlasPca.verify_pcactn(p, v['grant'], now: v['context']['now'], audience: v['context']['aud'])
    r.allow == false && r.checks == { 'wire' => false }
  end
  t('verify_threshold_share deep entry is false') do
    AtlasPca.verify_threshold_share({ 'role' => 'agent', 't' => 1, 'signer_set' => Depth.nested(100_000),
                                      'threshold_message' => 'AA', 'share' => Depth.nested(100_000) }) == false
  end
  t('signer_set_hash invalid-encoding role is nil, not a raise') do
    AtlasPca.signer_set_hash([{ 'role' => "\xff".dup.force_encoding('UTF-8'), 'publicKey' => 'x' }]).nil?
  end

  # Rack body mode, as the reference defaultExtract: the WHOLE {"pcactn": ...} body is strict-parsed with the cap of 32, so
  # the envelope counts (a PCActn of depth 31 fits, 32 does not); duplicate keys anywhere are refused (R6-01).
  # A fitting PCActn with a broken signature is a 403; a refused body is a 401 decode error.
  t('middleware body: whole envelope capped at 32, duplicate keys refused') do
    v = Corpus.core['vectors'].find { |x| x['expect']['allow'] == true && x['pcactn'].is_a?(Hash) && x['requires'].nil? }
    grant = v['grant']
    mw = AtlasPca::RackMiddleware.new(->(_e) { [200, {}, ['ok']] }, audience: v['context']['aud'],
                                                                    resolve_grant: ->(_r) { grant }, now: v['context']['now'], signature_only: true)
    status = lambda do |n| # pcactn(1) risk_claim(2) inputs(3) arrays 4..n+3
      p = v['pcactn'].merge('risk_claim' => v['pcactn']['risk_claim'].merge('inputs' => { 'zz_depth_probe' => 0 }))
      text = "{\"pcactn\":#{AtlasPca.canonicalize(p).sub('"zz_depth_probe":0', "\"zz_depth_probe\":#{Depth.nested_text(n)}")}}"
      mw.call('rack.input' => StringIO.new(text)).first
    end
    dup = "{\"pcactn\":#{AtlasPca.canonicalize(v['pcactn']).sub('{', '{"aud":"evil",')}}"
    status.call(28) == 403 && status.call(29) == 401 && mw.call('rack.input' => StringIO.new(dup)).first == 401
  end
end
