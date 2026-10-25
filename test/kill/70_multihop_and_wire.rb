# frozen_string_literal: true

require 'openssl'

# A genuinely signed TWO-hop chain (built here with OpenSSL keys) for the paths the TS corpus does not reach in Ruby:
# attenuation reasons, and a pure ML-DSA-65 LEAF whose key is bound by the LEAF hop's holder_pq (not the root's). Plus
# closed?, number?, the share-role binding, every registered PQ key length (as literals), frozen wire tables.
module MutationKill
  module M
    module_function

    def ed(label) = OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest("ruby-kill-mh/#{label}"))
    def pub(k) = AtlasPca.b64e(k.raw_public_key)
    def mldsa = (@mldsa ||= OpenSSL::PKey.generate_key('ML-DSA-65'))

    def sign_hop(body, key)
      d = AtlasPca.hash_canonical(body)
      sig = key.sign(nil, AtlasPca::CAP_DOMAIN + AtlasPca.b64d(d, 32))
      body.reject { |k, v| k == 'parent' && v.nil? }.merge('id' => d, 'body_digest' => d, 'sig' => AtlasPca.b64e(sig))
    end

    # [root, hop1]: principal -> agent -> leaf; hop1 commits holder_pq to the ML-DSA key when pq is set
    def chain(root_cavs, hop_cavs, pq: false)
      p, a, l = ed('principal'), ed('agent'), ed('leaf')
      root = sign_hop({ 'issuer' => pub(p), 'holder' => pub(a), 'caveats' => root_cavs, 'parent' => nil }, p)
      body = { 'issuer' => pub(a), 'holder' => pub(l), 'caveats' => hop_cavs, 'parent' => AtlasPca.cap_hash(root) }
      body['holder_pq'] = AtlasPca.holder_pq_commitment(AtlasPca.b64e(mldsa.raw_public_key)) if pq
      [root, sign_hop(body, a), pub(p)]
    end
  end

  t('attenuation reasons: dropped and altered parent caveats') do
    r, h, iss = M.chain([{ 'type' => 'a' }], [{ 'type' => 'a' }, { 'type' => 'b' }])
    ok = AtlasPca.verify_chain([r, h], iss, true)
    r2, h2, = M.chain([{ 'type' => 'a' }], [])
    r3, h3, = M.chain([{ 'type' => 'a' }, { 'type' => 'b' }], [{ 'type' => 'b' }, { 'type' => 'a' }])
    ok == ['', true] && AtlasPca.verify_chain([r2, h2], iss, true) == ['hop 1: drops parent caveat(s)', false] &&
      AtlasPca.verify_chain([r3, h3], iss, true) == ['hop 1: caveat 0 altered or reordered', false]
  end

  t('a pure ML-DSA-65 leaf is bound by the LEAF hop holder_pq on a two-hop chain', needs: 'ml-dsa-65') do
    v = Corpus.core['vectors'].find { |x| x['expect']['allow'] == true && x['pcactn'].is_a?(Hash) && x['requires'].nil? }
    root, hop, = M.chain([], [], pq: true)
    p = Marshal.load(Marshal.dump(v['pcactn'])).reject { |k, _| %w[pq_sig threshold].include?(k) }
    p['cap_chain'] = [root, hop]
    p['grant_ref'] = root['id']
    p['alg'] = 'ml-dsa-65'
    p['pq_pk'] = AtlasPca.b64e(M.mldsa.raw_public_key)
    p['sig'] = AtlasPca.b64e(M.mldsa.sign(nil, AtlasPca.threshold_message(p)))
    # as it arrives on the wire: JSON text -> parsed (UTF-8 strings; b64e returns US-ASCII strings, which tree_ok? refuses)
    wire = ->(x) { AtlasPca.parse_json(AtlasPca.canonicalize(x)) }
    grant = wire.call(root)
    g = AtlasPca.verify_pcactn(wire.call(p), grant, now: v['context']['now'], audience: v['context']['aud'])
    other = wire.call(p.merge('pq_pk' => AtlasPca.b64e(OpenSSL::PKey.generate_key('ML-DSA-65').raw_public_key)))
    g.allow == true && g.checks['leaf_signature'] == true &&
      AtlasPca.verify_pcactn(other, grant, now: v['context']['now'], audience: v['context']['aud']).checks['leaf_signature'] == false
  end

  t('closed? exact') do
    c = ->(*a) { AtlasPca.closed?(*a) }
    c.call({ 'a' => 1 }, %w[a]) == true && c.call({ 'a' => 1, 'b' => 2 }, %w[a], %w[b]) == true &&
      c.call({ 'a' => 1, 'b' => 2 }, %w[a]) == false && c.call({}, %w[a]) == false && c.call({ 'b' => 1 }, %w[a], %w[b]) == false &&
      c.call(5, %w[a]) == false && c.call(nil, []) == false && c.call(['a'], %w[a]) == false
  end
  t('number? exact') do
    n = ->(x) { AtlasPca.number?(x) }
    n.call(1) == true && n.call(1.5) == true && [2**60, Float::NAN, 0.0, 1.0, '1', nil, true].all? { |x| n.call(x) == false }
  end
  t('verify_threshold_share: share.role must equal the entry role') do
    e = Corpus.core['primitives']['threshold_share'].find { |s| s['valid'] != false && s['t'] == 1 && !s['share'].key?('alg') }
    AtlasPca.verify_threshold_share(e) == true &&
      AtlasPca.verify_threshold_share(e.merge('share' => e['share'].merge('role' => 'guardian'))).equal?(false)
  end
  t('signer_registry: the registered PQ key lengths, as literals') do
    ok = { 'role' => 'agent', 'publicKey' => AtlasPca.b64e("\x03".b * 32) }
    pq = ->(n) { AtlasPca.b64e("\x00".b * n) }
    lens = [1952, 2592, 32, 64, 897, 1793, 97_484]
    lens.all? { |n| AtlasPca.signer_registry([ok.merge('pq_pk' => pq.call(n))]).is_a?(Hash) } &&
      lens.flat_map { |n| [n - 1, n + 1] }.all? { |n| AtlasPca.signer_registry([ok.merge('pq_pk' => pq.call(n))]).nil? }
  end
  t('wire tables frozen') do
    m = AtlasPca
    [m::TOP_OPTIONAL, m::ACTION_KEYS, m::PLAN_REQUIRED, m::PROOF_KEYS, m::HOP_REQUIRED, m::HOP_OPTIONAL].all?(&:frozen?)
  end
end
