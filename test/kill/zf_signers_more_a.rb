# frozen_string_literal: true

# zf: direct kill tests for the producer-side signers of signers_more.rb (threshold shares and the bound share message, the PQ key
# binding and its pin, caution claims, the progress-step and mesh-action guards, the compact mesh proof, the session-root signer).
# Expected bytes and refusals are the TypeScript reference's (threshold.ts shareMessage / signPreparedShare, pq.ts signPqBinding /
# pqPinFor, agent-native.ts signCaution, mesh.ts assembleMeshProof, intent-session.ts signSessionRoot) over the same seeds as
# producer-vectors.json. AtlasPca is resolved at call time (the oracle replaces the module per mutant).
require 'json'
require 'digest'

module MutationKill
  module ZFSA
    module_function

    def gate? = ZC.gate?('signers_more.rb')
    def key(name) = AtlasPca::KeyPair.from_seed_b64u(AgentProducer.doc['keys'][name]['seed'])
    def vec(name) = AgentProducer.doc['cases'].find { |c| c['name'] == name }
    def hex(bin) = bin.unpack1('H*')
    def sha_hex(str) = Digest::SHA256.hexdigest(str)

    # the block must raise ArgumentError with exactly `msg` (any other exception propagates and fails the test)
    def refuses(label, msg)
      yield
      raise "#{label}: did not raise"
    rescue ArgumentError => e
      e.message == msg || raise("#{label}: raised #{e.message.inspect}, want #{msg.inspect}")
    end

    def signer_set = vec('threshold-share-agent')['args']['signer_set']
    def ml_dsa = AtlasPca::PqKeyPair.from_seed('ML-DSA-65', AtlasPca.b64d(AgentProducer.pq_doc['cases'].find { |c| c['name'] == 'pq-keygen-ml-dsa-65' }['args']['seed']))

    SM_BASE = '61746c61732d7063612f73686172652f6167656e740008114912f2077584d3c567da8a963a9640820d4d071dcc3dd6c976047e6353d1001cbcf315331119cf353e66a5d97b3756f9644b24443a9c22bd7ea621530fc502'
    SM_TAG = '0061746c61732d7063612f73686172652d73756974652f7631006d6c2d6473612d3635' # "\0atlas-pca/share-suite/v1\0ml-dsa-65"
    SM_ROLE = '61746c61732d7063612f73686172652f72c3b46c650008114912f2077584d3c567da8a963a9640820d4d071dcc3dd6c976047e6353d1001cbcf315331119cf353e66a5d97b3756f9644b24443a9c22bd7ea621530fc503'
    PREPARED = 'kill-zf prepared share'
    PS_ED_SIG = 'ZwSa0r0edUe9uf2TRvzAzzba4_vVdK5kCqwy-nbSlGqLGTVFA_2d2JCQ-athLMVKaYSyDrJ_zF0lz26umlU2DA'
    PS_PQ_SHA = '9a2a95fce5a891c01130fd456ba516ef0b796f9731a29776d895da22ddbb376c' # sha256 of the ML-DSA-65 signature's base64url text
    PQB_SIG = 'mrwvGLbdm1NbKOeyCmrtLw0_1vJmuAJEH4x53RNsIqMJJD_qMoRHTwrUUa5RkjWXctPSTEeso7BnD-_ioY2GCQ'
    DIGEST = 'q_iMcw9k7bxxH0GOM7p-UcFRTvwIPF0UoN5AONqHvqg'
    CAUTION0_SIG = 'bF7Vto4F1qArVXz3_6H4LwU-PWE5c8oILsQaUjKigEKEVdxIVkt3vIoC3yvdWpJVq-6V_jYuynUBSGoDc-dSAA'

    MESH_HOPS = <<~'JSON'
      [{"domain":"d1","head":{"head":{"log":"L","size":3,"root":"r1"},"sig":"s1","cosigs":[{"witness":"w1","sig":"c1"}]},"inclusion":{"i":1},
        "revocation":{"cap":{"size":3,"lo":{"leaf":"a","idx":1,"path":["x"]},"hi":{"leaf":"b","idx":2,"path":[]}},
                      "issuer_key":{"size":3,"lo":{"path":["x"],"idx":1,"leaf":"a"}}},"binding":{"b":1}},
       {"domain":"d2","head":{"head":{"root":"r1","size":3.0,"log":"L"},"sig":"s1","cosigs":[{"witness":"w1","sig":"c1x"},{"witness":"w2","sig":"c2"}]},
        "inclusion":{"i":2},"revocation":{"cap":{"size":4,"hi":{"leaf":"b","idx":2,"path":[]}},"issuer_key":{"size":0,"lo":{"leaf":"a","idx":1.0,"path":["x"]}}}},
       {"domain":"d3","head":{"head":{"log":"L","size":3,"root":"r1"},"sig":"s2","cosigs":[]},"inclusion":{"i":3},
        "revocation":{"cap":{"size":5,"lo":0,"hi":""},"issuer_key":{}},"binding":0},
       {"head":{"head":{"log":"L","size":3,"root":"r1"},"sig":"s2","cosigs":[{"witness":"w3","sig":"c3"}]},
        "revocation":{"cap":{"size":1},"issuer_key":{"size":1}},"binding":""}]
    JSON
    MESH_PROOF = <<~'JSON'
      {"heads":[{"head":{"log":"L","size":3,"root":"r1"},"sig":"s1","cosigs":[{"witness":"w1","sig":"c1"},{"witness":"w2","sig":"c2"}]},
                {"head":{"log":"L","size":3,"root":"r1"},"sig":"s2","cosigs":[{"witness":"w3","sig":"c3"}]}],
       "rev_leaves":[{"leaf":"a","idx":1,"path":["x"]},{"leaf":"b","idx":2,"path":[]}],
       "hops":[{"domain":"d1","head":0,"inclusion":{"i":1},"revocation":{"cap":{"size":3,"lo":0,"hi":1},"issuer_key":{"size":3,"lo":0}},"binding":{"b":1}},
               {"domain":"d2","head":0,"inclusion":{"i":2},"revocation":{"cap":{"size":4,"hi":1},"issuer_key":{"size":0,"lo":0}}},
               {"domain":"d3","head":1,"inclusion":{"i":3},"revocation":{"cap":{"size":5},"issuer_key":{}}},
               {"head":1,"revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}],
       "action_sig":"GJdbtJdZGMoS2KFPaAsGYciExvFxvdWD5MUgOk_AkVWu2xeI2FDsfXbR49yEmTC7AP336imYJ646dYGH3KQtBA"}
    JSON

    def mesh_args = vec('mesh-action')['args']

    # A PQ binding signed by the agent over (ed, pq, epoch, sig_aud), carrying `aud`.
    def binding(pq, epoch, aud, sig_aud = aud)
      k = key('agent')
      { 'ed' => k.public, 'pq' => pq, 'epoch' => epoch, 'aud' => aud,
        'sig' => AtlasPca.b64e(k.sign(AtlasPca.pq_binding_message(k.public, pq, epoch, sig_aud))) }
    end

    # A non-Hash that answers [] like a well-formed binding (the reference reads any object; this verifier takes a Hash only).
    class Duck
      def initialize(h) = (@h = h)
      def [](k) = @h[k]
    end
  end

  # ---- share message (threshold.ts shareMessage) ----------------------------------------------------------------------------

  t('zf share_message: the bound bytes, the suite tag only for a registered non-Ed25519 suite, a non-ASCII role, the default alg') do
    next true unless ZFSA.gate?

    z = ZFSA
    m = 'kill-zf threshold message'
    sm = ->(*a) { z.hex(AtlasPca.share_message('agent', m, z.signer_set, 2, *a)) }
    ZC.eq('no alg (default)', sm.call, z::SM_BASE) && ZC.eq('nil', sm.call(nil), z::SM_BASE) &&
      ZC.eq('ed25519 = no tag', sm.call('ed25519'), z::SM_BASE) &&
      ZC.eq('ml-dsa-65 tag', sm.call('ml-dsa-65'), z::SM_BASE + z::SM_TAG) &&
      ZC.eq('an unknown alg has no tag (resolveSigAlg null)', sm.call('bogus'), z::SM_BASE) &&
      ZC.eq('non-ASCII role, t=3', z.hex(AtlasPca.share_message('rôle', m, z.signer_set, 3)), z::SM_ROLE)
  end

  t('zf share_message: an empty signer set is refused (stricter than the reference, which hashes it)') do
    next true unless ZFSA.gate?

    ZFSA.refuses('empty set', 'shareMessage: malformed signer set') { AtlasPca.share_message('agent', 'm', [], 2) } &&
      ZFSA.refuses('ill-typed entry', 'shareMessage: malformed signer set') { AtlasPca.share_message('agent', 'm', [{ 'publicKey' => 1, 'role' => 'agent' }], 2) }
  end

  # ---- shares (threshold.ts signShare / signPreparedShare) -------------------------------------------------------------------

  t('zf sign_threshold_share / sign_prepared_share: the default suite (no alg: keyword) is Ed25519, byte for byte') do
    next true unless ZFSA.gate?

    z = ZFSA
    v = z.vec('threshold-share-agent')
    a = v['args']
    got = AtlasPca.sign_threshold_share(a['role'], z.key(a['signer']), AtlasPca.b64d(a['message']), a['signer_set'], a['t'])
    ZC.eq('threshold share', got, v['expect']) &&
      ZC.eq('prepared share', AtlasPca.sign_prepared_share('principal', z.key('principal'), z::PREPARED),
            { 'role' => 'principal', 'publicKey' => z.key('principal').public, 'sig' => z::PS_ED_SIG })
  end

  t('zf sign_prepared_share: ML-DSA-65 carries alg and no pq_sig; the hybrid carries the Ed25519 sig and pq_sig', needs: 'ml-dsa-65') do
    next true unless ZFSA.gate?

    z = ZFSA
    pq = z.ml_dsa
    pub = z.key('principal').public
    pure = AtlasPca.sign_prepared_share('principal', z.key('principal'), z::PREPARED, alg: 'ml-dsa-65', pq: pq)
    hyb = AtlasPca.sign_prepared_share('principal', z.key('principal'), z::PREPARED, alg: 'hybrid-ed25519-ml-dsa-65', pq: pq)
    ZC.eq('pure keys', pure.keys.sort, %w[alg publicKey role sig]) &&
      ZC.eq('pure fields', [pure['role'], pure['publicKey'], pure['alg'], z.sha_hex(pure['sig'])], ['principal', pub, 'ml-dsa-65', z::PS_PQ_SHA]) &&
      ZC.eq('hybrid keys', hyb.keys.sort, %w[alg pq_sig publicKey role sig]) &&
      ZC.eq('hybrid fields', [hyb['alg'], hyb['sig'], z.sha_hex(hyb['pq_sig'])], ['hybrid-ed25519-ml-dsa-65', z::PS_ED_SIG, z::PS_PQ_SHA])
  end

  # ---- PQ binding (pq.ts signPqBinding / pqPinFor) ----------------------------------------------------------------------------

  t('zf sign_pq_binding: exact binding; epoch must be a positive safe integer; aud a non-empty String') do
    next true unless ZFSA.gate?

    z = ZFSA
    k = z.key('agent')
    pq = AgentProducer.pq_doc['cases'].find { |c| c['name'] == 'pq-keygen-ml-dsa-65' }['expect']['public']
    em = 'signPqBinding: epoch must be a positive safe integer'
    am = 'signPqBinding: aud (the instance/audience id) is required'
    ZC.eq('binding', AtlasPca.sign_pq_binding(k, pq, 7, 'aud-zf'), { 'ed' => k.public, 'pq' => pq, 'epoch' => 7, 'aud' => 'aud-zf', 'sig' => z::PQB_SIG }) &&
      [0, -1, 1.5, 2**53].all? { |e| z.refuses("epoch #{e}", em) { AtlasPca.sign_pq_binding(k, pq, e, 'a') } } &&
      [5, '', ['x'], nil].all? { |a| z.refuses("aud #{a.inspect}", am) { AtlasPca.sign_pq_binding(k, pq, 1, a) } }
  end

  t('zf pq_pin_for: the pin of a verifying binding; nil (exactly) for every refusal the reference refuses') do
    next true unless ZFSA.gate?

    z = ZFSA
    ed = z.key('agent').public
    pq = z.vec('pq-binding')['args']['pq_pk']
    pk32 = AtlasPca.b64e("\x00".b * 32) # SLH-DSA-SHA2-128f public-key length
    good = z.binding(pq, 1, 'a')
    refused = {
      'wrong aud' => [good, 'b'], 'empty aud' => [z.binding(pq, 1, ''), ''],
      'aud not a String' => [z.binding(pq, 1, ['x']), ['x']],
      'epoch 0' => [z.binding(pq, 0, 'a'), 'a'], 'epoch 1.5' => [z.binding(pq, 1.5, 'a'), 'a'], 'epoch 2^53' => [z.binding(pq, 2**53, 'a'), 'a'],
      'pq not canonical' => [z.binding("#{pq}=", 1, 'a'), 'a'], 'pq 31 bytes' => [z.binding(AtlasPca.b64e("\x00".b * 31), 1, 'a'), 'a'],
      'bad sig' => [good.merge('sig' => z::PQB_SIG), 'a']
    }
    ZC.eq('pin', AtlasPca.pq_pin_for(good, 'a'), { ed => pq }) && ZC.eq('32-byte key', AtlasPca.pq_pin_for(z.binding(pk32, 1, 'a'), 'a'), { ed => pk32 }) &&
      refused.all? { |label, (b, aud)| ZC.eq(label, AtlasPca.pq_pin_for(b, aud), nil) }
  end

  t('zf pq_pin_for: a malformed binding or audience is refused before the key is decoded or a signature checked') do
    next true unless ZFSA.gate?

    z = ZFSA
    pq = z.vec('pq-binding')['args']['pq_pk']
    good = z.binding(pq, 1, 'a')
    calls = []
    cases = { 'not a Hash' => [ZFSA::Duck.new(good), 'a'], 'ed not a String' => [good.merge('ed' => 5), 'a'],
              'sig not a String' => [good.merge('sig' => 5), 'a'], 'pq not a String' => [good.merge('pq' => 5), 'a'],
              'aud not a String' => [good.merge('aud' => 5), 5], 'nil binding' => [nil, 'a'] }
    ZC.seam(AtlasPca, { b64d: ->(*_a) { calls << :b64d && nil }, verify_b64u: ->(*_a) { calls << :verify && true } }) do
      cases.all? { |label, (b, aud)| ZC.eq(label, AtlasPca.pq_pin_for(b, aud), nil) && ZC.eq("#{label}: no work", calls, []) }
    end
  end

  # ---- caution (agent-native.ts cautionBodyError / signCaution) ---------------------------------------------------------------

  t('zf sign_caution: caution 0 and a 64-character reason sign byte for byte; a valid body has no error (nil)') do
    next true unless ZFSA.gate?

    z = ZFSA
    k = z.key('agent')
    body = { 'action_digest' => z::DIGEST, 'caution' => 0, 'holder' => k.public, 'reason' => 'r' * 64 }
    ZC.eq('claim', AtlasPca.sign_caution(body, k), body.merge('sig' => z::CAUTION0_SIG)) && ZC.eq('no error', AtlasPca.caution_body_error(body), nil)
  end

  t('zf sign_caution: every malformed body is refused with the reference text') do
    next true unless ZFSA.gate?

    z = ZFSA
    k = z.key('agent')
    base = { 'action_digest' => z::DIGEST, 'caution' => 0.5, 'holder' => k.public }
    rows = [['x', 'not an object'], [[], 'not an object'], [nil, 'not an object']] +
           [{}, { 'action_digest' => 5 }, { 'action_digest' => '' }].map { |b| [base.reject { |n, _| n == 'action_digest' }.merge(b), 'action_digest required'] } +
           [{ 'holder' => '' }, { 'holder' => 5 }, { 'holder' => nil }].map { |b| [base.merge(b), 'holder required'] } +
           [-0.5, -1, 1.5, 2, 'x', '0.5', nil, true, Float::NAN, Float::INFINITY, -Float::INFINITY].map { |c| [base.merge('caution' => c), 'caution must be a finite number in [0,1]'] } +
           [5, '', 'bad reason', 'r' * 65, "ok\n", nil].map { |r| [base.merge('reason' => r), 'invalid reason'] }
    rows.all? { |b, msg| z.refuses(msg, "signCaution: #{msg}") { AtlasPca.sign_caution(b, k) } } &&
      [0, 1, 0.0, 1.0, 0.25].all? { |c| ZC.eq("caution #{c}", AtlasPca.caution_body_error(base.merge('caution' => c)), nil) }
  end

  # ---- progress step, mesh action guards --------------------------------------------------------------------------------------

  t('zf sign_progress_step / sign_mesh_action: a non-object step and a chain that is not a non-empty Array are refused') do
    next true unless ZFSA.gate?

    k = ZFSA.key('agent')
    action = ZFSA.mesh_args['action']
    ['x', [], 5].all? { |s| ZFSA.refuses("step #{s.inspect}", 'signProgressStep: step must be an object') { AtlasPca.sign_progress_step(s, k) } } &&
      ['x', 5, [], nil, { 'a' => 1 }].all? { |c| ZFSA.refuses("chain #{c.inspect}", 'signMeshAction: empty chain') { AtlasPca.sign_mesh_action(c, action, k) } }
  end

  # ---- compact mesh proof (mesh.ts assembleMeshProof) --------------------------------------------------------------------------

  t('zf assemble_mesh_proof: heads and leaves deduped canonically (any member order, 3.0 = 3), cosigs merged by witness, falsy and absent members left out') do
    next true unless ZFSA.gate?

    z = ZFSA
    a = z.mesh_args
    hops = JSON.parse(z::MESH_HOPS)
    before = JSON.parse(z::MESH_HOPS)
    want = JSON.parse(z::MESH_PROOF).merge('chain' => a['chain'], 'action' => a['action'])
    got = AtlasPca.assemble_mesh_proof(a['chain'], hops, a['action'], z.key('agent'))
    ZC.eq('proof keys', got.keys.sort, %w[action action_sig chain heads hops rev_leaves]) && ZC.eq('proof', got, want) &&
      ZC.eq('the input hops are not modified (cosigs are copied)', hops, before)
  end

  t('zf assemble_mesh_proof: pin proofs only when non-empty') do
    next true unless ZFSA.gate?

    z = ZFSA
    a = z.mesh_args
    pp = [{ 'domain' => 'd1', 'proof' => { 'a' => 1 } }]
    run = ->(**kw) { AtlasPca.assemble_mesh_proof(a['chain'], JSON.parse(z::MESH_HOPS), a['action'], z.key('agent'), **kw) }
    ZC.eq('default', run.call.key?('pin_proofs'), false) && ZC.eq('nil', run.call(pin_proofs: nil).key?('pin_proofs'), false) &&
      ZC.eq('empty', run.call(pin_proofs: []).key?('pin_proofs'), false) && ZC.eq('present', run.call(pin_proofs: pp)['pin_proofs'], pp)
  end

  t('zf assemble_mesh_proof: a non-object cosignature has no witness, a null one and absent cosigs are refused') do
    next true unless ZFSA.gate?

    z = ZFSA
    a = z.mesh_args
    hop = ->(cosigs) { { 'domain' => 'd', 'head' => { 'head' => { 'n' => 1 }, 'sig' => 's', 'cosigs' => cosigs }, 'inclusion' => {}, 'revocation' => { 'cap' => { 'size' => 1 }, 'issuer_key' => { 'size' => 1 } } } }
    run = ->(*hs) { AtlasPca.assemble_mesh_proof(a['chain'], hs, a['action'], z.key('agent')) }
    merged = run.call(hop.call([{ 'witness' => 'w1' }, 5]), hop.call([5, 'str', { 'witness' => 'w1', 'x' => 1 }, { 'witness' => 'w2' }]))
    nm = 'assembleMeshProof: a cosignature is null'
    ZC.eq('merged', merged['heads'], [{ 'head' => { 'n' => 1 }, 'sig' => 's', 'cosigs' => [{ 'witness' => 'w1' }, 5, { 'witness' => 'w2' }] }]) &&
      z.refuses('incoming null', nm) { run.call(hop.call([{ 'witness' => 'w1' }]), hop.call([nil])) } &&
      z.refuses('stored null', nm) { run.call(hop.call([nil]), hop.call([])) } &&
      ZC.eq('a first null is only copied', run.call(hop.call([nil]))['heads'][0]['cosigs'], [nil]) &&
      [nil, {}, 5].all? { |c| z.refuses("cosigs #{c.inspect}", 'assembleMeshProof: head cosigs must be an array') { run.call(hop.call(c)) } }
  end

  # ---- session root (intent-session.ts signSessionRoot) ------------------------------------------------------------------------

  t('zf sign_session_root: default suite byte for byte, the shape refusal, a signer outside the principals, a PQ suite without a key') do
    next true unless ZFSA.gate?

    z = ZFSA
    v = z.vec('session-root')
    body = v['args']['body']
    pr = z.key('principal')
    ZC.eq('root', AtlasPca.sign_session_root(body, pr), v['expect']) &&
      z.refuses('shape', 'signSessionRoot: not a pca-intent-session v1') { AtlasPca.sign_session_root(body.merge('v' => 2), pr) } &&
      z.refuses('signer', 'signSessionRoot: the signer is not one of the session principals') { AtlasPca.sign_session_root(body, z.key('agent')) } &&
      z.refuses('pq suite, no key', 'ml-dsa-65 needs a post-quantum key pair') { AtlasPca.sign_session_root(body, pr, alg: 'ml-dsa-65') }
  end

  # pqPinFor never raises: a failure inside the decode or the signature check is nil, exactly (not false)
  t('zf pq_pin_for: an error inside the check is nil, not false') do
    next true unless ZFSA.gate?

    z = ZFSA
    good = z.binding(z.vec('pq-binding')['args']['pq_pk'], 1, 'a')
    ZC.seam(AtlasPca, { verify_b64u: ->(*_a) { raise ZC::LoudError } }) do
      got = AtlasPca.pq_pin_for(good, 'a')
      ZC.eq('nil, not false', got.nil?, true)
    end
  end

  # heads are keyed by signature AND head: one signature over two different heads is two heads
  t('zf assemble_mesh_proof: the head key reads the head as well as the signature') do
    next true unless ZFSA.gate?

    z = ZFSA
    a = z.mesh_args
    hop = ->(head) { { 'domain' => 'd', 'head' => { 'head' => head, 'sig' => 's', 'cosigs' => [] }, 'inclusion' => {}, 'revocation' => { 'cap' => { 'size' => 1 }, 'issuer_key' => { 'size' => 1 } } } }
    got = AtlasPca.assemble_mesh_proof(a['chain'], [hop.call({ 'n' => 1 }), hop.call({ 'n' => 2 })], a['action'], z.key('agent'))
    ZC.eq('two heads', got['heads'].map { |h| h['head'] }, [{ 'n' => 1 }, { 'n' => 2 }]) &&
      ZC.eq('hop indices', got['hops'].map { |h| h['head'] }, [0, 1])
  end
end
