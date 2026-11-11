# frozen_string_literal: true

require 'timeout'
require 'stringio'

# Exact-outcome kill tests for lib/atlas_pca/agent.rb (issuer side) and lib/atlas_pca/arg_provenance.rb (provenance by default).
# Every AtlasPca constant, key and recorder is built at CALL time (the oracle replaces the module per mutant). Where an
# optional argument is only forwarded (nil vs false is invisible in the output) a spy on the callee pins that the callee receives
# nil; where a guard is redundant for the output a spy shows the guarded work is not done.
module MutationKill
  module C03
    module_function

    # A post-quantum key pair double: records the messages it signs (the real one needs OpenSSL >= 3.5).
    class StubPq
      SIG = ('S' * 8).b
      attr_reader :prim, :public, :seen

      def initialize(prim = 'ML-DSA-65', pub = 'PUBKEY')
        @prim = prim
        @public = pub
        @seen = []
      end

      def sign(msg)
        @seen << msg
        SIG
      end
    end

    # Stands in for the OpenSSL pkey (or an Ed25519 signer): records the message it is asked to sign.
    class SignSpy
      attr_reader :msgs

      def initialize
        @msgs = []
      end

      def sign(*args)
        @msgs << args.last
        'sig'.b
      end
    end

    # An IO with read only (no rewind), returning the very string it holds.
    class ReadOnlyIo
      def initialize(str)
        @str = str
      end

      def read = @str
    end

    SEND = { 'verb' => 'email.send', 'resource' => 'mail', 'params' => { 'to' => 'bob@acme.example' } }.freeze

    def skip?(files)
      f = ENV['MUT_FILE']
      f && !f.empty? && !files.include?(f)
    end

    def key(seed = 0x21)
      @keys ||= {}
      @keys[seed] ||= AtlasPca::KeyPair.new([seed].pack('C') * 32)
    end

    def env_ok
      { 'predicates' => [{ 'verb' => 'v', 'resource' => 'r' }], 'caveats' => [], 'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    end

    def grant_for(principal, holder) = AtlasPca.mint_grant(principal, holder.public, env_ok, 'g')['grant']

    def now_ms = (Time.now.to_f * 1000).to_i

    # Replace AtlasPca singleton methods by recorders that call through: log << [name, positional, keywords].
    def spy(names, log)
      names.to_h do |n|
        orig = AtlasPca.method(n)
        [n, lambda do |*a, **k|
          log << [n, a, k]
          k.empty? ? orig.call(*a) : orig.call(*a, **k)
        end]
      end
    end

    def raises_arg?(msg)
      yield
      false
    rescue ArgumentError => e
      e.message == msg
    end

    def mkrec(now: nil, **kw)
      AtlasPca::ProvenanceRecorder.new(mediator: 'm', kid: 'k1', key: key(0x31), session: AtlasPca.b64e("\x05".b * 32),
                                       now: now || -> { 1000 }, **kw)
    end

    def pin = { 'mediator' => 'm', 'kid' => 'k1', 'pk' => key(0x31).public }

    def bundle(segs = [['principal', 'mail bob@acme.example']], op = SEND, rec = mkrec)
      segs.each { |o, text| o == 'principal' ? rec.principal(text) : rec.public_send(o, 'src', text) }
      rec.for_action(op)
    end

    def deep(x) = Marshal.load(Marshal.dump(x))

    def decide(over = {})
      AtlasPca.decide_arg_provenance({ 'bundle' => nil, 'operation' => SEND, 'mediators' => [] }.merge(over))
    end
  end

  # ======================================================= agent.rb

  t('c03 agent: reference constants') do
    next true if C03.skip?(%w[agent.rb arg_provenance.rb])

    AtlasPca::DEFAULT_RISK_POLICY == {
      'weights' => { 'alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05 },
      'theta1' => 0.25, 'theta2' => 0.6, 'kappa' => 1, 'lambda' => 0.0005, 'rho' => 0.5, 'bMax' => 1
    } && AtlasPca::DEFAULT_RISK_POLICY['kappa'].eql?(1) && AtlasPca::DEFAULT_RISK_POLICY['bMax'].eql?(1) &&
      AtlasPca::PROV_HEADER == 'PCA-Provenance' && AtlasPca::PCA_HEADER == 'PCA-Action'
  end

  t('c03 agent: KeyPair seed guard, binary seed and message, inspect') do
    next true if C03.skip?(%w[agent.rb])

    fake = Object.new
    def fake.bytesize
      32
    end
    refused = begin
      AtlasPca::KeyPair.new(fake)
      false
    rescue ArgumentError => e
      e.message == 'an Ed25519 seed is 32 bytes'
    end
    seen = []
    orig = OpenSSL::PKey.method(:new_raw_private_key)
    Seam.with(OpenSSL::PKey, { new_raw_private_key: lambda { |a, s|
      seen << s.encoding
      orig.call(a, s)
    } }) { AtlasPca::KeyPair.new('x' * 32) }
    spy = C03::SignSpy.new
    k = AtlasPca::KeyPair.allocate
    k.instance_variable_set(:@pkey, spy)
    k.instance_variable_set(:@public, 'PUB')
    sig = k.sign('é')
    real = AtlasPca::KeyPair.new("\x01".b * 32)
    refused && seen == [Encoding::BINARY] && sig == 'sig'.b && spy.msgs.length == 1 && spy.msgs[0].encoding == Encoding::BINARY &&
      spy.msgs[0].bytes == 'é'.bytes && k.inspect == '#<AtlasPca::KeyPair public=PUB>' &&
      real.inspect == "#<AtlasPca::KeyPair public=#{real.public}>"
  end

  t('c03 agent: PqKeyPair refuses an unavailable suite exactly, signs binary, inspects') do
    next true if C03.skip?(%w[agent.rb])

    failure = Seam.with(OpenSSL::PKey, { generate_key: ->(*) { raise OpenSSL::PKey::PKeyError, 'no such suite' } }) do
      AtlasPca::PqKeyPair.new('ML-DSA-65')
      nil
    rescue AtlasPca::UnsupportedSigner => e
      e.message
    end
    spy = C03::SignSpy.new
    pq = AtlasPca::PqKeyPair.allocate
    pq.instance_variable_set(:@pkey, spy)
    pq.instance_variable_set(:@prim, 'ML-DSA-65')
    pq.sign('é')
    failure == 'unsupported_suite: ML-DSA-65 (needs OpenSSL >= 3.5)' && spy.msgs[0].encoding == Encoding::BINARY &&
      pq.inspect == '#<AtlasPca::PqKeyPair ML-DSA-65>'
  end

  t('c03 agent: sign_with_suite exact parts for every suite shape') do
    next true if C03.skip?(%w[agent.rb])

    ed = C03.key
    msg = 'é'
    e = ed.sign(msg)
    pq = C03::StubPq.new
    ok_ed = AtlasPca.sign_with_suite(nil, ed, nil, msg) == [AtlasPca.b64e(e), nil]
    pure = AtlasPca.sign_with_suite('ml-dsa-65', nil, pq, msg)
    plain = AtlasPca.sign_with_suite('hybrid-ed25519-ml-dsa-65', ed, pq, msg)
    plain_msg = pq.seen.last.b
    nested = AtlasPca.sign_with_suite('hybrid-nested-ed25519-ml-dsa-65', ed, pq, msg)
    nested_msg = pq.seen.last
    want = [AtlasPca.b64e(e), AtlasPca.b64e(C03::StubPq::SIG)]
    ok_ed && pure == [AtlasPca.b64e(C03::StubPq::SIG), nil] && pure[1].nil? && plain == want && plain_msg == msg.b &&
      nested == want && nested_msg == msg.b + e &&
      C03.raises_arg?('ml-dsa-65 needs a ML-DSA-65 key pair') { AtlasPca.sign_with_suite('ml-dsa-65', ed, C03::StubPq.new('ML-DSA-87'), msg) } &&
      C03.raises_arg?('hybrid-ed25519-ml-dsa-65 needs an Ed25519 key') { AtlasPca.sign_with_suite('hybrid-ed25519-ml-dsa-65', nil, pq, msg) }
  end

  t('c03 agent: bind_suite copies, sign_artifact binary message and defaults, sign_body, strict_bytes') do
    next true if C03.skip?(%w[agent.rb])

    ed = C03.key
    body = { 'v' => 1 }
    b1 = AtlasPca.bind_suite(body, nil, nil)
    b2 = AtlasPca.bind_suite(body, 'ed25519', nil)
    log = []
    signed = Seam.with(AtlasPca, C03.spy(%i[sign_with_suite], log)) { AtlasPca.sign_artifact('d', body, ed) }
    args = log[0][1]
    s = C03::SignSpy.new
    out = AtlasPca.sign_body(s, 'dom', { 'a' => 1 })
    plog = []
    Seam.with(AtlasPca, C03.spy(%i[parse_json], plog)) { AtlasPca.strict_bytes({ 'a' => 1 }) }
    !b1.equal?(body) && b1 == body && !b2.equal?(body) && b2 == body && body == { 'v' => 1 } && signed.keys.sort == %w[sig v] &&
      args[0].nil? && args[2].nil? && args[3].encoding == Encoding::BINARY && args[3] == 'd{"v":1}' &&
      out == AtlasPca.b64e('sig'.b) && s.msgs[0].encoding == Encoding::BINARY && s.msgs[0] == 'dom{"a":1}' &&
      plog.length == 1 && plog[0][1] == ['{"a":1}'] && plog[0][2] == { any_top: true } &&
      AtlasPca.strict_bytes([1]) == '[1]'.b && AtlasPca.strict_bytes('x') == '"x"'.b
  end

  t('c03 agent: seal_cap members per suite') do
    next true if C03.skip?(%w[agent.rb])

    ed = C03.key
    pq = C03::StubPq.new
    seal = ->(alg, p) { AtlasPca.seal_cap('iss', 'hold', [{ 'type' => 'sealed' }], nil, nil, ed, alg, p) }
    hyb = seal.call('hybrid-ed25519-ml-dsa-65', pq)
    pure = seal.call('ml-dsa-65', pq)
    base = %w[body_digest caveats holder id issuer sig]
    hyb.keys.sort == (base + %w[alg pq_pk pq_sig]).sort && hyb['alg'] == 'hybrid-ed25519-ml-dsa-65' && hyb['pq_pk'] == 'PUBKEY' &&
      hyb['pq_sig'] == AtlasPca.b64e(C03::StubPq::SIG) &&
      pure.keys.sort == (base + %w[alg pq_pk]).sort && pure['alg'] == 'ml-dsa-65' && pure['pq_pk'] == 'PUBKEY' &&
      seal.call('ed25519', pq).keys.sort == base && seal.call('ed25519', nil).keys.sort == base && seal.call(nil, nil).keys.sort == base
  end

  t('c03 agent: optional arguments reach the callee as nil') do
    next true if C03.skip?(%w[agent.rb])

    p = C03.key
    h = C03.key(0x22)
    log = []
    names = %i[seal_cap mint_root sign_artifact sign_pcactn sign_with_suite build_pcactn]
    Seam.with(AtlasPca, C03.spy(names, log)) do
      root = AtlasPca.mint_root(p, h.public, [])
      AtlasPca.delegate_cap(root, h)
      grant = AtlasPca.mint_grant(p, h.public, C03.env_ok, 'g')['grant']
      AtlasPca.sign_escalation_answer(p, { 'policy_digest' => 'a', 'action_digest' => 'b', 'history_head' => 'c' }, 'allow', 1, 2)
      AtlasPca.sign_discharge(p, 'cid', 'lbl', 'CH', {}, 1, 2)
      AtlasPca.sign_narrow(p, 'CH', [], 1, 2)
      AtlasPca.sign_passport(AtlasPca.issue_passport({ 'model_id' => 'm', 'operator' => 'o', 'hardware_rooted' => false, 'issued_at' => 10 }), p, 'sub', 99)
      AtlasPca.build_pcactn(grant: grant, chain: [grant], plan: [{ 'id' => 'a', 'verb' => 'v', 'resource' => 'r' }], node_id: 'a', counter: 1, signer: h,
                            aud: 'x', iat: 1000)
      AtlasPca.sign_pcactn({ 'ver' => 2 }, p)
    end
    by = ->(n) { log.select { |l| l[0] == n } }
    seals = by.call(:seal_cap).map { |l| l[1] }
    roots = by.call(:mint_root).map { |l| l[2] }.reject(&:empty?)
    arts = by.call(:sign_artifact).map { |l| l[2] }
    pcs = by.call(:sign_pcactn).map { |l| l[2] }.reject(&:empty?)
    suites = by.call(:sign_with_suite).map { |l| l[1] }
    seals.length == 3 && seals.all? { |a| a[4].nil? && a[6].nil? && a[7].nil? } && seals[0][3].nil? &&
      roots.length == 1 && roots[0].values_at(:holder_pq, :alg, :pq).all?(&:nil?) && roots[0].keys.sort == %i[alg holder_pq pq] &&
      arts.length == 4 && arts.all? { |k| k.key?(:alg) && k[:alg].nil? && k.key?(:pq) && k[:pq].nil? } &&
      pcs.length == 1 && pcs.all? { |k| k.key?(:alg) && k[:alg].nil? && k.key?(:pq) && k[:pq].nil? } &&
      suites.all? { |a| a[0].nil? && a[2].nil? }
  end

  t('c03 agent: attenuate_cap is delegate_cap with the added caveats') do
    next true if C03.skip?(%w[agent.rb])

    p = C03.key
    h = C03.key(0x22)
    grant = C03.grant_for(p, h)
    add = [{ 'type' => 'budget_alloc', 'limit' => 5 }]
    other = C03.key(0x23).public
    AtlasPca.attenuate_cap(grant, add, h) == AtlasPca.delegate_cap(grant, h, added: add) &&
      AtlasPca.attenuate_cap(grant, add, h, to_holder: other) == AtlasPca.delegate_cap(grant, h, to_holder: other, added: add) &&
      AtlasPca.attenuate_cap(grant, add, h)['caveats'] == grant['caveats'] + add
  end

  t('c03 agent: mint_grant refuses a non-String goal, a missing predicates or caveats member, a bad provenance member') do
    next true if C03.skip?(%w[agent.rb])

    p = C03.key
    h = C03.key(0x22).public
    e = C03.env_ok
    mg = ->(env, goal = 'g') { AtlasPca.mint_grant(p, h, env, goal) }
    C03.raises_arg?('mint_grant: goal required') { mg.call(e, ['x']) } && C03.raises_arg?('mint_grant: goal required') { mg.call(e, 5) } &&
      C03.raises_arg?('mint_grant: envelope.predicates and envelope.caveats required') { mg.call(e.reject { |k, _| k == 'caveats' }) } &&
      C03.raises_arg?('mint_grant: envelope.predicates and envelope.caveats required') { mg.call(e.reject { |k, _| k == 'predicates' }) } &&
      C03.raises_arg?('mint_grant: provenance must be an object') { mg.call(e.merge('provenance' => 'bad')) } &&
      mg.call(e.merge('provenance' => { 'mode' => 'enforce' }))['grant']['caveats'][0]['provenance'] == { 'mode' => 'enforce' }
  end

  t('c03 agent: commit_plan proofs for a six-node plan (right subtree offsets)') do
    next true if C03.skip?(%w[agent.rb])

    nodes = (0..5).map { |i| { 'id' => "n#{i}", 'verb' => 'v', 'resource' => 'r' } }
    hs = AtlasPca.plan_hashes(nodes)
    c = AtlasPca.commit_plan(nodes)
    h = ->(sub) { AtlasPca.b64e(AtlasPca.build(sub)) }
    side = ->(s, x) { { 'side' => s, 'hash' => x } }
    pr = c['proofs']
    c['root'] == h.call(hs) &&
      pr['n4'] == { 'index' => 4, 'size' => 6, 'path' => [side.call('R', AtlasPca.b64e(hs[5])), side.call('L', h.call(hs[0...4]))] } &&
      pr['n5'] == { 'index' => 5, 'size' => 6, 'path' => [side.call('L', AtlasPca.b64e(hs[4])), side.call('L', h.call(hs[0...4]))] } &&
      pr['n2']['path'] == [side.call('R', AtlasPca.b64e(hs[3])), side.call('L', h.call(hs[0...2])), side.call('R', h.call(hs[4..]))] &&
      pr['n0']['path'] == [side.call('R', AtlasPca.b64e(hs[1])), side.call('R', h.call(hs[2...4])), side.call('R', h.call(hs[4..]))]
  end

  t('c03 agent: build_pcactn audience guard, default iat, exp and params digest; sign_pcactn without suite arguments') do
    next true if C03.skip?(%w[agent.rb])

    k = C03.key
    grant = C03.grant_for(C03.key(0x22), k)
    node = { 'id' => 'a', 'verb' => 'v', 'resource' => 'r' }
    base = { grant: grant, chain: [grant], plan: [node], node_id: 'a', counter: 1, signer: k }
    t0 = C03.now_ms
    pc = AtlasPca.build_pcactn(**base, aud: 'x')
    t1 = C03.now_ms
    bad_aud = [nil, 5, '', ['x'], :aud].all? do |aud|
      C03.raises_arg?('build_pcactn: aud (audience) is required') { AtlasPca.build_pcactn(**base, aud: aud) }
    end
    unsigned = pc.reject { |key, _| key == 'sig' }
    bad_aud && pc['iat'].is_a?(Integer) && t0 <= pc['iat'] && pc['iat'] <= t1 && pc['exp'] == pc['iat'] + (20 * 60_000) &&
      pc['action']['params_digest'] == AtlasPca.params_digest(nil) && AtlasPca.sign_pcactn(unsigned, k) == pc
  end

  t('c03 agent: escalation answer nonce length and render digest') do
    next true if C03.skip?(%w[agent.rb])

    p = C03.key
    req = { 'policy_digest' => 'a', 'action_digest' => 'b', 'history_head' => 'c' }
    a = AtlasPca.sign_escalation_answer(p, req.merge('render_digest' => 'RD'), 'allow', 1, 2)
    n = AtlasPca.sign_escalation_answer(p, req.merge('render_digest' => 5), 'deny', 1, 2)
    z = AtlasPca.sign_escalation_answer(p, req, 'deny', 1, 2)
    f = AtlasPca.sign_escalation_answer(p, req, 'deny', 1, 2, nonce: 'N')
    a['render_digest'] == 'RD' && !n.key?('render_digest') && !z.key?('render_digest') && AtlasPca.b64d(a['nonce'], 16) &&
      AtlasPca.b64d(n['nonce'], 16) && f['nonce'] == 'N'
  end

  t('c03 agent: caveat builders are exact') do
    next true if C03.skip?(%w[agent.rb])

    want = { 'type' => 'needs_discharge', 'id' => 'c1', 'issuer' => 'iss', 'issuer_class' => 'artifact', 'bind' => 'chain_hop',
             'ttl_ms' => 300_000, 'require' => [{ 'k' => 1 }] }
    AtlasPca.needs_discharge_caveat('c1', 'iss', 'artifact', [{ 'k' => 1 }]) == want &&
      AtlasPca.needs_discharge_caveat('c1', 'iss', 'artifact', [{ 'k' => 1 }], issuer_spiffe: 'spiffe://x') == want.merge('issuer_spiffe' => 'spiffe://x') &&
      AtlasPca.needs_discharge_caveat('c2', 'i2', 'human', [], bind: 'action', ttl_ms: 7) ==
        { 'type' => 'needs_discharge', 'id' => 'c2', 'issuer' => 'i2', 'issuer_class' => 'human', 'bind' => 'action', 'ttl_ms' => 7, 'require' => [] } &&
      AtlasPca.sealed_caveat == { 'type' => 'sealed' } &&
      AtlasPca.max_uses_caveat('m1', 3, 99) == { 'type' => 'max_uses', 'id' => 'm1', 'n' => 3, 'until' => 99 }
  end

  t('c03 agent: discharge and narrow nonces, binding and action digest') do
    next true if C03.skip?(%w[agent.rb])

    p = C03.key
    d = AtlasPca.sign_discharge(p, 'cid', 'lbl', 'CH', { 'a' => 1 }, 1, 2)
    d2 = AtlasPca.sign_discharge(p, 'cid', 'lbl', 'CH', {}, 1, 2, bind: 'action', action_digest: 'AD', nonce: 'N')
    n = AtlasPca.sign_narrow(p, 'CH', [], 1, 2)
    n2 = AtlasPca.sign_narrow(p, 'CH', [], 1, 2, action_digest: 'AD', nonce: 'N')
    AtlasPca.b64d(d['nonce'], 16) && d['bind'] == 'chain_hop' && !d.key?('action_digest') && d['kind'] == 'pca-discharge' &&
      d2['nonce'] == 'N' && d2['action_digest'] == 'AD' && d2['bind'] == 'action' &&
      AtlasPca.b64d(n['nonce'], 16) && !n.key?('action_digest') && n['holder'] == p.public && n2['nonce'] == 'N' && n2['action_digest'] == 'AD'
  end

  t('c03 agent: passport fingerprint members and sign_passport iat, evidence and the hardware guard') do
    next true if C03.skip?(%w[agent.rb])

    ident = { 'model_id' => 'm', 'weights_digest' => 'w', 'system_prompt_digest' => 's', 'tool_manifest_digest' => 't', 'runtime_measurement' => 'r',
              'operator' => 'o', 'hardware_rooted' => false, 'issued_at' => 10 }
    want = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/passport/v1', 'model_id' => 'm', 'weights_digest' => 'w', 'system_prompt_digest' => 's',
                                     'tool_manifest_digest' => 't', 'runtime_measurement' => 'r', 'operator' => 'o', 'hardware_rooted' => false })
    empty = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/passport/v1', 'model_id' => nil, 'weights_digest' => nil, 'system_prompt_digest' => nil,
                                      'tool_manifest_digest' => nil, 'runtime_measurement' => nil, 'operator' => nil, 'hardware_rooted' => nil })
    issuer = C03.key
    hw = AtlasPca.issue_passport(ident.merge('hardware_rooted' => true))
    pp = AtlasPca.issue_passport(ident)
    s = AtlasPca.sign_passport(hw, issuer, 'sub', 99, evidence: { 'x' => 1 })
    s2 = AtlasPca.sign_passport(hw, issuer, 'sub', 99, iat: 20, evidence: { 'at' => 5 })
    s3 = AtlasPca.sign_passport(pp, issuer, 'sub', 99, iat: 20)
    AtlasPca.passport_fingerprint(ident) == want && pp['id'] == want && AtlasPca.passport_fingerprint({}) == empty &&
      s['evidence'] == { 'at' => 10, 'x' => 1 } && [s['iat'], s['nbf']] == [10, 10] &&
      s2['evidence'] == { 'at' => 5 } && [s2['iat'], s2['nbf']] == [20, 20] && s3['iat'] == 20 && !s3.key?('evidence') &&
      C03.raises_arg?('sign_passport: hardware_rooted requires attestation evidence (fail closed)') { AtlasPca.sign_passport(hw, issuer, 'sub', 99) }
  end

  t('c03 agent: wf_output members') do
    next true if C03.skip?(%w[agent.rb])

    d = ->(v) { AtlasPca.wf_value_digest(v) }
    lab = %w[b a]
    AtlasPca.wf_output('x') == { 'digest' => d.call('x'), 'num' => nil, 'unit' => nil, 'labels' => [] } &&
      AtlasPca.wf_output(5) == { 'digest' => d.call(5), 'num' => nil, 'unit' => nil, 'labels' => [] } &&
      AtlasPca.wf_output(5, num: true)['num'] == 5 && AtlasPca.wf_output('x', num: true)['num'].nil? &&
      AtlasPca.wf_output(true, num: true)['num'].nil? && AtlasPca.wf_output(5, num: false)['num'].nil? &&
      AtlasPca.wf_output(7, unit: 'usd', labels: lab, num: true) == { 'digest' => d.call(7), 'num' => 7, 'unit' => 'usd', 'labels' => %w[a b] } && lab == %w[b a]
  end

  t('c03 agent: Agent accessors, defaults, default clock, node selection, ttl') do
    next true if C03.skip?(%w[agent.rb])

    k = C03.key
    grant = C03.grant_for(C03.key(0x22), k)
    a = AtlasPca::Agent.new(k, grant, 'rs')
    defaults = a.alg.nil? && a.pq.nil? && a.ttl_ms == 20 * 60_000
    a.alg = 'x'
    a.pq = 5
    a.ttl_ms = 7
    setters = [a.alg, a.pq, a.ttl_ms] == ['x', 5, 7]
    log = []
    t0 = C03.now_ms
    Seam.with(AtlasPca, C03.spy(%i[build_pcactn], log)) { AtlasPca::Agent.new(k, grant, 'rs').act('v', 'r') }
    t1 = C03.now_ms
    iat = log[0][2][:iat]
    plan = [{ 'id' => 'a', 'verb' => 'x', 'resource' => 'r' }, { 'id' => 'b', 'verb' => 'v', 'resource' => 'r' }]
    twin = [{ 'id' => 'a', 'verb' => 'v', 'resource' => 'r' }, { 'id' => 'b', 'verb' => 'v', 'resource' => 'r' }]
    mk = -> { AtlasPca::Agent.new(k, grant, 'rs', clock: -> { 5000 }) }
    fixed = mk.call.act('v', 'r')
    ttl = mk.call
    ttl.ttl_ms = 7
    explicit = mk.call.use_plan(twin).act('v', 'r', node_id: 'b')
    free = mk.call.act('v', 'r', node_id: 'zz')
    defaults && setters && iat.is_a?(Integer) && t0 <= iat && iat <= t1 &&
      mk.call.use_plan(plan).act('v', 'r').node_id == 'b' && mk.call.use_plan(twin).act('v', 'r').node_id == 'a' &&
      explicit.node_id == 'b' && explicit.pcactn['plan']['node_id'] == 'b' && free.node_id == 'zz' && free.pcactn['plan']['node_id'] == 'zz' &&
      fixed.node_id == 'n1' && fixed.pcactn['action']['params_digest'] == AtlasPca.params_digest(nil) && ttl.act('v', 'r').pcactn['exp'] == 5007
  end

  # ======================================================= arg_provenance.rb

  t('c03 prov: prov_join returns its first argument on a tie') do
    next true if C03.skip?(%w[arg_provenance.rb])

    a = +'tool'
    b = +'tool'
    AtlasPca.prov_join(a, b).equal?(a) && AtlasPca.prov_join('trusted', 'web') == 'web' && AtlasPca.prov_join('web', 'tool') == 'web' &&
      AtlasPca.prov_join('agent', 'trusted') == 'agent'
  end

  t('c03 prov: read_only_action? type guards and trait rules') do
    next true if C03.skip?(%w[arg_provenance.rb])

    ro = ->(a) { AtlasPca.read_only_action?(a) }
    duck = Object.new
    def duck.[](key)
      key == 'effects' ? ['read'] : nil
    end

    def duck.key?(_key)
      false
    end
    ro.call(duck).equal?(false) && ro.call({ 'effects' => 'read' }).equal?(false) && ro.call({ 'effects' => ['read'], 'traits' => {} }).equal?(false) &&
      ro.call({ 'effects' => ['read'], 'traits' => 'x' }).equal?(false) && ro.call({ 'effects' => [] }).equal?(false) &&
      ro.call({ 'effects' => %w[read write] }).equal?(false) && ro.call({ 'effects' => ['read'], 'traits' => ['other'] }).equal?(false) &&
      ro.call(nil).equal?(false) && ro.call({ 'effects' => ['read'] }) == true && ro.call({ 'effects' => ['read'], 'traits' => [] }) == true &&
      ro.call({ 'effects' => ['read'], 'traits' => ['pca.pii_access'] }) == true
  end

  t('c03 prov: prov_word_byte? over every byte') do
    next true if C03.skip?(%w[arg_provenance.rb])

    (0..255).all? do |c|
      want = (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 95 || c >= 128
      AtlasPca.prov_word_byte?(c) == want
    end
  end

  t('c03 prov: occurs_as_token refuses non-strings and ends (deadline: a failed first match must advance)') do
    next true if C03.skip?(%w[arg_provenance.rb])

    o = ->(t, n) { AtlasPca.occurs_as_token(t, n) }
    guards = [[nil, 'a'], [5, 'a'], [:a, 'a'], ['a', nil], ['a', 5], ['a', :a], ['a', ['a']], [['a'], 'a']].all? { |t, n| o.call(t, n).equal?(false) }
    Timeout.timeout(2) do
      guards && o.call('xa', 'a').equal?(false) && o.call('ax', 'a').equal?(false) && o.call('xa a', 'a').equal?(true) && o.call('aa', 'aa') &&
        !o.call('aaa', 'aa') && o.call('a', '').equal?(false)
    end
  end

  t('c03 prov: prov_walk results, limits and early exit') do
    next true if C03.skip?(%w[arg_provenance.rb])

    w = ->(x, depth = 0, out = []) { AtlasPca.prov_walk(x, depth, out) }
    log = []
    early = Seam.with(AtlasPca, C03.spy(%i[wb_jsnorm], log)) { w.call(5, 0, Array.new(4097, 'a')) }
    early.equal?(false) && log.empty? &&
      w.call('x', 33).equal?(false) && w.call('x', 32).equal?(true) && w.call([], 0, Array.new(4096, 'a')).equal?(true) &&
      w.call('x', 0, Array.new(4095, 'a')).equal?(true) && w.call('x', 0, Array.new(4096, 'a')).equal?(false) &&
      w.call([['x']], 32).equal?(false) && w.call({ 'a' => 'x' }, 32).equal?(false) && w.call(Object.new).equal?(false) &&
      AtlasPca.prov_leaves(['a', { 'k' => 5 }, true]) == %w[a k 5 true]
  end

  t('c03 prov: prov_op_of refuses every malformed operation with the caller name') do
    next true if C03.skip?(%w[arg_provenance.rb])

    msg = 'w: the operation needs verb, resource and params'
    bad = [nil, 'x', [], { verb: 5, resource: 'r', params: {} }, { verb: 'v', resource: 5, params: {} }, { verb: 'v', resource: 'r', params: [1] },
           { verb: 'v', resource: 'r', params: 's' }, { verb: 'v', resource: 'r' }, { resource: 'r', params: {} }, { verb: 'v', params: {} },
           { 'verb' => 'v', 'resource' => 'r', 'params' => nil }]
    bad.all? { |op| C03.raises_arg?(msg) { AtlasPca.prov_op_of(op, 'w') } } &&
      AtlasPca.prov_op_of({ verb: 'v', resource: 'r', params: { 'a' => 1 } }, 'w') == { 'verb' => 'v', 'resource' => 'r', 'params' => { 'a' => 1 } } &&
      AtlasPca.prov_op_of({ 'verb' => 'v', 'resource' => 'r', 'params' => {} }, 'w') == { 'verb' => 'v', 'resource' => 'r', 'params' => {} }
  end

  t('c03 prov: the last receipt must be the action receipt (origin), the contents cap is exact') do
    next true if C03.skip?(%w[arg_provenance.rb])

    pins = [C03.pin]
    tampered = C03.deep(C03.bundle)
    tampered['receipts'][-1]['origin'] = 'tool'
    unbound = AtlasPca.prov_verify_chain(tampered, C03::SEND, pins)
    over = C03.mkrec
    over.principal('a' * 65_537)
    ob = over.for_action(C03::SEND)
    ob['contents'] = { '0' => 'a' * 65_537 }
    exact = C03.mkrec
    exact.principal('a' * 65_536)
    eb = exact.for_action(C03::SEND)
    ev = AtlasPca.prov_verify_chain(eb, C03::SEND, pins)
    unbound == { 'code' => 'unbound_action', 'reason' => 'the last receipt is not the action receipt of this operation' } &&
      AtlasPca.prov_verify_chain(ob, C03::SEND, pins) == { 'code' => 'malformed_bundle', 'reason' => "contents '0' must be a string of at most 65536 bytes" } &&
      eb['contents']['0'].bytesize == 65_536 && !ev.key?('code') && ev['verified'] == true
  end

  t('c03 prov: decide observations (shape, 256 byte source, duck objects) and the chain view is copied') do
    next true if C03.skip?(%w[arg_provenance.rb])

    duck = Object.new
    def duck.[](key)
      { 'origin' => 'tool', 'source' => 's' }[key]
    end
    bad = C03.decide('observed' => [duck])
    edge = C03.decide('observed' => [{ 'origin' => 'tool', 'source' => 'a' * 256 }])
    over = C03.decide('observed' => [{ 'origin' => 'tool', 'source' => 'a' * 257 }])
    frozen = ->(_b, _o, _p) { { 'verified' => true, 'context' => 'web', 'path' => ['x'].freeze, 'texts' => [] } }
    copied = Seam.with(AtlasPca, { prov_verify_chain: frozen }) { C03.decide('observed' => [{ 'origin' => 'tool', 'source' => 's' }]) }
    bad['outcome'] == 'deny' && bad['code'] == 'malformed_config' && bad['reason'] == 'observations must be a list of {origin, source}' &&
      edge['outcome'] == 'escalate' && edge['path'].include?("tool:#{'a' * 256}") &&
      over['outcome'] == 'deny' && over['code'] == 'malformed_config' && over['reason'] == 'observations must be a list of {origin, source}' &&
      copied['outcome'] == 'escalate' && copied['path'] == %w[tool:s x]
  end

  t('c03 prov: a trusted context never scans the principal texts; a verbatim value in a tool context still does') do
    next true if C03.skip?(%w[arg_provenance.rb])

    log = []
    trusted = Seam.with(AtlasPca, C03.spy(%i[occurs_as_token], log)) do
      C03.decide('bundle' => C03.bundle, 'mediators' => [C03.pin], 'action' => { 'effects' => ['send'] })
    end
    log2 = []
    mixed = Seam.with(AtlasPca, C03.spy(%i[occurs_as_token], log2)) do
      C03.decide('bundle' => C03.bundle([['principal', 'mail bob@acme.example'], ['tool', 'x']]), 'mediators' => [C03.pin],
                 'action' => { 'effects' => ['send'] }, 'principal_control' => true)
    end
    trusted['outcome'] == 'pass' && trusted['labels'] == { 'to' => 'trusted' } && log.empty? &&
      mixed['outcome'] == 'pass' && mixed['labels'] == { 'to' => 'trusted' } && log2.length >= 1
  end

  t('c03 prov: action floors only come from a Hash params member (seam over the wire check)') do
    next true if C03.skip?(%w[arg_provenance.rb])

    r = Seam.with(AtlasPca, { prov_action_info_error: ->(_a) {} }) do
      C03.decide('bundle' => C03.bundle, 'mediators' => [C03.pin], 'action' => { 'effects' => ['send'], 'params' => 'str' })
    end
    r['outcome'] == 'pass' && r['tainted'] == []
  end

  t('c03 prov: reason without a path, and an evaluation fault reports its class') do
    next true if C03.skip?(%w[arg_provenance.rb])

    nopath = ->(_b, _o, _p) { { 'verified' => true, 'context' => 'web', 'path' => [], 'texts' => [] } }
    r = Seam.with(AtlasPca, { prov_verify_chain: nopath }) { C03.decide }
    boom = Seam.with(AtlasPca, { prov_verify_chain: ->(_b, _o, _p) { raise 'boom' } }) { C03.decide }
    r['outcome'] == 'escalate' && r['code'] == 'untrusted_control_and_args' && r['path'] == [] &&
      r['reason'] == 'the choice of email.send derives from untrusted content; to derives from untrusted content: ' \
                     'the principal must confirm (prompt-injection path)' &&
      boom['outcome'] == 'deny' && boom['code'] == 'malformed_config' && boom['reason'] == 'evaluation error (fail closed): RuntimeError'
  end

  t('c03 prov: default_provenance_bundle header, body, rewind, empty and unreadable bodies, encodings') do
    next true if C03.skip?(%w[arg_provenance.rb])

    hdr = AtlasPca::PROV_RACK_HEADER
    refused = begin
      AtlasPca.default_provenance_bundle({ hdr => 'a=' })
      false
    rescue AtlasPca::PcaHeaderError => e
      e.message == 'PCA-Provenance is not canonical base64url' && e.code == 'invalid_pca_header'
    end
    io = StringIO.new('{"pca_provenance":{"a":1},"x":2}')
    got = AtlasPca.default_provenance_bundle({ 'rack.input' => io })
    rewound = io.pos.zero?
    plain = C03::ReadOnlyIo.new('{"pca_provenance":{"a":2}}')
    no_rewind = AtlasPca.default_provenance_bundle({ 'rack.input' => plain }) == { 'a' => 2 }
    nil_body = AtlasPca.default_provenance_bundle({ 'rack.input' => C03::ReadOnlyIo.new(nil) })
    log = []
    empty = Seam.with(AtlasPca, C03.spy(%i[parse_json], log)) { AtlasPca.default_provenance_bundle({ 'rack.input' => StringIO.new('') }) }
    buf = '{"pca_provenance":{"a":"é"}}'.b
    enc = AtlasPca.default_provenance_bundle({ 'rack.input' => C03::ReadOnlyIo.new(buf) })
    non_hash = Seam.with(AtlasPca, { parse_json: ->(*_a, **_k) { 'x pca_provenance' } }) do
      AtlasPca.default_provenance_bundle({ 'rack.input' => StringIO.new('{}') })
    end
    refused && got == { 'a' => 1 } && rewound && no_rewind && nil_body.nil? && empty.nil? && log.empty? && enc == { 'a' => 'é' } &&
      enc['a'].encoding == Encoding::UTF_8 && buf.encoding == Encoding::BINARY && non_hash.nil? &&
      AtlasPca.default_provenance_bundle({ 'rack.input' => StringIO.new('[1]') }).nil? && AtlasPca.default_provenance_bundle({}).nil?
  end

  t('c03 prov: provenance_flow_check pass value, operation guard, option handling') do
    next true if C03.skip?(%w[arg_provenance.rb])

    pin = C03.pin
    b = C03.bundle
    flow = ->(opts, op = C03::SEND, bundle = b, flags = {}) { AtlasPca.provenance_flow_check(opts, nil, nil, op, bundle, flags) }
    opts = { 'mediators' => [pin] }
    fail_msg = 'no operation is bound to this request (fail closed)'
    duck = Object.new
    def duck.[](key)
      { 'verb' => 'v', 'resource' => 'r' }[key]
    end
    ops = [nil, 'x', duck, { 'verb' => 5, 'resource' => 'r' }, { 'verb' => 'v', 'resource' => 5 }, { 'verb' => 'v' }, { 'resource' => 'r' }]
    guard = ops.all? { |op| flow.call(opts, op) == ['fail', fail_msg] }
    raising = ->(_pc, _op) { raise 'x' }
    array_opts = flow.call([['bundle', raising]], C03::SEND, nil)
    noncall = flow.call({ 'bundle' => { 'v' => 1 } }, C03::SEND, nil)
    explicit_wins = flow.call({ 'mediators' => [pin], 'bundle' => raising })
    from_opts = flow.call({ 'mediators' => [pin], 'bundle' => ->(_pc, _op) { b } }, C03::SEND, nil)
    unreadable = flow.call({ 'bundle' => raising }, C03::SEND, nil)
    sym = flow.call({ mediators: [pin] })
    bad_pins = flow.call({ 'mediators' => 'x' })
    guard && flow.call(opts) == ['pass', nil] && sym == ['pass', nil] && array_opts[0] == 'fail' && array_opts[1].start_with?('escalate: ') &&
      noncall[0] == 'fail' && noncall[1].start_with?('escalate: ') && explicit_wins == ['pass', nil] && from_opts == ['pass', nil] &&
      unreadable == ['fail', 'the provenance bundle is unreadable (fail closed)'] &&
      bad_pins == ['fail', 'malformed_config: mediator pins must be a list of {mediator, kid, pk, pq_pk?}']
  end

  t('c03 prov: provenance_flow_check envelope pins and non-Hash envelopes (seam over read_envelope)') do
    next true if C03.skip?(%w[arg_provenance.rb])

    pin = C03.pin
    b = C03.bundle
    flow = ->(opts) { AtlasPca.provenance_flow_check(opts, nil, nil, C03::SEND, b, {}) }
    str_env = Seam.with(AtlasPca, { read_envelope: ->(_g) { 'x' } }) { flow.call({ 'mediators' => [pin] }) }
    from_env = Seam.with(AtlasPca, { read_envelope: ->(_g) { { 'provenance' => { 'mediators' => [pin] } } } }) { flow.call({}) }
    loose = Seam.with(AtlasPca, { read_envelope: ->(_g) { { 'provenance' => { 'mediators' => 'str' } } }, prov_envelope_error: ->(_p) {} }) do
      flow.call({ 'mediators' => [pin] })
    end
    off = Seam.with(AtlasPca, { read_envelope: ->(_g) { { 'provenance' => { 'mode' => 'insecure_off' } } } }) { flow.call({}) }
    str_env == ['pass', nil] && from_env == ['pass', nil] && loose == ['pass', nil] && off == ['not-enforced', nil]
  end

  t('c03 prov: provenance_flow_check action facts and observations are read only from callables') do
    next true if C03.skip?(%w[arg_provenance.rb])

    pin = C03.pin
    b = C03.bundle
    flow = ->(extra) { AtlasPca.provenance_flow_check({ 'mediators' => [pin] }.merge(extra), nil, nil, C03::SEND, b, {}) }
    pass = ['pass', nil]
    unread = ['fail', 'the action facts or observations could not be read (fail closed)']
    flow.call({}) == pass && flow.call('actions' => { 'effects' => ['read'] }) == pass && flow.call('observed' => []) == pass &&
      flow.call('actions' => ->(_op) {}) == pass && flow.call('actions' => ->(_op) { raise 'x' }) == unread &&
      flow.call('observed' => ->(_pc, _op, _s) { raise 'x' }) == unread
  end

  t('c03 prov: provenance_flow_check passes the bundle session to observed exactly, and omits action when unknown') do
    next true if C03.skip?(%w[arg_provenance.rb])

    pin = C03.pin
    b = C03.bundle
    seen = []
    flow = lambda do |bundle|
      seen.clear
      r = AtlasPca.provenance_flow_check({ 'mediators' => [pin], 'observed' => ->(_pc, _op, s) { seen << s; [] } }, nil, nil, C03::SEND, bundle, {})
      [r, seen.dup]
    end
    sess = b['receipts'][0]['session']
    cases = [[b, [sess]], [nil, [nil]], [{}, [nil]], [{ 'receipts' => { 0 => { 'session' => 'S' } } }, [nil]], [{ 'receipts' => [5] }, [nil]],
             [{ 'receipts' => [nil] }, [nil]], [{ 'receipts' => [{ 'session' => 5 }] }, [nil]],
             [{ 'receipts' => [{ 'session' => 'S0' }, { 'session' => 'S1' }] }, ['S0']], [{ 'receipts' => [{ 'session' => 'S' }] }, ['S']],
             [[], [nil]]]
    sessions = cases.all? { |bundle, want| flow.call(bundle)[1] == want }
    arr = flow.call([])
    inputs = []
    orig = AtlasPca.method(:decide_arg_provenance)
    spy_decide = lambda do |i|
      inputs << i
      orig.call(i)
    end
    Seam.with(AtlasPca, { decide_arg_provenance: spy_decide }) do
      AtlasPca.provenance_flow_check({ 'mediators' => [pin] }, nil, nil, C03::SEND, b, {})
      AtlasPca.provenance_flow_check({ 'mediators' => [pin], 'actions' => ->(_op) { { 'effects' => ['read'] } } }, nil, nil, C03::SEND, b, {})
    end
    sessions && arr[0] == ['fail', 'malformed_bundle: the bundle must be an object'] && inputs.length == 2 && !inputs[0].key?('action') &&
      inputs[1]['action'] == { 'effects' => ['read'] }
  end

  t('c03 prov: recorder construction bounds, messages, pin per suite, defaults') do
    next true if C03.skip?(%w[arg_provenance.rb])

    k = C03.key(0x31)
    mk = ->(**kw) { AtlasPca::ProvenanceRecorder.new(**{ mediator: 'm', kid: 'k', key: k }.merge(kw)) }
    ok_edges = mk.call(mediator: 'm' * 256, kid: 'k' * 64).pin['mediator'].bytesize == 256
    msg = 'ProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required'
    refused = [{ mediator: 'm' * 257 }, { kid: 'k' * 65 }, { mediator: '' }, { kid: nil }, { mediator: 5 }].all? { |kw| C03.raises_arg?(msg) { mk.call(**kw) } }
    session = C03.raises_arg?('ProvenanceRecorder: session must be canonical base64url of 32 bytes') { mk.call(session: 'bad') }
    base = { 'mediator' => 'm', 'kid' => 'k', 'pk' => k.public }
    pq = C03::StubPq.new
    pins = mk.call.pin == base && mk.call(pq: pq).pin == base && mk.call(alg: 'ed25519', pq: pq).pin == base &&
           mk.call(alg: 'ml-dsa-65', pq: pq).pin == base.merge('pq_pk' => 'PUBKEY') && mk.call(alg: 'ml-dsa-65').pin == base &&
           mk.call(alg: 'hybrid-ed25519-ml-dsa-65', pq: pq).pin == base.merge('pq_pk' => 'PUBKEY')
    t0 = C03.now_ms
    r = mk.call.principal('x')
    t1 = C03.now_ms
    clock = mk.call(now: -> { 0 }).principal('x')['issued_at']
    seq = [5000, 3000]
    steps = mk.call(now: -> { seq.shift })
    issued = [steps.principal('a')['issued_at'], steps.tool('t', 'b')['issued_at']]
    log = []
    Seam.with(AtlasPca, C03.spy(%i[sign_artifact], log)) { mk.call.principal('x') }
    ok_edges && refused && session && pins && r['issued_at'].is_a?(Integer) && t0 <= r['issued_at'] && r['issued_at'] <= t1 && clock.zero? &&
      issued == [5000, 5000] && log.length == 1 && log[0][2].key?(:alg) && log[0][2][:alg].nil? && log[0][2][:pq].nil? &&
      mk.call.session.length == 43 && AtlasPca.b64d(mk.call.session, 32)
  end

  t('c03 prov: recorder operations, copies, inspect and messages') do
    next true if C03.skip?(%w[arg_provenance.rb])

    r = C03.mkrec
    r.principal('first')
    b1 = r.for_action(C03::SEND)
    r.principal('second')
    snapshot = r.receipts
    snapshot.clear
    msg = 'for_action: the operation needs verb, resource and params'
    direct = 'principal_direct_provenance: the operation needs verb, resource and params'
    d = C03.mkrec
    b2 = AtlasPca.principal_direct_provenance(d, C03::SEND)
    b1['contents'].keys == ['0'] && b1['receipts'].length == 2 && r.receipts.length == 3 && b2['receipts'].length == 2 &&
      b2['contents'] == { '0' => AtlasPca.canonicalize({ 'verb' => 'email.send', 'resource' => 'mail', 'params' => { 'to' => 'bob@acme.example' } }) } &&
      C03.raises_arg?(msg) { C03.mkrec.for_action(nil) } && C03.raises_arg?(direct) { AtlasPca.principal_direct_provenance(C03.mkrec, nil) } &&
      C03.mkrec.inspect == '#<AtlasPca::ProvenanceRecorder mediator=m kid=k1>' && !C03.mkrec.for_action(C03::SEND).key?('contents')
  end

  t('c03 prov: recorder text, source and encodings') do
    next true if C03.skip?(%w[arg_provenance.rb])

    r = C03.mkrec
    custom = Object.new
    def custom.to_s
      'custom-text'
    end
    text = r.send(:text_of, custom) == 'custom-text' && r.send(:text_of, { 'b' => 1, 'a' => 2 }) == '{"a":2,"b":1}' && r.send(:text_of, 'raw') == 'raw'
    sym = r.tool(:crm, 'out')['source'] == 'crm'
    bin = r.principal('é'.b)
    contents = r.for_action(C03::SEND)['contents']
    text && sym && bin['content_digest'] == AtlasPca.wb_hash('é') && contents[bin['seq'].to_s] == 'é' &&
      contents[bin['seq'].to_s].encoding == Encoding::UTF_8
  end

  t('c03 prov: clip scrubs invalid bytes, keeps surrogate pairs whole, and terminates') do
    next true if C03.skip?(%w[arg_provenance.rb])

    r = C03.mkrec
    clip = ->(s) { r.send(:clip, s) }
    bad = "ab\xFFcd".b
    Timeout.timeout(2) do
      clip.call(bad) == "ab\u{FFFD}cd" && clip.call('abc') == 'abc' && clip.call('a' * 300) == 'a' * 150 && clip.call('') == '-' &&
        clip.call("#{'a' * 149}\u{10000}#{'a' * 149}") == 'a' * 149 && clip.call("#{'a' * 149}\u{10FFFF}#{'a' * 149}") == 'a' * 149 &&
        clip.call(("\u{1F600}" * 50) + ("é" * 30) + 'x') == "\u{1F600}" * 32
    end
  end
end
