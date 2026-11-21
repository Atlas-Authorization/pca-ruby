# frozen_string_literal: true

# Exact-outcome kill tests for the site, principal and guardian signers of lib/atlas_pca/signers_more.rb (from the session root
# on): the pca-intent-required shape check and its cell coordinates (intent-required.ts intentRequiredShapeError /
# cellCoordsError), mintSessionGrant's defaults, fresh goal salt and refusals (intent-session.ts), signSessionRoot's member
# order, signActionSchema's refusals and actionSchemaKeyOf (action-schema.ts), signTemplate / signTighten refusals
# (policy-link.ts), and a post-quantum suite named without its key pair. Vectors: packages/pca/conformance/producer-vectors.json.
# Every AtlasPca constant and key is resolved at CALL time (the oracle replaces the module per mutant).
require 'json'
require_relative '../support/producer_ops'

module MutationKill
  module ZfSmB
    module_function

    def gate? = ZC.gate?('signers_more.rb')
    def doc = AgentProducer.doc
    def j(x) = JSON.parse(JSON.generate(x))
    def kase(name) = j(doc['cases'].find { |c| c['name'] == name } || raise("no vector #{name}"))
    def keys = ProducerOps.keys_of(doc['keys'])

    # the block raises ArgumentError with exactly `want` (another class propagates and fails the test)
    def refuses(label, want)
      yield
      raise "#{label}: did not raise"
    rescue ArgumentError => e
      e.message == want || raise("#{label}: got #{e.message.inspect}, want #{want.inspect}")
    end

    # a post-quantum key pair double: key_of reads only #public
    PqStub = Struct.new(:public)

    def table(label, cases, fn)
      cases.each_with_index { |(input, want), i| ZC.eq("#{label} ##{i}", fn.call(input), want) }
      true
    end
  end

  t('zf signers_more: cellCoordsError dimensions, paths (UTF-16 length), index ranges and value sets, with the reference text') do
    next true unless ZfSmB.gate?

    dim = 'coords must be an object of 1..64 dimensions'
    path = 'a coordinate path must be 1..256 characters'
    rs = "coords 'a': an index range [lo, hi] or a value set"
    lohi = "coords 'a': need 0 <= lo <= hi"
    one = ->(v) { { 'a' => v } }
    dims = ->(n) { (1..n).to_h { |i| ["d#{i}", [0, 1]] } }
    strs = ->(n) { (1..n).map { |i| "s#{i}" } }
    cases = [
      [nil, dim], [[], dim], [['a'], dim], ['abc', dim], [{}, dim], [dims.call(65), dim],
      [dims.call(64), nil], [dims.call(1), nil],
      [{ '' => [0, 1] }, path], [{ 'a' * 257 => [0, 1] }, path], [{ 'a' * 256 => [0, 1] }, nil], [{ 'b' => [0, 1] }, nil],
      [{ "\u{1F600}" * 128 => [0, 1] }, nil], [{ "\u{1F600}" * 129 => [0, 1] }, path], [{ 1 => [0, 1] }, path],
      [{ 'b' => [0, 1], '' => [0, 1] }, path],
      [one.call([0, 5]), nil], [one.call([5, 5]), nil], [one.call([0, 0]), nil], [one.call([0, (2**53) - 1]), nil], [one.call([3, 3]), nil],
      [one.call([-1, 5]), lohi], [one.call([6, 5]), lohi], [one.call([1, 0]), lohi],
      [one.call([0, 2**53]), rs], [one.call([0, 1.5]), rs], [one.call([1, 2, 3]), rs], [one.call('ab'), rs], [one.call('abc'), rs],
      [one.call(['a', 'b']), nil], [one.call(['USD']), nil], [one.call(strs.call(256)), nil],
      [one.call(%w[a a]), "coords 'a': values must be distinct"], [one.call(strs.call(257)), rs], [one.call([]), rs],
      [one.call(['a', 1]), rs], [one.call([nil]), rs], [one.call({ 'x' => 'y' }), rs], [one.call(5), rs], [one.call(nil), rs],
      [{ 'b' => ['x'], 'a' => [2, 1] }, lohi]
    ]
    ZfSmB.table('cellCoordsError', cases, ->(c) { AtlasPca.cell_coords_error(c) })
  end

  t('zf signers_more: intentRequiredShapeError refuses each malformed member with the reference text, in order; the vector body passes') do
    next true unless ZfSmB.gate?

    ok = ZfSmB.kase('intent-required')['args']['body']
    w = ->(h) { ok.merge(h) }
    d = ->(k) { ok.reject { |x, _| x == k } }
    v1 = 'not a pca-intent-required v1'
    cell = 'cell must be {verb, coords}'
    coords = ok['cell']['coords']
    qid = 'question_id must match [A-Za-z0-9_-]{1,64}'
    exp = 'expires_at must be a non-negative safe integer'
    cases = [
      [ok, nil], [nil, 'not an object'], [[], 'not an object'], ['x', 'not an object'], [w.call('x' => 1), "unknown member 'x'"],
      [w.call('v' => 2), v1], [w.call('v' => true), v1], [w.call('v' => false), v1], [d.call('v'), v1],
      [w.call('kind' => 'pca-intent'), v1], [d.call('kind'), v1]
    ]
    %w[session map_digest schema pcactn_digest action_digest].each do |k|
      m = "#{k} must be canonical base64url (32 bytes)"
      cases.push([w.call(k => 'abc'), m], [w.call(k => 7), m], [d.call(k), m], [w.call(k => AtlasPca.b64e(("\x00" * 33).b)), m])
    end
    cases.push([w.call('session' => 7, 'schema' => 7), 'session must be canonical base64url (32 bytes)'])
    cases.push(
      [w.call('cell' => nil), cell], [w.call('cell' => []), cell], [w.call('cell' => { 'verb' => 'refund' }), cell],
      [w.call('cell' => { 'coords' => coords }), cell], [w.call('cell' => { 'verb' => 'refund', 'coords' => coords, 'x' => 1 }), cell],
      [w.call('cell' => { 'verb' => 5, 'coords' => coords }), cell], [w.call('cell' => { 'verb' => '', 'coords' => coords }), cell],
      [w.call('cell' => { 'coords' => coords, 'verb' => 'refund' }), nil],
      [w.call('cell' => { 'verb' => 'refund', 'coords' => {} }), 'coords must be an object of 1..64 dimensions'],
      [w.call('cell' => { 'verb' => 'refund', 'coords' => { 'a' => [2, 1] } }), "coords 'a': need 0 <= lo <= hi"],
      [w.call('reason' => 'sure'), "reason must be 'uncertain'"], [d.call('reason'), "reason must be 'uncertain'"],
      [w.call('reason' => 'sure', 'question_id' => 7), "reason must be 'uncertain'"],
      [w.call('question_id' => 7), qid], [w.call('question_id' => 'a b'), qid], [w.call('question_id' => 'q' * 65), qid],
      [w.call('question_id' => ''), qid], [w.call('question_id' => "q-1\n"), qid], [d.call('question_id'), qid],
      [w.call('question_id' => 'q' * 64), nil], [w.call('question_id' => 'Az_9-'), nil],
      [w.call('friction' => 'swipe'), 'unknown friction tier'], [w.call('friction' => 'TAP'), 'unknown friction tier'],
      [d.call('friction'), 'unknown friction tier'],
      [w.call('delivered_to' => 'email'), "delivered_to must be 'wallet' or 'agent'"],
      [d.call('delivered_to'), "delivered_to must be 'wallet' or 'agent'"], [w.call('delivered_to' => 'agent'), nil],
      [w.call('expires_at' => -1), exp], [w.call('expires_at' => 1.5), exp], [w.call('expires_at' => '5'), exp],
      [w.call('expires_at' => 2**53), exp], [w.call('expires_at' => true), exp], [d.call('expires_at'), exp],
      [w.call('expires_at' => 0), nil], [w.call('expires_at' => (2**53) - 1), nil],
      [w.call('sig' => {}), 'an unsigned body must not carry sig'], [w.call('sig' => nil), 'an unsigned body must not carry sig']
    )
    %w[tap hold typed device].each { |f| cases << [w.call('friction' => f), nil] }
    ZfSmB.table('intentRequiredShapeError', cases, ->(b) { AtlasPca.intent_required_shape_error(b) }) &&
      ZfSmB.refuses('signIntentRequired', "signIntentRequired: reason must be 'uncertain'") do
        AtlasPca.sign_intent_required(w.call('reason' => 'x'), 'site-k1', ZfSmB.keys['site'])
      end
  end

  t('zf signers_more: mintSessionGrant omitted options are the reference defaults; a fresh salt is 16 random bytes; refusals') do
    next true unless ZfSmB.gate?

    c = ZfSmB.kase('session-grant-g0')
    a = c['args']
    k = ZfSmB.keys
    mint = lambda do |**over|
      args = { session: a['session'], seq: a['seq'], root: a['root'], map_digest: a['map_digest'], predicates: a['predicates'] }
      AtlasPca.mint_session_grant(k[a['principal']], k[a['holder']].public, **args.merge(over))
    end
    ZC.eq('g0 with only the required options', ZfSmB.j(mint.call(salt: a['salt'])), c['expect'])
    s1 = mint.call['goal_salt']
    r2 = mint.call
    s2 = r2['goal_salt']
    raw = AtlasPca.b64d(s2)
    goal = AtlasPca.intent_goal_v2(a['session'], a['map_digest'])
    ZC.eq('fresh salt', [s2.is_a?(String), s2.length, raw&.bytesize, s1 == s2], [true, 22, 16, false])
    ZC.eq('fresh salt is committed', r2['grant']['caveats'][0]['goal_commit'], AtlasPca.goal_commit_of(goal, s2))
    env = mint.call(salt: a['salt'], agent_binding: { 'model' => 'm-1' }, risk_policy: { 'max_ppm' => 7 })['grant']['caveats'][0]
    ZC.eq('agent_binding and risk_policy pass through', [env['agent_binding'], env['risk_policy']], [{ 'model' => 'm-1' }, { 'max_ppm' => 7 }])
    sc = 'mintSessionGrant: intent_session caveat: '
    md = 'mintSessionGrant: mapDigest must be canonical base64url (32 bytes)'
    ZfSmB.refuses('bad session', "#{sc}session and root must be canonical base64url (32 bytes)") { mint.call(session: 'x') } &&
      ZfSmB.refuses('seq 1 without prev', "#{sc}prev is present exactly when seq > 0") { mint.call(seq: 1) } &&
      ZfSmB.refuses('caveat before map digest', "#{sc}session and root must be canonical base64url (32 bytes)") { mint.call(session: 'x', map_digest: 'x') } &&
      ZfSmB.refuses('map digest text', md) { mint.call(map_digest: 'abc') } &&
      ZfSmB.refuses('map digest Integer', md) { mint.call(map_digest: 7) } &&
      ZfSmB.refuses('map digest nil', md) { mint.call(map_digest: nil) } &&
      ZfSmB.refuses('map digest 33 bytes', md) { mint.call(map_digest: AtlasPca.b64e(("\x01" * 33).b)) } &&
      ZC.raises('a PQ suite without its key pair', ArgumentError) { mint.call(salt: a['salt'], alg: 'ml-dsa-65') }
  end

  t('zf signers_more: signSessionRoot emits the reference member order whatever the input order') do
    next true unless ZfSmB.gate?

    c = ZfSmB.kase('session-root')
    body = c['args']['body'].to_a.reverse.to_h
    out = AtlasPca.sign_session_root(body, ZfSmB.keys[c['args']['signer']])
    ZC.eq('member order', out.keys, c['expect'].keys) && ZC.eq('artifact', ZfSmB.j(out), c['expect'])
  end

  t('zf signers_more: signActionSchema refuses a malformed or pre-signed schema; actionSchemaKeyOf entries per suite') do
    next true unless ZfSmB.gate?

    c = ZfSmB.kase('action-schema')
    site = ZfSmB.keys['site']
    sdoc = c['args']['doc']
    pq = ZfSmB::PqStub.new('PQPK')
    pk = site.public
    ok = ZfSmB.refuses('nil schema', 'signActionSchema: schema is not an object') { AtlasPca.sign_action_schema(nil, 'site-k1', site) } &&
         ZfSmB.refuses('pre-signed', 'signActionSchema: an unsigned schema must not carry sig') do
           AtlasPca.sign_action_schema(sdoc.merge('sig' => c['expect']['sig']), 'site-k1', site)
         end &&
         ZC.eq('signed', ZfSmB.j(AtlasPca.sign_action_schema(sdoc, 'site-k1', site)), c['expect'])
    ko = ->(**o) { AtlasPca.action_schema_key_of('site-k1', site, **o) }
    ed = { 'kid' => 'site-k1', 'alg' => 'ed25519', 'pk' => pk }
    ok && ZC.eq('default', ko.call, ed) && ZC.eq('default order', ko.call.keys, %w[kid alg pk]) &&
      ZC.eq('ed25519 ignores a PQ key', ko.call(alg: 'ed25519', pq: pq), ed) &&
      ZC.eq('ml-dsa-65 with its key', ko.call(alg: 'ml-dsa-65', pq: pq), { 'kid' => 'site-k1', 'alg' => 'ml-dsa-65', 'pk' => pk, 'pq_pk' => 'PQPK' }) &&
      ZC.eq('ml-dsa-65 without a key', ko.call(alg: 'ml-dsa-65'), { 'kid' => 'site-k1', 'alg' => 'ml-dsa-65', 'pk' => pk }) &&
      ZC.eq('a registered suite', ko.call(alg: 'fn-dsa-512'), { 'kid' => 'site-k1', 'alg' => 'fn-dsa-512', 'pk' => pk }) &&
      ZfSmB.refuses('unknown alg', 'unknown signature alg "rsa"') { ko.call(alg: 'rsa') }
  end

  t('zf signers_more: labels, fact, offer set and revocation epoch refuse a post-quantum suite named without its key pair') do
    next true unless ZfSmB.gate?

    k = ZfSmB.keys
    body = ->(n) { ZfSmB.kase(n)['args']['body'] }
    ZC.raises('labels', ArgumentError) { AtlasPca.sign_labels(body.call('labels'), k['site'], alg: 'ml-dsa-65') } &&
      ZC.raises('fact', ArgumentError) { AtlasPca.sign_fact(body.call('fact-integer'), k['oracle'], alg: 'ml-dsa-65') } &&
      ZC.raises('offer set', ArgumentError) { AtlasPca.sign_offer_set(body.call('offer-set-complete'), k['site'], alg: 'ml-dsa-65') } &&
      ZC.raises('revocation epoch', ArgumentError) { AtlasPca.sign_revocation_epoch(k['guardian'], body.call('revocation-epoch'), alg: 'ml-dsa-65') }
  end

  t('zf signers_more: signTemplate / signTighten refuse a malformed definition with the reference text') do
    next true unless ZfSmB.gate?

    k = ZfSmB.keys['principal']
    df = ZfSmB.kase('policy-template')['args']['def']
    ov = ZfSmB.kase('policy-tighten')['args']['overlay']
    ZfSmB.refuses('template nil', 'signTemplate: template must be an object') { AtlasPca.sign_template(nil, k) } &&
      ZfSmB.refuses('template v', 'signTemplate: template v / kind mismatch') { AtlasPca.sign_template(df.merge('v' => 2), k) } &&
      ZfSmB.refuses('overlay nil', 'signTighten: overlay must be an object') { AtlasPca.sign_tighten(nil, k) } &&
      ZfSmB.refuses('overlay kind', 'signTighten: overlay v / kind mismatch') { AtlasPca.sign_tighten(ov.merge('kind' => 'x'), k) }
  end
end
