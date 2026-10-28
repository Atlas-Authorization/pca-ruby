# frozen_string_literal: true

require 'openssl'
require 'stringio'
require 'base64'
require 'json'

# 0.4.1 kill tests (scoped mutation pass over the 0.4.1 changes): the policy-layer caveat helpers (policy_caveats /
# evaluate_caveats, corpus primitives.caveat_eval), the strict PCA-Action header (decode_pca_header, corpus
# primitives.pca_header, and the Rack header path), b64e's UTF-8 tag and the US-ASCII wire encoding gate.
# Every AtlasPca constant is resolved at CALL time (the oracle replaces the module per mutant).
module MutationKill
  module R041
    module_function

    KEYS = File.expand_path('../../conformance/keys.json', __dir__)

    def prim(name) = Corpus.core['primitives'][name] || []
    def keys = (@keys ||= JSON.parse(File.read(KEYS)))
    def ev(cavs, ctx) = AtlasPca.evaluate_caveats(cavs, ctx)
    def ok?(cavs, ctx) = ev(cavs, ctx) == [true, []]

    # Deep copy with every ASCII-only String re-tagged US-ASCII (keys too).
    def ascii(x, all: false)
      case x
      when String then all || x.ascii_only? ? x.dup.force_encoding(Encoding::US_ASCII) : x
      when Array then x.map { |e| ascii(e, all: all) }
      when Hash then x.to_h { |k, e| [ascii(k, all: all), ascii(e, all: all)] }
      else x
      end
    end

    # A PCActn built natively from the library's own helpers and signed: [pcactn, root, now].
    def native
      seed = ->(n) { AtlasPca.b64d(keys[n]['seed'], 32) }
      principal = OpenSSL::PKey.new_raw_private_key('ED25519', seed.call('principal'))
      agent = OpenSSL::PKey.new_raw_private_key('ED25519', seed.call('agent'))
      pub = ->(k) { AtlasPca.b64e(k.raw_public_key) }
      root = { 'issuer' => pub.call(principal), 'holder' => pub.call(agent), 'caveats' => [] }
      digest = AtlasPca.hash_canonical(AtlasPca.body_of(root))
      root = root.merge('id' => digest, 'body_digest' => digest,
                        'sig' => AtlasPca.b64e(principal.sign(nil, AtlasPca::CAP_DOMAIN + AtlasPca.b64d(digest, 32))))
      action = { 'verb' => 'read', 'resource' => 'doc:1', 'params_digest' => AtlasPca.params_digest({ 'q' => 1 }),
                 'reversibility_class' => 'reversible' }
      leaf = AtlasPca.plan_leaf('n1', action, AtlasPca.conditions_digest(nil, nil))
      zero = AtlasPca.b64e("\0".b * 32)
      now = 1_800_000_000_000
      p = {
        'ver' => 2, 'action' => action, 'grant_ref' => digest, 'cap_chain' => [root],
        'plan' => { 'root' => AtlasPca.merkle_root([leaf]), 'node_id' => 'n1', 'inclusion_proof' => { 'index' => 0, 'size' => 1, 'path' => [] } },
        'attestation' => { 'epoch' => 1, 'quote_digest' => zero, 'model_id' => 'm', 'measurement' => zero, 'operator' => 'op' },
        'provenance' => { 'causal_hash' => zero, 'taint_level' => 0, 'trusted_refs' => [] },
        'freshness' => { 'epoch' => 1, 'beacon_ref' => zero, 'accumulator_witness' => zero },
        'counter' => 0, 'risk_claim' => { 'r' => 0, 'inputs' => {} }, 'aud' => 'rs-native', 'iat' => now - 1000, 'exp' => now + 60_000
      }
      p['sig'] = AtlasPca.b64e(agent.sign(nil, AtlasPca.threshold_message(p)))
      [p, root, now]
    end
  end

  t('r041 caveat_eval corpus: evaluate_caveats(policy_caveats(grant, chain), ctx) == [allow, failed]') do
    cs = R041.prim('caveat_eval')
    cs.length >= 40 && cs.all? do |c|
      AtlasPca.evaluate_caveats(AtlasPca.policy_caveats(c['grant'], c['chain']), c['context']) == [c['expect']['allow'], c['expect']['failed']]
    end
  end

  t('r041 evaluate_caveats: list shape, failed types in order, fail closed on malformed / unknown') do
    ctx = { 'now' => 1_800_000_000_000, 'action' => { 'params' => { 'amount' => 5 } } }
    ms = { 'type' => 'max_spend', 'usd' => 5 }
    mal = [false, ['<malformed caveats>']]
    R041.ev(nil, ctx) == mal && R041.ev({}, ctx) == mal && R041.ev('x', ctx) == mal && R041.ev([], ctx) == [true, []] &&
      R041.ev(['max_spend', [], { 'type' => 1 }, { 'type' => 'note' }, ms, { 'type' => 'predicates' }], ctx) ==
        [false, ['<malformed>', '<malformed>', '<malformed>', 'note', 'predicates']] &&
      R041.ev([ms, ms], ctx) == [true, []] && R041.ev([ms], nil) == [false, ['max_spend']] &&
      R041.ev([{ type: 'max_spend', usd: 5 }], ctx) == [false, ['<malformed>']] &&
      # a raise inside one caveat is that caveat failing, the others are still judged
      R041.ev([{ 'type' => 'rate', 'max' => 1, 'per_secs' => 1 }, ms], ctx.merge('recent_action_times' => [Object.new])) == [true, []]
  end

  t('r041 max_spend: limit and amount finite >= 0, amount <= usd, currency usd/USD/absent, needs no now') do
    c = ->(usd, params) { R041.ok?([{ 'type' => 'max_spend', 'usd' => usd }], { 'action' => { 'params' => params } }) }
    c.call(5, { 'amount' => 5 }) && c.call(5.0, { 'amount' => 4 }) && c.call(0, { 'amount' => 0 }) && !c.call(4.99, { 'amount' => 5 }) &&
      !c.call(true, { 'amount' => 1 }) && !c.call(Float::INFINITY, { 'amount' => 1 }) && !c.call(Float::NAN, { 'amount' => 1 }) &&
      !c.call(-1, { 'amount' => -1 }) && !c.call(nil, { 'amount' => 1 }) && !c.call('5', { 'amount' => 1 }) && !c.call(10**400, { 'amount' => 1 }) &&
      !c.call(5, { 'amount' => true }) && !c.call(5, { 'amount' => -0.5 }) && !c.call(5, { 'amount' => '1' }) && !c.call(5, {}) &&
      !c.call(5, { 'amount' => nil }) && !c.call(5, { 'amount' => Float::NAN }) &&
      c.call(5, { 'amount' => 1, 'currency' => 'usd' }) && c.call(5, { 'amount' => 1, 'currency' => 'USD' }) &&
      !c.call(5, { 'amount' => 1, 'currency' => 'eur' }) && !c.call(5, { 'amount' => 1, 'currency' => nil }) &&
      !c.call(5, { 'amount' => 1, 'currency' => 'Usd' }) && !c.call(5, 'amount') && !c.call(5, [['amount', 1]]) &&
      !R041.ok?([{ 'type' => 'max_spend', 'usd' => 5 }], { 'action' => 'x' }) &&
      !R041.ok?([{ 'type' => 'max_spend', 'usd' => 5 }], { 'params' => { 'amount' => 1 } }) &&
      !R041.ok?(['type'], { 'action' => { 'params' => { 'amount' => 1 } } })
  end

  t('r041 time caveats: need a finite now; expires / not_before / budget_alloc boundaries') do
    c = ->(cv, now) { R041.ok?([cv], now.nil? ? {} : { 'now' => now }) }
    e = ->(at) { { 'type' => 'expires', 'at' => at } }
    nb = ->(at) { { 'type' => 'not_before', 'at' => at } }
    ba = ->(l) { { 'type' => 'budget_alloc', 'limit' => l } }
    c.call(e.call(11), 10) && !c.call(e.call(10), 10) && !c.call(e.call(9), 10) && !c.call(e.call(nil), 10) && !c.call(e.call(11), nil) &&
      !c.call(e.call(11), Float::NAN) && !c.call(e.call(11), true) && c.call(e.call(10.5), 10) &&
      c.call(nb.call(10), 10) && c.call(nb.call(9), 10) && !c.call(nb.call(11), 10) && !c.call(nb.call('1'), 10) && !c.call(nb.call(1), nil) &&
      c.call(ba.call(0), 1) && c.call(ba.call(3.5), 1) && !c.call(ba.call(-1), 1) && !c.call(ba.call(nil), 1) && !c.call(ba.call(0), nil) &&
      !c.call(ba.call(Float::INFINITY), 1) && !c.call({ 'type' => 'unknown' }, 1) && !c.call({ 'type' => 'envelope' }, 1)
  end

  t('r041 rate: fewer than max entries in (now - per_secs*1000, now]; malformed fields fail closed') do
    r = ->(max, per, times, now = 10_000) { R041.ok?([{ 'type' => 'rate', 'max' => max, 'per_secs' => per }], { 'now' => now, 'recent_action_times' => times }) }
    r.call(2, 5, [5000, 10_000]) == true && # 5000 is NOT inside (5000, 10000]
      r.call(2, 5, [5001, 10_000]) == false && r.call(2, 5, [10_001, 9000]) == true && r.call(2, 5, [10_000]) == true &&
      r.call(1, 5, [10_000]) == false && r.call(1, 5, []) == true && r.call(0, 5, []) == false &&
      r.call(2, 5, ['9000', true, nil, 9000]) == true && r.call(1, 5, [9000.5]) == false &&
      r.call(nil, 5, []) == false && r.call(1, nil, []) == false && r.call(1, 0, []) == false && r.call(1, -1, []) == false &&
      r.call(1, 5, nil) == false && r.call(1, 5, {}) == false && r.call(3, 2, [8001, 9000, 9999]) == false && r.call(3, 2, [7999, 8000, 8001, 9999]) == true &&
      r.call(3, 2, [7999, 8000, 8001]) == true && r.call(1.5, 5, [9000]) == true
  end

  t('r041 max_blast_radius / delegation_depth / reversibility_max boundaries') do
    c = ->(cv, ctx) { R041.ok?([cv], { 'now' => 1 }.merge(ctx)) }
    br = ->(m) { { 'type' => 'max_blast_radius', 'max' => m } }
    dd = ->(m) { { 'type' => 'delegation_depth', 'max' => m } }
    rv = ->(k) { { 'type' => 'reversibility_max', 'class' => k } }
    c.call(br.call(3), 'blast_radius' => 3) && c.call(br.call(3), 'blast_radius' => 2) && !c.call(br.call(3), 'blast_radius' => 4) &&
      !c.call(br.call(nil), 'blast_radius' => 1) && !c.call(br.call(3), {}) && !c.call(br.call(3), 'blast_radius' => '1') &&
      c.call(dd.call(2), 'delegation_depth' => 2) && c.call(dd.call(2), 'delegation_depth' => 0) && !c.call(dd.call(2), 'delegation_depth' => 3) &&
      !c.call(dd.call('2'), 'delegation_depth' => 1) && !c.call(dd.call(2), {}) &&
      c.call(rv.call('irreversible'), 'reversibility_class' => 'irreversible') && c.call(rv.call('rate_limited'), 'reversibility_class' => 'reversible') &&
      c.call(rv.call('rate_limited'), 'reversibility_class' => 'rate_limited') && !c.call(rv.call('rate_limited'), 'reversibility_class' => 'irreversible') &&
      !c.call(rv.call('reversible'), 'reversibility_class' => 'rate_limited') && c.call(rv.call('reversible'), 'reversibility_class' => 'reversible') &&
      !c.call(rv.call('bogus'), 'reversibility_class' => 'reversible') && !c.call(rv.call('irreversible'), 'reversibility_class' => 'bogus') &&
      !c.call(rv.call(1), 'reversibility_class' => 'reversible') && !c.call(rv.call('irreversible'), {}) &&
      !c.call(rv.call('irreversible'), 'action' => { 'reversibility_class' => 'reversible' }) &&
      AtlasPca::REVERSIBILITY_ORDER == %w[reversible rate_limited irreversible] && AtlasPca::REVERSIBILITY_ORDER.frozen? &&
      AtlasPca::ENVELOPE_CAVEAT == 'envelope'
  end

  t('r041 finite_num / action_spend_usd') do
    AtlasPca.finite_num(3) == 3.0 && AtlasPca.finite_num(3).is_a?(Float) && AtlasPca.finite_num(2.5) == 2.5 && AtlasPca.finite_num(-1) == -1.0 &&
      AtlasPca.finite_num(10**400).nil? && AtlasPca.finite_num(Float::NAN).nil? && AtlasPca.finite_num(-Float::INFINITY).nil? &&
      AtlasPca.finite_num(true).nil? && AtlasPca.finite_num('1').nil? && AtlasPca.finite_num(nil).nil? &&
      AtlasPca.action_spend_usd({ 'params' => { 'amount' => 7 } }) == 7.0 && AtlasPca.action_spend_usd({ 'params' => { 'amount' => 0 } }) == 0.0 &&
      AtlasPca.action_spend_usd({ 'params' => { 'amount' => 7, 'currency' => 'USD' } }) == 7.0 &&
      AtlasPca.action_spend_usd({ 'params' => { 'amount' => 7, 'currency' => 'eur' } }).nil? &&
      AtlasPca.action_spend_usd({ 'params' => { 'amount' => -7 } }).nil? && AtlasPca.action_spend_usd({ 'params' => {} }).nil? &&
      AtlasPca.action_spend_usd({ 'params' => 'x' }).nil? && AtlasPca.action_spend_usd({}).nil? && AtlasPca.action_spend_usd(nil).nil?
  end

  t('r041 policy_caveats: first envelope dropped (order kept), hop-appended caveats added, inputs untouched') do
    env = { 'type' => 'envelope' }
    a = { 'type' => 'max_spend', 'usd' => 1 }
    b = { 'type' => 'expires', 'at' => 2 }
    c = { 'type' => 'note' }
    grant = { 'caveats' => [a, env, env] }
    leaf = { 'caveats' => [a, env, env, b, c] }
    AtlasPca.policy_caveats(grant, nil) == [a, env] && AtlasPca.policy_caveats(grant) == [a, env] &&
      AtlasPca.policy_caveats(grant, 'nope') == [a, env] && AtlasPca.policy_caveats(grant, []) == [a, env] &&
      AtlasPca.policy_caveats(grant, [grant, leaf]) == [a, env, b, c] && AtlasPca.policy_caveats(grant, [leaf, grant]) == [a, env] &&
      AtlasPca.policy_caveats(grant, [grant, { 'caveats' => 'x' }]) == [a, env] && AtlasPca.policy_caveats(grant, [grant, 'leaf']) == [a, env] &&
      AtlasPca.policy_caveats(grant, [grant, { 'caveats' => [a] }]) == [a, env] &&
      AtlasPca.policy_caveats({ 'caveats' => [env, a, b] }, nil) == [a, b] && AtlasPca.policy_caveats({ 'caveats' => [a, b, env] }, nil) == [a, b] &&
      AtlasPca.policy_caveats({ 'caveats' => [a, b] }, nil) == [a, b] && AtlasPca.policy_caveats({ 'caveats' => ['envelope', env] }, nil) == ['envelope'] &&
      AtlasPca.policy_caveats({ 'caveats' => [] }, [{ 'caveats' => [b] }]) == [b] &&
      AtlasPca.policy_caveats({}, [leaf]).nil? && AtlasPca.policy_caveats({ 'caveats' => 'x' }, [leaf]) == 'x' &&
      AtlasPca.policy_caveats('grant', [leaf]).nil? && grant['caveats'] == [a, env, env] && leaf['caveats'] == [a, env, env, b, c] &&
      !AtlasPca.policy_caveats({ 'caveats' => [a] }, nil).equal?(nil) &&
      (g2 = { 'caveats' => [a] }; out = AtlasPca.policy_caveats(g2, nil); out << b; g2['caveats'] == [a])
  end

  t('r041 pca_header corpus + non-strings: strict decode yields UTF-8 text') do
    hs = R041.prim('pca_header')
    hs.length >= 27 && hs.all? do |c|
      got = AtlasPca.decode_pca_header(c['input'])
      !got.nil? == c['valid'] && (got.nil? || (got == c['text'] && got.encoding == Encoding::UTF_8))
    end && AtlasPca.decode_pca_header(nil).nil? && AtlasPca.decode_pca_header(123).nil? && AtlasPca.decode_pca_header('').nil? &&
      AtlasPca.decode_pca_header(['e30']).nil? && AtlasPca.decode_pca_header('e30') == '{}' &&
      AtlasPca.decode_pca_header('e30').encoding == Encoding::UTF_8 && AtlasPca.decode_pca_header('__57').nil? &&
      AtlasPca.decode_pca_header('e30=').nil? && (s = +'e30'; AtlasPca.decode_pca_header(s); s.encoding == Encoding::UTF_8) &&
      (b = AtlasPca.b64e('{}'.b); AtlasPca.decode_pca_header(b); b == 'e30')
  end

  t('r041 middleware header: canonical verifies, every lenient spelling and non-UTF-8 bytes are a 401 decode error') do
    v = Corpus.core['vectors'].find { |x| x['name'] == 'valid-raw-json-format-insensitive' }
    pc = AtlasPca.parse_json(v['pcactn_json'])
    grant = v['grant']
    mw = AtlasPca::RackMiddleware.new(->(_e) { [200, {}, ['ok']] }, audience: v['context']['aud'],
                                                                    resolve_grant: ->(r) { r == pc['grant_ref'] ? grant : nil }, now: v['context']['now'], signature_only: true)
    env = ->(h) { { 'HTTP_PCA_ACTION' => h, 'rack.input' => StringIO.new('') } }
    canon = Base64.urlsafe_encode64(v['pcactn_json'].b, padding: false)
    lenient = [canon + ('=' * ((4 - (canon.length % 4)) % 4)), canon.tr('-_', '+/'), Base64.strict_encode64(v['pcactn_json'].b),
               " #{canon}", "#{canon} ", "#{canon}\t", "#{canon[0, 8]}\n#{canon[8..]}"].uniq - [canon]
    bad = ->(h) { s, _hd, body = mw.call(env.call(h)); s == 401 && body.join.include?('not canonical base64url') }
    mw.call(env.call(canon))[0] == 200 && lenient.length >= 5 && lenient.all? { |h| bad.call(h) } && bad.call('__57') &&
      (s, _hd, body = mw.call(env.call(AtlasPca.b64e('[1]'.b))); s == 401 && !body.join.include?('not canonical base64url'))
  end

  t('r041 b64e is UTF-8-tagged; natively built PCActn (and its US-ASCII copy) verifies') do
    p, root, now = R041.native
    AtlasPca.b64e('x'.b).encoding == Encoding::UTF_8 && AtlasPca.b64e('x'.b) == 'eA' && AtlasPca.b64e(''.b) == '' &&
      AtlasPca.verify_pcactn(p, root, now: now, audience: 'rs-native').allow == true &&
      AtlasPca.verify_pcactn(R041.ascii(p, all: true), R041.ascii(root, all: true), now: now, audience: 'rs-native').allow == true
  end

  t('r041 wire encoding gate: UTF-8 / valid US-ASCII strings pass; BINARY, invalid bytes, UTF-16 refused') do
    vec = Corpus.core['vectors'].find { |x| x['name'] == 'valid-in-plan-action' }
    ctx = vec['context']
    run = ->(pc) { AtlasPca.verify_pcactn(pc, vec['grant'], now: ctx['now'], audience: ctx['aud']) }
    bad = ["a\xFFb".dup.force_encoding(Encoding::US_ASCII), 'node'.b, "a\xC0\xAF".dup.force_encoding(Encoding::UTF_8),
           'node'.encode(Encoding::UTF_16LE), 'node'.encode(Encoding::ISO_8859_1)]
    refused = ->(r) { r.allow == false && r.checks == { 'wire' => false } }
    run.call(vec['pcactn']).allow == true && run.call(R041.ascii(vec['pcactn'])).allow == true &&
      bad.all? do |str|
        refused.call(run.call(vec['pcactn'].merge('plan' => vec['pcactn']['plan'].merge('node_id' => str)))) &&
          refused.call(run.call(vec['pcactn'].merge('progress_step' => { str => 1 })))
      end &&
      AtlasPca.utf8_string?('a'.dup.force_encoding(Encoding::US_ASCII)) && AtlasPca.utf8_string?('é') && !AtlasPca.utf8_string?('a'.b) &&
      !AtlasPca.utf8_string?("\xFF".dup.force_encoding(Encoding::US_ASCII)) && !AtlasPca.utf8_string?("\xFF".dup.force_encoding(Encoding::UTF_8)) &&
      !AtlasPca.utf8_string?(:a) && !AtlasPca.utf8_string?(nil)
  end

  t('r041 share wire: validate_share_signature_wire per suite, pq_pk echo not judged; leaf still judges pq_pk', needs: 'ml-dsa-65') do
    ed = { 'sig' => AtlasPca.b64e("\x01".b * 64) }
    ml = { 'alg' => 'ml-dsa-65', 'sig' => AtlasPca.b64e("\x01".b * 3309) }
    pk = AtlasPca.b64e("\x02".b * 1952)
    AtlasPca.validate_share_signature_wire(ed).nil? && AtlasPca.validate_share_signature_wire(ml).nil? &&
      AtlasPca.validate_share_signature_wire(ml.merge('pq_pk' => 'junk')).nil? && AtlasPca.validate_share_signature_wire(ed.merge('pq_pk' => pk)).nil? &&
      !AtlasPca.validate_share_signature_wire(ed.merge('pq_sig' => 'AA')).nil? &&
      !AtlasPca.validate_share_signature_wire({ 'sig' => AtlasPca.b64e("\x01".b * 63) }).nil? &&
      !AtlasPca.validate_share_signature_wire(ml.merge('sig' => AtlasPca.b64e("\x01".b * 64))).nil? &&
      !AtlasPca.validate_share_signature_wire({ 'alg' => 'nope', 'sig' => ed['sig'] }).nil? &&
      !AtlasPca.validate_signature_wire(ed.merge('pq_pk' => pk)).nil? && !AtlasPca.validate_signature_wire(ml.merge('pq_pk' => 'junk')).nil? &&
      AtlasPca.validate_signature_wire(ml.merge('pq_pk' => pk)).nil? && AtlasPca.validate_signature_wire(ed).nil? &&
      AtlasPca.validate_signature_wire(ml).is_a?(String)
  end

  # caveat_satisfied? / action_spend_usd / policy_caveats / decode_pca_header are TOTAL and strictly typed on their own (not
  # only behind evaluate_caveats' rescue): every malformed input is a plain false / nil, never an exception.
  t('r041 caveat_satisfied? is total and strictly boolean on malformed input') do
    f = ->(cv, ctx) { AtlasPca.caveat_satisfied?(cv, ctx).equal?(false) }
    tr = ->(cv, ctx) { AtlasPca.caveat_satisfied?(cv, ctx).equal?(true) }
    now = { 'now' => 10 }
    act = ->(params) { { 'action' => { 'params' => params } } }
    f.call(5, now) && f.call({ 'type' => 'expires', 'at' => 11 }, 5) && f.call(5, 5) && f.call('x', now) &&
      f.call({ 'type' => 'max_spend', 'usd' => nil }, act.call({ 'amount' => 1 })) &&
      f.call({ 'type' => 'max_spend', 'usd' => '5' }, act.call({ 'amount' => 1 })) &&
      f.call({ 'type' => 'max_spend', 'usd' => 5 }, {}) && f.call({ 'type' => 'max_spend', 'usd' => 5 }, act.call({ 'amount' => 'x' })) &&
      tr.call({ 'type' => 'max_spend', 'usd' => 5 }, act.call({ 'amount' => 5 })) &&
      f.call({ 'type' => 'expires', 'at' => 11 }, {}) && f.call({ 'type' => 'expires', 'at' => nil }, now) &&
      f.call({ 'type' => 'not_before', 'at' => nil }, now) && tr.call({ 'type' => 'expires', 'at' => 11 }, now) &&
      f.call({ 'type' => 'rate', 'max' => nil, 'per_secs' => 5 }, now.merge('recent_action_times' => [])) &&
      f.call({ 'type' => 'rate', 'max' => 1, 'per_secs' => nil }, now.merge('recent_action_times' => [])) &&
      f.call({ 'type' => 'rate', 'max' => nil, 'per_secs' => nil }, now.merge('recent_action_times' => [])) &&
      f.call({ 'type' => 'max_blast_radius', 'max' => nil }, now.merge('blast_radius' => 1)) &&
      f.call({ 'type' => 'max_blast_radius', 'max' => 1 }, now) &&
      f.call({ 'type' => 'reversibility_max', 'class' => 'bogus' }, now.merge('reversibility_class' => 'reversible')) &&
      f.call({ 'type' => 'reversibility_max', 'class' => 'irreversible' }, now.merge('reversibility_class' => 'bogus')) &&
      f.call({ 'type' => 'reversibility_max', 'class' => ['irreversible'] }, now.merge('reversibility_class' => 'reversible')) &&
      f.call({ 'type' => 'reversibility_max', 'class' => 'irreversible' }, now) &&
      f.call({ 'type' => 'delegation_depth', 'max' => nil }, now.merge('delegation_depth' => 1)) &&
      f.call({ 'type' => 'delegation_depth', 'max' => 1 }, now) &&
      f.call({ 'type' => 'budget_alloc', 'limit' => nil }, now) && f.call({ 'type' => 'note' }, now)
  end

  t('r041 evaluate_caveats: a caveat that raises is unsatisfied (rescued), the rest are still judged') do
    boom = Hash.new { |_h, _k| raise 'boom' }
    AtlasPca.evaluate_caveats([{ 'type' => 'max_spend', 'usd' => 5 }], boom) == [false, ['max_spend']]
  end

  t('r041 helpers never raise on non-Hash / non-Array inputs') do
    g = { 'caveats' => [{ 'type' => 'a' }] }
    AtlasPca.action_spend_usd(5).nil? && AtlasPca.action_spend_usd({ 'params' => { 'amount' => 'x' } }).nil? &&
      AtlasPca.policy_caveats(5, nil).nil? && AtlasPca.policy_caveats({ 'caveats' => [5, { 'type' => 'envelope' }] }) == [5] &&
      AtlasPca.policy_caveats(g, 5) == [{ 'type' => 'a' }] && AtlasPca.policy_caveats(g, [g, 5]) == [{ 'type' => 'a' }] &&
      AtlasPca.policy_caveats(g, [g, { 'caveats' => 'xxxxxxxxxx' }]) == [{ 'type' => 'a' }] &&
      AtlasPca.decode_pca_header(123).nil? && AtlasPca.decode_pca_header(:sym).nil? &&
      AtlasPca.optional_wire_ok?({ 'threshold' => { 'shares' => [5] } }) == false &&
      AtlasPca.optional_wire_ok?({ 'threshold' => { 'shares' => ['role'] } }) == false
  end
end
