# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'digest'
require 'json'

# Intent Layer v2 W-B kill tests (rules 16, 17, 18 and their composition `decide_intent_wb`): every boundary is pinned on
# both sides and every refusal by its exact first-failure reason, with inputs that fail two steps so the earlier step must
# win. Artifacts are signed in-test from the conformance seeds (sha256("atlas-pca-conformance/<label>")) with OpenSSL
# Ed25519. Every AtlasPca constant / helper is resolved at CALL time (the oracle replaces the module per mutant): nothing
# derived from AtlasPca is memoized.
module MutationKill
  module WB
    module_function

    NOW = 1_800_000_000_000
    AUD = 'skyair.example'
    MAX_SAFE = 9_007_199_254_740_991
    FACT_D = "atlas-pca/fact/v1\u0000"
    OFFER_D = "atlas-pca/offer-set/v1\u0000"
    LABELS_D = "atlas-pca/labels/v1\u0000"
    CLS_D = "atlas-pca/intent-classifier/v1\u0000"
    OFFERS = [
      { 'offer_id' => 'OF-1', 'price' => 38_900, 'stops' => 1, 'refundable' => false },
      { 'offer_id' => 'OF-2', 'price' => 39_800, 'stops' => 0, 'refundable' => false },
      { 'offer_id' => 'OF-3', 'price' => 41_200, 'stops' => 0, 'refundable' => true }
    ].freeze
    QUERY = { 'from' => 'SFO', 'to' => 'JFK', 'date' => '2026-11-20', 'pax' => 2 }.freeze
    PARAMS = { 'offer_id' => 'OF-1', 'payment_ref' => 'pm_ana_visa', 'add_ons' => 'tripshield', 'passport' => 'X1234567', 'note' => 'hi',
               'pax' => { 'lead' => 'px_ana' } }.freeze
    T = { 'action.params.add_ons' => 'trusted', 'action.params.offer_id' => 'first_party', 'action.params.passport' => 'trusted',
          'action.params.payment_ref' => 'trusted' }.freeze
    MESSAGE = 'We are sorry for the delay.'

    def seed(l) = Digest::SHA256.digest("atlas-pca-conformance/#{l}")
    def b64(bin) = Base64.urlsafe_encode64(bin, padding: false)
    def key(l) = OpenSSL::PKey.new_raw_private_key('ED25519', seed(l))
    def pk(k) = b64(k.raw_public_key)
    def session = b64(seed('wb/session'))
    def other_session = b64(seed('wb/other-session'))
    def digest(l) = b64(Digest::SHA256.digest(l))
    def oracle(i) = key("wb/oracle-#{i + 1}")
    def rogue = key('wb/rogue')
    def site = key('wb/site')
    def gov = key('wb/gov')
    def judge(i) = key("wb/judge-#{i + 1}")

    # Sign `body` (no `sig`) over utf8(domain) || strictCanonical(body).
    def sign(domain, body, k)
      body.merge('sig' => b64(k.sign(nil, domain.b + AtlasPca.canon_bytes(body))))
    end

    # ---- rule 16
    def fact(i, name, value, t_obs: NOW - 1000, subject: 'OF-2', kid: "o#{i + 1}", k: oracle(i))
      sign(FACT_D, { 'v' => 1, 'kind' => 'pca-fact', 'name' => name, 'subject' => subject, 'value' => value, 't_obs' => t_obs,
                     'oracle' => kid }, k)
    end

    def oracles(n = 3) = (0...n).map { |i| { 'kid' => "o#{i + 1}", 'pk' => pk(oracle(i)) } }

    def fare_world(over = {})
      { 'name' => 'fare', 'subject_path' => 'action.params.offer_id', 'oracles' => oracles, 'freshness_ms' => 60_000,
        'min_oracles' => 3, 'max_faulty' => 1 }.merge(over)
    end

    def action(over = {})
      { 'verb' => 'air.book', 'resource' => 'skyair.example/bookings',
        'params' => { 'offer_id' => 'OF-2', 'total' => 77_800, 'quote' => 38_900, 'pax' => 2 }.merge(over) }
    end

    def w_in(facts, policy, over = {})
      { 'now' => NOW, 'aud' => AUD, 'session' => session, 'action' => action,
        'committed' => { 'facts' => facts.map { |f| AtlasPca.fact_ref(f) } }, 'facts' => facts, 'policy' => policy }.merge(over)
    end

    def three = [fact(0, 'fare', 39_800), fact(1, 'fare', 39_900), fact(2, 'fare', 1)]
    def world(input) = AtlasPca.decide_intent_world(input)
    def wr(input) = world(input)['reason']
    def wok(input, want) = world(input) == { 'ok' => true, 'world' => want, 'single_source' => [] }
    def rel(name, fn, a, b) = { 'name' => name, 'fn' => fn, 'a' => a, 'b' => b }

    def offer_set(over = {}, k = site)
      sign(OFFER_D, { 'v' => 1, 'kind' => 'pca-offer-set', 'site' => AUD, 'session' => session, 'query' => QUERY, 'rank' => 'price_asc',
                      'complete' => true, 'offers' => OFFERS, 'issued_at' => NOW - 10_000, 'kid' => 'skyair-2026' }.merge(over), k)
    end

    def offer_policy(over = {})
      { 'name' => 'excess_cents', 'site_keys' => [{ 'kid' => 'skyair-2026', 'pk' => pk(site) }], 'max_age_ms' => 600_000,
        'offer_param' => 'action.params.offer_id', 'filter' => { 'query' => QUERY, 'offer' => { 'refundable' => false } } }.merge(over)
    end

    def os_in(os, policy = offer_policy, over = {})
      { 'now' => NOW, 'aud' => AUD, 'session' => session, 'action' => action,
        'committed' => { 'offer_set' => AtlasPca.offer_set_ref(os) }, 'offer_set' => os, 'policy' => { 'offers' => policy } }.merge(over)
    end

    def excess(input)
      r = world(input)
      r['ok'] ? r['world']['excess_cents'] : r['reason']
    end

    # ---- rule 17
    def p_policy(over = {})
      { 'params' => { 'action.params.offer_id' => 'material', 'action.params.add_ons' => 'material', 'action.params.payment_ref' => 'critical',
                      'action.params.passport' => 'critical' },
        'registry' => { 'skyair:offer_set:1' => 'first_party', 'wallet:profile:ana' => 'trusted', 'web:ad-3' => 'web', 'tool:fx' => 'tool',
                        'agent:planner' => 'agent' },
        'label_keys' => [{ 'site' => AUD, 'kid' => 'k1', 'pk' => pk(site) }, { 'site' => 'gov.example', 'kid' => 'g1', 'pk' => pk(gov) }] }
        .merge(over)
    end

    def clean
      { 'action.params.offer_id' => ['skyair:offer_set:1'], 'action.params.payment_ref' => ['wallet:profile:ana'],
        'action.params.add_ons' => ['wallet:profile:ana'], 'action.params.passport' => ['wallet:profile:ana'] }
    end

    def p_in(prov_over = {}, policy_over = {}, over = {})
      { 'aud' => AUD, 'session' => session, 'action' => { 'params' => PARAMS }, 'prov' => clean.merge(prov_over),
        'policy' => p_policy(policy_over) }.merge(over)
    end

    def vd(v) = AtlasPca.hash_canonical(v)

    def receipt(site_name, k, kid, fields, sess = session)
      sign(LABELS_D, { 'v' => 1, 'kind' => 'pca-labels', 'site' => site_name, 'session' => sess, 'response_digest' => b64(seed('wb/response')),
                       'fields' => fields, 'issued_at' => NOW - 5000, 'kid' => kid }, k)
    end

    def pass_fields(cls = 'pii.identity') = { 'travellers[0].passport' => { 'class' => cls, 'value_digest' => vd('X1234567') } }
    def passport(sess = session, k = site, kid = 'k1') = receipt(AUD, k, kid, pass_fields, sess)
    def gov_receipt(cls = 'pii.identity') = receipt('gov.example', gov, 'g1', { 'passport' => { 'class' => cls, 'value_digest' => vd('X1234567') } })
    def lref(r, f) = "pca-labels:#{AtlasPca.label_receipt_ref(r)}##{f}"

    def with_label(r, f, extra = {})
      { 'committed_labels' => [AtlasPca.label_receipt_ref(r)], 'labels' => [r],
        'prov' => clean.merge('action.params.passport' => [lref(r, f)]) }.merge(extra)
    end

    def prov(input) = AtlasPca.decide_param_provenance(input)
    def pr(input) = prov(input)['reason']
    def out3(r) = [r['outcome'], r['friction'], r['labels']]

    # ---- rule 18
    def verdict(k, label, over = {})
      sign(CLS_D, { 'v' => 1, 'kind' => 'pca-intent-classification', 'classifier' => 'tone', 'session' => session,
                    'content_digest' => vd(MESSAGE), 'label' => label, 'measurement' => 'm-tone-1' }.merge(over).merge('judge' => pk(k)), k)
    end

    def tone(over = {})
      { 'id' => 'tone', 'param' => 'action.params.body', 'labels' => %w[neutral apologetic hostile other],
        'keys' => (0..2).map { |i| pk(judge(i)) }, 'k' => 2, 'measurements' => ['m-tone-1'] }.merge(over)
    end

    def c_in(vs, pol_over = {}, over = {})
      { 'session' => session, 'action' => { 'params' => { 'body' => MESSAGE } }, 'committed' => vs.map { |v| AtlasPca.classifier_verdict_ref(v) },
        'verdicts' => vs, 'policy' => { 'classifiers' => [tone(pol_over)] } }.merge(over)
    end

    def cls(input) = AtlasPca.decide_classifier_dimensions(input)
    def cr(input) = cls(input)['reason']
    def j(i) = judge(i)

    # ---- composition
    def wb(session_member, policy, over = {})
      { 'now' => NOW, 'aud' => AUD, 'session' => session, 'action' => { 'verb' => 'air.book', 'resource' => 'r', 'params' => PARAMS.merge('offer_id' => 'OF-2', 'body' => MESSAGE) },
        'intent_session' => session_member, 'policy' => policy }.merge(over)
    end
  end

  # =================================================================== shared plumbing

  t('W-B constants') do
    a = AtlasPca
    a::FACT_DOMAIN == "atlas-pca/fact/v1\u0000" && a::FACT_REF_DOMAIN == 'atlas-pca/fact-ref/v1' && a::MAX_COMMITTED_FACTS == 16 &&
      a::MAX_WORLDS == 16 && a::MAX_RELATIONAL == 16 && a::DEFAULT_WORLD_SKEW_MS == 60_000 &&
      a::OFFER_SET_DOMAIN == "atlas-pca/offer-set/v1\u0000" && a::OFFER_SET_REF_DOMAIN == 'atlas-pca/offer-set-ref/v1' &&
      a::MAX_OFFERS == 256 && a::MAX_OFFER_ATTRS == 32 && a::MAX_QUERY_KEYS == 32 &&
      a::LABELS_DOMAIN == "atlas-pca/labels/v1\u0000" && a::LABELS_REF_DOMAIN == 'atlas-pca/labels-ref/v1' && a::MAX_LABEL_FIELDS == 64 &&
      a::PUBLIC_CLASS == 'public' && a::LABEL_REF_PREFIX == 'pca-labels:' && a::MAX_PROV_PATHS == 32 && a::MAX_PROV_REFS == 8 &&
      a::MAX_COMMITTED_LABELS == 16 && a::INTENT_CLASSIFIER_DOMAIN == "atlas-pca/intent-classifier/v1\u0000" &&
      a::INTENT_CLASSIFIER_REF_DOMAIN == 'atlas-pca/intent-classifier-ref/v1' && a::MAX_COMMITTED_CLASSES == 8 &&
      a::MAX_CLASSIFIER_LABELS == 32 && a::TAINT_LEVELS == %w[trusted first_party tool web agent]
  end

  t('references: b64u(sha256(canonical {d, slot: artifact})) with the right domain and slot, signature included') do
    w = WB
    f = w.fact(0, 'fare', 5)
    lit = '{"d":"atlas-pca/fact-ref/v1","f":{"kind":"pca-fact","name":"fare","oracle":"o1","sig":"' + f['sig'] +
          '","subject":"OF-2","t_obs":1799999999000,"v":1,"value":5}}'
    os = w.offer_set
    r = w.passport
    v = w.verdict(w.j(0), 'neutral')
    AtlasPca.fact_ref(f) == w.b64(Digest::SHA256.digest(lit)) &&
      AtlasPca.fact_ref(f) != AtlasPca.fact_ref(f.merge('sig' => w.b64("\0" * 64))) &&
      AtlasPca.offer_set_ref(os) == AtlasPca.hash_canonical({ 'd' => 'atlas-pca/offer-set-ref/v1', 'o' => os }) &&
      AtlasPca.label_receipt_ref(r) == AtlasPca.hash_canonical({ 'd' => 'atlas-pca/labels-ref/v1', 'l' => r }) &&
      AtlasPca.classifier_verdict_ref(v) == AtlasPca.hash_canonical({ 'd' => 'atlas-pca/intent-classifier-ref/v1', 'c' => v }) &&
      AtlasPca.value_digest('X1234567') == w.b64(Digest::SHA256.digest('"X1234567"')) &&
      AtlasPca.classifier_content_digest({ 'b' => 'x', 'a' => [1, 2] }) == w.b64(Digest::SHA256.digest('{"a":[1,2],"b":"x"}'))
  end

  t('JS number model when hashing: an integral Float is the Integer; -0.0, 1e20, NaN and lone surrogates have no canonical form') do
    f = WB.fact(0, 'fare', 39_800)
    g = f.merge('value' => 39_800.0, 't_obs' => f['t_obs'].to_f)
    bad = "\xED\xA0\x80".dup.force_encoding(Encoding::UTF_8)
    raises = lambda do |v|
      AtlasPca.value_digest(v)
      false
    rescue AtlasPca::Malformed
      true
    end
    AtlasPca.fact_ref(g) == AtlasPca.fact_ref(f) && AtlasPca.value_digest(5.0) == AtlasPca.value_digest(5) &&
      AtlasPca.value_digest(0.0) == AtlasPca.value_digest(0) && AtlasPca.value_digest([1.0, { 'a' => 2.0 }]) == AtlasPca.value_digest([1, { 'a' => 2 }]) &&
      AtlasPca.value_digest(1.5) == WB.b64(Digest::SHA256.digest('1.5')) &&
      [-0.0, 1e20, Float::NAN, Float::INFINITY, 9_007_199_254_740_992, bad, { 'k' => bad }].all? { |v| raises.call(v) }
  end

  t('scalar_eq: same JSON type and value (2 == 2.0, 2 != "2", true != 1, nil only equals nil)') do
    e = ->(a, b) { AtlasPca.scalar_eq(a, b) }
    e.(2, 2.0) && e.(2.0, 2) && e.('a', 'a') && e.(true, true) && e.(false, false) && e.(nil, nil) && e.(-0.0, 0) &&
      !e.(2, '2') && !e.('2', 2) && !e.(true, 1) && !e.(1, true) && !e.(false, 0) && !e.(nil, false) && !e.(false, nil) &&
      !e.(Float::NAN, Float::NAN) && !e.('a', 'b') && !e.(true, false) && !e.([1], [1]) && !e.({}, {})
  end

  t('param paths: own members, [A-Za-z0-9_-]{1,64} segments, never prototype names, 1..8 segments, empty segments refused') do
    pp = { 'a' => { 'b' => 1 }, 'add-ons' => 'x', 'x' * 64 => 2, 'x' * 65 => 3, '__proto__' => 4, 'constructor' => 5, 'prototype' => 6, '' => 7 }
    rp = ->(p) { AtlasPca.resolve_param_path(pp, p) }
    rp.('action.params.a.b') == { 'found' => true, 'value' => 1 } && rp.('action.params.a') == { 'found' => true, 'value' => { 'b' => 1 } } &&
      rp.('action.params.add-ons')['found'] && rp.("action.params.#{'x' * 64}")['found'] &&
      [ "action.params.#{'x' * 65}", 'action.params.__proto__', 'action.params.constructor', 'action.params.prototype', 'action.params.',
        'action.params.a.', 'action.params..a', 'action.params.a.b.c', 'action.params.zz', 'params.a', 'action.params.a.b ', "action.params.a\n",
        5, nil ].all? { |p| rp.(p) == { 'found' => false } } &&
      AtlasPca.resolve_param_path({ 'a' => 1 }, 'action.params.a.b') == { 'found' => false } &&
      AtlasPca.param_path?("action.params.#{(['a'] * 8).join('.')}") && !AtlasPca.param_path?("action.params.#{(['a'] * 9).join('.')}") &&
      AtlasPca.param_path?('action.params.a') && !AtlasPca.param_path?('action.params.') && !AtlasPca.param_path?('action.params.a..b') &&
      !AtlasPca.param_path?("action.params.a\n") && !AtlasPca.param_path?('action.params.__proto__') && !AtlasPca.param_path?(nil)
  end

  # =================================================================== rule 16: facts

  t('rule 16: lower median (odd, even, liar), single source, string agreement; inactive empty policy') do
    w = WB
    o4 = w.key('wb/oracle-4')
    even = w.w_in([w.fact(0, 'fare', 40), w.fact(1, 'fare', 10), w.fact(2, 'fare', 30), w.fact(3, 'fare', 20, k: o4)],
                  { 'worlds' => [w.fare_world('oracles' => w.oracles + [{ 'kid' => 'o4', 'pk' => w.pk(o4) }], 'min_oracles' => 4)] })
    w.wok(w.w_in(w.three, { 'worlds' => [w.fare_world] }), { 'fare' => 39_800 }) && w.wok(even, { 'fare' => 20 }) &&
      w.world(w.w_in([w.fact(0, 'fare', 5)], { 'worlds' => [w.fare_world('min_oracles' => 1, 'max_faulty' => 0)] })) ==
        { 'ok' => true, 'world' => { 'fare' => 5 }, 'single_source' => ['fare'] } &&
      w.wok(w.w_in([w.fact(0, 'fare', 'gold'), w.fact(1, 'fare', 'gold'), w.fact(2, 'fare', 'gold')], { 'worlds' => [w.fare_world] }), { 'fare' => 'gold' }) &&
      w.world({ 'now' => WB::NOW, 'aud' => WB::AUD, 'session' => w.session, 'action' => w.action, 'committed' => {}, 'policy' => {} }) ==
        { 'ok' => true, 'world' => {}, 'single_source' => [] } &&
      AtlasPca.lower_median([3, 1, 2]) == 2 && AtlasPca.lower_median([4, 1, 3, 2]) == 2 && AtlasPca.lower_median([7]) == 7 &&
      AtlasPca.lower_median([2, 1]) == 1 &&
      begin
        AtlasPca.lower_median([])
        false
      rescue ArgumentError
        true
      end
  end

  t('rule 16: freshness is inclusive at now - freshness_ms and at now + skew; one ms beyond is not counted (never an error)') do
    w = WB
    n = WB::NOW
    pol = { 'worlds' => [w.fare_world] }
    few = "facts: world 'fare' has 2 fresh fact(s), needs 3"
    w.wok(w.w_in([w.fact(0, 'fare', 5, t_obs: n - 60_000), w.fact(1, 'fare', 6, t_obs: n + 60_000), w.fact(2, 'fare', 7)], pol), { 'fare' => 6 }) &&
      w.wr(w.w_in([w.fact(0, 'fare', 5, t_obs: n - 60_001), w.fact(1, 'fare', 6), w.fact(2, 'fare', 7)], pol)) == few &&
      w.wr(w.w_in([w.fact(0, 'fare', 5, t_obs: n + 60_001), w.fact(1, 'fare', 6), w.fact(2, 'fare', 7)], pol)) == few &&
      w.wok(w.w_in([w.fact(0, 'fare', 5, t_obs: n + 1), w.fact(1, 'fare', 6), w.fact(2, 'fare', 7)],
                   { 'skew_ms' => 0, 'worlds' => [w.fare_world('min_oracles' => 2, 'max_faulty' => 0)] }), { 'fare' => 6 }) &&
      w.wok(w.w_in([w.fact(0, 'fare', 5, t_obs: n), w.fact(1, 'fare', 6), w.fact(2, 'fare', 7)],
                   { 'skew_ms' => 0, 'worlds' => [w.fare_world] }), { 'fare' => 6 }) &&
      w.wok(w.w_in([w.fact(0, 'fare', 5, t_obs: n)], { 'worlds' => [w.fare_world('min_oracles' => 1, 'max_faulty' => 0, 'freshness_ms' => 0)] })
              .merge('policy' => { 'worlds' => [w.fare_world('min_oracles' => 1, 'max_faulty' => 0, 'freshness_ms' => 0)] }), { 'fare' => 5 }) == false &&
      w.world(w.w_in([w.fact(0, 'fare', 5, t_obs: n)], { 'worlds' => [w.fare_world('min_oracles' => 1, 'max_faulty' => 0, 'freshness_ms' => 0)] }))['ok'] &&
      w.wr(w.w_in([w.fact(0, 'fare', 5, t_obs: n - 1)], { 'worlds' => [w.fare_world('min_oracles' => 1, 'max_faulty' => 0, 'freshness_ms' => 0)] })) ==
        "facts: world 'fare' has 0 fresh fact(s), needs 1"
  end

  t('rule 16 CLOCK: a now that is not a safe integer makes every fact stale (never coerced); an integral Float now is the same clock') do
    w = WB
    pol = { 'worlds' => [w.fare_world('min_oracles' => 1, 'max_faulty' => 0)] }
    base = w.w_in([w.fact(0, 'fare', 5)], pol)
    none = "facts: world 'fare' has 0 fresh fact(s), needs 1"
    rel = { 'relational' => [w.rel('d', 'sub', 'action.params.total', 'action.params.quote')] }
    w.world(base)['ok'] && w.world(base.merge('now' => WB::NOW.to_f))['ok'] &&
      [WB::NOW.to_s, WB::NOW + 0.5, nil, Float::NAN, Float::INFINITY, -0.0, true, [WB::NOW], { 'n' => 1 }, 2**53]
        .all? { |now| w.wr(base.merge('now' => now)) == none } &&
      w.wr(base.reject { |k, _| k == 'now' }) == none &&
      w.world(w.w_in([], rel).merge('now' => WB::NOW.to_s)) == { 'ok' => true, 'world' => { 'd' => 38_900 }, 'single_source' => [] }
  end

  t('rule 16 step 1: committed facts list <= 16 distinct digests; offer_set commitment a digest when present; policy first') do
    w = WB
    pol = { 'worlds' => [w.fare_world] }
    ds = (0...17).map { |i| w.digest("c#{i}") }
    w.wr(w.w_in([], pol).merge('committed' => { 'facts' => ds })) == 'facts: committed facts must be a list of at most 16 digests' &&
      w.wr(w.w_in([], pol).merge('committed' => { 'facts' => ds[0, 16] })) == 'facts: a committed fact was not supplied (or is malformed)' &&
      w.wr(w.w_in([], pol).merge('committed' => { 'facts' => {} })) == 'facts: committed facts must be a list of at most 16 digests' &&
      w.wr(w.w_in([], pol).merge('committed' => { 'facts' => 'abc' })) == 'facts: committed facts must be a list of at most 16 digests' &&
      w.wr(w.w_in([], pol).merge('committed' => { 'facts' => ['abc'] })) == 'facts: a committed fact digest is not canonical base64url (32 bytes)' &&
      w.wr(w.w_in([], pol).merge('committed' => { 'facts' => ["#{ds[0]}\n"] })) == 'facts: a committed fact digest is not canonical base64url (32 bytes)' &&
      w.wr(w.w_in([], pol).merge('committed' => { 'facts' => [ds[0], ds[1], ds[0]] })) == 'facts: duplicate committed fact digest' &&
      w.wr(w.w_in([], pol).merge('committed' => { 'facts' => [ds[0], 'x', ds[0]] })) == 'facts: a committed fact digest is not canonical base64url (32 bytes)' &&
      w.wr(w.w_in([], {}).merge('committed' => { 'offer_set' => nil })) == 'facts: the committed offer_set is not canonical base64url (32 bytes)' &&
      w.wr(w.w_in([], {}).merge('committed' => { 'offer_set' => 'abc' })) == 'facts: the committed offer_set is not canonical base64url (32 bytes)' &&
      w.world(w.w_in([], {}).merge('committed' => { 'offer_set' => ds[0] }))['ok'] &&
      w.wr(w.w_in([], {}).merge('committed' => { 'offer_set' => ds[0], 'facts' => nil })) == 'facts: committed facts must be a list of at most 16 digests' &&
      w.wr(w.w_in([], {}).merge('committed' => nil)) == 'facts: committed must be an object' &&
      w.wr(w.w_in([], {}).merge('committed' => [])) == 'facts: committed must be an object' &&
      w.world(w.w_in([], {}).reject { |k, _| k == 'committed' })['ok'] &&
      w.wr(w.w_in([], { 'skew_ms' => -1 }).merge('committed' => { 'facts' => {} })) ==
        'facts: policy misconfigured (fail closed): skew_ms must be a non-negative safe integer'
  end

  t('rule 16 steps 2-3: supplied facts by reference; per committed fact: declared world, pinned kid, signature, subject, distinct oracle') do
    w = WB
    pol = { 'worlds' => [w.fare_world] }
    t3 = w.three
    forged = w.fact(0, 'fare', 999_999, k: w.rogue)
    w.wok(w.w_in(t3, pol).merge('facts' => t3 + [forged]), { 'fare' => 39_800 }) &&
      w.wr(w.w_in(t3, pol).merge('facts' => t3[0, 2])) == 'facts: a committed fact was not supplied (or is malformed)' &&
      w.wr(w.w_in(t3 + [w.fact(0, 'tier', 'gold')], pol)) == "facts: fact for undeclared world 'tier'" &&
      w.wr(w.w_in([t3[0], t3[1], w.fact(2, 'fare', 3, kid: 'o9')], pol)) == "facts: oracle 'o9' is not pinned for world 'fare'" &&
      w.wr(w.w_in([t3[0], t3[1], w.fact(2, 'fare', 3, k: w.rogue)], pol)) == "facts: bad oracle signature on a 'fare' fact" &&
      w.wr(w.w_in([t3[0], t3[1], w.fact(2, 'fare', 3, subject: 'OF-1')], pol)) == "facts: a 'fare' fact names another subject" &&
      w.wr(w.w_in(t3 + [w.fact(0, 'fare', 5, t_obs: WB::NOW - 2000)], pol)) == "facts: two facts from oracle 'o1' for world 'fare'" &&
      # first failure in COMMITTED order; within one fact: pin before signature before subject before duplicate
      w.wr(w.w_in([w.fact(0, 'tier', 'x'), w.fact(1, 'fare', 1, kid: 'o9')], pol)) == "facts: fact for undeclared world 'tier'" &&
      w.wr(w.w_in([w.fact(1, 'fare', 1, kid: 'o9'), w.fact(0, 'tier', 'x')], pol)) == "facts: oracle 'o9' is not pinned for world 'fare'" &&
      w.wr(w.w_in([w.fact(0, 'fare', 1, kid: 'o9', k: w.rogue)], pol)) == "facts: oracle 'o9' is not pinned for world 'fare'" &&
      w.wr(w.w_in([w.fact(0, 'fare', 1, subject: 'OF-1', k: w.rogue)], pol)) == "facts: bad oracle signature on a 'fare' fact" &&
      w.wr(w.w_in([t3[0], w.fact(0, 'fare', 1, subject: 'OF-1')], pol)) == "facts: a 'fare' fact names another subject" &&
      # a fact signed under another domain is a bad signature
      w.wr(w.w_in([t3[0], t3[1], w.sign('atlas-pca/fact/v2', t3[2].reject { |k, _| k == 'sig' }, w.oracle(2))], pol)) ==
        "facts: bad oracle signature on a 'fare' fact" &&
      # a value tampered after signing (the commitment covers the tampered bytes)
      w.wr(w.w_in([t3[0], t3[1], t3[2].merge('value' => 39_850)], pol)) == "facts: bad oracle signature on a 'fare' fact"
  end

  t('rule 16: subject paths action.resource / action.verb / nested params; a non-string subject never matches; no action fails closed') do
    w = WB
    one = ->(over) { { 'worlds' => [w.fare_world({ 'min_oracles' => 1, 'max_faulty' => 0 }.merge(over))] } }
    w.world(w.w_in([w.fact(0, 'fare', 5, subject: 'skyair.example/bookings')], one.({ 'subject_path' => 'action.resource' })))['ok'] &&
      w.world(w.w_in([w.fact(0, 'fare', 5, subject: 'air.book')], one.({ 'subject_path' => 'action.verb' })))['ok'] &&
      w.world(w.w_in([w.fact(0, 'fare', 5, subject: 'X')], one.({ 'subject_path' => 'action.params.a.b' }))
                .merge('action' => w.action('a' => { 'b' => 'X' })))['ok'] &&
      w.wr(w.w_in([w.fact(0, 'fare', 5, subject: '2')], one.({ 'subject_path' => 'action.params.pax' }))) == "facts: a 'fare' fact names another subject" &&
      w.wr(w.w_in([w.fact(0, 'fare', 5, subject: 'OF-2')], one.({ 'subject_path' => 'action.params' }))) == "facts: a 'fare' fact names another subject" &&
      w.wr(w.w_in([w.fact(0, 'fare', 5)], one.({})).reject { |k, _| k == 'action' }) == 'facts: action must be an object'
  end

  t('rule 16 step 4: mixed integer / string facts and disagreeing strings fail; worlds in policy order; integral Float values') do
    w = WB
    pol = { 'worlds' => [w.fare_world] }
    t3 = w.three
    flt = t3.map { |f| f.merge('value' => f['value'].to_f) }
    r = w.world(w.w_in(flt, pol))
    two = { 'worlds' => [w.fare_world('name' => 'aaa'), w.fare_world] }
    w.wr(w.w_in([w.fact(0, 'fare', 1), w.fact(1, 'fare', 'x'), w.fact(2, 'fare', 3)], pol)) == "facts: world 'fare': facts mix integer and string values" &&
      w.wr(w.w_in([w.fact(0, 'fare', 'gold'), w.fact(1, 'fare', 'gold'), w.fact(2, 'fare', 'silver')], pol)) == "facts: world 'fare': string facts disagree" &&
      r['ok'] && r['world']['fare'] == 39_800 && r['world']['fare'].is_a?(Integer) &&
      w.wr(w.w_in(t3, two)) == "facts: world 'aaa' has 0 fresh fact(s), needs 3"
  end

  t('rule 16 step 5: relational sub / ratio_ppm, chained, exact floor, bounds, operands in order') do
    w = WB
    pol = { 'worlds' => [w.fare_world('min_oracles' => 1, 'max_faulty' => 0)],
            'relational' => [w.rel('excess_vs_quote', 'sub', 'action.params.total', 'action.params.quote'),
                             w.rel('vs_fare', 'sub', 'action.params.quote', 'env.world.fare'),
                             w.rel('ratio', 'ratio_ppm', 'action.params.total', 'env.world.fare'),
                             w.rel('third', 'ratio_ppm', 'action.params.pax', 'env.world.ratio')] }
    only = ->(r, params = {}) { w.w_in([], { 'relational' => [r] }).merge('action' => w.action(params)) }
    und = "facts: relational 'r': result undefined or outside the safe integer range"
    opm = "facts: relational 'r': an operand is missing or not a safe integer"
    w.world(w.w_in([w.fact(0, 'fare', 38_900)], pol)) == { 'ok' => true, 'single_source' => ['fare'],
                                                            'world' => { 'fare' => 38_900, 'excess_vs_quote' => 38_900, 'vs_fare' => 0, 'ratio' => 2_000_000, 'third' => 1 } } &&
      w.wok(only.(w.rel('d', 'sub', 'action.params.quote', 'action.params.total')), { 'd' => -38_900 }) &&
      w.wok(only.(w.rel('r', 'ratio_ppm', 'action.params.a', 'action.params.b'), { 'a' => 1, 'b' => 3 }), { 'r' => 333_333 }) &&
      w.wok(only.(w.rel('r', 'ratio_ppm', 'action.params.a', 'action.params.b'), { 'a' => 0, 'b' => 5 }), { 'r' => 0 }) &&
      w.wok(only.(w.rel('r', 'ratio_ppm', 'action.params.a', 'action.params.b'), { 'a' => 9_007_199_254, 'b' => 1 }), { 'r' => 9_007_199_254_000_000 }) &&
      w.wr(only.(w.rel('r', 'ratio_ppm', 'action.params.a', 'action.params.b'), { 'a' => 9_007_199_255, 'b' => 1 })) == und &&
      w.wr(only.(w.rel('r', 'ratio_ppm', 'action.params.a', 'action.params.b'), { 'a' => 1, 'b' => 0 })) == und &&
      w.wr(only.(w.rel('r', 'ratio_ppm', 'action.params.a', 'action.params.b'), { 'a' => -1, 'b' => 5 })) == und &&
      w.wr(only.(w.rel('r', 'ratio_ppm', 'action.params.a', 'action.params.b'), { 'a' => 1, 'b' => -5 })) == und &&
      w.wok(only.(w.rel('r', 'sub', 'action.params.a', 'action.params.b'), { 'a' => WB::MAX_SAFE, 'b' => 0 }), { 'r' => WB::MAX_SAFE }) &&
      w.wr(only.(w.rel('r', 'sub', 'action.params.a', 'action.params.b'), { 'a' => WB::MAX_SAFE, 'b' => -1 })) == und &&
      w.wr(only.(w.rel('r', 'sub', 'action.params.a', 'action.params.b'), { 'a' => -WB::MAX_SAFE, 'b' => 1 })) == und &&
      w.wok(only.(w.rel('r', 'sub', 'action.params.a', 'action.params.b'), { 'a' => 5.0, 'b' => 2 }), { 'r' => 3 }) &&
      [{ 'a' => 'x', 'b' => 1 }, { 'a' => 1.5, 'b' => 1 }, { 'a' => true, 'b' => 1 }, { 'a' => -0.0, 'b' => 1 }, { 'b' => 1 },
       { 'a' => WB::MAX_SAFE + 1, 'b' => 1 }, { 'a' => nil, 'b' => 1 }].all? { |pa| w.wr(only.(w.rel('r', 'sub', 'action.params.a', 'action.params.b'), pa)) == opm } &&
      AtlasPca.ratio_ppm(WB::MAX_SAFE, 1_000_000) == WB::MAX_SAFE && AtlasPca.ratio_ppm(WB::MAX_SAFE, 999_999).nil? &&
      AtlasPca.ratio_ppm(2, 3) == 666_666 && AtlasPca.ratio_ppm(0, 1) == 0 && AtlasPca.ratio_ppm(1, 0).nil? && AtlasPca.ratio_ppm(-1, 1).nil?
  end

  t('rule 16 step 0: world policy sanity at every edge') do
    w = WB
    mis = ->(pol) { w.wr(w.w_in([], pol)) }
    pre = 'facts: policy misconfigured (fail closed): '
    sixteen = (0...16).map { |i| w.fare_world('name' => "w#{i}", 'min_oracles' => 1, 'max_faulty' => 0) }
    mis.({ 'skew_ms' => -1 }) == "#{pre}skew_ms must be a non-negative safe integer" &&
      mis.({ 'skew_ms' => 1.5 }) == "#{pre}skew_ms must be a non-negative safe integer" &&
      mis.({ 'skew_ms' => nil }) == "#{pre}skew_ms must be a non-negative safe integer" &&
      w.world(w.w_in([], { 'skew_ms' => 0, 'worlds' => [], 'relational' => [] }))['ok'] &&
      mis.({ 'worlds' => nil }) == "#{pre}worlds must be a list of at most 16" &&
      mis.({ 'relational' => nil }) == "#{pre}relational must be a list of at most 16" &&
      w.wr(w.w_in([], {}).merge('policy' => nil)) == "#{pre}world policy must be an object" &&
      mis.({ 'skew' => 1 }) == "#{pre}unknown member 'policy.skew'" &&
      mis.({ 'worlds' => [w.fare_world('note' => 1)] }) == "#{pre}unknown member 'world.note'" &&
      mis.({ 'worlds' => [w.fare_world.reject { |k, _| k == 'max_faulty' }] }) == "#{pre}missing member 'world.max_faulty'" &&
      mis.({ 'worlds' => [w.fare_world('min_oracles' => '3')] }) == "#{pre}world 'fare': min_oracles must be a safe integer >= 2*max_faulty+1" &&
      mis.({ 'worlds' => [w.fare_world('freshness_ms' => 1.5)] }) == "#{pre}world 'fare': freshness_ms must be a non-negative safe integer" &&
      mis.({ 'relational' => [w.rel('a', 'sub', 'action.params.total', 'action.params.quote').merge('c' => 1)] }) == "#{pre}unknown member 'relational.c'" &&
      mis.({ 'worlds' => 'abc' }) == "#{pre}worlds must be a list of at most 16" &&
      w.wr(w.w_in([], {}).merge('policy' => 'abc')) == "#{pre}world policy must be an object" &&
      w.world(w.w_in([], {}).reject { |k, _| k == 'policy' })['ok'] &&
      mis.({ 'worlds' => sixteen }) == "facts: world 'w0' has 0 fresh fact(s), needs 1" &&
      mis.({ 'worlds' => sixteen + [w.fare_world] }) == "#{pre}worlds must be a list of at most 16" &&
      mis.({ 'worlds' => {} }) == "#{pre}worlds must be a list of at most 16" &&
      mis.({ 'worlds' => [1] }) == "#{pre}world entry must be an object" &&
      mis.({ 'worlds' => [w.fare_world('name' => 'x' * 64)] }) == "facts: world '#{'x' * 64}' has 0 fresh fact(s), needs 3" &&
      mis.({ 'worlds' => [w.fare_world('name' => 'x' * 65)] }) == "#{pre}dimension name '#{'x' * 65}' must match ^[a-z][a-z0-9_]{0,63}$" &&
      mis.({ 'worlds' => [w.fare_world('name' => "fare\n")] }) == "#{pre}dimension name 'fare\n' must match ^[a-z][a-z0-9_]{0,63}$" &&
      mis.({ 'worlds' => [w.fare_world('name' => 'Fare')] }) == "#{pre}dimension name 'Fare' must match ^[a-z][a-z0-9_]{0,63}$" &&
      mis.({ 'worlds' => [w.fare_world('name' => 5)] }) == "#{pre}dimension name '5' must match ^[a-z][a-z0-9_]{0,63}$" &&
      mis.({ 'worlds' => [w.fare_world, w.fare_world] }) == "#{pre}duplicate dimension name 'fare'" &&
      mis.({ 'worlds' => [w.fare_world('subject_path' => 'params.offer_id')] }) == "#{pre}world 'fare': subject_path must be rooted at action." &&
      mis.({ 'worlds' => [w.fare_world('freshness_ms' => -1)] }) == "#{pre}world 'fare': freshness_ms must be a non-negative safe integer" &&
      mis.({ 'worlds' => [w.fare_world('max_faulty' => -1)] }) == "#{pre}world 'fare': max_faulty must be a non-negative safe integer" &&
      mis.({ 'worlds' => [w.fare_world('min_oracles' => 2)] }) == "#{pre}world 'fare': min_oracles must be a safe integer >= 2*max_faulty+1" &&
      mis.({ 'worlds' => [w.fare_world('min_oracles' => 3.0)] }) == "facts: world 'fare' has 0 fresh fact(s), needs 3" &&
      mis.({ 'worlds' => [w.fare_world('oracles' => w.oracles(2))] }) == "#{pre}world 'fare': fewer pinned oracles than min_oracles" &&
      mis.({ 'worlds' => [w.fare_world('oracles' => w.oracles(2) + [{ 'kid' => 'o1', 'pk' => w.pk(w.rogue) }])] }) ==
        "#{pre}world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk" &&
      mis.({ 'worlds' => [w.fare_world('oracles' => w.oracles(2) + [{ 'kid' => 'x' * 65, 'pk' => w.pk(w.rogue) }])] }) ==
        "#{pre}world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk" &&
      mis.({ 'worlds' => [w.fare_world('oracles' => w.oracles(2) + [{ 'kid' => 'o3', 'pk' => 'abc' }])] }) ==
        "#{pre}world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk" &&
      ['', nil, 5].all? { |pq|
        mis.({ 'worlds' => [w.fare_world('oracles' => w.oracles(2) + [{ 'kid' => 'o3', 'pk' => w.pk(w.oracle(2)), 'pq_pk' => pq }])] }) ==
          "#{pre}world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
      } &&
      mis.({ 'worlds' => [w.fare_world('oracles' => w.oracles(2) + [{ 'kid' => 'o3', 'pk' => w.pk(w.oracle(2)), 'x' => 1 }])] }) ==
        "#{pre}world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk" &&
      mis.({ 'worlds' => [w.fare_world('oracles' => w.oracles(2) + [{ 'kid' => 'o3', 'pk' => w.pk(w.oracle(2)), 'pq_pk' => 'x' }])] }) ==
        "facts: world 'fare' has 0 fresh fact(s), needs 3"
  end

  t('rule 16 step 0: relational and offers policy sanity (earlier dimensions only, no self reference, distinct names)') do
    w = WB
    mis = ->(pol) { w.wr(w.w_in([], pol)) }
    pre = 'facts: policy misconfigured (fail closed): '
    r = ->(name, a, b = 'action.params.quote', fn = 'sub') { w.rel(name, fn, a, b) }
    sixteen = (0...16).map { |i| r.("r#{i}", 'action.params.total') }
    w.world(w.w_in([], { 'relational' => sixteen }))['ok'] &&
      mis.({ 'relational' => sixteen + [r.('x', 'action.params.total')] }) == "#{pre}relational must be a list of at most 16" &&
      mis.({ 'relational' => ['x'] }) == "#{pre}relational entry must be an object" &&
      mis.({ 'relational' => [r.('a', 'env.world.b'), r.('b', 'action.params.total')] }) ==
        "#{pre}relational 'a': operand 'env.world.b' must be an action.params path or an earlier env.world dimension" &&
      mis.({ 'relational' => [r.('a', 'env.world.a')] }) ==
        "#{pre}relational 'a': operand 'env.world.a' must be an action.params path or an earlier env.world dimension" &&
      mis.({ 'relational' => [r.('a', 'action.params.total', 'world.x')] }) ==
        "#{pre}relational 'a': operand 'world.x' must be an action.params path or an earlier env.world dimension" &&
      mis.({ 'relational' => [r.('a', 'action.params.total', nil)] }) ==
        "#{pre}relational 'a': operand 'null' must be an action.params path or an earlier env.world dimension" &&
      mis.({ 'relational' => [r.('a', 'action.params.total', 'action.params.quote', 'mul')] }) ==
        "#{pre}relational 'a': fn must be \"sub\" or \"ratio_ppm\"" &&
      mis.({ 'worlds' => [w.fare_world], 'relational' => [r.('fare', 'action.params.total')] }) == "#{pre}duplicate dimension name 'fare'" &&
      mis.({ 'relational' => [r.('Fare', 'action.params.total')] }) == "#{pre}dimension name 'Fare' must match ^[a-z][a-z0-9_]{0,63}$" &&
      mis.({ 'relational' => [r.('a', 'action.params.total')], 'offers' => w.offer_policy('name' => 'a') }) == "#{pre}duplicate dimension name 'a'" &&
      mis.({ 'offers' => nil }) == "#{pre}offers policy must be an object" &&
      mis.({ 'offers' => w.offer_policy('name' => 5) }) == "#{pre}offers policy needs a name" &&
      mis.({ 'offers' => w.offer_policy('site_keys' => []) }) == "#{pre}offers policy needs at least one pinned site key" &&
      mis.({ 'offers' => w.offer_policy('site_keys' => [{ 'kid' => 'a', 'pk' => w.pk(w.site) }, { 'kid' => 'a', 'pk' => w.pk(w.gov) }]) }) ==
        "#{pre}offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk" &&
      mis.({ 'offers' => w.offer_policy('max_age_ms' => -1) }) == "#{pre}offers policy: max_age_ms must be a non-negative safe integer" &&
      mis.({ 'offers' => w.offer_policy('offer_param' => 'params.offer_id') }) == "#{pre}offers policy: offer_param must be an action.params.* path" &&
      mis.({ 'offers' => w.offer_policy('filter' => { 'query' => {} }) }) == "#{pre}offers policy: filter must be exactly {query: {}, offer: {}}" &&
      mis.({ 'offers' => w.offer_policy('filter' => { 'query' => {}, 'offer' => {}, 'x' => {} }) }) == "#{pre}offers policy: filter must be exactly {query: {}, offer: {}}" &&
      mis.({ 'offers' => w.offer_policy('x' => 1) }) == "#{pre}unknown member 'offers.x'" &&
      mis.({ 'offers' => w.offer_policy.reject { |k, _| k == 'filter' } }) == "#{pre}missing member 'offers.filter'" &&
      mis.({ 'offers' => w.offer_policy('max_age_ms' => '600000') }) == "#{pre}offers policy: max_age_ms must be a non-negative safe integer" &&
      mis.({ 'offers' => w.offer_policy('site_keys' => [{ 'kid' => 'a', 'pk' => w.pk(w.site), 'pq_pk' => nil }]) }) ==
        "#{pre}offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk" &&
      mis.({ 'offers' => w.offer_policy('site_keys' => [{ 'kid' => 'a', 'pk' => w.pk(w.site), 'x' => 1 }]) }) ==
        "#{pre}offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk" &&
      w.world(w.w_in([], { 'offers' => w.offer_policy('site_keys' => [{ 'kid' => 'a', 'pk' => w.pk(w.site), 'pq_pk' => 'x' }]) })
                .merge('committed' => {}))['reason'] == 'facts: offers: the PCActn commits no offer set but the policy requires one' &&
      mis.({ 'offers' => w.offer_policy('filter' => { 'query' => { 'a' => [1] }, 'offer' => {} }) }) == "#{pre}offers policy: filter values must be scalars" &&
      mis.({ 'offers' => w.offer_policy('filter' => { 'query' => {}, 'offer' => { 'a' => 1.5 } }) }) == "#{pre}offers policy: filter values must be scalars" &&
      mis.({ 'offers' => w.offer_policy('name' => 'Bad') }) == "#{pre}dimension name 'Bad' must match ^[a-z][a-z0-9_]{0,63}$"
  end

  t('rule 16: wire validation of a fact (closed set in JS key order, every member at its edge)') do
    f = WB.fact(0, 'fare', 5)
    v = ->(over) { AtlasPca.validate_fact_wire(f.merge(over)) }
    AtlasPca.validate_fact_wire(f).nil? && AtlasPca.validate_fact_wire([f]) == 'fact must be an object' &&
      AtlasPca.validate_fact_wire(f.merge('b' => 1, '1' => 2)) == "unknown member 'fact.1'" &&
      AtlasPca.validate_fact_wire(f.merge('10' => 1, '9' => 2)) == "unknown member 'fact.9'" &&
      AtlasPca.validate_fact_wire(f.reject { |k, _| %w[name value].include?(k) }) == "missing member 'fact.name'" &&
      v.({ 'v' => 1.0 }).nil? && v.({ 'v' => true }) == 'fact must be {v: 1, kind: "pca-fact"}' && v.({ 'v' => '1' }) == 'fact must be {v: 1, kind: "pca-fact"}' &&
      v.({ 'kind' => 'pca-facts' }) == 'fact must be {v: 1, kind: "pca-fact"}' &&
      v.({ 'name' => 'x' * 64 }).nil? && v.({ 'name' => 'x' * 65 }) == "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$" &&
      v.({ 'name' => "fare\n" }) == "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$" &&
      v.({ 'subject' => 'é' * 128 }).nil? && v.({ 'subject' => "#{'é' * 128}a" }) == "'fact.subject' must be a non-empty string (<= 256 bytes)" &&
      v.({ 'subject' => '' }) == "'fact.subject' must be a non-empty string (<= 256 bytes)" &&
      [true, 1.5, -0.0, '', 'x' * 257, nil, WB::MAX_SAFE + 1].all? { |x| v.({ 'value' => x }) == "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)" } &&
      [-WB::MAX_SAFE, 'x' * 256, 0, 5.0].all? { |x| v.({ 'value' => x }).nil? } &&
      [-1, -0.0, 1.5, '5', nil].all? { |x| v.({ 't_obs' => x }) == "'fact.t_obs' must be a non-negative safe integer" } && v.({ 't_obs' => 0 }).nil? &&
      v.({ 'oracle' => 'o' * 64 }).nil? && v.({ 'oracle' => 'o' * 65 }) == "'fact.oracle' must be a non-empty string (<= 64 bytes)" &&
      v.({ 'sig' => 5 }) == "'fact.sig' must be a string" && v.({ 'sig' => '' }).nil? &&
      v.({ 'name' => 'X', 'subject' => '' }) == "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$"
  end

  t('rule 16: supplied lists must be real arrays (a string or object fails closed); lone surrogates have no reference') do
    w = WB
    pol = { 'worlds' => [w.fare_world] }
    t3 = w.three
    bad = t3[0].merge('subject' => "\xED\xA0\x80".dup.force_encoding(Encoding::UTF_8))
    w.wok(w.w_in(t3, pol).merge('facts' => t3 + [bad, 1, nil, 'x']), { 'fare' => 39_800 }) &&
      ['abc', { 'a' => 1 }, 5, true, nil].all? { |fs| w.wr(w.w_in(t3, pol).merge('facts' => fs)) == 'facts: facts must be an array' } &&
      w.world(w.w_in([], {}).reject { |k, _| k == 'facts' })['ok'] &&
      w.wr(w.w_in([], {}).merge('action' => { 'verb' => 'v', 'resource' => 'r', 'params' => nil })) == 'facts: action.params must be an object' &&
      w.wr(w.w_in([], {}).merge('action' => { 'params' => [] })) == 'facts: action.params must be an object' &&
      w.world(w.w_in([], {}).merge('action' => {}))['ok'] &&
      [nil, 'x', []].all? { |a| w.wr(w.w_in([], {}).merge('action' => a)) == 'facts: action must be an object' } &&
      w.wr(w.w_in([], {}).reject { |k, _| k == 'action' }) == 'facts: action must be an object' &&
      [nil, [], 'x'].all? { |o| w.wr(w.w_in([], {}).merge('offer_set' => o)) == 'facts: offer_set must be an object' } &&
      # order: policy, action, params, committed, committed facts, supplied facts, offer_set
      w.wr(w.w_in([], { 'skew_ms' => -1 }).merge('action' => nil)) == 'facts: policy misconfigured (fail closed): skew_ms must be a non-negative safe integer' &&
      w.wr(w.w_in([], {}).merge('action' => nil, 'committed' => nil)) == 'facts: action must be an object' &&
      w.wr(w.w_in([], {}).merge('committed' => nil, 'facts' => nil)) == 'facts: committed must be an object' &&
      w.wr(w.w_in([], {}).merge('facts' => nil, 'offer_set' => nil)) == 'facts: facts must be an array' &&
      # a non-object input is refused up front (TS oracle-facts.ts: 'input must be an object'), not an evaluation error
      w.wr(nil) == 'facts: input must be an object' && w.wr([]) == 'facts: input must be an object'
  end

  # =================================================================== rule 16 step 6: offer sets

  t('offers: excess over the cheapest matching offer; broader / empty query, inclusive age and skew, Float filter values') do
    w = WB
    n = WB::NOW
    w.excess(w.os_in(w.offer_set)) == 900 &&
      w.excess(w.os_in(w.offer_set, w.offer_policy, 'action' => w.action('offer_id' => 'OF-1'))) == 0 &&
      w.excess(w.os_in(w.offer_set('query' => { 'from' => 'SFO', 'to' => 'JFK' }))) == 900 &&
      w.excess(w.os_in(w.offer_set('query' => {}))) == 900 &&
      w.excess(w.os_in(w.offer_set('issued_at' => n - 600_000))) == 900 &&
      w.excess(w.os_in(w.offer_set('issued_at' => n + 60_000))) == 900 &&
      w.excess(w.os_in(w.offer_set, w.offer_policy('filter' => { 'query' => WB::QUERY.merge('pax' => 2.0), 'offer' => { 'refundable' => false } }))) == 900 &&
      w.excess(w.os_in(w.offer_set, w.offer_policy('max_age_ms' => 0)).merge('now' => n - 10_000)) == 900 &&
      w.excess(w.os_in(w.offer_set, w.offer_policy('filter' => { 'query' => WB::QUERY, 'offer' => {} }), 'action' => w.action('offer_id' => 'OF-3'))) == 41_200 - 38_900 &&
      w.world(w.os_in(w.offer_set))['world'] == { 'excess_cents' => 900 }
  end

  t('offers: every refusal by its exact reason and in step order') do
    w = WB
    n = WB::NOW
    x = ->(input) { w.excess(input) }
    pre = 'facts: offers: '
    os = w.offer_set
    x.(w.os_in(w.offer_set('query' => WB::QUERY.merge('stops' => 0)))) == "#{pre}the search was narrowed beyond the intent filter (coverage)" &&
      x.(w.os_in(w.offer_set('query' => WB::QUERY.merge('date' => '2026-11-21')))) == "#{pre}the search was narrowed beyond the intent filter (coverage)" &&
      x.(w.os_in(w.offer_set('query' => WB::QUERY.merge('pax' => '2')))) == "#{pre}the search was narrowed beyond the intent filter (coverage)" &&
      x.(w.os_in(w.offer_set('complete' => false))) == "#{pre}the offer set is not declared complete" &&
      x.(w.os_in(w.offer_set('kid' => 'other'))) == "#{pre}signing key 'other' is not pinned" &&
      x.(w.os_in(w.offer_set({}, w.rogue))) == "#{pre}bad site signature" &&
      x.(w.os_in(w.offer_set('site' => 'evil.example'))) == "#{pre}the offer set was issued for another audience" &&
      x.(w.os_in(w.offer_set('session' => w.other_session))) == "#{pre}the offer set is bound to another session" &&
      x.(w.os_in(w.offer_set('issued_at' => n - 600_001))) == "#{pre}the offer set is stale" &&
      x.(w.os_in(w.offer_set('issued_at' => n + 60_001))) == "#{pre}the offer set is issued in the future" &&
      x.(w.os_in(os, w.offer_policy, 'action' => w.action('offer_id' => 'OF-9'))) == "#{pre}the chosen offer is not in the signed offer set" &&
      x.(w.os_in(os, w.offer_policy, 'action' => w.action('offer_id' => 'OF-3'))) == "#{pre}the chosen offer does not satisfy the intent filter" &&
      x.(w.os_in(os, w.offer_policy, 'action' => w.action('offer_id' => 2))) == "#{pre}the action names no offer id at the declared parameter" &&
      x.(w.os_in(os, w.offer_policy('offer_param' => 'action.params.nope'))) == "#{pre}the action names no offer id at the declared parameter" &&
      x.(w.os_in(os).merge('committed' => {})) == "#{pre}the PCActn commits no offer set but the policy requires one" &&
      x.(w.os_in(os).merge('committed' => { 'offer_set' => AtlasPca.offer_set_ref(w.offer_set('issued_at' => n - 9000)) })) ==
        "#{pre}the supplied offer set does not match the committed reference" &&
      x.(w.os_in(os).reject { |k, _| k == 'offer_set' }) == "#{pre}the committed offer set was not supplied" &&
      x.(w.os_in(os).merge('offer_set' => nil)) == 'facts: offer_set must be an object' &&
      # order: not committed before not supplied; wire before reference; reference before pin; pin before signature;
      # signature before audience; audience before session; session before clock / age; future before stale; complete before coverage
      x.(w.os_in(os).merge('committed' => {}).reject { |k, _| k == 'offer_set' }) == "#{pre}the PCActn commits no offer set but the policy requires one" &&
      x.(w.os_in(os).merge('offer_set' => os.merge('rank' => 'x'))) == "#{pre}'offer_set.rank' must be \"price_asc\"" &&
      x.(w.os_in(os).merge('offer_set' => w.offer_set('kid' => 'other'))) == "#{pre}the supplied offer set does not match the committed reference" &&
      x.(w.os_in(w.offer_set({ 'kid' => 'other' }, w.rogue))) == "#{pre}signing key 'other' is not pinned" &&
      x.(w.os_in(w.offer_set({ 'site' => 'evil.example' }, w.rogue))) == "#{pre}bad site signature" &&
      x.(w.os_in(w.offer_set('site' => 'evil.example', 'session' => w.other_session))) == "#{pre}the offer set was issued for another audience" &&
      x.(w.os_in(w.offer_set('session' => w.other_session, 'issued_at' => n - 600_001))) == "#{pre}the offer set is bound to another session" &&
      x.(w.os_in(w.offer_set('complete' => false, 'issued_at' => n - 600_001))) == "#{pre}the offer set is stale" &&
      x.(w.os_in(w.offer_set('complete' => false, 'query' => { 'stops' => 0 }))) == "#{pre}the offer set is not declared complete" &&
      x.(w.os_in(w.offer_set('query' => { 'stops' => 0 }), w.offer_policy, 'action' => w.action('offer_id' => 'OF-9'))) ==
        "#{pre}the search was narrowed beyond the intent filter (coverage)"
  end

  t('offers CLOCK: a now (or skew) that is not a safe integer makes the offer set stale, after the session check') do
    w = WB
    clock = 'facts: offers: no usable clock (now must be a safe integer): the offer set counts as stale'
    [WB::NOW.to_s, WB::NOW + 0.5, nil, Float::NAN, -0.0].all? { |now| w.excess(w.os_in(w.offer_set).merge('now' => now)) == clock } &&
      w.excess(w.os_in(w.offer_set).merge('now' => WB::NOW.to_f)) == 900 &&
      w.excess(w.os_in(w.offer_set('session' => w.other_session)).merge('now' => 'x')) == 'facts: offers: the offer set is bound to another session' &&
      w.excess(w.os_in(w.offer_set('complete' => false)).merge('now' => 'x')) == clock &&
      AtlasPca.decide_offer_set({ 'policy' => w.offer_policy, 'committed' => AtlasPca.offer_set_ref(w.offer_set), 'offerSet' => w.offer_set,
                                  'params' => w.action['params'], 'aud' => WB::AUD, 'session' => w.session, 'now' => WB::NOW, 'skewMs' => 1.5 }) ==
        { 'ok' => false, 'reason' => 'offers: no usable clock (now must be a safe integer): the offer set counts as stale' } &&
      AtlasPca.decide_offer_set({ 'policy' => w.offer_policy, 'committed' => AtlasPca.offer_set_ref(w.offer_set), 'offerSet' => w.offer_set,
                                  'params' => w.action['params'], 'aud' => WB::AUD, 'session' => w.session, 'now' => WB::NOW, 'skewMs' => 60_000 }) ==
        { 'ok' => true, 'excess' => 900, 'chosen_price' => 39_800, 'min_price' => 38_900 }
  end

  t('offers: wire validation at every cap (query keys, attrs, offers, id / key lengths) in check order') do
    os = WB.offer_set
    v = ->(over) { AtlasPca.validate_offer_set_wire(os.merge(over)) }
    q32 = (0...32).to_h { |i| ["k#{i}", i] }
    a32 = (0...32).to_h { |i| ["a#{i}", true] }
    offers = ->(n) { (0...n).map { |i| { 'offer_id' => "id#{i}", 'price' => i } } }
    AtlasPca.validate_offer_set_wire(os).nil? && AtlasPca.validate_offer_set_wire([]) == 'offer set must be an object' &&
      v.({ 'x' => 1 }) == "unknown member 'offer_set.x'" &&
      AtlasPca.validate_offer_set_wire(os.reject { |k, _| k == 'kid' }) == "missing member 'offer_set.kid'" &&
      v.({ 'v' => 2 }) == 'offer set must be {v: 1, kind: "pca-offer-set"}' &&
      v.({ 'site' => '' }) == "'offer_set.site' must be a non-empty string (<= 256 bytes)" && v.({ 'site' => 's' * 256 }).nil? &&
      v.({ 'site' => 's' * 257 }) == "'offer_set.site' must be a non-empty string (<= 256 bytes)" &&
      v.({ 'session' => 'abc' }) == "'offer_set.session' must be canonical base64url (32 bytes)" &&
      v.({ 'query' => q32 }).nil? && v.({ 'query' => q32.merge('k32' => 1) }) == "'offer_set.query' must be an object with <= 32 keys" &&
      v.({ 'query' => [] }) == "'offer_set.query' must be an object with <= 32 keys" &&
      v.({ 'query' => { 'k' * 64 => 1 } }).nil? && v.({ 'query' => { 'k' * 65 => 1 } }) == "'offer_set.query.#{'k' * 65}' must be a scalar" &&
      v.({ 'query' => { 'b' => [1], '0' => {} } }) == "'offer_set.query.0' must be a scalar" &&
      v.({ 'query' => { 'a' => nil } }) == "'offer_set.query.a' must be a scalar" && v.({ 'query' => { 'a' => 1.5 } }) == "'offer_set.query.a' must be a scalar" &&
      v.({ 'rank' => 'price_desc' }) == "'offer_set.rank' must be \"price_asc\"" &&
      v.({ 'complete' => 'true' }) == "'offer_set.complete' must be a boolean" && v.({ 'complete' => false }).nil? &&
      v.({ 'offers' => [] }) == "'offer_set.offers' must hold 1..256 offers" && v.({ 'offers' => offers.(256) }).nil? &&
      v.({ 'offers' => offers.(257) }) == "'offer_set.offers' must hold 1..256 offers" &&
      v.({ 'offers' => [1] }) == 'offer 0 must be an object' &&
      v.({ 'offers' => [{ 'offer_id' => 'o' * 128, 'price' => 1 }] }).nil? &&
      v.({ 'offers' => [{ 'offer_id' => 'o' * 129, 'price' => 1 }] }) == "offer 0: 'offer_id' must be a non-empty string (<= 128 bytes)" &&
      v.({ 'offers' => [{ 'offer_id' => 'a', 'price' => 1 }, { 'offer_id' => 'a', 'price' => -1 }] }) == 'offer 1: duplicate offer_id' &&
      v.({ 'offers' => [{ 'offer_id' => 'a', 'price' => -1 }] }) == "offer 0: 'price' must be a non-negative safe integer" &&
      v.({ 'offers' => [{ 'offer_id' => 'a', 'price' => 1.5 }] }) == "offer 0: 'price' must be a non-negative safe integer" &&
      v.({ 'offers' => [{ 'offer_id' => 'a', 'price' => 0 }.merge(a32)] }).nil? &&
      v.({ 'offers' => [{ 'offer_id' => 'a', 'price' => 0 }.merge(a32).merge('a32' => 1)] }) == 'offer 0: more than 32 attributes' &&
      v.({ 'offers' => [{ 'offer_id' => 'a', 'price' => 0, 'x' => { 'y' => 1 } }] }) == "offer 0: attribute 'x' must be a scalar" &&
      v.({ 'issued_at' => -1 }) == "'offer_set.issued_at' must be a non-negative safe integer" &&
      v.({ 'kid' => 'k' * 65 }) == "'offer_set.kid' must be a non-empty string (<= 64 bytes)" && v.({ 'kid' => 'k' * 64 }).nil? &&
      v.({ 'sig' => nil }) == "'offer_set.sig' must be a string" &&
      v.({ 'rank' => 'x', 'complete' => 1 }) == "'offer_set.rank' must be \"price_asc\""
  end

  t('offer_matches / query_covers: own keys, typed scalar equality, every key of the subset side') do
    o = { 'a' => 1, 'b' => 'x', 'c' => true }
    AtlasPca.offer_matches(o, {}) && AtlasPca.offer_matches(o, { 'a' => 1.0, 'c' => true }) && !AtlasPca.offer_matches(o, { 'a' => '1' }) &&
      !AtlasPca.offer_matches(o, { 'c' => 1 }) && !AtlasPca.offer_matches(o, { 'd' => nil }) && !AtlasPca.offer_matches(o, { 'a' => 1, 'b' => 'y' }) &&
      AtlasPca.query_covers({}, { 'a' => 1 }) && AtlasPca.query_covers({ 'a' => 1 }, { 'a' => 1, 'z' => 2 }) &&
      !AtlasPca.query_covers({ 'a' => 1, 'z' => 2 }, { 'a' => 1 }) && !AtlasPca.query_covers({ 'a' => 2 }, { 'a' => 1 })
  end

  # =================================================================== rule 17: provenance

  t('rule 17: registry classification, join (least trusted wins), own registry entries only, free and object parameters') do
    w = WB
    env = { 'action' => { 'params' => WB::T.transform_keys { |k| k.delete_prefix('action.params.') } } }
    w.prov(w.p_in) == { 'outcome' => 'pass', 'labels' => WB::T, 'classes' => {}, 'env' => env } &&
      w.out3(w.prov(w.p_in('action.params.offer_id' => ['skyair:offer_set:1', 'web:ad-3']))) ==
        ['question', 'tap', WB::T.merge('action.params.offer_id' => 'web')] &&
      w.out3(w.prov(w.p_in('action.params.offer_id' => %w[__proto__ constructor toString]))) ==
        ['question', 'tap', WB::T.merge('action.params.offer_id' => 'agent')] &&
      w.prov(w.p_in({ 'action.params.offer_id' => ['constructor'] }, 'registry' => { 'constructor' => 'trusted' }))['labels']['action.params.offer_id'] == 'trusted' &&
      w.prov(w.p_in({ 'action.params.offer_id' => ['wallet:profile:ana', 'skyair:offer_set:1'] }))['labels']['action.params.offer_id'] == 'first_party' &&
      w.prov(w.p_in({ 'action.params.offer_id' => ['agent:planner', 'wallet:profile:ana'] }, 'material_tainted' => 'allow'))['labels']['action.params.offer_id'] == 'agent' &&
      w.out3(w.prov(w.p_in('action.params.note' => ['web:ad-3']))) == ['pass', nil, WB::T.merge('action.params.note' => 'web')] &&
      w.out3(w.prov(w.p_in('action.params.pax' => ['wallet:profile:ana']))) == ['pass', nil, WB::T.merge('action.params.pax' => 'trusted')] &&
      w.out3(w.prov(w.p_in({}, 'params' => w.p_policy['params'].merge('action.params.seat' => 'material')))) == ['pass', nil, WB::T]
  end

  t('rule 17: undeclared material / critical parameters are agent; absent vs null members') do
    w = WB
    no_pay = w.p_in.tap { |x| x['prov'] = x['prov'].reject { |k, _| k == 'action.params.payment_ref' } }
    all_agent = WB::T.transform_values { 'agent' }
    w.out3(w.prov(no_pay)) == ['question', 'typed', WB::T.merge('action.params.payment_ref' => 'agent')] &&
      w.out3(w.prov(w.p_in.reject { |k, _| k == 'prov' })) == ['question', 'typed', all_agent] &&
      w.pr(w.p_in.merge('prov' => nil)) == "provenance: 'prov' must be an object" &&
      w.pr(w.p_in.merge('committed_labels' => nil)) == 'provenance: committed labels must be a list of at most 16 digests' &&
      [nil, 'x', []].all? { |act| w.pr(w.p_in.merge('action' => act)) == 'provenance: action must be an object' } &&
      w.pr(w.p_in.reject { |k, _| k == 'action' }) == 'provenance: action must be an object' &&
      [nil, []].all? { |pa| w.pr(w.p_in.merge('action' => { 'params' => pa })) == 'provenance: action.params must be an object' } &&
      w.pr(w.p_in.merge('action' => {})) == "provenance: prov names 'action.params.add_ons', a parameter the action does not carry" &&
      # order: prov, committed labels, action, params, labels
      w.pr(w.p_in.merge('committed_labels' => nil, 'action' => nil)) == 'provenance: committed labels must be a list of at most 16 digests' &&
      w.pr(w.p_in.merge('action' => { 'params' => nil }, 'labels' => nil)) == 'provenance: action.params must be an object' &&
      w.out3(w.prov(w.p_in.merge('action' => {}).reject { |k, _| k == 'prov' })) == ['pass', nil, {}]
  end

  t('rule 17 steps 6-7: critical_max cap (inclusive), tainted modes, tainted means rank >= tool, friction typed wins') do
    w = WB
    pay = ->(ref, pol = {}) { w.prov(w.p_in({ 'action.params.payment_ref' => [ref] }, pol)) }
    add = ->(ref, pol = {}) { w.prov(w.p_in({ 'action.params.add_ons' => [ref] }, pol)) }
    capr = "provenance: critical parameter 'action.params.payment_ref' has provenance 'tool', above the policy maximum 'first_party'"
    w.out3(pay.('tool:fx', 'critical_max' => 'tool'))[0, 2] == %w[question typed] &&
      pay.('tool:fx', 'critical_max' => 'first_party')['reason'] == capr &&
      pay.('tool:fx', 'critical_max' => 'first_party', 'critical_tainted' => 'deny')['reason'] == capr &&
      pay.('web:ad-3', 'critical_max' => 'web')['outcome'] == 'question' && pay.('agent:planner', 'critical_max' => 'web')['outcome'] == 'deny' &&
      pay.('wallet:profile:ana', 'critical_max' => 'trusted')['outcome'] == 'pass' &&
      pay.('skyair:offer_set:1', 'critical_max' => 'trusted')['outcome'] == 'deny' &&
      w.out3(pay.('tool:fx', 'critical_tainted' => 'question'))[0, 2] == %w[question tap] &&
      pay.('tool:fx', 'critical_tainted' => 'deny')['reason'] ==
        "provenance: tainted critical parameter 'action.params.payment_ref' (provenance 'tool') is denied by policy" &&
      add.('web:ad-3', 'material_tainted' => 'deny')['reason'] ==
        "provenance: tainted material parameter 'action.params.add_ons' (provenance 'web') is denied by policy" &&
      add.('tool:fx', 'material_tainted' => 'deny')['outcome'] == 'deny' &&
      add.('skyair:offer_set:1', 'material_tainted' => 'deny')['outcome'] == 'pass' &&
      add.('web:ad-3', 'material_tainted' => 'allow')['outcome'] == 'pass' &&
      w.out3(add.('web:ad-3', 'material_tainted' => 'question_typed'))[0, 2] == %w[question typed] &&
      w.out3(add.('web:ad-3'))[0, 2] == %w[question tap] &&
      w.out3(w.prov(w.p_in({ 'action.params.add_ons' => ['web:ad-3'], 'action.params.payment_ref' => ['tool:fx'] })))[0, 2] == %w[question typed] &&
      w.out3(w.prov(w.p_in({ 'action.params.add_ons' => ['web:ad-3'], 'action.params.payment_ref' => ['tool:fx'] }, 'critical_tainted' => 'question')))[0, 2] ==
        %w[question tap] &&
      # a deny for a later (sorted) parameter still wins over an earlier question
      w.prov(w.p_in({ 'action.params.add_ons' => ['web:ad-3'], 'action.params.payment_ref' => ['tool:fx'] }, 'critical_tainted' => 'deny'))['outcome'] == 'deny' &&
      # a question result carries the reason
      add.('web:ad-3')['reason'] == 'provenance: a tainted value needs the principal (lazy question)'
  end

  t('rule 17: label receipts (first party, value mismatch, foreign with flows, public, star) and the classes output') do
    w = WB
    pp = w.passport
    g = w.gov_receipt
    mism = w.p_in({}, {}, w.with_label(pp, 'travellers[0].passport')).merge('action' => { 'params' => WB::PARAMS.merge('passport' => 'Y7654321') })
    fp = w.prov(w.p_in({}, {}, w.with_label(pp, 'travellers[0].passport')))
    w.out3(fp) == ['pass', nil, WB::T.merge('action.params.passport' => 'first_party')] &&
      fp['classes'] == { 'action.params.passport' => ['pii.identity'] } &&
      w.prov(mism)['outcome'] == 'question' && w.prov(mism)['labels']['action.params.passport'] == 'agent' &&
      w.prov(mism)['classes'] == { 'action.params.passport' => ['pii.identity'] } &&
      w.out3(w.prov(w.p_in({}, { 'flows' => { 'pii.*' => [WB::AUD] } }, w.with_label(g, 'passport')))) ==
        ['question', 'typed', WB::T.merge('action.params.passport' => 'tool')] &&
      w.prov(w.p_in({}, {}, w.with_label(w.gov_receipt('public'), 'passport')))['labels']['action.params.passport'] == 'tool' &&
      w.prov(w.p_in({}, { 'flows' => { '*' => [WB::AUD] } }, w.with_label(g, 'passport')))['outcome'] == 'question' &&
      w.prov(w.p_in({}, {}, w.with_label(pp, 'travellers[0].passport')).merge('prov' => w.clean.merge(
        'action.params.passport' => [w.lref(pp, 'travellers[0].passport'), 'wallet:profile:ana'])))['labels']['action.params.passport'] == 'first_party' &&
      w.prov(w.p_in({}, {}, w.with_label(pp, 'travellers[0].passport')).merge('prov' => w.clean.merge(
        'action.params.passport' => [w.lref(pp, 'travellers[0].passport'), 'web:ad-3'])))['labels']['action.params.passport'] == 'web'
  end

  t('rule 17: classes are de-duplicated and sorted; a label ref splits at the FIRST #') do
    w = WB
    d = w.vd('X1234567')
    r = w.receipt(WB::AUD, w.site, 'k1', { 'z' => { 'class' => 'pii.zeta', 'value_digest' => d }, 'a#b' => { 'class' => 'pii.alpha', 'value_digest' => d },
                                           'c' => { 'class' => 'pii.zeta', 'value_digest' => d } })
    input = w.p_in({}, {}, w.with_label(r, 'z')).merge('prov' => w.clean.merge('action.params.passport' => [w.lref(r, 'z'), w.lref(r, 'a#b'), w.lref(r, 'c')]))
    got = w.prov(input)
    got['outcome'] == 'pass' && got['classes'] == { 'action.params.passport' => ['pii.alpha', 'pii.zeta'] } &&
      AtlasPca.parse_label_ref("pca-labels:#{w.session}#a#b") == { 'receipt' => w.session, 'field' => 'a#b' } &&
      AtlasPca.parse_label_ref("pca-labels:#{w.session}#").nil? && AtlasPca.parse_label_ref("pca-labels:#{w.session}").nil? &&
      AtlasPca.parse_label_ref('pca-labels:abc#x').nil? && AtlasPca.parse_label_ref("pca-label:#{w.session}#x").nil? &&
      AtlasPca.parse_label_ref("pca-labels:#{w.session}\n#x").nil?
  end

  t('rule 17 step 5: flow rules (origin, public, most specific: exact > longest prefix.* > *), own keys only') do
    a = 'b.example'
    fa = ->(rules, c, o = 'a.example') { AtlasPca.flow_allowed(rules, c, o, a) }
    fa.({}, 'pii.x', a) && fa.({}, 'public') && !fa.({}, 'pii.x') && !fa.({}, 'constructor') && fa.({ 'constructor' => [a] }, 'constructor') &&
      fa.({ 'pii.*' => [a] }, 'pii.identity') && !fa.({ 'pii.*' => [a] }, 'piix') && !fa.({ 'pii.*' => [a] }, 'pii') &&
      !fa.({ 'pii.*' => [a], 'pii.identity' => ['x'] }, 'pii.identity') && fa.({ 'pii.*' => ['x'], 'pii.identity' => [a] }, 'pii.identity') &&
      !fa.({ 'pii.*' => [a], 'pii.identity.*' => ['x'] }, 'pii.identity.passport') &&
      fa.({ 'pii.*' => ['x'], 'pii.identity.*' => [a] }, 'pii.identity.passport') &&
      fa.({ '*' => [a] }, 'anything') && !fa.({ '*' => [a], 'pii.*' => ['x'] }, 'pii.x') && !fa.({ '*' => 'b.example' }, 'pii.x') &&
      AtlasPca.flow_rule_for({ 'pii.*' => [], 'pii.identity.*' => [] }, 'pii.identity.x') == 'pii.identity.*' &&
      AtlasPca.flow_rule_for({ 'pii.identity.*' => [], 'pii.*' => [] }, 'pii.identity.x') == 'pii.identity.*' &&
      AtlasPca.flow_rule_for({}, 'toString').nil? && AtlasPca.flow_rule_for({ '*' => [] }, 'x') == '*'
  end

  t('rule 17: every label / flow refusal by exact reason (deny keeps the labels so far, env empty)') do
    w = WB
    pp = w.passport
    pre = "provenance: label receipt for 'action.params.passport'"
    flow = "provenance: flow: class 'pii.identity' from 'gov.example' may not reach 'skyair.example' (parameter 'action.params.passport')"
    nr = w.prov(w.p_in({}, {}, w.with_label(w.gov_receipt, 'passport')))
    nr['reason'] == flow && nr['env'] == {} && nr['labels']['action.params.passport'] == 'tool' &&
      w.pr(w.p_in({}, { 'flows' => { 'pii.*' => [WB::AUD], 'pii.identity' => ['elsewhere.example'] } }, w.with_label(w.gov_receipt, 'passport'))) == flow &&
      w.pr(w.p_in({}, {}, w.with_label(pp, 'travellers[0].passport')).merge('committed_labels' => [])) ==
        "provenance: label ref on 'action.params.passport' names a receipt the PCActn does not commit" &&
      w.pr(w.p_in({}, {}, w.with_label(pp, 'travellers[0].passport')).merge('labels' => [])) == "#{pre} was not supplied" &&
      w.pr(w.p_in({}, {}, w.with_label(w.passport(w.session, w.rogue), 'travellers[0].passport'))) == "#{pre}: bad label receipt signature" &&
      w.pr(w.p_in({}, {}, w.with_label(w.passport(w.session, w.site, 'k9'), 'travellers[0].passport'))) ==
        "#{pre}: no pinned label key for site 'skyair.example' kid 'k9'" &&
      w.pr(w.p_in({}, {}, w.with_label(w.receipt('gov.example', w.gov, 'k1', w.pass_fields), 'travellers[0].passport'))) ==
        "#{pre}: no pinned label key for site 'gov.example' kid 'k1'" &&
      w.pr(w.p_in({}, {}, w.with_label(w.passport(w.other_session), 'travellers[0].passport'))) == "#{pre} is bound to another session" &&
      w.pr(w.p_in({}, {}, w.with_label(pp, 'travellers[1].passport'))) == "#{pre} has no field 'travellers[1].passport'" &&
      w.pr(w.p_in('action.params.passport' => ['pca-labels:abc#passport'])) == "provenance: malformed label ref on 'action.params.passport'" &&
      w.pr(w.p_in({ 'action.params.passport' => ["pca-labels:#{AtlasPca.label_receipt_ref(pp)}"] }, {},
                  'committed_labels' => [AtlasPca.label_receipt_ref(pp)], 'labels' => [pp])) == "provenance: malformed label ref on 'action.params.passport'" &&
      w.pr(w.p_in({}, {}, w.with_label(pp.merge('note' => 'x'), 'travellers[0].passport'))) == "#{pre} was not supplied" &&
      # order: commitment before supply before signature before session before field
      w.pr(w.p_in({}, {}, w.with_label(w.passport(w.other_session, w.rogue), 'travellers[9]'))) == "#{pre}: bad label receipt signature" &&
      w.pr(w.p_in({}, {}, w.with_label(w.passport(w.other_session), 'travellers[9]'))) == "#{pre} is bound to another session" &&
      w.pr(w.p_in({}, {}, w.with_label(pp, 'travellers[0].passport')).merge('committed_labels' => [], 'labels' => [])) ==
        "provenance: label ref on 'action.params.passport' names a receipt the PCActn does not commit" &&
      # a flow refusal comes before the critical cap and the tainted modes
      w.pr(w.p_in({}, { 'critical_max' => 'trusted', 'critical_tainted' => 'deny' }, w.with_label(w.gov_receipt, 'passport'))) == flow
  end

  t('rule 17 steps 1-2: prov wire and committed labels at every cap, in order') do
    w = WB
    pr = ->(input) { w.pr(input) }
    k33 = (0...33).to_h { |i| ["action.params.p#{i}", ['x']] }
    par33 = (0...33).to_h { |i| ["p#{i}", i] }
    ds = (0...17).map { |i| w.digest("l#{i}") }
    pr.(w.p_in.merge('prov' => k33, 'action' => { 'params' => par33 }, 'policy' => { 'params' => {} })) == "provenance: 'prov' holds more than 32 paths" &&
      w.prov(w.p_in.merge('prov' => k33.first(32).to_h, 'action' => { 'params' => par33 }, 'policy' => { 'params' => {} }))['outcome'] == 'pass' &&
      pr.(w.p_in.merge('prov' => [])) == "provenance: 'prov' must be an object" &&
      pr.(w.p_in('action.params.pax.lead' => ['x'])) ==
        "provenance: 'prov' key 'action.params.pax.lead' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)" &&
      pr.(w.p_in({ 'action.params.add-ons' => ['x'] }, {}, 'action' => { 'params' => WB::PARAMS.merge('add-ons' => 'x') })).include?("'prov' key 'action.params.add-ons'") &&
      pr.(w.p_in('action.params.__proto__' => ['x'])).include?("'prov' key 'action.params.__proto__'") &&
      pr.(w.p_in({ 'action.params.constructor' => ['x'] }, {}, 'action' => { 'params' => WB::PARAMS.merge('constructor' => 'x') })).include?("'prov' key") &&
      pr.(w.p_in("action.params.#{'p' * 65}" => ['x'])).include?("'prov' key") &&
      pr.(w.p_in({ "action.params.#{'p' * 64}" => ['x'] }, {}, 'action' => { 'params' => WB::PARAMS.merge('p' * 64 => 1) })).nil? &&
      pr.(w.p_in("action.params.note\n" => ['x'])).include?("'prov' key") &&
      pr.(w.p_in('env.world.x' => ['x'])).include?("'prov' key 'env.world.x'") &&
      pr.(w.p_in('action.params.offer_id' => [])) == "provenance: 'prov.action.params.offer_id' must hold 1..8 refs" &&
      pr.(w.p_in('action.params.offer_id' => 'x')) == "provenance: 'prov.action.params.offer_id' must hold 1..8 refs" &&
      pr.(w.p_in('action.params.offer_id' => (0...9).map { |i| "r#{i}" })) == "provenance: 'prov.action.params.offer_id' must hold 1..8 refs" &&
      w.prov(w.p_in('action.params.offer_id' => ['skyair:offer_set:1'] * 8))['outcome'] == 'pass' &&
      ['', 'x' * 257, "#{'é' * 128}a", 5].all? { |r| pr.(w.p_in('action.params.offer_id' => [r])) == "provenance: 'prov.action.params.offer_id' refs must be non-empty strings (<= 256 bytes)" } &&
      w.prov(w.p_in('action.params.offer_id' => ['é' * 128]))['outcome'] == 'question' &&
      pr.(w.p_in.merge('committed_labels' => ds)) == 'provenance: committed labels must be a list of at most 16 digests' &&
      w.prov(w.p_in.merge('committed_labels' => ds[0, 16]))['outcome'] == 'pass' &&
      pr.(w.p_in.merge('committed_labels' => {})) == 'provenance: committed labels must be a list of at most 16 digests' &&
      pr.(w.p_in.merge('committed_labels' => [ds[0], ds[0]])) == 'provenance: committed labels must be distinct canonical 32-byte digests' &&
      pr.(w.p_in.merge('committed_labels' => ['abc'])) == 'provenance: committed labels must be distinct canonical 32-byte digests' &&
      pr.(w.p_in('action.params.seat' => ['x'])) == "provenance: prov names 'action.params.seat', a parameter the action does not carry" &&
      # order: policy, prov wire, committed labels, carried
      pr.(w.p_in({ 'action.params.offer_id' => [] }, {}, 'committed_labels' => ds)) == "provenance: 'prov.action.params.offer_id' must hold 1..8 refs" &&
      pr.(w.p_in({ 'action.params.seat' => ['x'] }, {}, 'committed_labels' => ds)) == 'provenance: committed labels must be a list of at most 16 digests' &&
      pr.(w.p_in({ 'action.params.offer_id' => [] }, { 'critical_max' => 'none' })) ==
        'provenance: policy misconfigured (fail closed): critical_max must be a taint level'
  end

  t('rule 17 step 0: provenance policy sanity (null members are present and misconfigured)') do
    w = WB
    pre = 'provenance: policy misconfigured (fail closed): '
    m = ->(over) { w.pr(w.p_in({}, over)) }
    w.pr(w.p_in.reject { |k, _| k == 'policy' }) == "#{pre}provenance policy needs a params map" &&
      m.({ 'params' => [] }) == "#{pre}provenance policy needs a params map" &&
      m.({ 'params' => { 'params.x' => 'material' } }) == "#{pre}policy param 'params.x' is not an action.params path" &&
      m.({ 'params' => { 'action.params.x' => 'free' } }) == "#{pre}policy param 'action.params.x': sensitivity must be material or critical" &&
      m.({ 'params' => { 'b' => 'free', '1' => 'material' } }) == "#{pre}policy param '1' is not an action.params path" &&
      m.({ 'registry' => { 'x' => 'super' } }) == "#{pre}registry entry 'x' must map to a taint level" &&
      m.({ 'registry' => { 'x' => 'toString' } }) == "#{pre}registry entry 'x' must map to a taint level" &&
      m.({ 'registry' => { 'x' * 257 => 'web' } }) == "#{pre}registry entry '#{'x' * 257}' must map to a taint level" &&
      m.({ 'registry' => nil }) == "#{pre}registry must be an object" && m.({ 'registry' => [] }) == "#{pre}registry must be an object" &&
      m.({ 'label_keys' => nil }) == "#{pre}label_keys must be a list" &&
      m.({ 'label_keys' => [{ 'site' => 'a', 'kid' => 'k' * 65, 'pk' => w.pk(w.site) }] }) == "#{pre}every label key needs site, kid, a 32-byte pk and an optional string pq_pk" &&
      m.({ 'critical_max' => 'none' }) == "#{pre}critical_max must be a taint level" && m.({ 'critical_max' => nil }) == "#{pre}critical_max must be a taint level" &&
      m.({ 'material_tainted' => 'maybe' }) == "#{pre}material_tainted must be allow | question | question_typed | deny" &&
      m.({ 'material_tainted' => nil }) == "#{pre}material_tainted must be allow | question | question_typed | deny" &&
      m.({ 'critical_tainted' => 'allow' }) == "#{pre}critical_tainted must be question | question_typed | deny" &&
      m.({ 'critical_tainted' => nil }) == "#{pre}critical_tainted must be question | question_typed | deny" &&
      m.({ 'flows' => { 'PII!' => [WB::AUD] } }) == "#{pre}flow pattern 'PII!' is not a class, a 'prefix.*' or '*'" &&
      m.({ 'flows' => { 'pii.*.*' => [WB::AUD] } }) == "#{pre}flow pattern 'pii.*.*' is not a class, a 'prefix.*' or '*'" &&
      m.({ 'flows' => { 'pii.*' => 'x' } }) == "#{pre}flow pattern 'pii.*' needs a list of audiences" &&
      m.({ 'flows' => { 'pii.*' => [''] } }) == "#{pre}flow pattern 'pii.*' needs a list of audiences" &&
      m.({ 'flows' => nil }) == "#{pre}flows must be an object" &&
      m.({ 'x' => 1 }) == "#{pre}unknown member 'policy.x'" &&
      m.({ 'label_keys' => [{ 'site' => 'a', 'kid' => 'k', 'pk' => w.pk(w.site), 'x' => 1 }] }) ==
        "#{pre}every label key needs site, kid, a 32-byte pk and an optional string pq_pk" &&
      m.({ 'label_keys' => [{ 'site' => 'a', 'kid' => 'k', 'pk' => w.pk(w.site), 'pq_pk' => nil }] }) ==
        "#{pre}every label key needs site, kid, a 32-byte pk and an optional string pq_pk" &&
      m.({ 'critical_max' => 4 }) == "#{pre}critical_max must be a taint level" &&
      w.prov(w.p_in({}, { 'label_keys' => [{ 'site' => 'a', 'kid' => 'k', 'pk' => w.pk(w.site), 'pq_pk' => 'x' }] }))['outcome'] == 'pass' &&
      w.prov(w.p_in({}, { 'flows' => { '*' => [], 'pii.*' => ['a'], 'pii' => [] }, 'critical_max' => 'agent' }))['outcome'] == 'pass'
  end

  t('rule 17 step 8: env.prov nests the labels; a classified path that prefixes another denies (after the tainted modes)') do
    w = WB
    pol = { 'params' => { 'action.params.pax' => 'material', 'action.params.pax.lead' => 'material' } }
    base = { 'aud' => WB::AUD, 'session' => w.session, 'action' => { 'params' => WB::PARAMS }, 'policy' => pol }
    w.pr(base) == "provenance: provenance paths overlap at 'action.params.pax.lead'" &&
      w.pr(base.merge('policy' => pol.merge('material_tainted' => 'deny'))) ==
        "provenance: tainted material parameter 'action.params.pax' (provenance 'agent') is denied by policy" &&
      w.prov(base.merge('policy' => { 'params' => { 'action.params.pax.lead' => 'material' } }))['env'] ==
        { 'action' => { 'params' => { 'pax' => { 'lead' => 'agent' } } } }
  end

  t('rule 17: supplied labels must be a real array (strings / objects / null deny); malformed receipts never match') do
    w = WB
    pp = w.passport
    bad = pp.merge('site' => "\xED\xA0\x80".dup.force_encoding(Encoding::UTF_8))
    ['abc', { 'a' => 1 }, 5, nil].all? { |ls| w.pr(w.p_in.merge('labels' => ls)) == 'provenance: labels must be an array' } &&
      w.prov(w.p_in.reject { |k, _| k == 'labels' })['outcome'] == 'pass' &&
      w.prov(w.p_in({}, {}, w.with_label(pp, 'travellers[0].passport')).merge('labels' => [bad, 1, nil, pp]))['outcome'] == 'pass' &&
      # a non-object input is refused up front (TS param-provenance.ts: 'input must be an object'), not an evaluation error
      w.pr(nil) == 'provenance: input must be an object' && w.pr('x') == 'provenance: input must be an object'
  end

  t('rule 17: label receipt wire validation at its edges') do
    r = WB.passport
    v = ->(over) { AtlasPca.validate_labels_wire(r.merge(over)) }
    f = ->(fields) { v.({ 'fields' => fields }) }
    d = WB.vd('x')
    ok = { 'class' => 'pii.x', 'value_digest' => d }
    AtlasPca.validate_labels_wire(r).nil? && AtlasPca.validate_labels_wire(nil) == 'label receipt must be an object' &&
      v.({ 'z' => 1 }) == "unknown member 'labels.z'" && v.({ 'kind' => 'pca-label' }) == 'label receipt must be {v: 1, kind: "pca-labels"}' &&
      v.({ 'response_digest' => 'x' }) == "'labels.response_digest' must be canonical base64url (32 bytes)" &&
      f.({}) == "'labels.fields' must hold 1..64 fields" && f.([]) == "'labels.fields' must be an object" &&
      f.((0...64).to_h { |i| ["f#{i}", ok] }).nil? && f.((0...65).to_h { |i| ["f#{i}", ok] }) == "'labels.fields' must hold 1..64 fields" &&
      f.({ 'x' * 256 => ok }).nil? && f.({ 'x' * 257 => ok }) == 'label field paths must be non-empty strings (<= 256 bytes)' &&
      f.({ 'a' => ok.merge('n' => 1) }) == "label field 'a' must be exactly {class, value_digest}" &&
      f.({ 'a' => { 'class' => 'x' } }) == "label field 'a' must be exactly {class, value_digest}" &&
      f.({ 'a' => ok.merge('class' => 'a' * 128) }).nil? && f.({ 'a' => ok.merge('class' => 'a' * 129) }) == "label field 'a': invalid data class" &&
      ['Pii', 'pii.', '.pii', 'pii..x', '1pii', "pii\n", 5].all? { |c| f.({ 'a' => ok.merge('class' => c) }) == "label field 'a': invalid data class" } &&
      f.({ 'a' => ok.merge('class' => 'p.1.x_y') }).nil? &&
      f.({ 'a' => ok.merge('value_digest' => 'x') }) == "label field 'a': value_digest must be canonical base64url (32 bytes)" &&
      v.({ 'issued_at' => -1 }) == "'labels.issued_at' must be a non-negative safe integer" &&
      v.({ 'kid' => '' }) == "'labels.kid' must be a non-empty string (<= 64 bytes)" && v.({ 'sig' => 1 }) == "'labels.sig' must be a string" &&
      AtlasPca.verify_labels(r, [{ 'site' => WB::AUD, 'kid' => 'k1', 'pk' => WB.pk(WB.site) }]).nil? &&
      AtlasPca.verify_labels(r, [{ 'site' => 'x', 'kid' => 'k1', 'pk' => WB.pk(WB.site) }]) == "no pinned label key for site 'skyair.example' kid 'k1'" &&
      AtlasPca.verify_labels(r.merge('kid' => 'k2'), [{ 'site' => WB::AUD, 'kid' => 'k2', 'pk' => WB.pk(WB.site) }]) == 'bad label receipt signature'
  end

  # =================================================================== rule 18: classifiers

  t('rule 18: k-of-n quorum, k = 1, unpinned measurements, structured content, prototype-named labels and ids') do
    w = WB
    labs = %w[constructor __proto__ toString valueOf hasOwnProperty]
    proto = lambda do |label|
      vs = [w.verdict(w.j(0), label, 'classifier' => 'constructor'), w.verdict(w.j(1), label, 'classifier' => 'constructor')]
      w.cls(w.c_in(vs, {}, 'policy' => { 'classifiers' => [w.tone('id' => 'constructor', 'labels' => labs, 'measurements' => ['m-tone-1'])] }))
    end
    body = { 'b' => 'x', 'a' => [1, 2] }
    sv = ->(k) { w.verdict(k, 'neutral', 'content_digest' => w.vd(body)) }
    q = w.cls(w.c_in([w.verdict(w.j(0), 'apologetic'), w.verdict(w.j(1), 'apologetic'), w.verdict(w.j(2), 'neutral')]))
    q == { 'ok' => true, 'classes' => { 'tone' => 'apologetic' }, 'votes' => { 'tone' => { 'apologetic' => 2, 'neutral' => 1 } } } &&
      w.cls(w.c_in([w.verdict(w.j(0), 'neutral')], 'k' => 1))['classes'] == { 'tone' => 'neutral' } &&
      w.cls(w.c_in([w.verdict(w.j(0), 'neutral')], 'k' => 1.0))['classes'] == { 'tone' => 'neutral' } &&
      w.cls(w.c_in([w.verdict(w.j(0), 'neutral', 'measurement' => 'a'), w.verdict(w.j(1), 'neutral', 'measurement' => 'b')], {}).tap { |x| x['policy']['classifiers'][0].delete('measurements') })['ok'] &&
      w.cls(w.c_in([sv.(w.j(0)), sv.(w.j(1))], {}, 'action' => { 'params' => { 'body' => body } }))['classes'] == { 'tone' => 'neutral' } &&
      w.cls({ 'session' => w.session, 'action' => { 'params' => {} }, 'committed' => [], 'verdicts' => [], 'policy' => { 'classifiers' => [] } }) ==
        { 'ok' => true, 'classes' => {}, 'votes' => {} } &&
      labs.all? { |l| proto.(l)['classes'] == { 'constructor' => l } }
  end

  t('rule 18: every refusal by exact reason and the step-3 order') do
    w = WB
    a0 = w.verdict(w.j(0), 'apologetic')
    a1 = w.verdict(w.j(1), 'apologetic')
    pre = "classes: classifier 'tone': "
    ds = (0...9).map { |i| w.digest("c#{i}") }
    w.cr(w.c_in([a0, w.verdict(w.j(1), 'neutral')])) == "#{pre}no label reaches the quorum 2" &&
      w.cr(w.c_in([a0, w.verdict(w.j(1), 'neutral')], 'k' => 1)) == "#{pre}ambiguous, 2 labels reach the quorum" &&
      w.cr(w.c_in([a0, w.verdict(w.rogue, 'apologetic')])) == "#{pre}judge key is not on the allowlist" &&
      w.cr(w.c_in([a0, a1.merge('label' => 'neutral')])) == "#{pre}bad verdict signature" &&
      w.cr(w.c_in([a0, w.verdict(w.j(1), 'apologetic', 'session' => w.other_session)])) == "#{pre}verdict bound to another session" &&
      w.cr(w.c_in([a0, w.verdict(w.j(1), 'apologetic', 'content_digest' => w.vd('other'))])) == "#{pre}verdict is about other content" &&
      w.cr(w.c_in([a0, w.verdict(w.j(1), 'sarcastic')])) == "#{pre}label 'sarcastic' is not in its label set" &&
      w.cr(w.c_in([a0, w.verdict(w.j(1), 'apologetic', 'measurement' => 'm-evil')])) == "#{pre}measurement is not pinned" &&
      w.cr(w.c_in([a0, w.verdict(w.j(0), 'neutral'), a1])) == "#{pre}two verdicts from one judge" &&
      w.cr(w.c_in([a0, a1]).merge('committed' => [AtlasPca.classifier_verdict_ref(a0)])) == "#{pre}no label reaches the quorum 2" &&
      w.cr(w.c_in([a0, a1]).merge('verdicts' => [a0])) == 'classes: a committed verdict was not supplied (or is malformed)' &&
      w.cr(w.c_in([a0]).merge('committed' => [AtlasPca.classifier_verdict_ref(a0)] * 2)) == 'classes: committed verdicts must be distinct canonical 32-byte digests' &&
      w.cr(w.c_in([a0]).merge('committed' => ds)) == 'classes: committed verdicts must be a list of at most 8 digests' &&
      w.cr(w.c_in([a0]).merge('committed' => ds[0, 8])) == 'classes: a committed verdict was not supplied (or is malformed)' &&
      w.cr(w.c_in([a0.merge('note' => 'x'), a1])) == 'classes: a committed verdict was not supplied (or is malformed)' &&
      w.cr(w.c_in([a0, a1, w.verdict(w.j(2), 'x', 'classifier' => 'spam')])) == "classes: verdict for undeclared classifier 'spam'" &&
      w.cr(w.c_in([a0, a1]).merge('action' => { 'params' => {} })) == "#{pre}the action carries no 'action.params.body'" &&
      w.cr(w.c_in([])) == "#{pre}no label reaches the quorum 2" &&
      # order within one verdict: allowlist, signature, session, content, label, measurement, distinct judge
      w.cr(w.c_in([w.verdict(w.rogue, 'apologetic').merge('label' => 'x')])) == "#{pre}judge key is not on the allowlist" &&
      w.cr(w.c_in([w.verdict(w.j(0), 'apologetic', 'session' => w.other_session).merge('label' => 'neutral')])) == "#{pre}bad verdict signature" &&
      w.cr(w.c_in([w.verdict(w.j(0), 'apologetic', 'session' => w.other_session, 'content_digest' => w.vd('o'))])) == "#{pre}verdict bound to another session" &&
      w.cr(w.c_in([w.verdict(w.j(0), 'x', 'content_digest' => w.vd('o'))])) == "#{pre}verdict is about other content" &&
      w.cr(w.c_in([w.verdict(w.j(0), 'x', 'measurement' => 'm')])) == "#{pre}label 'x' is not in its label set" &&
      w.cr(w.c_in([a0, w.verdict(w.j(0), 'neutral', 'measurement' => 'm')])) == "#{pre}measurement is not pinned" &&
      # undeclared classifier before allowlist; content needs a canonical value (a lone surrogate fails closed)
      w.cr(w.c_in([w.verdict(w.rogue, 'x', 'classifier' => 'spam')])) == "classes: verdict for undeclared classifier 'spam'" &&
      w.cr(w.c_in([a0]).merge('action' => { 'params' => { 'body' => "\xED\xA0\x80".dup.force_encoding(Encoding::UTF_8) } })).start_with?('classes: evaluation error (fail closed): ')
  end

  t('rule 18 step 0: classifier policy sanity at its edges') do
    w = WB
    a0 = w.verdict(w.j(0), 'apologetic')
    pre = 'classes: policy misconfigured (fail closed): '
    m = ->(over) { w.cr(w.c_in([a0], over)) }
    l32 = (0...32).map { |i| "l#{i}" }
    m.({ 'k' => 4 }) == "#{pre}classifier 'tone': k must be an integer in [1, 3]" && m.({ 'k' => 0 }) == "#{pre}classifier 'tone': k must be an integer in [1, 3]" &&
      m.({ 'k' => 1.5 }) == "#{pre}classifier 'tone': k must be an integer in [1, 3]" && m.({ 'k' => 3 }) == "classes: classifier 'tone': no label reaches the quorum 3" &&
      m.({ 'labels' => %w[a a] }) == "#{pre}classifier 'tone': labels must be distinct non-empty strings" &&
      m.({ 'labels' => ['a', ''] }) == "#{pre}classifier 'tone': labels must be distinct non-empty strings" &&
      m.({ 'labels' => ['x' * 65] }) == "#{pre}classifier 'tone': labels must be distinct non-empty strings" &&
      m.({ 'labels' => [] }) == "#{pre}classifier 'tone': labels must hold 1..32 strings" &&
      m.({ 'labels' => l32 + ['apologetic'] }) == "#{pre}classifier 'tone': labels must hold 1..32 strings" &&
      m.({ 'labels' => l32[0, 31] + ['apologetic'], 'k' => 1 }).nil? &&
      m.({ 'keys' => [] }) == "#{pre}classifier 'tone': keys must be distinct 32-byte keys" &&
      m.({ 'keys' => [w.pk(w.j(0))] * 2 }) == "#{pre}classifier 'tone': keys must be distinct 32-byte keys" &&
      m.({ 'keys' => ['abc'] }) == "#{pre}classifier 'tone': keys must be distinct 32-byte keys" &&
      m.({ 'measurements' => [1] }) == "#{pre}classifier 'tone': measurements must be a list of strings" &&
      m.({ 'measurements' => nil }) == "#{pre}classifier 'tone': measurements must be a list of strings" &&
      m.({ 'param' => 'body' }) == "#{pre}classifier 'tone': param must be an action.params path" &&
      m.({ 'id' => 'Tone' }) == "#{pre}every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$" &&
      w.cr(w.c_in([a0], {}, 'policy' => { 'classifiers' => [w.tone, w.tone] })) == "#{pre}every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$" &&
      w.cr(w.c_in([a0], {}, 'policy' => { 'classifiers' => {} })) == "#{pre}classifier policy needs a classifiers list" &&
      w.cr(w.c_in([a0], {}, 'policy' => nil)) == "#{pre}classifier policy needs a classifiers list" &&
      w.cr(w.c_in([a0], { 'k' => 4 }).merge('committed' => 'x')) == "#{pre}classifier 'tone': k must be an integer in [1, 3]" &&
      ['x', { 'a' => 1 }, nil].all? { |vs| w.cr(w.c_in([a0]).merge('verdicts' => vs)) == 'classes: verdicts must be an array' } &&
      w.cr(w.c_in([a0]).merge('committed' => nil)) == 'classes: committed verdicts must be a list of at most 8 digests' &&
      [nil, 'x'].all? { |a| w.cr(w.c_in([a0]).merge('action' => a)) == 'classes: action must be an object' } &&
      w.cr(w.c_in([a0]).merge('action' => { 'params' => nil })) == 'classes: action.params must be an object' &&
      w.cr(w.c_in([a0]).merge('action' => {})) == "classes: classifier 'tone': the action carries no 'action.params.body'" &&
      # order: committed, verdicts, action, params
      w.cr(w.c_in([a0]).merge('committed' => nil, 'verdicts' => nil)) == 'classes: committed verdicts must be a list of at most 8 digests' &&
      w.cr(w.c_in([a0]).merge('verdicts' => nil, 'action' => nil)) == 'classes: verdicts must be an array' &&
      m.({ 'x' => 1 }) == "#{pre}every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}" &&
      w.cr(w.c_in([a0], {}, 'policy' => { 'classifiers' => [w.tone], 'x' => 1 })) == "#{pre}unknown member 'policy.x'" &&
      m.({ 'k' => '2' }) == "#{pre}classifier 'tone': k must be an integer in [1, 3]" &&
      m.({ 'pq_keys' => { w.pk(w.rogue) => 'x' } }) == "#{pre}classifier 'tone': pq_keys must map allowlisted keys to PQ keys" &&
      m.({ 'pq_keys' => { w.pk(w.j(0)) => '' } }) == "#{pre}classifier 'tone': pq_keys must map allowlisted keys to PQ keys" &&
      m.({ 'pq_keys' => nil }) == "#{pre}classifier 'tone': pq_keys must map allowlisted keys to PQ keys" &&
      m.({ 'pq_keys' => { w.pk(w.j(0)) => 'x' } }) == "classes: classifier 'tone': no label reaches the quorum 2"
  end

  t('rule 18: verdict wire validation') do
    v0 = WB.verdict(WB.j(0), 'neutral')
    v = ->(over) { AtlasPca.validate_classifier_verdict_wire(v0.merge(over)) }
    AtlasPca.validate_classifier_verdict_wire(v0).nil? && AtlasPca.validate_classifier_verdict_wire('x') == 'verdict must be an object' &&
      v.({ 'n' => 1 }) == "unknown member 'verdict.n'" && v.({ 'v' => 2 }) == 'verdict must be {v: 1, kind: "pca-intent-classification"}' &&
      v.({ 'classifier' => 'T' }) == "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$" &&
      v.({ 'session' => 'x' }) == "'verdict.session' must be canonical base64url (32 bytes)" &&
      v.({ 'content_digest' => 'x' }) == "'verdict.content_digest' must be canonical base64url (32 bytes)" &&
      v.({ 'label' => 'l' * 64 }).nil? && v.({ 'label' => 'l' * 65 }) == "'verdict.label' must be a non-empty string (<= 64 bytes)" &&
      v.({ 'measurement' => 'm' * 256 }).nil? && v.({ 'measurement' => 'm' * 257 }) == "'verdict.measurement' must be a non-empty string (<= 256 bytes)" &&
      v.({ 'judge' => 'x' }) == "'verdict.judge' must be canonical base64url (32 bytes)" && v.({ 'sig' => nil }) == "'verdict.sig' must be a string"
  end

  # =================================================================== activity and composition

  t('activity: only a non-empty Array, a String offer_set or a Hash policy makes a check active (strict typing)') do
    w = WB
    d = w.session
    act = ->(s, p) { AtlasPca.intent_wb_active({ 'intent_session' => s, 'policy' => p }) }
    none = { 'facts' => false, 'provenance' => false, 'classes' => false }
    act.({}, {}) == none && AtlasPca.intent_wb_active({}) == none && AtlasPca.intent_wb_active(nil) == none &&
      act.({ 'facts' => { 'length' => 1 }, 'labels' => { 'length' => 1 }, 'classes' => { 'length' => 1 }, 'offer_set' => { 'length' => 43 } }, {}) == none &&
      act.({ 'facts' => [], 'labels' => [], 'classes' => [], 'offer_set' => nil }, {}) == none &&
      act.({ 'facts' => 'abc', 'classes' => 'abc', 'labels' => 'abc', 'offer_set' => 5 }, {}) == none &&
      act.({}, { 'world' => { 'worlds' => { 'length' => 2 }, 'relational' => [], 'offers' => [] }, 'classifiers' => { 'length' => 1 }, 'provenance' => [] }) == none &&
      act.({}, { 'world' => nil, 'provenance' => nil, 'classifiers' => nil }) == none &&
      act.({ 'facts' => [d], 'prov' => nil, 'classes' => [d] }, {}) == { 'facts' => true, 'provenance' => true, 'classes' => true } &&
      act.({ 'offer_set' => 'x' }, {})['facts'] && act.({}, { 'world' => { 'worlds' => [1] } })['facts'] &&
      act.({}, { 'world' => { 'relational' => [1] } })['facts'] && act.({}, { 'world' => { 'offers' => {} } })['facts'] &&
      act.({ 'labels' => [d] }, {})['provenance'] && act.({}, { 'provenance' => {} })['provenance'] && act.({ 'prov' => 5 }, {})['provenance'] &&
      act.({}, { 'classifiers' => [1] })['classes'] &&
      AtlasPca.intent_world_active({ 'committed' => { 'offer_set' => nil }, 'policy' => {} }) == false &&
      AtlasPca.intent_provenance_active({ 'policy' => nil }) == false && AtlasPca.intent_provenance_active({ 'prov' => nil }) &&
      AtlasPca.classifier_check_active({ 'committed' => [1], 'policy' => nil }) && !AtlasPca.classifier_check_active({ 'committed' => 'x' })
  end

  t('decide_intent_wb: inactive unit is the pre-v2 verdict; nil input fails closed without raising') do
    w = WB
    AtlasPca.decide_intent_wb(w.wb({}, {})) == { 'outcome' => 'admit', 'checks' => {}, 'env' => {} } &&
      AtlasPca.decide_intent_wb(w.wb({}, nil)) == { 'outcome' => 'deny', 'checks' => { 'facts' => 'fail' }, 'env' => {},
                                                    'reason' => 'facts: the W-B context is malformed: policy must be an object' } &&
      AtlasPca.decide_intent_wb(w.wb({}, {}).reject { |k, _| k == 'policy' }) == { 'outcome' => 'admit', 'checks' => {}, 'env' => {} } &&
      AtlasPca.decide_intent_wb(w.wb(nil, {}))['reason'] == 'facts: the W-B context is malformed: intent_session must be an object' &&
      AtlasPca.decide_intent_wb(w.wb({ 'facts' => [], 'labels' => [], 'classes' => [] }, { 'world' => {}, 'classifiers' => [] })) ==
        { 'outcome' => 'admit', 'checks' => {}, 'env' => {} } &&
      AtlasPca.decide_intent_wb(nil)['outcome'] == 'deny' && AtlasPca.decide_intent_wb(nil)['checks'] == { 'facts' => 'fail' }
  end

  t('decide_intent_wb: facts -> provenance -> classes; the first failure ends the unit; a question does not') do
    w = WB
    f = w.fact(0, 'fare', 5)
    wpol = { 'worlds' => [w.fare_world('min_oracles' => 1, 'max_faulty' => 0)] }
    a0 = w.verdict(w.j(0), 'apologetic')
    a1 = w.verdict(w.j(1), 'apologetic')
    vrefs = [a0, a1].map { |v| AtlasPca.classifier_verdict_ref(v) }
    clean = w.clean
    q_prov = clean.merge('action.params.add_ons' => ['web:ad-3'])
    full = lambda do |prov, verdicts, world_ok: true|
      w.wb({ 'facts' => [AtlasPca.fact_ref(f)], 'prov' => prov, 'classes' => vrefs },
           { 'world' => wpol, 'provenance' => w.p_policy, 'classifiers' => [w.tone] },
           'artifacts' => { 'facts' => world_ok ? [f] : [], 'verdicts' => verdicts })
    end
    ok = AtlasPca.decide_intent_wb(full.(clean, [a0, a1]))
    q = AtlasPca.decide_intent_wb(full.(q_prov, [a0, a1]))
    qf = AtlasPca.decide_intent_wb(full.(q_prov, [a0]))
    ff = AtlasPca.decide_intent_wb(full.({ 'x' => 1 }, [a0], world_ok: false))
    pf = AtlasPca.decide_intent_wb(full.({ 'action.params.seat' => ['x'] }, [a0]))
    ok['outcome'] == 'admit' && ok['checks'] == { 'facts' => 'pass', 'provenance' => 'pass', 'classes' => 'pass' } &&
      ok['env']['world'] == { 'fare' => 5 } && ok['env']['class'] == { 'tone' => 'apologetic' } && ok['single_source'] == ['fare'] &&
      ok['env']['prov']['action']['params']['offer_id'] == 'first_party' && !ok.key?('reason') && !ok.key?('friction') &&
      q['outcome'] == 'question' && q['checks'] == { 'facts' => 'pass', 'provenance' => 'question', 'classes' => 'pass' } && q['friction'] == 'tap' &&
      q['reason'] == 'provenance: a tainted value needs the principal (lazy question)' &&
      qf['outcome'] == 'deny' && qf['checks'] == { 'facts' => 'pass', 'provenance' => 'question', 'classes' => 'fail' } &&
      qf['reason'] == 'classes: a committed verdict was not supplied (or is malformed)' && !qf.key?('friction') && qf['env'] == {} &&
      ff == { 'outcome' => 'deny', 'checks' => { 'facts' => 'fail' }, 'env' => {}, 'reason' => 'facts: a committed fact was not supplied (or is malformed)' } &&
      pf['outcome'] == 'deny' && pf['checks'] == { 'facts' => 'pass', 'provenance' => 'fail' } && pf['env'] == {} &&
      pf['reason'] == "provenance: prov names 'action.params.seat', a parameter the action does not carry" && !pf.key?('single_source')
  end

  t('decide_intent_wb: context shape (closed, absent vs null) and activity edges (a present prov is judged; single_source only when non-empty)') do
    w = WB
    np = AtlasPca.decide_intent_wb(w.wb({ 'prov' => nil }, {}))
    pol_nil = AtlasPca.decide_intent_wb(w.wb({}, { 'provenance' => nil }))
    pol_obj = AtlasPca.decide_intent_wb(w.wb({}, { 'provenance' => {} }))
    rel = AtlasPca.decide_intent_wb(w.wb({}, { 'world' => { 'relational' => [w.rel('d', 'sub', 'action.params.n', 'action.params.n')] } },
                                         'action' => { 'verb' => 'v', 'resource' => 'r', 'params' => { 'n' => 3 } }))
    bad_prov = AtlasPca.decide_intent_wb(w.wb({ 'prov' => [] }, {}))
    ce = ->(sm, pol, over = {}) { AtlasPca.decide_intent_wb(w.wb(sm, pol, over))['reason'].to_s.delete_prefix('facts: the W-B context is malformed: ') }
    np == { 'outcome' => 'deny', 'checks' => { 'provenance' => 'fail' }, 'env' => {}, 'reason' => "provenance: 'prov' must be an object" } &&
      AtlasPca.decide_intent_wb(w.wb({ 'prov' => {} }, {})) == { 'outcome' => 'admit', 'checks' => { 'provenance' => 'pass' }, 'env' => { 'prov' => {} } } &&
      pol_nil == { 'outcome' => 'deny', 'checks' => { 'facts' => 'fail' }, 'env' => {}, 'reason' => 'facts: the W-B context is malformed: policy.provenance must be an object' } &&
      ce.({}, { 'world' => nil }) == 'policy.world must be an object' && ce.({}, { 'world' => [] }) == 'policy.world must be an object' &&
      ce.({}, { 'classifiers' => nil }) == 'policy.classifiers must be an array' && ce.({}, { 'classifiers' => 'abc' }) == 'policy.classifiers must be an array' &&
      ce.({}, { 'x' => 1 }) == "unknown member 'policy.x'" && ce.({}, []) == 'policy must be an object' &&
      ce.({}, {}, 'artifacts' => nil) == 'artifacts must be an object' && ce.({}, {}, 'artifacts' => { 'x' => [] }) == "unknown member 'artifacts.x'" &&
      %w[facts labels verdicts].all? { |k| ce.({}, {}, 'artifacts' => { k => nil }) == "artifacts.#{k} must be an array" && ce.({}, {}, 'artifacts' => { k => {} }) == "artifacts.#{k} must be an array" } &&
      ce.({}, {}, 'artifacts' => { 'offer_set' => nil }) == 'artifacts.offer_set must be an object' &&
      ce.({}, {}, 'artifacts' => { 'offer_set' => [] }) == 'artifacts.offer_set must be an object' &&
      ce.([], {}) == 'intent_session must be an object' &&
      # order: intent_session, artifacts, policy
      ce.({}, nil, 'artifacts' => nil) == 'artifacts must be an object' && ce.(nil, nil, 'artifacts' => nil) == 'intent_session must be an object' &&
      AtlasPca.intent_wb_context_error({ 'intent_session' => {} }).nil? &&
      AtlasPca.intent_wb_context_error({ 'intent_session' => {}, 'artifacts' => { 'facts' => [], 'labels' => [], 'verdicts' => [], 'offer_set' => {} },
                                         'policy' => { 'world' => {}, 'provenance' => { 'params' => {} }, 'classifiers' => [] } }).nil? &&
      pol_obj['checks'] == { 'provenance' => 'fail' } &&
      pol_obj['reason'] == 'provenance: policy misconfigured (fail closed): provenance policy needs a params map' &&
      rel == { 'outcome' => 'admit', 'checks' => { 'facts' => 'pass' }, 'env' => { 'world' => { 'd' => 0 } } } &&
      bad_prov['checks'] == { 'provenance' => 'fail' } && bad_prov['reason'] == "provenance: 'prov' must be an object"
  end

  # =================================================================== suite capability (alg / pq_pk / pq_sig)

  t('suites: artifact suite members (unsupported_suite, malformed members, ed25519 carries no PQ members), signed body') do
    e = ->(a) { AtlasPca.wb_artifact_suite_error(a) }
    d = "atlas-pca/fact/v1\u0000"
    base = { 'v' => 1, 'kind' => 'pca-fact', 'sig' => 'x' }
    AtlasPca::WB_SUITE_MEMBERS == %w[alg pq_pk pq_sig] &&
      e.({}).nil? && e.({ 'alg' => 'ed25519' }).nil? &&
      [5, nil, true, ['ed25519']].all? { |a| e.({ 'alg' => a }) == 'alg must be a string' } &&
      e.({ 'alg' => 'nope' }) == "unsupported_suite: 'nope'" && e.({ 'alg' => 'fn-dsa-512' }) == "unsupported_suite: 'fn-dsa-512'" &&
      e.({ 'alg' => 'nope', 'pq_pk' => 5 }) == "unsupported_suite: 'nope'" &&
      e.({ 'pq_pk' => 5 }) == 'pq_pk must be a string' && e.({ 'pq_sig' => nil }) == 'pq_sig must be a string' &&
      e.({ 'pq_pk' => 1, 'pq_sig' => 1 }) == 'pq_pk must be a string' &&
      e.({ 'pq_pk' => 'x' }) == 'an ed25519 artifact must not carry pq_pk / pq_sig' &&
      e.({ 'alg' => 'ed25519', 'pq_sig' => 'x' }) == 'an ed25519 artifact must not carry pq_pk / pq_sig' &&
      AtlasPca.wb_artifact_message(d, base) == AtlasPca.wb_artifact_message(d, base.merge('pq_sig' => 'y')) &&
      AtlasPca.wb_artifact_message(d, base) == d.b + '{"kind":"pca-fact","v":1}'.b &&
      AtlasPca.wb_artifact_message(d, base) != AtlasPca.wb_artifact_message(d, base.merge('pq_pk' => 'y')) &&
      AtlasPca.wb_artifact_message(d, base) != AtlasPca.wb_artifact_message(d, base.merge('alg' => 'ed25519'))
  end

  t('suites: every W-B artifact refuses an unimplemented alg with unsupported_suite before anything else about it') do
    w = WB
    pol = { 'worlds' => [w.fare_world] }
    t3 = w.three
    nope = w.fact(0, 'tier', 1, kid: 'o9', k: w.rogue).reject { |k, _| k == 'sig' }.merge('alg' => 'nope')
    nope = w.sign(WB::FACT_D, nope, w.rogue)
    explicit = w.sign(WB::FACT_D, t3[2].reject { |k, _| k == 'sig' }.merge('alg' => 'ed25519'), w.oracle(2))
    pqf = w.sign(WB::FACT_D, t3[2].reject { |k, _| k == 'sig' }.merge('alg' => 'ml-dsa-65', 'pq_pk' => 'x'), w.oracle(2))
    pq_ok = AtlasPca.supported_suites.include?('ml-dsa-65')
    pq_pin = { 'worlds' => [w.fare_world('oracles' => w.oracles(2) + [{ 'kid' => 'o3', 'pk' => w.pk(w.oracle(2)), 'pq_pk' => 'x' }])] }
    os_nope = w.offer_set('alg' => 'nope', 'kid' => 'other')
    os_bad = w.offer_set('alg' => 'nope', 'rank' => 'x')
    pp_nope = w.receipt(WB::AUD, w.site, 'k9', w.pass_fields).then { |r| w.sign(WB::LABELS_D, r.reject { |k, _| k == 'sig' }.merge('alg' => 'nope'), w.site) }
    v_nope = w.sign(WB::CLS_D, w.verdict(w.rogue, 'x', 'classifier' => 'spam').reject { |k, _| k == 'sig' }.merge('alg' => 'nope'), w.rogue)
    a1 = w.verdict(w.j(1), 'apologetic')
    w.wr(w.w_in([t3[0], t3[1], nope], pol)) == "facts: fact signature suite: unsupported_suite: 'nope'" &&
      w.wok(w.w_in([t3[0], t3[1], explicit], pol), { 'fare' => 39_800 }) &&
      w.wr(w.w_in([t3[0], t3[1], t3[2].merge('pq_pk' => 'x')], pol)) == "facts: fact signature suite: an ed25519 artifact must not carry pq_pk / pq_sig" &&
      w.wr(w.w_in([t3[0], t3[1], pqf], pol)) == (pq_ok ? "facts: bad oracle signature on a 'fare' fact" : "facts: fact signature suite: unsupported_suite: 'ml-dsa-65'") &&
      w.wr(w.w_in([t3[0], t3[1], pqf], pq_pin)) == (pq_ok ? "facts: bad oracle signature on a 'fare' fact" : "facts: fact signature suite: unsupported_suite: 'ml-dsa-65'") &&
      w.excess(w.os_in(os_nope)) == "facts: offers: signature suite: unsupported_suite: 'nope'" &&
      w.excess(w.os_in(os_bad)) == "facts: offers: 'offer_set.rank' must be \"price_asc\"" &&
      w.pr(w.p_in({}, {}, w.with_label(pp_nope, 'travellers[0].passport'))) ==
        "provenance: label receipt for 'action.params.passport': signature suite: unsupported_suite: 'nope'" &&
      w.cr(w.c_in([v_nope, a1])) == "classes: verdict signature suite: unsupported_suite: 'nope'" &&
      AtlasPca.verify_labels(pp_nope, []) == "signature suite: unsupported_suite: 'nope'" &&
      AtlasPca.wb_verify_artifact_sig(WB::FACT_D, t3[0], { 'pk' => w.pk(w.oracle(0)), 'pq_pk' => 'x' }) &&
      AtlasPca.wb_verify_artifact_sig(WB::FACT_D, t3[0], w.pk(w.oracle(0))) &&
      !AtlasPca.wb_verify_artifact_sig(WB::FACT_D, t3[0], { 'pk' => w.pk(w.oracle(1)) }) &&
      !AtlasPca.wb_verify_artifact_sig(WB::FACT_D, t3[0], {}) && !AtlasPca.wb_verify_artifact_sig(WB::FACT_D, t3[0].merge('sig' => 5), w.pk(w.oracle(0)))
  end

  # =================================================================== V14 read purpose

  t('read purpose: minimise / uncovered / allow, own-member coverage, patterns, de-duplicated UTF-8 byte order') do
    fields = [{ 'path' => 'passengers[].name', 'class' => 'pii.identity' }, { 'path' => 'passengers[].email', 'class' => 'pii.contact', 'optional' => true },
              { 'path' => 'loyalty', 'class' => 'internal', 'optional' => true }, { 'path' => 'fares', 'class' => 'public' }]
    cov = { 'booking' => ['pii.identity', 'itinerary'], 'support' => ['pii.*', 'internal'], 'comparison' => [] }
    rp = ->(purpose, over = {}) { AtlasPca.decide_read_purpose({ 'fields' => fields, 'purpose' => purpose, 'coverage' => cov }.merge(over)) }
    q = { 'outcome' => 'question', 'minimise' => ['loyalty', 'passengers[].email'], 'uncovered' => ['passengers[].name'] }
    utf = ["\u{1F600}", "�", 'zé', 'a'].map { |x| { 'path' => x, 'class' => 'secret' } }
    one = ->(cls, pats) { AtlasPca.decide_read_purpose({ 'fields' => [{ 'path' => 'x', 'class' => cls }], 'purpose' => 'p', 'coverage' => { 'p' => pats } })['outcome'] }
    rp.('booking') == { 'outcome' => 'allow', 'minimise' => ['loyalty', 'passengers[].email'], 'uncovered' => [] } &&
      rp.('support') == { 'outcome' => 'allow', 'minimise' => [], 'uncovered' => [] } &&
      rp.('comparison') == q && rp.('nope') == q && rp.('constructor') == q && rp.('toString') == q &&
      rp.('comparison', 'on_uncovered' => 'deny') == q.merge('outcome' => 'deny') &&
      rp.('comparison', 'on_uncovered' => 'question') == q &&
      AtlasPca.decide_read_purpose({ 'fields' => utf, 'purpose' => 'p', 'coverage' => { 'p' => [] } })['uncovered'] == ['a', 'zé', "�", "\u{1F600}"] &&
      AtlasPca.decide_read_purpose({ 'fields' => utf.map { |f| f.merge('optional' => true) }, 'purpose' => 'p', 'coverage' => {} }) ==
        { 'outcome' => 'allow', 'minimise' => ['a', 'zé', "�", "\u{1F600}"], 'uncovered' => [] } &&
      AtlasPca.decide_read_purpose({ 'fields' => [{ 'path' => 'x', 'class' => 's' }] * 2, 'purpose' => 'p', 'coverage' => {} })['uncovered'] == ['x'] &&
      AtlasPca.decide_read_purpose({ 'fields' => [{ 'path' => 'x', 'class' => 's', 'optional' => false }], 'purpose' => 'p', 'coverage' => {} })['uncovered'] == ['x'] &&
      AtlasPca.decide_read_purpose({ 'fields' => [], 'purpose' => 'p', 'coverage' => {} }) == { 'outcome' => 'allow', 'minimise' => [], 'uncovered' => [] } &&
      one.('pii.x', ['pii.*']) == 'allow' && one.('piix', ['pii.*']) == 'question' && one.('pii', ['pii.*']) == 'question' &&
      one.('anything', ['*']) == 'allow' && one.('a.b', ['a.b']) == 'allow' && one.('a.b', ['a']) == 'question' && one.('public', []) == 'allow'
  end

  t('read purpose: malformed input (JSON null anywhere, wrong types, unknown on_uncovered) is deny with empty lists') do
    ok = { 'fields' => [{ 'path' => 'x', 'class' => 's' }], 'purpose' => 'p', 'coverage' => { 'p' => ['s'] } }
    m = { 'outcome' => 'deny', 'minimise' => [], 'uncovered' => [] }
    rp = ->(over) { AtlasPca.decide_read_purpose(ok.merge(over)) }
    rp.({})['outcome'] == 'allow' &&
      [{ 'fields' => nil }, { 'fields' => {} }, { 'fields' => 'x' }, { 'purpose' => nil }, { 'purpose' => 5 }, { 'coverage' => nil },
       { 'coverage' => [] }, { 'coverage' => { 'p' => 's' } }, { 'coverage' => { 'p' => [1] } }, { 'coverage' => { 'q' => nil } },
       { 'on_uncovered' => nil }, { 'on_uncovered' => 'maybe' }, { 'on_uncovered' => true },
       { 'fields' => [nil] }, { 'fields' => ['x'] }, { 'fields' => [{ 'path' => 5, 'class' => 's' }] }, { 'fields' => [{ 'path' => 'x', 'class' => nil }] },
       { 'fields' => [{ 'path' => 'x', 'class' => 's', 'optional' => nil }] }, { 'fields' => [{ 'path' => 'x', 'class' => 's', 'optional' => 1 }] },
       { 'fields' => [{ 'class' => 's' }] }].all? { |o| rp.(o) == m } &&
      AtlasPca.decide_read_purpose(nil) == m && AtlasPca.decide_read_purpose('x') == m
  end

  # =================================================================== the conformance primitives (rules 16-18, activity)

  t('conformance primitives intent_world / intent_provenance / intent_classifier / intent_wb_active all match') do
    prims = Corpus.core['primitives'] || {}
    # A `requires_suite` vector this runtime cannot run must fail closed with unsupported_suite; `reason_contains` is checked.
    skip = ->(v) { v['requires_suite'] && !AtlasPca.supported_suites.include?(v['requires_suite']) }
    why = ->(v, r) { !v['expect'].key?('reason_contains') || r['reason'].to_s.include?(v['expect']['reason_contains']) }
    world = (prims['intent_world'] || []).all? do |v|
      r = AtlasPca.decide_intent_world(v['input'])
      e = v['expect']
      next r['ok'] == false && r['reason'].include?('unsupported_suite') if skip.(v)

      why.(v, r) && r['ok'] == e['ok'] && (!e['ok'] || (r['world'] == e['world'] && r['single_source'] == e['single_source']))
    end
    prov = (prims['intent_provenance'] || []).all? do |v|
      r = AtlasPca.decide_param_provenance(v['input'])
      e = v['expect']
      next r['outcome'] == 'deny' && r['reason'].include?('unsupported_suite') if skip.(v)

      why.(v, r) && r['outcome'] == e['outcome'] &&
        (e['outcome'] == 'deny' || (r['labels'] == e['labels'] && r['classes'] == e['classes'] && r['friction'] == e['friction']))
    end
    cls = (prims['intent_classifier'] || []).all? do |v|
      r = AtlasPca.decide_classifier_dimensions(v['input'])
      e = v['expect']
      next r['ok'] == false && r['reason'].include?('unsupported_suite') if skip.(v)

      why.(v, r) && r['ok'] == e['ok'] && (!e['ok'] || r['classes'] == e['classes'])
    end
    act = (prims['intent_wb_active'] || []).all? { |v| AtlasPca.intent_wb_active(v['input']) == v['expect'] }
    read = (prims['intent_read_purpose'] || []).all? { |v| AtlasPca.decide_read_purpose(v['input']) == v['expect'] }
    world && prov && cls && act && read && (prims['intent_world'] || []).length >= 66
  end
end
