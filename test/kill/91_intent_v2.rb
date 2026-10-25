# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'digest'
require 'json'

# Intent Layer v2 W-A kill tests: the `intent_session` wire slot, the v2 goal amendment of rule 12, the `intent_session`
# policy caveat, rule 14 (`schema`), rule 13 (`intent_session` incl. revocation), rule 15 (`accumulators`), the strict
# verifier context, suite capability (`unsupported_suite`), check reporting and pipeline order in verify_pcactn and the
# Rack `intent_v2:` option. Every boundary is pinned on both sides and every refusal by its exact first-failure reason;
# inputs failing two steps pin the order. Everything is signed in-test with OpenSSL Ed25519 from the conformance seeds
# (sha256("atlas-pca-conformance/<label>")). Every AtlasPca constant / helper is resolved at CALL time (the oracle replaces
# the module per mutant): nothing derived from AtlasPca is memoized.
module MutationKill
  module V2
    module_function

    NOW = 1_800_000_000_000
    AUD = 'skyair.example'
    MAX_SAFE = 9_007_199_254_740_991
    SCHEMA_D = "atlas-pca/action-schema/v1\u0000"
    ROOT_D = "atlas-pca/intent-session/v1\u0000"
    REV_D = "atlas-pca/revepoch/v1\u0000"
    RECEIPT_D = "atlas-pca/acc-receipt/v1\u0000"
    KEYS_D = "atlas-pca/sequencer-keys/v1\u0000"
    BASE = %w[wire version audience validity chain grant_ref_bound plan_inclusion leaf_signature counter].freeze

    def seed(l) = Digest::SHA256.digest("atlas-pca-conformance/#{l}")
    def b64(bin) = Base64.urlsafe_encode64(bin, padding: false)
    def key(l) = OpenSSL::PKey.new_raw_private_key('ED25519', seed(l))
    def pk(k) = b64(k.raw_public_key)
    def sign(k, msg) = b64(k.sign(nil, msg))
    def canon(v) = AtlasPca.canon_bytes(v)
    def principal = key('kv2/principal')
    def agent = key('kv2/agent')
    def site = key('kv2/site')
    def stranger = key('kv2/stranger')
    def sequencer = key('kv2/sequencer')
    def seq_root = key('kv2/sequencer-root')
    def session = b64(seed('kv2/session'))
    def ref = b64(seed('kv2/ref'))
    def map0 = b64(seed('kv2/map0'))
    def map1 = b64(seed('kv2/map1'))

    def unsigned_schema
      {
        'v' => 1, 'kind' => 'pca-action-schema', 'site' => 'https://skyair.example', 'aud' => AUD, 'version' => '2026-10-01',
        'units' => { 'usd_cents' => { 'kind' => 'money', 'currency' => 'USD', 'exponent' => 2 } },
        'verbs' => [
          { 'verb' => 'air.book', 'kind' => 'write', 'params' => {
            'action.params.offer_id' => { 'type' => 'string', 'semantic' => 'product.ref', 'sensitivity' => 'material' },
            'action.params.total' => { 'type' => 'integer', 'unit' => 'usd_cents', 'min' => 0, 'max' => 5_000_000, 'semantic' => 'money.amount',
                                       'sensitivity' => 'critical', 'accumulates_into' => ['spend.usd_cents'] },
            'action.params.add_ons' => { 'type' => 'set', 'values' => %w[none tripshield seat_plus], 'semantic' => 'product.addon',
                                         'sensitivity' => 'material' },
            'action.params.refundable' => { 'type' => 'boolean', 'semantic' => 'flag', 'sensitivity' => 'material' },
            'action.params.passengers' => { 'type' => 'array', 'max_items' => 9, 'max_len' => 64, 'semantic' => 'person.identity',
                                            'sensitivity' => 'critical', 'required' => false },
            'action.params.note' => { 'type' => 'string', 'semantic' => 'text.note', 'sensitivity' => 'free', 'required' => false, 'max_len' => 16 },
            'action.params.ext' => { 'type' => 'array', 'items' => 'integer', 'min' => 1, 'max' => 9, 'min_items' => 1,
                                     'semantic' => 'quantity', 'sensitivity' => 'material', 'required' => false }
          } },
          { 'verb' => 'air.search', 'kind' => 'read', 'params' => {
            'action.params.from' => { 'type' => 'string', 'values' => %w[SFO JFK], 'semantic' => 'place.airport', 'sensitivity' => 'material' },
            'action.params.date' => { 'type' => 'date', 'semantic' => 'schedule.date', 'sensitivity' => 'material' },
            'action.params.pax' => { 'type' => 'integer', 'min' => 1, 'max' => 9, 'semantic' => 'quantity', 'sensitivity' => 'material' }
          } }
        ]
      }
    end

    def sign_schema(doc, kid = 'site-1', k = site, alg = 'ed25519')
      doc.merge('sig' => { 'alg' => alg, 'kid' => kid, 'value' => sign(k, SCHEMA_D.b + canon(doc)) })
    end

    def schema(over = {}) = sign_schema(unsigned_schema.merge(over))
    def skey(kid = 'site-1', k = site) = { 'kid' => kid, 'alg' => 'ed25519', 'pk' => pk(k) }
    def sd(doc = schema) = AtlasPca.action_schema_digest(doc)

    def trip(over = {})
      { 'id' => 'trip_spend', 'agg' => 'sum', 'unit' => 'usd_cents', 'sel' => { 'accumulates_into' => 'spend.usd_cents' },
        'win' => { 'kind' => 'task' }, 'key' => nil, 'domain_max' => 500_000, 'holder' => { 'kind' => 'site_local' } }.merge(over)
    end

    def root_body(over = {})
      { 'v' => 1, 'kind' => 'pca-intent-session', 'session' => session, 'principals' => [{ 'key' => pk(principal) }], 'intent_ref' => ref,
        'schema' => { 'aud' => AUD, 'digest' => sd }, 'layers' => { 'task' => { 'map_digest' => map0 } }, 'accumulators' => [trip],
        'monitors' => [], 'question_uri' => 'https://atlas.example/q', 'expires_at' => NOW + 86_400_000 }.merge(over)
    end

    # A session root S signed by `k` (an ed25519 principal: no alg / pq_pk bound).
    def sroot(over = {}, k = principal)
      b = root_body(over).merge('signer' => pk(k))
      b.merge('sig' => sign(k, ROOT_D.b + canon(b)))
    end

    def rd(s = sroot) = AtlasPca.session_root_digest(s)

    # A ROOT capability carrying `caveats`, signed by `k`.
    def cap(caveats, k = principal)
      r = { 'issuer' => pk(k), 'holder' => pk(agent), 'caveats' => caveats }
      d = AtlasPca.hash_canonical(AtlasPca.body_of(r))
      r.merge('id' => d, 'body_digest' => d, 'sig' => b64(k.sign(nil, AtlasPca::CAP_DOMAIN + AtlasPca.b64d(d, 32))))
    end

    def scav(seq: 0, root: rd, prev: nil, sess: session)
      { 'type' => 'intent_session', 'session' => sess, 'seq' => seq, 'root' => root }.merge(prev.nil? ? {} : { 'prev' => prev })
    end

    # G_0 / D_k: the envelope goal is the v2 session goal (literal canonical JSON, built WITHOUT the library) + the caveat.
    def grant(seq: 0, map: map0, salt: 'salt0', prev: nil, root: rd, k: principal)
      goal = "{\"d\":\"atlas-pca/goal/v1\\u0000\",\"goal\":\"pca-intent:v2:#{session}:#{map}\",\"salt\":\"#{salt}\"}"
      cap([{ 'type' => 'envelope', 'goal_commit' => b64(Digest::SHA256.digest(goal.b)) }, scav(seq: seq, root: root, prev: prev)], k)
    end

    def params(over = {}) = { 'offer_id' => 'OF-1', 'total' => 38_900, 'add_ons' => ['none'], 'refundable' => false }.merge(over)

    def is0(over = {})
      { 'session' => session, 'root' => rd, 'seq' => 0, 'schema' => sd, 'acc' => [{ 'id' => 'trip_spend', 'post' => 38_900 }] }.merge(over)
    end

    # A signed PCActn under `g` (an intent binding with `map` / `salt`, the `intent_session` slot `is` when not nil).
    def pcactn(g, is: is0, map: map0, salt: 'salt0', prm: params, ref_: ref)
      action = { 'verb' => 'air.book', 'resource' => 'skyair.example/bookings', 'params_digest' => AtlasPca.params_digest(prm),
                 'reversibility_class' => 'irreversible' }
      leaf = AtlasPca.plan_leaf('book', action, AtlasPca.conditions_digest(nil, nil))
      zero = b64("\0".b * 32)
      p = {
        'ver' => 2, 'action' => action, 'grant_ref' => g['id'], 'cap_chain' => [g],
        'plan' => { 'root' => AtlasPca.merkle_root([leaf]), 'node_id' => 'book', 'inclusion_proof' => { 'index' => 0, 'size' => 1, 'path' => [] } },
        'attestation' => { 'epoch' => 1, 'quote_digest' => zero, 'model_id' => 'm', 'measurement' => zero, 'operator' => 'op' },
        'provenance' => { 'causal_hash' => zero, 'taint_level' => 0, 'trusted_refs' => [] },
        'freshness' => { 'epoch' => 1, 'beacon_ref' => zero, 'accumulator_witness' => zero },
        'counter' => 1, 'risk_claim' => { 'r' => 0, 'inputs' => {} }, 'aud' => AUD, 'iat' => NOW - 1000, 'exp' => NOW + 60_000,
        'intent' => { 'ref' => ref_, 'map_digest' => map, 'goal_salt' => salt, 'fidelity_ppm' => 1_000_000, 'residual_risk_ppm' => 0 }
      }
      p['intent_session'] = is unless is.nil?
      p.merge('sig' => sign(agent, AtlasPca.threshold_message(p)))
    end

    def ctx(over = {})
      { 'params' => params, 'schema' => { 'docs' => [schema], 'keys' => [skey] }, 'session' => { 'root' => sroot, 'grants' => [] },
        'acc' => { 'state' => { 'trip_spend' => { 'sum' => 0 } }, 'monitors' => {} } }.merge(over)
    end

    def decide(p, g, c = ctx, now = NOW) = AtlasPca.decide_intent_v2(p, g, c, now)
    def chk(d, name) = d['checks'].find { |c| c['name'] == name }
    def names(d) = d['checks'].map { |c| c['name'] }
    def ok?(d, name) = chk(d, name)&.fetch('ok') == true
    def why(d, name) = chk(d, name)&.fetch('reason', nil)
    def verify(p, g, c = ctx) = AtlasPca.verify_pcactn(p, g, now: NOW, audience: AUD, intent_v2: c)

    # The standard accepted case: G_0, the PCActn, the verifier context.
    def g0 = grant
    def p0 = pcactn(g0)

    # ---- revocation: the sorted-set root of a full revoked list, built WITHOUT the library
    def rev_auth = key('kv2/revocation-authority')
    def lh(id) = Digest::SHA256.digest("\x00".b + canon(id))
    def nh(l, r) = Digest::SHA256.digest("\x01".b + l + r)

    def split(n)
      k = 1
      k *= 2 while k * 2 < n
      k
    end

    def mroot(hs) = hs.length == 1 ? hs[0] : nh(mroot(hs[0, split(hs.length)]), mroot(hs[split(hs.length)..]))
    def bind(size, tree) = b64(Digest::SHA256.digest("pca-revset/v1\x00".b + canon({ 'size' => size, 'tree' => tree })))
    def set_root(list) = list.empty? ? bind(0, b64(Digest::SHA256.digest(''))) : bind(list.length, b64(mroot(list.map { |x| lh(x) })))

    # A signed epoch over the sorted `revoked` list (epoch == set_size), by `k` (default: the dedicated authority).
    def epoch(revoked, issued: NOW - 10_000, k: rev_auth, scope: "pca-intent-session:#{session}", not_after: nil, over: {})
      list = revoked.sort_by(&:b)
      body = { 'instance_id' => 'ana', 'grant_ref' => scope, 'epoch' => list.length, 'set_size' => list.length,
               'root' => set_root(list), 'issued_at' => issued, 'not_after' => not_after || (issued + 300_000) }.merge(over)
      body.merge('guardian' => pk(k), 'sig' => sign(k, REV_D.b + canon(body)))
    end

    # Evidence {epoch, revoked}: the full signed list (or `list` in its place).
    def evidence(revoked, list: nil, **kw) = { 'epoch' => epoch(revoked, **kw), 'revoked' => list || revoked.sort_by(&:b) }

    # A session whose root names the dedicated revocation authority (max 60 s); [S, G_0, PCActn, ids of the action].
    def rev_session(rev = { 'epoch_uri' => 'https://atlas.example/rev', 'max_age_s' => 60, 'key' => pk(rev_auth) })
      s = sroot('revocation' => rev)
      g = grant(root: rd(s))
      [s, g, pcactn(g, is: is0('root' => rd(s))),
       ["pca-intent:session:#{session}", "pca-intent:map:#{map0}", "pca-intent:delta:#{g['id']}"]]
    end

    def rev_decide(s, g, p, ev, pol = nil, last: nil)
      se = { 'root' => s, 'grants' => [], 'revocation' => ev }
      se['revocation_last'] = last unless last.nil?
      c = ctx('session' => se)
      c['policy'] = pol if pol
      decide(p, g, c)
    end

    # ---- sequenced accumulators: key set + receipt
    def keyset(entries, k = seq_root, issued = NOW - 100, version = 1)
      b = { 'v' => 1, 'kind' => 'pca-sequencer-keys', 'sequencer' => pk(k), 'version' => version, 'issued_at' => issued, 'keys' => entries }
      b.merge('sig' => sign(k, KEYS_D.b + canon(b)))
    end

    def entry(over = {}) = { 'kid' => 's2', 'pk' => pk(sequencer), 'not_before' => NOW - 1_000_000 }.merge(over)

    def receipt(digest, over = {}, k = sequencer)
      b = { 'v' => 1, 'kind' => 'pca-acc-receipt', 'session' => session, 'acc' => 'trip_spend', 'seq' => 3, 'pre' => 10_000,
            'delta' => 38_900, 'post' => 48_900, 'pcactn_digest' => digest, 'aud' => AUD, 'issued_at' => NOW, 'expires_at' => NOW + 60_000,
            'kid' => 's2', 'ledger' => { 'index' => 0, 'head' => b64(seed('kv2/head')) }, 'signer' => pk(k) }.merge(over)
      b.merge('sig' => sign(k, RECEIPT_D.b + canon(b)))
    end

    # A sequenced session: [S, G_0, draft PCActn (no intent_session), reservation digest].
    def seq_session
      s = sroot('accumulators' => [trip('holder' => { 'kind' => 'sequenced', 'uri' => 'https://atlas.example/seq', 'root' => pk(seq_root) })])
      g = grant(root: rd(s))
      draft = pcactn(g, is: nil)
      [s, g, draft, AtlasPca.pcactn_reservation_digest(draft)]
    end

    # Decide the sequenced case with receipt `rc` (claimed post `post`), key sets `ks`, optional last_seq / versions / policy.
    def seq_decide(rc, post: 48_900, ks: nil, last: nil, receipts: nil, versions: nil, pol: nil)
      s, g, = seq_session
      p = pcactn(g, is: is0('root' => rd(s), 'acc' => [{ 'id' => 'trip_spend', 'post' => post, 'receipt' => AtlasPca.acc_receipt_digest(rc) }]))
      acc = { 'receipts' => receipts || [rc], 'monitors' => {}, 'sequencer_keys' => ks || [keyset([entry])] }
      acc['last_seq'] = last unless last.nil?
      acc['keyset_versions'] = versions unless versions.nil?
      c = ctx('session' => { 'root' => s, 'grants' => [] }, 'acc' => acc)
      c['policy'] = pol unless pol.nil?
      decide(p, g, c)
    end

    # ---- rule 19: a committed map built WITHOUT the library (salted, kind-tagged leaves; RFC 9162 tree)
    MAP_TAG = { 'header' => "atlas-pca/intent-map/header/v1\u0000", 'cell' => "atlas-pca/intent-map/cell/v1\u0000",
                'metrics' => "atlas-pca/intent-map/metrics/v1\u0000", 'learner' => "atlas-pca/intent-map/learner/v1\u0000" }.freeze
    def mnode(l, r) = Digest::SHA256.digest("atlas-pca/intent-map/node/v1\u0000".b + l + r)
    def mtree(hs) = hs.length == 1 ? hs[0] : mnode(mtree(hs[0, split(hs.length)]), mtree(hs[split(hs.length)..]))

    def maudit(hs, i)
      return [] if hs.length == 1

      k = split(hs.length)
      i < k ? maudit(hs[0, k], i) + [mtree(hs[k..])] : maudit(hs[k..], i - k) + [mtree(hs[0, k])]
    end

    def mcommit(n, root) = b64(Digest::SHA256.digest("atlas-pca/intent-map/commit/v1\u0000".b + [n].pack('Q>') + root))
    def msalt(secret, i) = Digest::SHA256.digest("atlas-pca/intent-map/salt/v1\u0000".b + secret + [i].pack('Q>'))
    def metrics(over = {})
      { 'residual_risk_ppm' => 2000, 'burden_ppm' => 0, 'uncertainty_ppm' => 0, 'disagreement_ppm' => 0, 'mean_harm_ppm' => 0,
        'fidelity_est_ppm' => 1_000_000, 'entropy_mbits' => 0, 'questions' => 0, 'conflicts' => 0 }.merge(over)
    end

    def dims
      [{ 'kind' => 'num', 'path' => 'action.params.total', 'lo' => 0, 'hi' => 5_000_000, 'cuts' => [40_000] },
       { 'kind' => 'cat', 'path' => 'action.resource',
         'values' => [{ 'kind' => 'exact', 'value' => 'skyair.example/bookings' }, { 'kind' => 'prefix', 'value' => 'skyair.example/' },
                      { 'kind' => 'other', 'value' => "⊥" }] }]
    end

    # One verb (air.book, 3 x 3 = 9 cells: [0, 39999], {40000}, [40001, 5000000] x exact / prefix / other); cell (0, 0) has
    # in_grant `grant0`, flat cell 5 ({40000} x other) is outside the grant, every other cell inside. Returns {leaves, hashes, commit, size} for `secret`.
    def cmap(secret = seed('kv2/map-secret'), grant0: true, met: metrics)
      header = { 'verb' => 'air.book', 'first' => 1, 'cells' => 9, 'dims' => dims }
      cells = (0...9).map { |f| { 'verb' => 'air.book', 'cell' => [f / 3, f % 3], 'p_ppm' => 100_000 * (f + 1), 'in_grant' => f.zero? ? grant0 : f != 5 } }
      leaves = [['header', header]] + cells.map { |c| ['cell', c] } + [['metrics', met], ['learner', { 'learner_digest' => b64(seed('kv2/learner')) }]]
      hs = leaves.each_with_index.map { |(k, l), i| Digest::SHA256.digest(MAP_TAG[k].b + msalt(secret, i) + canon(l)) }
      { 'leaves' => leaves, 'hashes' => hs, 'secret' => secret, 'size' => leaves.length, 'commit' => mcommit(leaves.length, mtree(hs)) }
    end

    def mentry(m, i) = { 'index' => i, 'salt' => b64(msalt(m['secret'], i)), 'leaf' => m['leaves'][i][1], 'path' => maudit(m['hashes'], i).map { |h| b64(h) } }
    # The Z0 disclosure of flat cell `flat` (the action total 38900 at skyair.example/bookings is flat 0).
    def disclose(m, flat = 0) = { 'size' => m['size'], 'header' => mentry(m, 0), 'cell' => mentry(m, 1 + flat), 'metrics' => mentry(m, m['size'] - 2) }

    def zdecide(m, disc, action: nil, params: params(), eps: :absent)
      act = action || { 'verb' => 'air.book', 'resource' => 'skyair.example/bookings', 'params_digest' => AtlasPca.params_digest(params) }
      kw = { map_commit: m['commit'], action: act, disclosure: disc, params: params }
      kw[:max_residual_risk_ppm] = eps unless eps == :absent
      AtlasPca.decide_map_disclosure(**kw)
    end

    # A committed-map session: [S, G (v2c goal), PCActn with map_form "commit"].
    def map_session(m = cmap, form: 'commit', mint_form: 'commit')
      s = sroot('layers' => { 'task' => { 'map_digest' => m['commit'] } })
      prefix = mint_form == 'commit' ? 'pca-intent:v2c:' : 'pca-intent:v2:'
      goal = "{\"d\":\"atlas-pca/goal/v1\\u0000\",\"goal\":\"#{prefix}#{session}:#{m['commit']}\",\"salt\":\"saltc\"}"
      g = cap([{ 'type' => 'envelope', 'goal_commit' => b64(Digest::SHA256.digest(goal.b)) }, scav(root: rd(s))])
      is = is0('root' => rd(s))
      is['map_form'] = form unless form.nil?
      [s, g, pcactn(g, is: is, map: m['commit'], salt: 'saltc')]
    end

    def map_ctx(s, m, over = {}) = ctx('session' => { 'root' => s, 'grants' => [] }, 'map' => { 'disclosure' => disclose(m) }).merge(over)
  end

  # ================================================================== wire slot, goal, caveat

  t('v2: intent_session is an optional SIGNED top-level field; the closed member set') do
    AtlasPca::TOP_OPTIONAL.include?('intent_session') && !AtlasPca::TOP_REQUIRED.include?('intent_session') &&
      AtlasPca::INTENT_SESSION_FIELDS == %w[session root seq schema acc facts offer_set prov classes labels map_form] &&
      AtlasPca::INTENT_GOAL_V2_PREFIX == 'pca-intent:v2:'
  end

  t('v2 wire: well-formed edges (seq 0 / 2^31-1; 16 acc; 16 facts / 8 classes / 16 labels; 32 prov paths of 8 refs of 256 bytes)') do
    v = V2
    w = ->(over) { AtlasPca.validate_intent_session_wire(v.is0.merge(over)) }
    ds = ->(n) { (0...n).map { |i| v.b64(v.seed("kv2/d#{i}")) } }
    AtlasPca.validate_intent_session_wire(v.is0).nil? && w.call('seq' => 0).nil? && w.call('seq' => 2_147_483_647).nil? &&
      w.call('acc' => (0...16).map { |i| { 'id' => "a#{i}", 'post' => 0, 'receipt' => ds.call(1)[0] } }).nil? &&
      w.call('acc' => [{ 'id' => 'a' * 64, 'post' => MutationKill::V2::MAX_SAFE }]).nil? && w.call('acc' => []).nil? &&
      w.call('facts' => ds.call(16), 'classes' => ds.call(8), 'labels' => ds.call(16), 'offer_set' => ds.call(1)[0]).nil? &&
      w.call('prov' => (0...32).to_h { |i| ["action.params.p#{i}", ['r'] * 7 + ['é' * 128]] }).nil? &&
      w.call('seq' => 5.0).nil?
  end

  t('v2 wire: every refusal with its exact reason, first failure wins') do
    v = V2
    w = ->(over) { AtlasPca.validate_intent_session_wire(v.is0.merge(over)) }
    d = v.b64(v.seed('kv2/d'))
    without = ->(k) { v.is0.reject { |kk, _| kk == k } }
    seq = "'intent_session.seq' must be a safe integer in [0, 2147483647]"
    [nil, [v.is0], 'x', 1].all? { |x| AtlasPca.validate_intent_session_wire(x) == "'intent_session' must be an object" } &&
      w.call('note' => 1) == "unknown field 'intent_session.note'" &&
      %w[session root seq schema].all? { |k| AtlasPca.validate_intent_session_wire(without.call(k)) == "missing field 'intent_session.#{k}'" } &&
      AtlasPca.validate_intent_session_wire(without.call('root').merge('x' => 1)) == "unknown field 'intent_session.x'" &&
      %w[session root schema].all? { |k| w.call(k => v.b64('x' * 31)) == "'intent_session.#{k}' is not canonical base64url (32 bytes)" } &&
      w.call('session' => 1, 'seq' => -1) == "'intent_session.session' is not canonical base64url (32 bytes)" &&
      [-1, 2_147_483_648, 1.5, -0.0, '0', nil, true].all? { |x| w.call('seq' => x) == seq } &&
      w.call('acc' => (0...17).map { |i| { 'id' => "a#{i}", 'post' => 0 } }) == "'intent_session.acc' must be an array of at most 16 entries" &&
      w.call('acc' => nil) == "'intent_session.acc' must be an array of at most 16 entries" &&
      w.call('acc' => [1]) == "'intent_session.acc[0]' must be an object" &&
      w.call('acc' => [{ 'id' => 'a', 'post' => 0, 'x' => 1 }]) == "unknown field 'intent_session.acc[0].x'" &&
      ['a-b', '', 'a' * 65, "a\n", 5].all? { |x| w.call('acc' => [{ 'id' => x, 'post' => 0 }]) == "'intent_session.acc[0].id' must match [A-Za-z0-9_]{1,64}" } &&
      w.call('acc' => [{ 'id' => 'a', 'post' => 1 }, { 'id' => 'a', 'post' => 2 }]) == "'intent_session.acc' ids must be distinct" &&
      [-1, 1.5, -0.0, nil, '1', MutationKill::V2::MAX_SAFE + 1].all? { |x| w.call('acc' => [{ 'id' => 'a', 'post' => x }]) == "'intent_session.acc[0].post' must be a non-negative safe integer" } &&
      w.call('acc' => [{ 'id' => 'a', 'post' => 0, 'receipt' => 'x' }]) == "'intent_session.acc[0].receipt' is not canonical base64url (32 bytes)" &&
      w.call('facts' => [d] * 17) == "'intent_session.facts' must be an array of at most 16 digests" &&
      w.call('facts' => [d, d]) == "'intent_session.facts' entries must be distinct" &&
      w.call('facts' => ['x']) == "'intent_session.facts' entries must be canonical base64url (32 bytes)" &&
      w.call('classes' => (0..8).map { |i| v.b64(v.seed("c#{i}")) }) == "'intent_session.classes' must be an array of at most 8 digests" &&
      w.call('labels' => (0..16).map { |i| v.b64(v.seed("l#{i}")) }) == "'intent_session.labels' must be an array of at most 16 digests" &&
      w.call('offer_set' => nil) == "'intent_session.offer_set' is not canonical base64url (32 bytes)" &&
      w.call('prov' => (0..32).to_h { |i| ["action.params.p#{i}", ['r']] }) == "'intent_session.prov' must be an object of at most 32 entries" &&
      w.call('prov' => { 'env.x' => ['r'] }) == "'intent_session.prov' key 'env.x' is not action.params.<name>" &&
      [[], ['r'] * 9, [''], ['a' * 257], [1], 'r'].all? { |x| w.call('prov' => { 'action.params.total' => x }) == "'intent_session.prov.action.params.total' must be 1..8 non-empty strings of at most 256 UTF-8 bytes" }
  end

  t('v2 wire: a malformed intent_session is a terminal wire failure of verify_pcactn') do
    v = V2
    g = v.g0
    [[v.is0], v.is0('note' => 'x'), v.is0('seq' => -1), v.is0('acc' => [{ 'id' => 'a-b', 'post' => 1 }]), nil].all? do |bad|
      r = v.verify(v.pcactn(g, is: bad.nil? ? v.is0 : bad).tap { |p| p['intent_session'] = nil if bad.nil? }, g)
      r.allow == false && r.checks == { 'wire' => false }
    end
  end

  t('v2 goal (rule 13 amends rule 12 step 2): "pca-intent:v2:" + session + ":" + map_digest when intent_session is present') do
    v = V2
    lit = ->(goal, salt) { v.b64(Digest::SHA256.digest("{\"d\":\"atlas-pca/goal/v1\\u0000\",\"goal\":\"#{goal}\",\"salt\":\"#{salt}\"}".b)) }
    g = v.g0
    intent = v.p0['intent']
    AtlasPca.intent_goal_commit(v.ref, v.map0, 's', v.session) == lit.call("pca-intent:v2:#{v.session}:#{v.map0}", 's') &&
      AtlasPca.intent_goal_commit(v.ref, v.map0, 's') == lit.call("pca-intent:v1:#{v.ref}:#{v.map0}", 's') &&
      AtlasPca.intent_goal_v2(v.session, v.map0) == "pca-intent:v2:#{v.session}:#{v.map0}" &&
      AtlasPca.decide_intent_binding(intent, g, nil, v.session) == [:pass, nil] &&
      AtlasPca.decide_intent_binding(intent, g, nil)[0] == :fail &&
      AtlasPca.decide_intent_binding(intent, g, nil, v.b64(v.seed('kv2/other')))[0] == :fail &&
      v.verify(v.p0, g).checks['intent'] == true &&
      # the same grant without the member: the v1 goal does not open the v2 commitment, and no v2 check is reported
      v.verify(v.pcactn(g, is: nil), g, nil).checks.then { |c| c['intent'] == false && c.keys == BASE_KEYS_V2 }
  end
  BASE_KEYS_V2 = (%w[wire version audience validity chain grant_ref_bound plan_inclusion leaf_signature counter] + ['intent']).freeze

  t('v2 caveat: a well-formed intent_session caveat is satisfied (needs ctx.now), a malformed one is not') do
    v = V2
    ctx = { 'now' => 1 }
    good = [v.scav, v.scav(seq: 1, prev: v.rd), v.scav(seq: 2_147_483_647, prev: v.rd)]
    bad = [v.scav(seq: 1), v.scav(prev: v.rd), v.scav.merge('x' => 1), v.scav(seq: -1), v.scav(seq: 2_147_483_648, prev: v.rd),
           v.scav(seq: 1.5, prev: v.rd), v.scav.merge('session' => 'x'), v.scav(seq: 1, prev: 'x'), v.scav.merge('seq' => nil)]
    good.all? { |c| AtlasPca.evaluate_caveats([c], ctx) == [true, []] } &&
      bad.all? { |c| AtlasPca.evaluate_caveats([c], ctx) == [false, ['intent_session']] } &&
      AtlasPca.evaluate_caveats([v.scav], {}) == [false, ['intent_session']] &&
      AtlasPca.evaluate_caveats([v.scav(seq: 1.0, prev: v.rd)], ctx) == [true, []]
  end

  t('v2 caveat: intent_session_caveat_error exact reasons in order') do
    v = V2
    e = ->(c) { AtlasPca.intent_session_caveat_error(c) }
    pre = 'intent_session caveat: '
    [nil, {}, { 'type' => 'envelope' }, [v.scav]].all? { |c| e.call(c) == 'not an intent_session caveat' } &&
      e.call(v.scav.merge('x' => 1, 'seq' => -1)) == "#{pre}unknown member 'x'" &&
      e.call(v.scav.merge('root' => 'x', 'seq' => -1)) == "#{pre}session and root must be canonical base64url (32 bytes)" &&
      e.call(v.scav(seq: -1)) == "#{pre}seq must be a safe integer in [0, 2147483647]" &&
      e.call(v.scav(seq: 2_147_483_648, prev: v.rd)) == "#{pre}seq must be a safe integer in [0, 2147483647]" &&
      e.call(v.scav(seq: 0, prev: v.rd)) == "#{pre}prev is present exactly when seq > 0" &&
      e.call(v.scav(seq: 3)) == "#{pre}prev is present exactly when seq > 0" &&
      e.call(v.scav(seq: 3, prev: 'x')) == "#{pre}prev must be canonical base64url (32 bytes)" &&
      e.call(v.scav(seq: 1).merge('prev' => nil)) == "#{pre}prev must be canonical base64url (32 bytes)" &&
      e.call(v.scav).nil? && e.call(v.scav(seq: 7, prev: v.rd)).nil?
  end

  # ================================================================== the accepted case, reporting, pipeline order

  t('v2: G_0 accepted; checks appended after intent in pipeline order; env.acc / env.canon computed by the verifier') do
    v = V2
    r = v.verify(v.p0, v.g0)
    d = v.decide(v.p0, v.g0)
    r.allow == true && r.reason == '' &&
      r.checks.keys == BASE_KEYS_V2 + %w[schema intent_session accumulators] && r.checks.values.all? &&
      v.names(d) == %w[schema intent_session accumulators] &&
      d['env']['acc'] == { 'trip_spend' => { 'post' => 38_900 } } && d['env']['mon'] == {} &&
      d['env']['canon'] == { 'add_ons' => '["none"]', 'refundable' => 'false' } && d['schema'] == v.schema
  end

  t('v2 reporting: back-compat (no member, no policy: nothing reported) and the two policies alone') do
    v = V2
    p = v.pcactn(v.g0, is: nil)
    base = v.decide(p, v.g0)
    cw = v.decide(p, v.g0, v.ctx('policy' => { 'schema' => { 'closed_world' => true } }))
    rq = v.decide(p, v.g0, v.ctx('policy' => { 'session' => { 'require' => true } }))
    both = v.decide(p, v.g0, v.ctx('policy' => { 'schema' => { 'closed_world' => true }, 'session' => { 'require' => true } }))
    off = v.decide(p, v.g0, v.ctx('policy' => { 'schema' => { 'closed_world' => false }, 'session' => { 'require' => false } }))
    base['checks'] == [] && v.names(cw) == ['schema'] && v.ok?(cw, 'schema') &&
      v.names(rq) == ['intent_session'] && v.why(rq, 'intent_session') == 'this verifier requires an intent_session but the PCActn carries none' &&
      v.names(both) == %w[schema intent_session] && off['checks'] == [] &&
      AtlasPca.decide_intent_v2(p, v.g0, nil, MutationKill::V2::NOW)['checks'] == [] &&
      AtlasPca.intent_v2_active?(p, nil) == false && AtlasPca.intent_v2_active?(v.p0, nil) == true &&
      AtlasPca.intent_v2_active?(p, { 'policy' => { 'session' => { 'require' => true } } }) == true
  end

  t('v2 pipeline: checks 1-4 are independent, layers reported only when configured, the first failing check is the reason') do
    v = V2
    c = v.ctx('params' => v.params('total' => 1), 'layers' => { 'site' => { 'predicates' => [] } })
    d = v.decide(v.p0, v.g0, c)
    r = v.verify(v.p0, v.g0, c)
    v.names(d) == %w[schema intent_session layers accumulators] && !v.ok?(d, 'schema') && v.ok?(d, 'intent_session') &&
      !v.ok?(d, 'layers') && !v.ok?(d, 'accumulators') &&
      v.why(d, 'schema') == 'params do not hash to action.params_digest' &&
      v.why(d, 'layers') == 'layers: the action is outside the site ceiling (a ceiling is never a question)' &&
      r.allow == false && r.reason == 'schema: params do not hash to action.params_digest' &&
      r.checks.keys == BASE_KEYS_V2 + %w[schema intent_session layers accumulators]
  end

  t('v2 layers: env.canon reaches the ceilings; a passing ceiling is reported ok; layers null is a malformed context') do
    v = V2
    ceil = { 'predicates' => [{ 'verb' => 'air.book', 'where' => [{ 'field' => 'env.canon.add_ons', 'op' => 'eq', 'value' => '["none"]' }] }] }
    d = v.decide(v.p0, v.g0, v.ctx('layers' => { 'site' => ceil }))
    m = v.decide(v.p0, v.g0, v.ctx('layers' => { 'site' => nil }))
    v.ok?(d, 'layers') && v.names(d) == %w[schema intent_session layers accumulators] &&
      v.names(m) == %w[schema intent_session accumulators] && m['checks'].none? { |x| x['ok'] } &&
      v.why(m, 'schema') == 'malformed v2 context: layers.site must be {predicates: [...]}'
  end

  t('v2 context: absent = default, null / wrong type = malformed (schema, intent_session, accumulators fail with the reason)') do
    v = V2
    mal = lambda do |c, reason, present: true|
      d = v.decide(present ? v.p0 : v.pcactn(v.g0, is: nil), v.g0, c)
      d['checks'].map { |x| [x['name'], x['ok'], x['reason']] } ==
        (%w[schema intent_session] + (present ? ['accumulators'] : [])).map { |n| [n, false, "malformed v2 context: #{reason}"] }
    end
    mal.call('x', 'the v2 verifier context must be an object') && mal.call([], 'the v2 verifier context must be an object') &&
      mal.call(v.ctx('policy' => nil), 'policy must be an object') &&
      mal.call(v.ctx('policy' => { 'session' => nil }), 'policy.session must be an object') &&
      mal.call(v.ctx('policy' => { 'schema' => [] }), 'policy.schema must be an object') &&
      mal.call(v.ctx('params' => nil), 'params must be an object') &&
      %w[schema session acc].all? { |k| mal.call(v.ctx(k => nil), "#{k} must be an object") } &&
      mal.call(v.ctx('layers' => []), 'layers must be an object') &&
      mal.call(v.ctx('layers' => { 'task' => { 'predicates' => [] } }), "layers: unknown member 'task'") &&
      mal.call(v.ctx('wb' => nil), 'wb must be an object') &&
      mal.call(v.ctx('wb' => { 'artifacts' => { 'facts' => 'x' } }), 'wb.artifacts.facts must be an array') &&
      mal.call(v.ctx('wb' => { 'artifacts' => { 'offer_set' => [] } }), 'wb.artifacts.offer_set must be an object') &&
      mal.call(v.ctx('wb' => { 'policy' => { 'classifiers' => {} } }), 'wb.policy.classifiers must be an array') &&
      mal.call(v.ctx('wb' => { 'policy' => { 'world' => nil } }), 'wb.policy.world / provenance must be objects') &&
      mal.call(v.ctx('params' => nil), 'params must be an object', present: false) &&
      AtlasPca.intent_v2_context_error(v.ctx).nil? && AtlasPca.intent_v2_context_error(nil).nil? &&
      AtlasPca.intent_v2_context_error({ policy: nil }) == 'policy must be an object'
  end

  t('v2 policy: closed and typed (unknown members, non-boolean flags, bad ages make the context malformed, even when inactive)') do
    v = V2
    mal = lambda do |pol, reason, p = v.p0|
      d = v.decide(p, v.g0, v.ctx('policy' => pol))
      n = %w[schema intent_session] + (p.key?('intent_session') ? ['accumulators'] : [])
      d['checks'].map { |x| [x['name'], x['ok'], x['reason']] } == n.map { |x| [x, false, "malformed v2 context: #{reason}"] }
    end
    v1 = v.pcactn(v.g0, is: nil)
    age = 'policy.session.max_revocation_age_s must be a non-negative safe integer'
    mal.call({ 'x' => 1 }, "policy: unknown member 'x'") &&
      mal.call({ 'session' => { 'x' => 1 } }, "policy.session: unknown member 'x'") &&
      mal.call({ 'schema' => { 'x' => 1 } }, "policy.schema: unknown member 'x'") &&
      [nil, 'true', 1, 0, [], {}].all? { |f| mal.call({ 'session' => { 'require' => f } }, 'policy.session.require must be a boolean', v1) } &&
      [nil, 'false', 0, 1].all? { |f| mal.call({ 'schema' => { 'closed_world' => f } }, 'policy.schema.closed_world must be a boolean', v1) } &&
      [-1, '60', nil, 1.5, -0.0, MutationKill::V2::MAX_SAFE + 1].all? { |a| mal.call({ 'session' => { 'max_revocation_age_s' => a } }, age) } &&
      mal.call({ 'session' => { 'max_revocation_age_s' => -1 } }, age, v1) &&
      v.decide(v1, v.g0, v.ctx('policy' => { 'session' => { 'require' => false }, 'schema' => { 'closed_world' => false } }))['checks'] == [] &&
      v.decide(v1, v.g0, v.ctx('policy' => {}))['checks'] == [] &&
      v.decide(v1, v.g0, v.ctx('policy' => { 'session' => { 'max_revocation_age_s' => MutationKill::V2::MAX_SAFE } }))['checks'] == []
  end

  t('v2 clock: a verifier clock that is not a safe integer fails every v2 check') do
    v = V2
    clk = 'the verifier clock is not a safe integer (fail closed)'
    ['1', nil, 1.5, MutationKill::V2::MAX_SAFE + 1, -0.0].all? do |now|
      d = v.decide(v.p0, v.g0, v.ctx, now)
      v.names(d) == %w[schema intent_session accumulators] && d['checks'].all? { |x| x['reason'] == clk }
    end && v.ok?(v.decide(v.p0, v.g0, v.ctx, MutationKill::V2::NOW.to_f), 'accumulators')
  end

  # ================================================================== rule 14: schema

  t('rule 14: schema step refusals in order') do
    v = V2
    s = ->(c, p = v.p0) { v.why(v.decide(p, v.g0, c), 'schema') }
    other = v.schema('aud' => 'other.example')
    po = v.pcactn(v.g0, is: v.is0('schema' => v.sd(other)))
    s.call(v.ctx('schema' => { 'docs' => [], 'keys' => [] })) == 'this verifier has no action schema configured' &&
      s.call(v.ctx('schema' => { 'docs' => 'x', 'keys' => [] })) == 'the schema context must be {docs: [...], keys: [...]}' &&
      s.call(v.ctx('schema' => { 'docs' => [v.schema('version' => 'v2')], 'keys' => [v.skey] })) == 'intent_session.schema names no schema this verifier accepts' &&
      s.call(v.ctx('schema' => { 'docs' => [v.schema], 'keys' => [v.skey('site-1', v.stranger)] })) == 'schema does not verify: schema signature invalid' &&
      s.call(v.ctx('schema' => { 'docs' => [other], 'keys' => [v.skey] }), po) == 'schema aud does not match the PCActn aud' &&
      s.call(v.ctx.reject { |k, _| k == 'params' }) == 'no plaintext params to check against the schema (closed world needs them)' &&
      s.call(v.ctx('params' => v.params('total' => 2))) == 'params do not hash to action.params_digest' &&
      s.call(v.ctx('params' => v.params('x' => 1)), v.pcactn(v.g0, prm: v.params('x' => 1))) ==
        "schema_violation: undeclared_param: parameter 'action.params.x' is not declared for 'air.book'" &&
      # closed world without the member: against the FIRST accepted schema
      v.ok?(v.decide(v.pcactn(v.g0, is: nil), v.g0, v.ctx('policy' => { 'schema' => { 'closed_world' => true } },
                                                          'schema' => { 'docs' => [v.schema, other], 'keys' => [v.skey] })), 'schema') &&
      !v.ok?(v.decide(v.pcactn(v.g0, is: nil), v.g0, v.ctx('policy' => { 'schema' => { 'closed_world' => true } },
                                                           'schema' => { 'docs' => [other, v.schema], 'keys' => [v.skey] })), 'schema')
  end

  t('rule 14: verify_action_schema (kid, pinned suite, unsupported_suite, keys array, pq_pk type, tamper, shape)', needs: 'ml-dsa-65') do
    v = V2
    vs = ->(doc, keys = [v.skey]) { AtlasPca.verify_action_schema(doc, keys) }
    sc = v.schema
    unk = sc.merge('sig' => sc['sig'].merge('alg' => 'x-unknown-suite'))
    vs.call(sc) == { 'ok' => true } &&
      vs.call(sc, [v.skey('other')])['reason'] == "no schema key with kid 'site-1'" &&
      vs.call(sc, [nil, 5, v.skey]) == { 'ok' => true } &&
      vs.call(sc, { '0' => v.skey })['reason'] == 'the schema keys must be an array' &&
      vs.call(sc, [v.skey.merge('pq_pk' => nil)])['reason'] == 'the schema key pq_pk must be a string' &&
      vs.call(sc, [v.skey.merge('pk' => 'x')])['reason'] == 'schema key pk is not canonical base64url (32 bytes)' &&
      vs.call(sc, [v.skey.merge('alg' => 'x-unknown-suite')])['reason'] == "schema key: unsupported_suite: 'x-unknown-suite'" &&
      vs.call(sc, [v.skey.merge('alg' => 5)])['reason'] == 'schema key: alg must be a string' &&
      vs.call(sc.merge('sig' => sc['sig'].merge('alg' => 'ml-dsa-65')))['reason'] == 'sig.alg does not match the pinned key suite' &&
      vs.call(unk)['reason'] == "sig.alg: unsupported_suite: 'x-unknown-suite'" &&
      vs.call(sc.merge('version' => 'x'))['reason'] == 'schema signature invalid' &&
      vs.call(sc.merge('extra' => 1))['reason'] == "unknown member 'extra'" &&
      vs.call(sc.merge('sig' => sc['sig'].merge('value' => 'x=')))['reason'] == 'sig.value is not canonical base64url' &&
      vs.call(sc.merge('sig' => sc['sig'].merge('kid' => '')))['reason'] == 'sig.kid must be a non-empty string' &&
      vs.call(sc.merge('sig' => sc['sig'].merge('pq_value' => nil)))['reason'] == 'sig.pq_value is not canonical base64url' &&
      AtlasPca.action_schema_digest(sc) == v.b64(Digest::SHA256.digest(AtlasPca.canon_bytes({ 'd' => 'atlas-pca/action-schema-ref/v1', 's' => sc })))
  end

  t('rule 14: schema shape boundaries (reserved names, null default, counts at max and max+1)') do
    v = V2
    us = v.unsigned_schema
    e = ->(doc) { AtlasPca.action_schema_shape_error(doc, signed: false) }
    with_param = ->(path, decl) { us.merge('verbs' => [us['verbs'][0].merge('params' => us['verbs'][0]['params'].merge(path => decl))]) }
    dcl = { 'type' => 'string', 'semantic' => 's', 'sensitivity' => 'free' }
    many = ->(n) { us.merge('verbs' => [us['verbs'][0].merge('params' => (0...n).to_h { |i| ["action.params.p#{i}", dcl] })]) }
    verbs = ->(n) { us.merge('verbs' => (0...n).map { |i| { 'verb' => "v#{i}", 'kind' => 'read', 'params' => {} } }) }
    e.call(us).nil? && e.call(many.call(64)).nil? &&
      e.call(many.call(65)) == "verb 'air.book': more than 64 parameters" &&
      e.call(verbs.call(256)).nil? && e.call(verbs.call(257)) == 'verbs must be 1..256 entries' && e.call(verbs.call(0)) == 'verbs must be 1..256 entries' &&
      %w[__proto__ constructor prototype].all? { |n| e.call(with_param.call("action.params.#{n}", dcl)) == "verb 'air.book': parameter name 'action.params.#{n}' is reserved (__proto__ / constructor / prototype)" } &&
      e.call(with_param.call('action.params.y', dcl.merge('default' => nil))) == "verb 'air.book': action.params.y: default must not be null (absent = no default)" &&
      e.call(with_param.call('action.params.y', dcl.merge('values' => (0...256).map(&:to_s)))).nil? &&
      e.call(with_param.call('action.params.y', dcl.merge('values' => (0...257).map(&:to_s)))) == "verb 'air.book': action.params.y: values must be 1..256 strings" &&
      e.call(with_param.call('action.params.y', dcl.merge('values' => %w[a a]))) == "verb 'air.book': action.params.y: values must be distinct" &&
      e.call(with_param.call('action.params.y', dcl.merge('type' => 'set'))) == "verb 'air.book': action.params.y: a set needs values" &&
      e.call(with_param.call('action.params.y', dcl.merge('type' => 'integer', 'min' => 2, 'max' => 1))) == "verb 'air.book': action.params.y: min > max" &&
      e.call(with_param.call('action.params.y', dcl.merge('max_len' => 0))) == "verb 'air.book': action.params.y: max_len must be a positive safe integer" &&
      e.call(with_param.call('action.params.a-b', dcl)) == "verb 'air.book': parameter path 'action.params.a-b' is not action.params.<name>" &&
      e.call(us.merge('units' => { 'usd_cents' => { 'kind' => 'money', 'exponent' => 19 } })) == "unit 'usd_cents': exponent must be an integer in [0, 18]" &&
      e.call(us.merge('units' => { 'usd_cents' => { 'kind' => 'money', 'exponent' => 18 } })).nil? &&
      e.call(us.merge('sig' => {})) == 'an unsigned schema must not carry sig' &&
      e.call(us.merge('v' => 1.0)).nil? && e.call(us.merge('v' => 2)) == 'unsupported schema version'
  end

  t('rule 14: conform_action codes, paths and the first-failure order') do
    v = V2
    sc = v.schema
    c = ->(prm, verb = 'air.book') { AtlasPca.conform_action(sc, verb, prm).then { |r| r['ok'] ? :ok : [r['code'], r['path']] } }
    srch = ->(o) { c.call({ 'from' => 'SFO', 'date' => '2026-11-20', 'pax' => 2 }.merge(o), 'air.search') }
    pt = 'action.params.total'
    c.call(v.params) == :ok && c.call([]) == ['params_not_object', nil] && c.call(v.params, 'air.cancel') == ['unknown_verb', nil] &&
      c.call(v.params('zz' => 1, 'aa' => 1)) == ['undeclared_param', 'action.params.aa'] &&
      c.call({ 'offer_id' => 'x', 'extra' => 1 }) == ['undeclared_param', 'action.params.extra'] &&
      c.call({}) == ['missing_param', 'action.params.add_ons'] &&
      c.call(JSON.parse('{"__proto__":1,"offer_id":"OF-1","total":38900,"add_ons":["none"],"refundable":false}')) == ['undeclared_param', 'action.params.__proto__'] &&
      ['38900', 1.5, -0.0, nil, true].all? { |x| c.call(v.params('total' => x)) == ['bad_type', pt] } &&
      c.call(v.params('total' => -1)) == ['out_of_domain', pt] && c.call(v.params('total' => 0)) == :ok &&
      c.call(v.params('total' => 5_000_000)) == :ok && c.call(v.params('total' => 5_000_000.0)) == :ok &&
      c.call(v.params('total' => 5_000_001)) == ['out_of_domain', pt] &&
      c.call(v.params('refundable' => 'false')) == ['bad_type', 'action.params.refundable'] &&
      c.call(v.params('add_ons' => %w[none none])) == ['out_of_domain', 'action.params.add_ons'] &&
      c.call(v.params('add_ons' => [])) == :ok && c.call(v.params('add_ons' => [1])) == ['bad_type', 'action.params.add_ons'] &&
      c.call(v.params('add_ons' => ['bag'])) == ['out_of_domain', 'action.params.add_ons'] &&
      c.call(v.params('add_ons' => %w[none tripshield seat_plus])) == :ok &&
      c.call(v.params('passengers' => (0...9).map { |i| "p#{i}" })) == :ok &&
      c.call(v.params('passengers' => (0...10).map { |i| "p#{i}" })) == ['out_of_domain', 'action.params.passengers'] &&
      c.call(v.params('passengers' => ['x' * 64])) == :ok && c.call(v.params('passengers' => ['x' * 65])) == ['bad_type', 'action.params.passengers'] &&
      c.call(v.params('passengers' => 'p')) == ['bad_type', 'action.params.passengers'] &&
      c.call(v.params('note' => 'é' * 8)) == :ok && c.call(v.params('note' => "#{'é' * 8}a")) == ['out_of_domain', 'action.params.note'] &&
      c.call(v.params('ext' => [1, 9])) == :ok && c.call(v.params('ext' => [0])) == ['out_of_domain', 'action.params.ext'] &&
      c.call(v.params('ext' => [10])) == ['out_of_domain', 'action.params.ext'] && c.call(v.params('ext' => [])) == ['out_of_domain', 'action.params.ext'] &&
      c.call(v.params('ext' => ['1'])) == ['bad_type', 'action.params.ext'] &&
      srch.call({}) == :ok && srch.call('from' => 'LAX') == ['out_of_domain', 'action.params.from'] &&
      srch.call('date' => '2028-02-29') == :ok && srch.call('date' => '2000-02-29') == :ok &&
      srch.call('date' => '2026-02-29') == ['out_of_domain', 'action.params.date'] && srch.call('date' => '1900-02-29') == ['out_of_domain', 'action.params.date'] &&
      srch.call('date' => '2026-1-05') == ['out_of_domain', 'action.params.date'] && srch.call('date' => "2026-11-20\n") == ['out_of_domain', 'action.params.date'] &&
      srch.call('date' => '0000-01-01') == ['out_of_domain', 'action.params.date'] && srch.call('date' => '2026-12-31') == :ok &&
      srch.call('date' => '2026-13-01') == ['out_of_domain', 'action.params.date'] && srch.call('date' => 20_261_120) == ['bad_type', 'action.params.date'] &&
      srch.call('pax' => 9) == :ok && srch.call('pax' => 10) == ['out_of_domain', 'action.params.pax'] && srch.call('pax' => 0) == ['out_of_domain', 'action.params.pax']
  end

  # ================================================================== rule 13: intent_session

  t('rule 13: the session step refusals in order') do
    v = V2
    s = ->(p, g, c = v.ctx) { v.why(v.decide(p, g, c), 'intent_session') }
    exp = v.sroot('expires_at' => MutationKill::V2::NOW)
    ge = v.grant(root: v.rd(exp))
    live = v.sroot('expires_at' => MutationKill::V2::NOW + 1)
    gl = v.grant(root: v.rd(live))
    # the default session root names no revocation authority, so a policy that requires an epoch refuses at that step (TS
    # intent-v2.ts: `S.revocation === undefined` before the evidence is read); the absent-evidence reason is covered in step 7
    v.why(v.decide(v.p0, v.g0, v.ctx('policy' => { 'session' => { 'max_revocation_age_s' => 0 } })), 'intent_session') ==
      'revocation: the policy requires a revocation epoch but the session root names no revocation authority' &&
      s.call(v.p0, v.g0, v.ctx('session' => { 'root' => v.sroot, 'grants' => 'G0' })) == 'the session grants must be an array' &&
      s.call(v.p0, v.g0, v.ctx('session' => { 'root' => v.sroot, 'grants' => [], 'revocation' => [] })) == 'the session revocation evidence must be an object' &&
      s.call(v.p0.reject { |k, _| k == 'intent' }, v.g0) == 'an intent_session needs the envelope.intent binding' &&
      s.call(v.p0, v.g0, v.ctx('session' => { 'grants' => [] })) == 'no session root for this session' &&
      s.call(v.p0, v.g0, v.ctx('session' => { 'root' => nil })) == 'session root: session root is not an object' &&
      s.call(v.p0, v.g0, v.ctx('session' => { 'root' => v.sroot.merge('question_uri' => 'x') })) == 'session root: session root signature invalid' &&
      s.call(v.p0, v.g0, v.ctx('session' => { 'root' => v.sroot({}, v.stranger) })) == 'session root: signer is not one of the session principals' &&
      s.call(v.p0, v.g0, v.ctx('session' => { 'root' => live })) == 'intent_session.root is not the digest of the session root' &&
      s.call(v.pcactn(ge, is: v.is0('root' => v.rd(exp))), ge, v.ctx('session' => { 'root' => exp })) == 'the session root has expired' &&
      v.ok?(v.decide(v.pcactn(gl, is: v.is0('root' => v.rd(live))), gl, v.ctx('session' => { 'root' => live })), 'intent_session') &&
      s.call(v.pcactn(v.g0, ref_: v.b64(v.seed('kv2/x'))), v.g0) == 'intent.ref is not the session statement' &&
      s.call(v.pcactn(v.g0, map: v.map1), v.g0) == 'a seq-0 action must use the session task map' &&
      s.call(v.p0, v.cap([v.scav])).nil? && s.call(v.p0, v.cap([v.scav], v.stranger)) == 'the admitting root is not signed by a session principal' &&
      s.call(v.p0, v.cap([{ 'type' => 'envelope' }])) == 'admitting root: not an intent_session caveat' &&
      s.call(v.pcactn(v.g0, is: v.is0('seq' => 1)), v.g0) == 'the admitting root is bound to another session, root or seq' &&
      s.call(v.p0, v.grant(k: v.stranger)) == 'the admitting root is not signed by a session principal'
  end

  t('rule 13: the session schema digest and audience are S-bound') do
    v = V2
    other = v.schema('version' => 'v9')
    s2 = v.sroot('schema' => { 'aud' => 'other.example', 'digest' => v.sd })
    g2 = v.grant(root: v.rd(s2))
    v.why(v.decide(v.pcactn(v.g0, is: v.is0('schema' => v.sd(other))), v.g0, v.ctx('schema' => { 'docs' => [other], 'keys' => [v.skey] })),
          'intent_session') == 'intent_session.schema is not the session schema' &&
      v.why(v.decide(v.pcactn(g2, is: v.is0('root' => v.rd(s2))), g2, v.ctx('session' => { 'root' => s2 })), 'intent_session') ==
        'the session schema is for another audience'
  end

  t('rule 13: the delta chain G_0 -> D_1 (held grants, prev, principal, suite)') do
    v = V2
    g0 = v.g0
    d1 = v.grant(seq: 1, prev: g0['id'], map: v.map1, salt: 'salt1')
    p1 = v.pcactn(d1, is: v.is0('seq' => 1, 'acc' => [{ 'id' => 'trip_spend', 'post' => 77_800 }]), map: v.map1, salt: 'salt1')
    c = ->(grants) { v.ctx('session' => { 'root' => v.sroot, 'grants' => grants }, 'acc' => { 'state' => { 'trip_spend' => { 'sum' => 38_900 } }, 'monitors' => {} }) }
    s = ->(g, p, grants) { v.why(v.decide(p, g, c.call(grants)), 'intent_session') }
    loose = v.grant(seq: 1, prev: v.b64(v.seed('kv2/notg0')), map: v.map1, salt: 'salt1')
    pl = v.pcactn(loose, is: v.is0('seq' => 1, 'acc' => [{ 'id' => 'trip_spend', 'post' => 77_800 }]), map: v.map1, salt: 'salt1')
    v.decide(p1, d1, c.call([g0]))['checks'].all? { |x| x['ok'] } && v.verify(p1, d1, c.call([g0])).allow == true &&
      s.call(d1, p1, []) == 'the verifier does not hold the 1 earlier grants of this session' &&
      s.call(d1, p1, [g0.merge('id' => 5)]) == 'session grant 0 is not a capability' &&
      s.call(d1, p1, [nil]) == 'session grant 0 is not a capability' &&
      s.call(d1, p1, [g0.merge('alg' => 'x-unknown-suite')]) == "session grant 0: unsupported_suite: 'x-unknown-suite'" &&
      s.call(d1, p1, [v.grant(seq: 1, prev: g0['id'])]) == 'session grant 0 does not belong to this session at seq 0' &&
      s.call(d1, p1, [v.grant(k: v.stranger)]) == 'session grant 0 is not signed by a session principal' &&
      s.call(loose, pl, [g0]) == 'the admitting root does not chain to grant 0'
  end

  t('rule 13 step 7: revocation by the dedicated authority (fresh, absent, inclusive max age, revoked ids, principal signer, policy)') do
    v = V2
    s, g, p, ids = v.rev_session
    r = ->(ev, pol = nil, last: nil) { v.why(v.rev_decide(s, g, p, ev, pol, last: last), 'intent_session') }
    pre = 'revocation: '
    now = MutationKill::V2::NOW
    v.ok?(v.rev_decide(s, g, p, v.evidence(['pca-intent:session:zz'])), 'intent_session') &&
      v.ok?(v.rev_decide(s, g, p, v.evidence([], issued: now - 60_000)), 'intent_session') &&
      r.call(v.evidence([], issued: now - 60_001)) == "#{pre}the session revocation epoch is older than 60000 ms" &&
      r.call(nil) == 'the session revocation evidence must be an object' &&
      v.why(v.decide(p, g, v.ctx('session' => { 'root' => s, 'grants' => [] })), 'intent_session') == "#{pre}no session revocation epoch supplied" &&
      ids.all? { |id| r.call(v.evidence([id])) == "#{pre}'#{id}' is revoked" } &&
      r.call(v.evidence([], k: v.principal)) == "#{pre}the revocation epoch is not signed by the session revocation authority" &&
      r.call(v.evidence([], k: v.stranger)) == "#{pre}the revocation epoch is not signed by the session revocation authority" &&
      r.call(v.evidence([], issued: now - 20_000), { 'session' => { 'max_revocation_age_s' => 10 } }) == "#{pre}the session revocation epoch is older than 10000 ms" &&
      v.ok?(v.rev_decide(s, g, p, v.evidence([], issued: now - 10_000), { 'session' => { 'max_revocation_age_s' => 10 } }), 'intent_session') &&
      v.why(v.decide(v.p0, v.g0, v.ctx('policy' => { 'session' => { 'max_revocation_age_s' => 60 } })), 'intent_session') ==
        "#{pre}the policy requires a revocation epoch but the session root names no revocation authority" &&
      v.why(v.decide(p, g, v.ctx('session' => { 'root' => s, 'grants' => [], 'revocation' => v.evidence([]), 'revocation_last' => nil })), 'intent_session') ==
        'the tracked last revocation epoch must be an object' &&
      # append-only against the tracked last epoch
      v.ok?(v.rev_decide(s, g, p, v.evidence(%w[pca-intent:a pca-intent:b]), last: v.evidence(%w[pca-intent:a])), 'intent_session') &&
      v.ok?(v.rev_decide(s, g, p, v.evidence(%w[pca-intent:a]), last: v.evidence(%w[pca-intent:a])), 'intent_session') &&
      r.call(v.evidence(%w[pca-intent:c]), last: v.evidence(%w[pca-intent:a])) ==
        "#{pre}the epoch drops 'pca-intent:a', revoked in the last accepted epoch (not append-only)" &&
      r.call(v.evidence(%w[pca-intent:a]), last: v.evidence(%w[pca-intent:a pca-intent:b])) == "#{pre}revocation epoch rollback (older than the last accepted)" &&
      r.call(v.evidence(%w[pca-intent:b pca-intent:c]), last: v.evidence(%w[pca-intent:a pca-intent:b])) ==
        "#{pre}the epoch drops 'pca-intent:a', revoked in the last accepted epoch (not append-only)" &&
      r.call(v.evidence(%w[pca-intent:a]), last: v.evidence(%w[pca-intent:a], list: ['pca-intent:z'])) == "#{pre}the tracked last epoch is malformed (fail closed)" &&
      r.call(v.evidence([]).merge('note' => 'x')) == "#{pre}the revocation evidence has the unknown member 'note' (it is exactly {epoch, revoked})" &&
      r.call(v.evidence(%w[pca-intent:a]), last: v.evidence(%w[pca-intent:a]).merge('note' => 'x')) == "#{pre}the tracked last epoch is malformed (fail closed)"
  end

  t('rule 13 step 7: check_session_revocation strict typing, the epoch checks and the full signed list, first failure wins') do
    v = V2
    now = MutationKill::V2::NOW
    id = "pca-intent:session:#{v.session}"
    auth = v.pk(v.rev_auth)
    ev = v.evidence(%w[pca-intent:map:a pca-intent:session:zzzz])
    c = lambda do |e = ev, **kw|
      AtlasPca.check_session_revocation(e, **{ session: v.session, authority: auth, ids: [id], now: now, max_age_ms: 60_000 }.merge(kw))['reason']
    end
    ep = ev['epoch']
    sorted_err = 'revoked must be sorted by UTF-8 bytes and distinct'
    c.call.nil? && c.call(v.evidence([])).nil? &&
      [-1, 1.5, '60000', nil].all? { |m| c.call(max_age_ms: m) == 'revocation max age misconfigured (fail closed)' } &&
      ['1', nil, 1.5].all? { |n| c.call(now: n) == 'the verifier clock is not a safe integer (fail closed)' } &&
      c.call(ids: id) == 'ids must be an array and the authority a key' && c.call(authority: nil) == 'ids must be an array and the authority a key' &&
      c.call([ev]) == 'no session revocation epoch supplied' &&
      c.call(ev.merge('epoch' => nil)) == 'the revocation epoch must be an object' &&
      c.call(ev.merge('epoch' => ep.merge('epoch' => '2'))) == 'revocation epoch epoch must be a non-negative safe integer' &&
      c.call(ev.merge('epoch' => ep.merge('alg' => 'x-unknown-suite'))) == "revocation epoch alg: unsupported_suite: 'x-unknown-suite'" &&
      c.call(authority: v.pk(v.principal)) == 'the revocation epoch is not signed by the session revocation authority' &&
      c.call(v.evidence([], scope: 'pca-intent-session:other')) == 'revocation epoch is for a different grant' &&
      c.call(v.evidence([], scope: 'pca-intent-session:other'), scope: 'pca-intent-session:other').nil? &&
      c.call(v.evidence([], issued: now - 10_000, not_after: now - 1)) == 'revocation epoch expired (stale revocation root)' &&
      c.call(v.evidence([], issued: now - 10_000, not_after: now)).nil? &&
      c.call(v.evidence([], issued: now + 60_001)) == 'revocation epoch issued in the future' && c.call(v.evidence([], issued: now + 60_000)).nil? &&
      c.call(ev.merge('epoch' => ep.merge('issued_at' => ep['issued_at'] - 1))) == 'revocation epoch signature invalid' &&
      c.call(ev.reject { |k, _| k == 'revoked' }) == 'revoked must be an array of ids' &&
      c.call(ev.merge('proofs' => {})) == "the revocation evidence has the unknown member 'proofs' (it is exactly {epoch, revoked})" &&
      c.call(ev.merge('proofs' => {}, 'epoch' => nil)) == "the revocation evidence has the unknown member 'proofs' (it is exactly {epoch, revoked})" &&
      c.call(ev.reject { |k, _| k == 'epoch' }) == 'the revocation epoch must be an object' &&
      c.call(ev.reject { |k, _| k == 'revoked' }.merge('epoch' => ep.merge('issued_at' => ep['issued_at'] - 1))) == 'revocation epoch signature invalid' &&
      c.call(last: { 'epoch' => ev['epoch'] }) == 'the tracked last epoch is malformed (fail closed)' &&
      c.call(ev.merge('revoked' => nil)) == 'revoked must be an array of ids' &&
      c.call(last: v.evidence(%w[pca-intent:map:a]).merge('x' => 1)) == 'the tracked last epoch is malformed (fail closed)' &&
      c.call(last: v.evidence(%w[pca-intent:map:a])).nil? &&
      c.call(ev.merge('revoked' => { '0' => 'pca-intent:map:a' })) == 'revoked must be an array of ids' &&
      c.call(ev.merge('revoked' => ['pca-intent:map:a', 5])) == 'revoked must be an array of ids' &&
      c.call(ev.merge('revoked' => ev['revoked'].reverse)) == sorted_err &&
      c.call(ev.merge('revoked' => ['pca-intent:map:a', 'pca-intent:map:a'])) == sorted_err &&
      c.call(ev.merge('revoked' => ['pca-intent:map:a'])) == 'the epoch must be numbered by its set size and list exactly set_size ids' &&
      c.call(v.evidence(%w[pca-intent:a], over: { 'epoch' => 7 })) == 'the epoch must be numbered by its set size and list exactly set_size ids' &&
      c.call(ev.merge('revoked' => ['pca-intent:map:a', 'pca-intent:session:zzzy'])) == 'the revoked list is not the signed set (root mismatch)' &&
      c.call(ids: [5]) == "'5' is revoked" && c.call(v.evidence([id])) == "'#{id}' is revoked" &&
      c.call(last: nil) == 'the tracked last epoch is malformed (fail closed)' &&
      c.call(last: { 'epoch' => ep }) == 'the tracked last epoch is malformed (fail closed)' &&
      c.call(v.evidence(%w[pca-intent:b], issued: now - 1_000), last: v.evidence(%w[pca-intent:a], issued: now - 1_000)) ==
        "the epoch drops 'pca-intent:a', revoked in the last accepted epoch (not append-only)" &&
      AtlasPca.revset_root([]) == v.set_root([]) && AtlasPca.revset_root(%w[a b c]) == v.set_root(%w[a b c])
  end

  t('rule 13 step 7: the intent_revocation primitive form {epoch, revoked, session, authority, ids, now, max_age_ms, last?}') do
    v = V2
    id = "pca-intent:session:#{v.session}"
    e = v.evidence(%w[pca-intent:map:a])
    inp = { 'epoch' => e['epoch'], 'revoked' => e['revoked'], 'session' => v.session, 'authority' => v.pk(v.rev_auth), 'ids' => [id],
            'now' => MutationKill::V2::NOW, 'max_age_ms' => 60_000 }
    l = v.evidence(%w[pca-intent:map:a pca-intent:map:b])
    AtlasPca.intent_revocation_primitive(inp)['ok'] == true &&
      AtlasPca.intent_revocation_primitive(inp.merge('last' => { 'epoch' => e['epoch'], 'revoked' => e['revoked'] }))['ok'] == true &&
      AtlasPca.intent_revocation_primitive(inp.merge('last' => l))['ok'] == false &&
      AtlasPca.intent_revocation_primitive(inp.reject { |k, _| k == 'revoked' })['ok'] == false &&
      AtlasPca.intent_revocation_primitive(inp.merge('authority' => v.pk(v.principal)))['ok'] == false &&
      AtlasPca.intent_revocation_primitive(inp.merge('last' => nil))['ok'] == false &&
      AtlasPca.intent_revocation_primitive(inp.merge('last' => e.merge('extra' => 1)))['ok'] == false &&
      AtlasPca.intent_revocation_primitive(inp.merge('proofs' => {}))['reason'] == "the revocation evidence has the unknown member 'proofs' (it is exactly {epoch, revoked})" &&
      AtlasPca.intent_revocation_primitive(inp.merge('scope' => "pca-intent-session:#{v.session}"))['ok'] == true &&
      AtlasPca.intent_revocation_primitive('x')['ok'] == false
  end

  t('rule 13: session root shape (reserved / null members, revocation.pq_pk, unsupported principal suite)') do
    v = V2
    e = ->(over) { AtlasPca.session_root_shape_error(v.sroot(over)) }
    e.call({}).nil? &&
      e.call('layers' => { 'task' => { 'map_digest' => v.map0 }, 'org' => nil }) == 'layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)' &&
      e.call('layers' => { 'task' => { 'map_digest' => v.map0 }, 'std' => nil }) == 'layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)' &&
      e.call('layers' => { 'task' => { 'map_digest' => v.map0 }, 'std' => { 'profile' => 'p', 'version' => 0, 'digest' => v.map1 } }).start_with?('layers.std must be') &&
      e.call('layers' => { 'task' => { 'map_digest' => v.map0 }, 'std' => { 'profile' => 'p', 'version' => 1, 'digest' => v.map1 } }).nil? &&
      e.call('revocation' => { 'epoch_uri' => 'u', 'max_age_s' => 60 }) == 'revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)' &&
      e.call('revocation' => { 'epoch_uri' => 'u', 'max_age_s' => 60, 'key' => v.pk(v.principal) }) ==
        'revocation.key must not be a session principal (a dedicated revocation authority)' &&
      e.call('revocation' => { 'epoch_uri' => 'u', 'max_age_s' => 60, 'key' => v.map0, 'pq_pk' => 'x=' }) == 'revocation.pq_pk must be canonical base64url' &&
      e.call('revocation' => { 'epoch_uri' => 'u', 'max_age_s' => 60, 'key' => v.map0, 'pq_pk' => v.map1 }).nil? &&
      e.call('revocation' => { 'epoch_uri' => 'u', 'max_age_s' => 60, 'key' => v.map0, 'x' => 1 }) == 'revocation must be {epoch_uri, max_age_s, key, pq_pk?}' &&
      e.call('revocation' => { 'epoch_uri' => 'u', 'max_age_s' => '60', 'key' => v.map0 }) == 'revocation.max_age_s must be a non-negative safe integer' &&
      e.call('principals' => [{ 'key' => v.pk(v.principal), 'alg' => 'x-unknown-suite' }]) == "principal alg: unsupported_suite: 'x-unknown-suite'" &&
      e.call('principals' => [{ 'key' => v.pk(v.principal), 'alg' => nil }]) == 'principal alg: alg must be a string' &&
      e.call('principals' => (0..16).map { |i| { 'key' => v.pk(v.key("kv2/p#{i}")) } }) == 'principals must be 1..16 keys' &&
      e.call('accumulators' => [v.trip('id' => 'constructor')]) == 'accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype' &&
      e.call('monitors' => [{ 'id' => '__proto__', 'kind' => 'never', 'p' => { 'verb' => 'x' } }]) ==
        'monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype' &&
      e.call('accumulators' => (0..16).map { |i| v.trip('id' => "t#{i}") }) == 'accumulators must be an array of at most 16' &&
      e.call('accumulators' => [v.trip('holder' => { 'kind' => 'sequenced', 'uri' => 'u', 'root' => v.map0, 'root_alg' => 'x-unknown-suite' })]) ==
        "accumulator 'trip_spend': holder.root_alg: unsupported_suite: 'x-unknown-suite'" &&
      v.why(v.decide(v.p0, v.g0, v.ctx('session' => { 'root' => v.sroot.merge('alg' => 'x-unknown-suite') })), 'intent_session') ==
        "session root: alg: unsupported_suite: 'x-unknown-suite'"
  end

  # ================================================================== rule 15: accumulators

  t('rule 15: site-local claims, pre-state and the domain bound (inclusive)') do
    v = V2
    a = ->(state, is = v.is0, extra = {}) { v.why(v.decide(v.pcactn(v.g0, is: is), v.g0, v.ctx('acc' => { 'state' => state, 'monitors' => {} }.merge(extra))), 'accumulators') }
    claim = ->(post) { v.is0('acc' => [{ 'id' => 'trip_spend', 'post' => post }]) }
    a.call({ 'trip_spend' => { 'sum' => 461_100 } }, claim.call(500_000)).nil? &&
      a.call({ 'trip_spend' => { 'sum' => 461_101 } }, claim.call(500_001)) == "accumulator 'trip_spend' post 500001 is outside its domain (max 500000)" &&
      a.call({ 'trip_spend' => { 'sum' => 0 } }, claim.call(38_901)) == "claimed post 38901 for 'trip_spend' differs from the verifier's 38900" &&
      a.call({ 'trip_spend' => { 'sum' => 0 } }, v.is0('acc' => [])) == "no claim for accumulator 'trip_spend' that this action feeds" &&
      a.call({ 'trip_spend' => { 'sum' => 0 } }, v.is0('acc' => [{ 'id' => 'nope', 'post' => 1 }])) == "claim 'nope' names no accumulator of the session" &&
      a.call({}) == "no state for site-local accumulator 'trip_spend'" &&
      a.call(JSON.parse('{"__proto__":{"sum":0}}')) == "no state for site-local accumulator 'trip_spend'" &&
      [nil, '0', 0.5, -1, -0.0].all? { |x| a.call({ 'trip_spend' => { 'sum' => x } }) == "accumulator 'trip_spend': pre-state sum must be a non-negative safe integer" } &&
      a.call({ 'trip_spend' => { 'count' => 0 } }) == "accumulator 'trip_spend': pre-state of a sum accumulator is {sum}" &&
      a.call({ 'trip_spend' => { 'sum' => 0, 'x' => 1 } }) == "accumulator 'trip_spend': pre-state of a sum accumulator is {sum}" &&
      a.call({ 'trip_spend' => [] }) == "accumulator 'trip_spend': pre-state must be an object" &&
      a.call({ 'trip_spend' => { 'sum' => MutationKill::V2::MAX_SAFE } }) == "accumulator 'trip_spend' overflows 2^53-1" &&
      a.call({ 'trip_spend' => { 'sum' => 0 } }, v.is0('acc' => [{ 'id' => 'trip_spend', 'post' => 38_900, 'receipt' => v.map0 }])) ==
        "accumulator 'trip_spend' is site-local: a receipt is not accepted" &&
      a.call({ 'trip_spend' => { 'sum' => 0.0 } }).nil?
  end

  t('rule 15: the accumulator context is strictly typed') do
    v = V2
    a = ->(acc) { v.why(v.decide(v.p0, v.g0, v.ctx('acc' => acc)), 'accumulators') }
    st = { 'trip_spend' => { 'sum' => 0 } }
    a.call('state' => [], 'monitors' => {}) == 'acc.state must be an object' &&
      a.call('state' => st, 'monitors' => nil) == 'acc.monitors must be an object' &&
      a.call('state' => st, 'last_seq' => { 'trip_spend' => '3' }) == 'acc.last_seq values must be non-negative safe integers' &&
      a.call('state' => st, 'last_seq' => { 'trip_spend' => nil }) == 'acc.last_seq values must be non-negative safe integers' &&
      a.call('state' => st, 'receipts' => 'r') == 'acc.receipts must be an array' &&
      a.call('state' => st, 'sequencer_keys' => {}) == 'acc.sequencer_keys must be an array' &&
      a.call('state' => st, 'last_seq' => { 'trip_spend' => 3 }).nil? &&
      v.why(v.decide(v.p0, v.g0, v.ctx('schema' => { 'docs' => [v.schema], 'keys' => {} })), 'accumulators') == 'the schema context must be {docs: [...], keys: [...]}' &&
      v.why(v.decide(v.p0, v.g0, v.ctx('schema' => { 'docs' => [v.schema('version' => 'z')], 'keys' => [v.skey] })), 'accumulators') ==
        "accumulator 'trip_spend' selects by accumulates_into but the session schema is not available"
  end

  t('rule 15: verbs selector, keyed groups (identity key, not free text), monitors, wallet holders, unfed groups') do
    v = V2
    per = { 'id' => 'per_offer', 'agg' => 'count', 'sel' => { 'verbs' => ['air.book'] }, 'win' => { 'kind' => 'task' },
            'key' => 'action.params.offer_id', 'domain_max' => 1, 'holder' => { 'kind' => 'site_local' } }
    txt = per.merge('id' => 'per_note', 'key' => 'action.params.note')
    q = { 'id' => 'questions', 'agg' => 'count', 'sel' => { 'event' => 'intent_required' }, 'win' => { 'kind' => 'task' }, 'key' => nil, 'cap' => 6,
          'holder' => { 'kind' => 'wallet' } }
    other = { 'id' => 'searches', 'agg' => 'count', 'sel' => { 'verbs' => ['air.search'] }, 'win' => { 'kind' => 'task' }, 'key' => nil,
              'holder' => { 'kind' => 'site_local' } }
    mon = { 'id' => 'hotel_after_flight', 'kind' => 'requires_prior', 'p' => { 'verb' => 'air.book' }, 'q' => { 'verb' => 'hotel.book' } }
    run = lambda do |accs, claims, state, mons = [], monstate = {}, prm = v.params|
      s = v.sroot('accumulators' => accs, 'monitors' => mons)
      g = v.grant(root: v.rd(s))
      p = v.pcactn(g, is: v.is0('root' => v.rd(s), 'acc' => claims), prm: prm)
      v.decide(p, g, v.ctx('params' => prm, 'session' => { 'root' => s, 'grants' => [] }, 'acc' => { 'state' => state, 'monitors' => monstate }))
    end
    tc = { 'id' => 'trip_spend', 'post' => 38_900 }
    d = run.call([v.trip, per, q, other], [tc, { 'id' => 'per_offer', 'post' => 1 }], { 'trip_spend' => { 'sum' => 0 }, 'per_offer' => { 'count' => 0 }, 'searches' => { 'count' => 4 } })
    v.ok?(d, 'accumulators') && d['env']['acc'] == { 'trip_spend' => { 'post' => 38_900 }, 'per_offer' => { 'post' => 1 }, 'searches' => { 'post' => 4 } } &&
      v.why(run.call([v.trip, per], [tc, { 'id' => 'per_offer', 'post' => 2 }], { 'trip_spend' => { 'sum' => 0 }, 'per_offer' => { 'count' => 1 } }), 'accumulators') ==
        "accumulator 'per_offer' post 2 is outside its domain (max 1)" &&
      v.why(run.call([v.trip, txt], [tc, { 'id' => 'per_note', 'post' => 1 }], { 'trip_spend' => { 'sum' => 0 }, 'per_note' => { 'count' => 0 } }, [], {},
                     v.params('note' => 'n')), 'accumulators') == "accumulator 'per_note': the key must be a schema-declared identity (not free text)" &&
      v.why(run.call([v.trip, txt], [tc, { 'id' => 'per_note', 'post' => 1 }], { 'trip_spend' => { 'sum' => 0 } }), 'accumulators') ==
        "accumulator 'per_note': the key parameter action.params.note is missing" &&
      v.why(run.call([v.trip, q], [tc, { 'id' => 'questions', 'post' => 1 }], { 'trip_spend' => { 'sum' => 0 } }), 'accumulators') ==
        "accumulator 'questions' is wallet-held and cannot be claimed at a site" &&
      v.why(run.call([v.trip, other], [tc, { 'id' => 'searches', 'post' => 1 }], { 'trip_spend' => { 'sum' => 0 } }), 'accumulators') ==
        "claim 'searches' for an accumulator this action does not feed" &&
      v.why(run.call([v.trip, other], [tc], { 'trip_spend' => { 'sum' => 0 }, 'searches' => { 'sum' => 1 } }), 'accumulators') ==
        "accumulator 'searches': pre-state of a count accumulator is {count}" &&
      v.ok?(run.call([v.trip], [tc], { 'trip_spend' => { 'sum' => 0 } }, [mon], { 'hotel_after_flight' => 'unmet' }), 'accumulators') &&
      v.why(run.call([v.trip], [tc], { 'trip_spend' => { 'sum' => 0 } }, [mon], { 'hotel_after_flight' => 'maybe' }), 'accumulators') ==
        "no valid state for monitor 'hotel_after_flight'" &&
      v.why(run.call([v.trip], [tc], { 'trip_spend' => { 'sum' => 0 } }, [mon], {}), 'accumulators') == "no valid state for monitor 'hotel_after_flight'"
  end

  t('rule 15: values, combination, pre-state and monitor states (unit level)') do
    sum = { 'agg' => 'sum' }
    mx = { 'agg' => 'max' }
    ds = { 'agg' => 'distinct' }
    ct = { 'agg' => 'count' }
    AtlasPca.combine_acc(sum, { 'sum' => 10 }, { 'val' => 5 }) == 15 && AtlasPca.combine_acc(ct, { 'count' => 4 }, { 'val' => 1 }) == 5 &&
      AtlasPca.combine_acc(mx, { 'max' => 40_000 }, { 'val' => 38_900 }) == 40_000 && AtlasPca.combine_acc(mx, { 'max' => 1 }, { 'val' => 2 }) == 2 &&
      AtlasPca.combine_acc(ds, { 'values' => ['"OF-1"', '"OF-7"'] }, { 'val' => 1, 'key' => '"OF-1"' }) == 2 &&
      AtlasPca.combine_acc(ds, { 'values' => ['"OF-7"'] }, { 'val' => 1, 'key' => '"OF-1"' }) == 2 &&
      AtlasPca.combine_acc(sum, { 'sum' => MutationKill::V2::MAX_SAFE - 1 }, { 'val' => 1 }) == MutationKill::V2::MAX_SAFE &&
      AtlasPca.combine_acc(sum, { 'sum' => MutationKill::V2::MAX_SAFE }, { 'val' => 1 }).nil? &&
      AtlasPca.distinct_key('OF-1') == '"OF-1"' && AtlasPca.distinct_key(5) == '5' && AtlasPca.distinct_key(5.0) == '5' &&
      [1.5, -0.0, nil, true, [], {}].all? { |x| AtlasPca.distinct_key(x).nil? } &&
      AtlasPca.pre_state_error(ds, { 'values' => %w[a a] }) == 'pre-state values must be distinct' &&
      AtlasPca.pre_state_error(ds, { 'values' => [1] }) == 'pre-state values must be strings' &&
      AtlasPca.pre_state_error(ds, { 'values' => [] }).nil? && AtlasPca.pre_value(ds, { 'values' => %w[a b] }) == 2 &&
      AtlasPca.monitor_states({ 'kind' => 'responds_within', 'within' => 2 }) == %w[idle pending:1 pending:2 missed] &&
      AtlasPca.monitor_states({ 'kind' => 'precedes' }) == %w[unmet met] && AtlasPca.monitor_states({ 'kind' => 'never' }) == %w[clean seen] &&
      AtlasPca.monitor_states({ 'kind' => 'always' }) == %w[ok broken] &&
      AtlasPca.monitor_decl_error({ 'id' => 'm', 'kind' => 'responds_within', 'p' => { 'verb' => 'a' }, 'q' => { 'verb' => 'b' }, 'within' => 64 }).nil? &&
      AtlasPca.monitor_decl_error({ 'id' => 'm', 'kind' => 'responds_within', 'p' => { 'verb' => 'a' }, 'q' => { 'verb' => 'b' }, 'within' => 65 }) ==
        "monitor 'm': within must be an integer in 1..64" &&
      AtlasPca.accumulator_decl_error({ 'id' => 'a', 'agg' => 'max', 'sel' => { 'verbs' => ['x'] }, 'win' => { 'kind' => 'task' }, 'key' => nil,
                                        'holder' => { 'kind' => 'site_local' } }) == "accumulator 'a': max needs val (or sel.accumulates_into for a sum)" &&
      AtlasPca.accumulator_decl_error({ 'id' => 'a', 'agg' => 'count', 'sel' => { 'verbs' => ['x'] }, 'win' => { 'kind' => 'task' },
                                        'holder' => { 'kind' => 'site_local' } }) == "accumulator 'a': key must be null or action.params.<name>" &&
      AtlasPca.accumulator_decl_error({ 'id' => 'a', 'agg' => 'count', 'sel' => { 'verbs' => ['x'] }, 'win' => { 'kind' => 'sliding', 'ms' => 0 },
                                        'key' => nil, 'holder' => { 'kind' => 'site_local' } }) == "accumulator 'a': win sliding needs a positive ms"
  end

  t('rule 15: reservation receipts against the sequencer root-signed key set (every refusal and boundary)', needs: 'ml-dsa-65') do
    v = V2
    _, _, _, dg = v.seq_session
    rc = v.receipt(dg)
    r = ->(rcpt, **kw) { v.why(v.seq_decide(rcpt, **kw), 'accumulators') }
    sig = "the reservation receipt for 'trip_spend' is not signed by a key the session sequencer's root-signed key set lists for its issue time"
    pre = "the reservation receipt for 'trip_spend'"
    v.ok?(v.seq_decide(rc), 'accumulators') && v.seq_decide(rc)['env']['acc'] == { 'trip_spend' => { 'post' => 48_900 } } &&
      r.call(rc, ks: []) == sig && r.call(rc, ks: [v.keyset([v.entry], v.stranger)]) == sig &&
      r.call(rc, ks: [v.keyset([v.entry('pk' => v.pk(v.stranger))])]) == sig &&
      r.call(rc, ks: [v.keyset([v.entry('not_after' => MutationKill::V2::NOW - 1)])]) == sig &&
      r.call(rc, ks: [v.keyset([v.entry('not_after' => MutationKill::V2::NOW)])]).nil? &&
      r.call(rc, ks: [v.keyset([v.entry('not_before' => MutationKill::V2::NOW + 1)])]) == sig &&
      r.call(rc, ks: [v.keyset([v.entry('not_before' => MutationKill::V2::NOW)])]).nil? &&
      r.call(rc, ks: [v.keyset([v.entry('alg' => 'ml-dsa-65')])]) == sig &&
      r.call(rc, ks: [v.keyset([v.entry('alg' => 'x-unknown-suite')])]) == "#{pre}: key set key alg: unsupported_suite: 'x-unknown-suite'" &&
      r.call(rc, ks: [v.keyset([v.entry('kid' => 's1')]), v.keyset([v.entry])]).nil? &&
      r.call(v.receipt(dg, 'issued_at' => MutationKill::V2::NOW + 60_001, 'expires_at' => MutationKill::V2::NOW + 120_001)) == sig &&
      r.call(v.receipt(dg, 'issued_at' => MutationKill::V2::NOW + 60_000, 'expires_at' => MutationKill::V2::NOW + 120_000),
             ks: [v.keyset([v.entry], v.seq_root, MutationKill::V2::NOW)]).nil? &&
      r.call(v.receipt(dg, {}, v.stranger)) == sig &&
      r.call(rc, receipts: []) == "#{pre} was not presented" &&
      r.call(rc, last: { 'trip_spend' => 3 }) == "#{pre} replays seq 3 (last accepted 3)" &&
      r.call(rc, last: { 'trip_spend' => 2 }).nil? && r.call(rc, last: { 'other' => 9 }).nil? &&
      r.call(v.receipt(dg, 'post' => 48_901), post: 48_901) == "#{pre} does not add up" &&
      r.call(v.receipt(dg, 'delta' => 1, 'post' => 10_001), post: 10_001) == "#{pre} does not add up" &&
      r.call(v.receipt(dg, 'aud' => 'other.example')) == "#{pre} is for another session, accumulator or audience" &&
      r.call(v.receipt(dg, 'acc' => 'other')) == "#{pre} is for another session, accumulator or audience" &&
      r.call(v.receipt(dg, 'issued_at' => MutationKill::V2::NOW - 1_000, 'expires_at' => MutationKill::V2::NOW - 1)) == "#{pre} has expired" &&
      r.call(v.receipt(dg, 'expires_at' => MutationKill::V2::NOW)).nil? &&
      r.call(v.receipt(v.b64(v.seed('kv2/other-action')))) == "#{pre} is for another action" &&
      r.call(v.receipt(dg).merge('alg' => 'x-unknown-suite')) == "#{pre}: receipt.alg: unsupported_suite: 'x-unknown-suite'" &&
      r.call(v.receipt(dg, 'post' => 600_000, 'pre' => 561_100), post: 600_000) == "accumulator 'trip_spend' post 600000 is outside its domain (max 500000)"
  end

  t('rule 15: a sequenced claim needs a receipt; receipt arithmetic per aggregate') do
    v = V2
    s, g, = v.seq_session
    p = v.pcactn(g, is: v.is0('root' => v.rd(s), 'acc' => [{ 'id' => 'trip_spend', 'post' => 48_900 }]))
    no = v.why(v.decide(p, g, v.ctx('session' => { 'root' => s, 'grants' => [] })), 'accumulators')
    ar = ->(agg, r, val) { AtlasPca.receipt_arithmetic_ok({ 'agg' => agg }, r, val) }
    no == "accumulator 'trip_spend' is sequenced: the claim needs a reservation receipt" &&
      ar.call('sum', { 'pre' => 1, 'delta' => 2, 'post' => 3 }, 2) && !ar.call('sum', { 'pre' => 1, 'delta' => 2, 'post' => 3 }, 1) &&
      ar.call('count', { 'pre' => 4, 'delta' => 1, 'post' => 5 }, 1) && !ar.call('count', { 'pre' => 4, 'delta' => 2, 'post' => 6 }, 1) &&
      ar.call('max', { 'pre' => 9, 'delta' => 5, 'post' => 9 }, 5) && !ar.call('max', { 'pre' => 9, 'delta' => 5, 'post' => 5 }, 5) &&
      ar.call('distinct', { 'pre' => 2, 'delta' => 0, 'post' => 2 }, 1) && ar.call('distinct', { 'pre' => 2, 'delta' => 1, 'post' => 3 }, 1) &&
      !ar.call('distinct', { 'pre' => 2, 'delta' => 2, 'post' => 4 }, 1)
  end

  t('rule 15: receipt lifetime and freshness, key-set version / age, a retired key stops verifying') do
    v = V2
    now = MutationKill::V2::NOW
    _, _, _, dg = v.seq_session
    r = ->(rcpt, **kw) { v.why(v.seq_decide(rcpt, **kw), 'accumulators') }
    sig = "the reservation receipt for 'trip_spend' is not signed by a key the session sequencer's root-signed key set lists for its issue time"
    life = ->(i, e) { AtlasPca.acc_receipt_shape_error(v.receipt(dg, 'issued_at' => i, 'expires_at' => e)) }
    old = v.receipt(dg, 'issued_at' => now - 120_000, 'expires_at' => now + 600_000)
    life.call(now, now + 900_000).nil? && life.call(now, now).nil? &&
      life.call(now, now + 900_001) == 'receipt.expires_at must be within 900000 ms after issued_at' &&
      life.call(now, now - 1) == 'receipt.expires_at must be within 900000 ms after issued_at' &&
      # receipt age: policy.acc.max_receipt_age_s (inclusive), default 900 s
      r.call(old, pol: { 'acc' => { 'max_receipt_age_s' => 120 } }).nil? &&
      r.call(old, pol: { 'acc' => { 'max_receipt_age_s' => 119 } }) == sig &&
      r.call(old).nil? &&
      # key-set age (inclusive, default 3600 s), future key sets, the tracked version
      r.call(v.receipt(dg), ks: [v.keyset([v.entry], v.seq_root, now - 3_600_000)]).nil? &&
      r.call(v.receipt(dg), ks: [v.keyset([v.entry], v.seq_root, now - 3_600_001)]) == sig &&
      r.call(v.receipt(dg), ks: [v.keyset([v.entry], v.seq_root, now - 60_000)], pol: { 'acc' => { 'max_keyset_age_s' => 59 } }) == sig &&
      r.call(v.receipt(dg), ks: [v.keyset([v.entry], v.seq_root, now - 59_000)], pol: { 'acc' => { 'max_keyset_age_s' => 59 } }).nil? &&
      r.call(v.receipt(dg), ks: [v.keyset([v.entry], v.seq_root, now + 60_001)]) == sig &&
      r.call(v.receipt(dg), ks: [v.keyset([v.entry], v.seq_root, now + 60_000)]).nil? &&
      # the tracked key set {version, digest}: below its version or another set at its version (equivocation) is skipped
      (lambda do
        root = v.pk(v.seq_root)
        k2 = v.keyset([v.entry], v.seq_root, now - 100, 2)
        k2b = v.keyset([v.entry], v.seq_root, now - 200, 2)
        t2 = { 'version' => 2, 'digest' => AtlasPca.sequencer_key_set_digest(k2) }
        ctxerr = ->(t) { v.why(v.seq_decide(v.receipt(dg), versions: { root => t }), 'accumulators') }
        pre_t = 'acc.keyset_versions: '
        AtlasPca.sequencer_key_set_digest(k2) == v.b64(Digest::SHA256.digest(AtlasPca.canon_bytes({ 'd' => 'atlas-pca/sequencer-keys-ref/v1', 'k' => k2 }))) &&
          r.call(v.receipt(dg), versions: { root => t2 }) == sig &&
          r.call(v.receipt(dg), versions: { root => t2 }, ks: [k2]).nil? &&
          r.call(v.receipt(dg), versions: { root => t2 }, ks: [k2b]) == sig &&
          r.call(v.receipt(dg), versions: { root => t2 }, ks: [k2b, k2]).nil? &&
          r.call(v.receipt(dg), versions: { root => t2.merge('version' => 1) }, ks: [k2b]).nil? &&
          r.call(v.receipt(dg), versions: { 'other-root' => t2 }).nil? &&
          [2, nil, '2', []].all? { |t| ctxerr.call(t) == "#{pre_t}a tracked key set must be an object {version, digest}" } &&
          ctxerr.call(t2.merge('x' => 1)) == "#{pre_t}a tracked key set has the unknown member 'x'" &&
          [0, '2', 1.5, nil].all? { |x| ctxerr.call(t2.merge('version' => x)) == "#{pre_t}a tracked key set version must be a safe integer >= 1" } &&
          ctxerr.call(t2.reject { |k, _| k == 'digest' }) == "#{pre_t}a tracked key set digest must be canonical base64url (32 bytes)" &&
          ctxerr.call(t2.merge('digest' => v.b64('x' * 31))) == "#{pre_t}a tracked key set digest must be canonical base64url (32 bytes)" &&
          AtlasPca.tracked_key_set_error(t2).nil?
      end).call &&
      # a retired key: not_after < now - 60 s stops verifying even for a receipt issued inside its window
      r.call(old, ks: [v.keyset([v.entry('not_after' => now - 60_001)])]) == sig &&
      r.call(old, ks: [v.keyset([v.entry('not_after' => now - 60_000)])]).nil? &&
      AtlasPca.sequencer_key_set_shape_error(v.keyset([v.entry]).merge('version' => 0)) == 'version must be a safe integer >= 1' &&
      AtlasPca.sequencer_key_set_shape_error(v.keyset([v.entry]).reject { |k, _| k == 'version' }) == 'version must be a safe integer >= 1'
  end

  t('v2 policy: acc and map members are closed and typed; the context member map has only disclosure') do
    v = V2
    mal = lambda do |c, reason|
      d = v.decide(v.p0, v.g0, c)
      d['checks'].map { |x| [x['name'], x['ok'], x['reason']] } == %w[schema intent_session accumulators].map { |x| [x, false, "malformed v2 context: #{reason}"] }
    end
    pc = ->(pol) { v.ctx('policy' => pol) }
    mal.call(pc.call('acc' => nil), 'policy.acc must be an object') &&
      mal.call(pc.call('acc' => { 'x' => 1 }), "policy.acc: unknown member 'x'") &&
      %w[max_receipt_age_s max_keyset_age_s].all? do |k|
        [-1, '60', nil, 1.5].all? { |a| mal.call(pc.call('acc' => { k => a }), "policy.acc.#{k} must be a non-negative safe integer") }
      end &&
      mal.call(pc.call('map' => nil), 'policy.map must be an object') &&
      mal.call(pc.call('map' => { 'x' => 1 }), "policy.map: unknown member 'x'") &&
      [nil, 'true', 1].all? { |f| mal.call(pc.call('map' => { 'require' => f }), 'policy.map.require must be a boolean') } &&
      [-1, '5', nil, 0.5].all? { |e| mal.call(pc.call('map' => { 'max_residual_risk_ppm' => e }), 'policy.map.max_residual_risk_ppm must be a non-negative safe integer') } &&
      mal.call(v.ctx('map' => nil), 'map must be an object') &&
      mal.call(v.ctx('map' => { 'x' => 1 }), "map: unknown member 'x'") &&
      v.ok?(v.decide(v.p0, v.g0, pc.call('acc' => { 'max_receipt_age_s' => 0, 'max_keyset_age_s' => 0 }, 'map' => { 'require' => false })), 'accumulators') &&
      AtlasPca.intent_v2_active?(v.pcactn(v.g0, is: nil), { 'policy' => { 'map' => { 'require' => true } } }) == true
  end

  # ================================================================== rule 19: committed map, Z0

  t('rule 19: map_form wire ("commit" only) and the v2c goal (never interchangeable with the v2 goal)') do
    v = V2
    m = v.cmap
    w = ->(x) { AtlasPca.validate_intent_session_wire(v.is0('map_form' => x)) }
    lit = ->(goal) { v.b64(Digest::SHA256.digest("{\"d\":\"atlas-pca/goal/v1\\u0000\",\"goal\":\"#{goal}\",\"salt\":\"s\"}".b)) }
    _, g, p = v.map_session(m)
    _, gv, pv = v.map_session(m, mint_form: nil)
    _, gn, pn = v.map_session(m, form: nil)
    w.call('commit').nil? && ['plain', nil, 1, 'Commit'].all? { |x| w.call(x) == "'intent_session.map_form' must be \"commit\" when present" } &&
      AtlasPca.intent_goal_commit(v.ref, m['commit'], 's', v.session, 'commit') == lit.call("pca-intent:v2c:#{v.session}:#{m['commit']}") &&
      AtlasPca.intent_goal_commit(v.ref, m['commit'], 's', v.session) == lit.call("pca-intent:v2:#{v.session}:#{m['commit']}") &&
      AtlasPca.intent_goal_v2(v.session, m['commit'], 'commit') == "pca-intent:v2c:#{v.session}:#{m['commit']}" &&
      AtlasPca.decide_intent_binding(p['intent'], g, nil, v.session, 'commit') == [:pass, nil] &&
      AtlasPca.decide_intent_binding(p['intent'], g, nil, v.session)[0] == :fail &&
      AtlasPca.decide_intent_binding(pv['intent'], gv, nil, v.session, 'commit')[0] == :fail &&
      AtlasPca.decide_intent_binding(pn['intent'], gn, nil, v.session)[0] == :fail &&
      v.verify(v.pcactn(g, is: v.is0('map_form' => 'plain')), g).checks == { 'wire' => false }
  end

  t('rule 19: the map check in the pipeline (after accumulators), reporting, policy require and epsilon') do
    v = V2
    m = v.cmap
    s, g, p = v.map_session(m)
    c = v.map_ctx(s, m)
    r = v.verify(p, g, c)
    d = v.decide(p, g, c)
    _, gn, pn = v.map_session(m, form: nil)
    eps = ->(e) { v.why(v.decide(p, g, v.map_ctx(s, m, 'policy' => { 'map' => { 'max_residual_risk_ppm' => e } })), 'map') }
    r.allow == true && r.checks.keys == BASE_KEYS_V2 + %w[schema intent_session accumulators map] &&
      v.names(d) == %w[schema intent_session accumulators map] && v.ok?(d, 'map') &&
      eps.call(2_000).nil? && eps.call(1_999) == "the committed residual risk 2000 ppm exceeds ε = 1999" &&
      v.why(v.decide(p, g, v.map_ctx(s, m, 'map' => {})), 'map') == 'no disclosure of the committed map was presented' &&
      v.why(v.decide(p, g, v.map_ctx(s, m, 'map' => { 'disclosure' => nil })), 'map') ==
        'map disclosure malformed: the disclosure must be exactly {size, header, cell, metrics}' &&
      v.why(v.decide(p.reject { |k, _| k == 'intent' }, g, c), 'map') == 'a committed map needs the envelope.intent binding' &&
      !v.names(v.decide(pn, gn, c)).include?('map') &&
      v.why(v.decide(v.p0, v.g0, v.ctx('policy' => { 'map' => { 'require' => true } })), 'map') ==
        'this verifier requires a committed map (intent_session.map_form "commit")' &&
      v.names(v.decide(v.pcactn(v.g0, is: nil), v.g0, v.ctx('policy' => { 'map' => { 'require' => true } }))) == ['map'] &&
      v.names(v.decide(v.p0, v.g0, v.ctx('policy' => { 'map' => { 'require' => false } }))) == %w[schema intent_session accumulators] &&
      v.names(v.decide(p, g, v.map_ctx(s, m, 'map' => nil))) == %w[schema intent_session accumulators map]
  end

  t('rule 19: decide_map_disclosure - the cell of omega, openings, layout, kinds, and every refusal in order') do
    v = V2
    m = v.cmap
    ok = ->(dc, **kw) { v.zdecide(m, dc, **kw) }
    disc = v.disclose(m)
    act = ->(total, res = 'skyair.example/bookings') { [{ 'verb' => 'air.book', 'resource' => res, 'params_digest' => AtlasPca.params_digest(v.params('total' => total)) }, v.params('total' => total)] }
    at = lambda do |total, res, flat|
      a, prm = act.call(total, res)
      v.zdecide(m, v.disclose(m, flat), action: a, params: prm)
    end
    why = ->(dc, **kw) { ok.call(dc, **kw)['reason'] }
    swap = ->(k, over) { disc.merge(k => disc[k].merge(over)) }
    ok.call(disc) == { 'ok' => true, 'cell' => [0, 0], 'p_ppm' => 100_000, 'residual_risk_ppm' => 2000 } &&
      at.call(40_000, 'skyair.example/bookings', 3)['cell'] == [1, 0] && at.call(40_001, 'skyair.example/x', 7)['cell'] == [2, 1] &&
      at.call(0, 'skyair.example/bookingsX', 1)['cell'] == [0, 1] && at.call(5_000_000, 'other.example', 8)['cell'] == [2, 2] &&
      at.call(40_000, 'other.example', 5)['reason'] == "the action's cell is outside the committed grant" &&
      at.call(5_000_001, 'skyair.example/bookings', 0)['reason'] == "the action's action.params.total lies outside the committed map's dimension" &&
      ok.call(disc, eps: 2000)['ok'] && why.call(disc, eps: 1999) == "the committed residual risk 2000 ppm exceeds ε = 1999" &&
      why.call(nil) == 'map disclosure malformed: the disclosure must be exactly {size, header, cell, metrics}' &&
      why.call(disc.merge('size' => 3)) == 'map disclosure malformed: disclosure.size must be a safe integer in [4, 16777216]' &&
      why.call(swap.call('cell', 'salt' => 'x')) == 'map disclosure malformed: disclosure.cell.salt must be canonical base64url (32 bytes)' &&
      why.call(swap.call('cell', 'leaf' => disc['cell']['leaf'].merge('p_ppm' => 1_000_001))) ==
        'map disclosure malformed: cell.p_ppm must be a safe integer in [0, 1000000]' &&
      why.call(swap.call('metrics', 'leaf' => v.metrics('log2_vs_mbits' => nil))) ==
        'map disclosure malformed: metrics.log2_vs_mbits must be a non-negative safe integer' &&
      why.call(swap.call('header', 'leaf' => disc['header']['leaf'].merge('cells' => 8))) ==
        "map disclosure malformed: header.cells is not the product of the dimensions' cell counts" &&
      v.zdecide(m.merge('commit' => 'x'), disc)['reason'] == 'the PCActn carries no map commitment' &&
      v.zdecide(m, disc, params: v.params('total' => 1),
                action: { 'verb' => 'air.book', 'resource' => 'skyair.example/bookings', 'params_digest' => AtlasPca.params_digest(v.params) })['reason'] ==
        'the params do not hash to action.params_digest' &&
      why.call(disc, action: { 'verb' => 'air.search', 'resource' => 'skyair.example/bookings', 'params_digest' => AtlasPca.params_digest(v.params) }) ==
        "the disclosed header is not the action's verb" &&
      why.call(swap.call('header', 'index' => 1)) == 'the disclosed header does not fit the committed layout' &&
      v.zdecide(v.cmap(v.seed('kv2/other-secret')), disc)['reason'] == 'the header leaf does not open the map commitment' &&
      why.call(swap.call('cell', 'salt' => v.b64(v.seed('kv2/x')))) == 'the cell leaf does not open the map commitment' &&
      why.call(swap.call('metrics', 'path' => disc['metrics']['path'][0..-2])) == 'the metrics leaf does not open the map commitment' &&
      why.call(swap.call('metrics', 'leaf' => v.metrics('residual_risk_ppm' => 1))) == 'the metrics leaf does not open the map commitment' &&
      why.call(disc.merge('cell' => v.mentry(m, 2))) == "the disclosed cell is not the action's cell" &&
      why.call(disc.merge('size' => 13)) == 'the header leaf does not open the map commitment' &&
      # kind confusion: the learner leaf presented as the metrics entry
      why.call(disc.merge('metrics' => v.mentry(m, 11).merge('leaf' => v.metrics))) == 'the metrics leaf does not open the map commitment' &&
      v.zdecide(v.cmap(grant0: false), v.disclose(v.cmap(grant0: false)))['reason'] == "the action's cell is outside the committed grant" &&
      [{ '__proto__' => { 'total' => 38_900 } }, v.params.merge('total' => '38900'), v.params.merge('total' => 1.5),
       v.params.merge('total' => nil), v.params.reject { |k, _| k == 'total' }].all? do |prm|
        v.zdecide(m, disc, params: prm, action: { 'verb' => 'air.book', 'resource' => 'skyair.example/bookings', 'params_digest' => AtlasPca.params_digest(prm) })['reason'] ==
          "the action's action.params.total lies outside the committed map's dimension"
      end
  end

  t('rule 19: commitment primitives (leaf hash, RFC 9162 path fold, commit of a leaf list, numeric cells, header shape)') do
    v = V2
    m = v.cmap
    leaves = m['leaves'].each_with_index.map { |(k, l), i| { 'kind' => k, 'salt' => v.b64(v.msalt(m['secret'], i)), 'leaf' => l } }
    path = ->(i) { v.maudit(m['hashes'], i) }
    root = v.mtree(m['hashes'])
    AtlasPca.map_commit_of_leaves(leaves) == m['commit'] &&
      AtlasPca.map_commit_of_leaves(leaves.map.with_index { |l, i| i == 3 ? l.merge('kind' => 'header') : l }) != m['commit'] &&
      (0...m['size']).all? { |i| AtlasPca.map_root_from_path(i, m['size'], m['hashes'][i], path.call(i)) == root } &&
      AtlasPca.map_root_from_path(3, m['size'], m['hashes'][3], path.call(3)[0..-2]).nil? &&
      AtlasPca.map_root_from_path(3, m['size'], m['hashes'][3], path.call(3) + [root]).nil? &&
      AtlasPca.map_root_from_path(12, m['size'], m['hashes'][3], path.call(3)).nil? &&
      AtlasPca.map_root_from_path(0, 1, m['hashes'][0], []) == m['hashes'][0] &&
      AtlasPca.map_num_cells({ 'kind' => 'num', 'path' => 'action.params.x', 'lo' => 0, 'hi' => 10, 'cuts' => [0, 5, 10] }) == [[0, 0], [1, 4], [5, 5], [6, 9], [10, 10]] &&
      AtlasPca.map_num_cells({ 'kind' => 'num', 'path' => 'action.params.x', 'lo' => 3, 'hi' => 3, 'cuts' => [] }) == [[3, 3]] &&
      AtlasPca.map_header_error({ 'verb' => 'v', 'first' => 1, 'cells' => 1, 'dims' => [] }).nil? &&
      AtlasPca.map_header_error({ 'verb' => 'v', 'first' => 1, 'cells' => 1, 'dims' => [{ 'kind' => 'num', 'path' => 'action.resource', 'lo' => 0, 'hi' => 0, 'cuts' => [] }] }) ==
        'header.dims[0].path must be action.params.<name>' &&
      AtlasPca.map_header_error({ 'verb' => 'v', 'first' => 1, 'cells' => 2, 'dims' => [{ 'kind' => 'num', 'path' => 'action.params.x', 'lo' => 0, 'hi' => 9, 'cuts' => [5, 5] }] }) ==
        'header.dims[0].cuts must be strictly increasing safe integers in [lo, hi]' &&
      AtlasPca.map_header_error({ 'verb' => 'v', 'first' => 1, 'cells' => 2, 'dims' => [{ 'kind' => 'cat', 'path' => 'action.resource',
                                                                                          'values' => [{ 'kind' => 'other', 'value' => "⊥" }, { 'kind' => 'exact', 'value' => 'a' }] }] }) ==
        "header.dims[0].values: exactly one other ('⊥'), last; prefixes non-empty" &&
      AtlasPca.map_header_error({ 'verb' => 'v', 'first' => 1, 'cells' => 2, 'dims' => [{ 'kind' => 'cat', 'path' => 'action.resource',
                                                                                          'values' => [{ 'kind' => 'prefix', 'value' => '' }, { 'kind' => 'other', 'value' => "⊥" }] }] }) ==
        "header.dims[0].values: exactly one other ('⊥'), last; prefixes non-empty" &&
      AtlasPca.map_learner_error({ 'learner_digest' => 'x' }) == 'learner.learner_digest must be canonical base64url (32 bytes)' &&
      AtlasPca.intent_map_primitive({ 'map_commit' => m['commit'], 'action' => { 'verb' => 'air.book', 'resource' => 'skyair.example/bookings',
                                                                                  'params_digest' => AtlasPca.params_digest({}) }, 'disclosure' => v.disclose(m) })['reason'] ==
        "the action's action.params.total lies outside the committed map's dimension"
  end

  # ================================================================== W-B totality (45a1599e)

  t('W-B entry points never raise: non-object input fails closed (facts, offers, provenance, classes) or is inactive') do
    odd = [nil, 42, 'x', true, [], { 'intent_session' => 5, 'policy' => 'p' }]
    odd.all? do |x|
      wb = AtlasPca.decide_intent_wb(x)
      wb['outcome'] == 'deny' && wb['checks'] == { 'facts' => 'fail' } &&
        AtlasPca.intent_wb_context_error(x).is_a?(String) &&
        [true, false].include?(AtlasPca.intent_wb_active(x)['facts']) &&
        AtlasPca.decide_intent_world(x)['ok'] == false && AtlasPca.decide_offer_set(x)['ok'] == false &&
        AtlasPca.decide_param_provenance(x)['outcome'] == 'deny' && AtlasPca.decide_classifier_dimensions(x)['ok'] == false &&
        AtlasPca.intent_world_active(x) == false && AtlasPca.classifier_check_active(x) == false &&
        [true, false].include?(AtlasPca.intent_provenance_active(x)) &&
        AtlasPca.flow_rule_for(x, x).nil? && AtlasPca.flow_allowed(x, x, x, x) == (x.is_a?(String)) && AtlasPca.parse_label_ref(x).nil? &&
        AtlasPca.verify_labels(x, x).is_a?(String)
    end &&
      AtlasPca.decide_intent_wb(nil)['reason'] == 'facts: the W-B context is malformed: input must be an object' &&
      AtlasPca.decide_intent_world(nil)['reason'] == 'facts: input must be an object' &&
      AtlasPca.ratio_ppm(1.5, 2).nil? && AtlasPca.ratio_ppm(1, 2.5).nil? && AtlasPca.ratio_ppm(1, 2) == 500_000 &&
      AtlasPca.decide_offer_set({})['reason'] == 'offers: policy misconfigured (fail closed): offers policy must be an object' &&
      AtlasPca.decide_offer_set(nil)['reason'] == 'offers: input must be an object'
  end

  t('parse_json_text (raw *_json members): tokenizer-aware negative zero, binary64 numbers, strings and keys untouched') do
    nz = ->(x) { x.is_a?(Float) && x.zero? && (1.0 / x).negative? }
    # An Integer of that value. Not `equal?`: on Windows a C `long` is 32 bits, so Fixnums stop at 2^30-1 and a larger
    # Integer (9007199254740991) is a Bignum, a distinct object from the literal; identity is false there.
    int = ->(x, n) { x.is_a?(Integer) && x == n }
    j = ->(t) { AtlasPca.parse_json_text(t) }
    str = j.call('{"a":"x:-0,y","b":{"c":"-0","d":[":-0,", " -0 "]},"-0":"k",":-0,":1,"e":"[-0]"}')
    arr = j.call('[-0, [ -0 ], {"x": -0 }, -0.0, -0e0, -0E+0, 0, 1.0, 1e6, 9007199254740993, 9007199254740991, -1, 5]')
    raises = lambda do |t|
      j.call(t)
      false
    rescue AtlasPca::Malformed
      true
    end
    str == { 'a' => 'x:-0,y', 'b' => { 'c' => '-0', 'd' => [':-0,', ' -0 '] }, '-0' => 'k', ':-0,' => 1, 'e' => '[-0]' } &&
      nz.call(j.call('-0')) && nz.call(j.call(' -0 ')) && nz.call(j.call('{"min_fidelity_ppm":-0}')['min_fidelity_ppm']) &&
      nz.call(arr[0]) && nz.call(arr[1][0]) && nz.call(arr[2]['x']) && nz.call(arr[3]) && nz.call(arr[4]) && nz.call(arr[5]) &&
      int.call(arr[6], 0) && arr[7].is_a?(Float) && arr[7] == 1.0 && arr[8] == 1_000_000.0 && arr[8].is_a?(Float) &&
      arr[9] == 9_007_199_254_740_992.0 && arr[9].is_a?(Float) && int.call(arr[10], 9_007_199_254_740_991) && int.call(arr[11], -1) &&
      int.call(arr[12], 5) &&
      j.call('{"a":1,"a":2}') == { 'a' => 2 } && j.call('"s"') == 's' && j.call('null').nil? &&
      raises.call('{"a":-}') && raises.call('{"a":01}') && raises.call('{"a":1') &&
      AtlasPca.parse_intent_policy_json('{"min_fidelity_ppm":-0,"note":":-0,"}').then { |h| nz.call(h['min_fidelity_ppm']) && h['note'] == ':-0,' } &&
      AtlasPca.decide_intent_binding(nil, nil, AtlasPca.parse_intent_policy_json('{"min_fidelity_ppm":-0}'))[0] == :fail
  end

  # ================================================================== W-B unit and Rack

  t('v2: the W-B checks follow accumulators; a W-B question fails its check with an intent_required reason') do
    v = V2
    wb_ok = { 'outcome' => 'admit', 'checks' => { 'facts' => 'pass' }, 'env' => { 'world' => { 'fare' => 1 } } }
    wb_q = { 'outcome' => 'question', 'checks' => { 'facts' => 'pass', 'provenance' => 'question' }, 'env' => {}, 'reason' => 'tainted' }
    orig = AtlasPca.method(:decide_intent_wb)
    res = []
    begin
      [wb_ok, wb_q, :raise].each do |w|
        AtlasPca.define_singleton_method(:decide_intent_wb) { |_i| w == :raise ? raise('boom') : w }
        res << v.decide(v.p0, v.g0)
      end
    ensure
      AtlasPca.define_singleton_method(:decide_intent_wb, orig)
    end
    a, b, c = res
    v.names(a) == %w[schema intent_session accumulators facts] && v.ok?(a, 'facts') && a['env']['world'] == { 'fare' => 1 } &&
      v.names(b) == %w[schema intent_session accumulators facts provenance] && v.why(b, 'provenance') == 'intent_required: tainted' &&
      v.names(c) == %w[schema intent_session accumulators facts] && v.why(c, 'facts') == 'W-B error (fail closed): boom'
  end

  t('Rack: intent_v2 Hash or callable(pcactn) per request; a raising callable is a 403 intent_v2_context_error') do
    v = V2
    p = v.p0
    g = v.g0
    header = Base64.urlsafe_encode64(JSON.generate(p), padding: false)
    mk = ->(iv2) { AtlasPca::RackMiddleware.new(->(_e) { [200, {}, ['ok']] }, audience: MutationKill::V2::AUD, resolve_grant: ->(_r) { g }, now: MutationKill::V2::NOW, intent_v2: iv2) }
    seen = []
    ok = mk.call(->(pc) { seen << pc['grant_ref']; v.ctx }).call('HTTP_PCA_ACTION' => header)
    deny = mk.call(->(_pc) { v.ctx('params' => v.params('total' => 1)) }).call('HTTP_PCA_ACTION' => header)
    boom = mk.call(->(_pc) { raise 'store down' }).call('HTTP_PCA_ACTION' => header)
    hash = mk.call(v.ctx).call('HTTP_PCA_ACTION' => header)
    ok[0] == 200 && seen == [g['id']] && hash[0] == 200 && deny[0] == 403 && deny[2].join.include?('schema') &&
      boom[0] == 403 && boom[2].join.include?('intent_v2_context_error') &&
      (begin
        mk.call(5)
        false
      rescue ArgumentError
        true
      end)
  end
end
