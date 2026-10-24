# frozen_string_literal: true
require 'openssl'
# Intent Layer v2 (intent_v2.rb) targeted kills for the branches no shared oracle reaches: the optional `min_keyset_version`
# freshness bound of verify_receipt_against_holder (absent from every generator), the totality of the internal entry points on
# non-array / non-string inputs, and the suite seam verify_pinned_suite. Fixtures are the killAcc.json.gz `holder/valid` case (a
# TS-signed receipt and key set) and a key derived like the conformance keys (sha256("atlas-pca-conformance/" + label)). Every
# expectation follows intent-acc.ts / pq.ts (noted per case). Only intent_v2.rb bears on it.
module MutationKill
  module V2Targeted
    module_function

    def iv2 = AtlasPca::IntentV2
    def absent = AtlasPca::V2JS::UNDEF
    def n(x) = AtlasPca::V2JS.jsnorm(x)

    def holder_case = (@holder_case ||= KillAcc.cases.find { |c| c['name'] == 'holder/valid' }['in'])

    # verifyReceiptAgainstHolder(r, holder, keySets, now, fresh) on the valid fixture with `fresh` / key sets / now replaced
    def holder(fresh, key_sets = :fixture, now: holder_case['now'])
      i = holder_case
      ks = key_sets == :fixture ? n(i['keySets']) : key_sets
      iv2.verify_receipt_against_holder(n(i['r']), n(i['holder']), ks, now, fresh)
    end

    def holder_checks
      v = holder_case['keySets'][0]['version'] # 1
      [
        ['valid', holder({}) == true],
        # minKeysetVersion: a set below the floor is skipped (`ks.version < min` continue); equal passes
        ['min = version', holder({ 'min_keyset_version' => v }) == true],
        ['min = 0', holder({ 'min_keyset_version' => 0 }) == true],
        ['min > version', holder({ 'min_keyset_version' => v + 1 }) == false],
        # a malformed floor fails closed (`!isNonNegSafeInt(min)` -> false)
        ['min negative', holder({ 'min_keyset_version' => -1 }) == false],
        ['min fraction', holder({ 'min_keyset_version' => 0.5 }) == false],
        ['min string', holder({ 'min_keyset_version' => '1' }) == false],
        ['min null', holder({ 'min_keyset_version' => nil }) == false],
        # with a tracked version too: both bounds apply
        ['min + tracked', holder({ 'min_keyset_version' => v + 1, 'tracked' => { 'version' => v, 'digest' => iv2.sequencer_key_set_digest(n(holder_case['keySets'][0])) } }) == false],
        # `!Array.isArray(keySets)` -> false (never a raise), whatever the value
        ['key sets string', holder({}, 'x') == false],
        ['key sets number', holder({}, 5) == false],
        ['key sets nil', holder({}, nil) == false],
        ['key sets object', holder({}, n(holder_case['keySets'][0])) == false],
        # the default receipt age bound is 15 minutes (DEFAULT_MAX_RECEIPT_AGE_MS = 900000), inclusive
        ['default receipt age edge', holder({}, now: holder_case['r']['issued_at'] + 900_000) == true],
        ['default receipt age over', holder({}, now: holder_case['r']['issued_at'] + 900_001) == false]
      ]
    end

    # ---- the revocation ids / scopes / goals (intent-revocation.ts, intent-session.ts): literal formats ----
    def id_checks
      x = AtlasPca
      [
        ['session id', x.session_revocation_id('s1') == 'pca-intent:session:s1' && iv2.session_revocation_id('s1') == 'pca-intent:session:s1'],
        ['map id', x.map_revocation_id('d1') == 'pca-intent:map:d1' && iv2.map_revocation_id('d1') == 'pca-intent:map:d1'],
        ['delta id', x.delta_revocation_id('g1') == 'pca-intent:delta:g1' && iv2.delta_revocation_id('g1') == 'pca-intent:delta:g1'],
        ['profile id', x.profile_revocation_id('p1', 3) == 'pca-intent:profile:p1@3' && iv2.profile_revocation_id('p1', 3) == 'pca-intent:profile:p1@3'],
        ['session scope', x.session_revocation_scope('s1') == 'pca-intent-session:s1' && iv2.session_revocation_scope('s1') == 'pca-intent-session:s1'],
        ['profile scope', x.profile_revocation_scope('p1') == 'pca-intent-profile:p1' && iv2.profile_revocation_scope('p1') == 'pca-intent-profile:p1'],
        ['goal', x.intent_goal_v2('s', 'd') == 'pca-intent:v2:s:d' && x.intent_goal_v2('s', 'd', 'commit') == 'pca-intent:v2c:s:d' &&
          iv2.intent_goal_v2('s', 'd', 'other') == 'pca-intent:v2:s:d']
      ]
    end

    # ---- primitives.intent_map_commit on malformed leaf lists: a StrictError with the helper's own message ----
    def strict_msg
      yield
      :no_raise
    rescue AtlasPca::V2JS::StrictError => e
      e.message
    rescue StandardError => e
      "#{e.class}"
    end

    def commit_checks
      salt = AtlasPca.b64e("\x07".b * 32)
      leaf = ->(h) { { 'kind' => 'header', 'salt' => salt, 'leaf' => { 'verb' => 'v' } }.merge(h) }
      bad_list = 'leaves must be a non-empty array'
      bad_entry = 'a leaf entry must be {kind, salt, leaf}'
      bad_salt = 'a leaf salt must be canonical base64url (32 bytes)'
      cases = [[5, bad_list], [[], bad_list], [{}, bad_list], [nil, bad_list], ['x', bad_list],
               [[5], bad_entry], [[nil], bad_entry], [[leaf.call('kind' => 'bogus')], bad_entry], [[leaf.call('kind' => nil)], bad_entry],
               [[leaf.call({}).reject { |k, _| k == 'leaf' }], bad_entry], [[leaf.call({}), 7], bad_entry],
               [[leaf.call('salt' => 'AAAA')], bad_salt], [[leaf.call('salt' => nil)], bad_salt], [[leaf.call('salt' => "#{salt}A")], bad_salt]]
      out = cases.flat_map do |input, want|
        [["internal #{input.inspect[0, 60]}", strict_msg { iv2.map_commit_of_leaves(input) } == want],
         ["public #{input.inspect[0, 60]}", strict_msg { AtlasPca.map_commit_of_leaves(input) } == want]]
      end
      # a well-formed one-leaf list commits (the leaf hash itself is the root)
      ok = iv2.map_commit_of_leaves([leaf.call({})])
      h = iv2.map_leaf_hash('header', "\x07".b * 32, { 'verb' => 'v' })
      out << ['one leaf', ok.is_a?(String) && ok == iv2.map_commit_of(1, h)]
      out << ['leaf null is a value', iv2.map_commit_of_leaves([leaf.call('leaf' => nil)]).is_a?(String)]
      out
    end

    # ---- verify_pinned_suite (pq.ts verifyPinnedSuite through the SDK dispatch) ----
    def ed_key = (@ed_key ||= OpenSSL::PKey.new_raw_private_key('ED25519', OpenSSL::Digest::SHA256.digest('atlas-pca-conformance/v2-targeted/ed')))
    def b64(x) = AtlasPca.b64e(x)
    def ed_pk = b64(ed_key.raw_public_key)
    def ed_sig(msg) = b64(ed_key.sign(nil, msg))

    def vps(alg, identity, apq, msg, sig, pq_sig, pins) = iv2.verify_pinned_suite(alg, identity, apq, msg, sig, pq_sig, pins)

    def pinned_checks
      msg = "atlas-pca/v2-targeted\0m".b
      sig = ed_sig(msg)
      pk = ed_pk
      [
        ['ed25519 (alg absent)', vps(absent, pk, absent, msg, sig, absent, nil) == true],
        ['ed25519 named', vps('ed25519', pk, absent, msg, sig, absent, nil) == true],
        ['ed25519 other msg', vps(absent, pk, absent, "#{msg}x", sig, absent, nil) == false],
        # an unknown / unavailable suite is refused before any key is resolved, even over a valid Ed25519 signature
        ['unknown suite', vps('rot13', pk, absent, msg, sig, absent, nil) == false],
        ['malformed alg', vps(5, pk, absent, msg, sig, absent, nil) == false],
        ['null alg', vps(nil, pk, absent, msg, sig, absent, nil) == false],
        # a PQ suite resolves its key only through a pin for `identity`; no pin / another key -> false
        ['pq unpinned', vps('hybrid-ed25519-ml-dsa-65', pk, 'AAAA', msg, sig, 'AAAA', nil) == false],
        ['pq pin mismatch', vps('hybrid-ed25519-ml-dsa-65', pk, 'AAAA', msg, sig, 'AAAA', { pk => 'BBBB' }) == false],
        ['pq absent pk', vps('hybrid-ed25519-ml-dsa-65', pk, absent, msg, sig, 'AAAA', { pk => 'AAAA' }) == false],
        # non-string signature / identity: false (total, never a raise)
        ['sig number', vps(absent, pk, absent, msg, 5, absent, nil) == false],
        ['sig nil', vps(absent, pk, absent, msg, nil, absent, nil) == false],
        ['identity number', vps(absent, 5, absent, msg, sig, absent, nil) == false],
        ['identity nil', vps(absent, nil, absent, msg, sig, absent, nil) == false],
        ['msg nil', vps(absent, pk, absent, nil, sig, absent, nil) == false]
      ]
    end

    # ---- session revocation with non-ASCII ids (intent-revocation.ts checkSessionRevocation: ids compared as strings) ----
    # Epochs signed here by the k042-sessrevoc revocation authority (seed "v2/revocation-authority"), built ONCE at registry
    # load by the unmutated library (signed bytes = REVEPOCH_DOMAIN + canonical {instance_id .. not_after}).
    def rev_base = (@rev_base ||= SessRevocDiff.data['rev'].find { |c| c['name'] == 'ok' })
    def rev_key = (@rev_key ||= OpenSSL::PKey.new_raw_private_key('ED25519', OpenSSL::Digest::SHA256.digest('atlas-pca-conformance/v2/revocation-authority')))

    def rev_ev(list)
      c = rev_base
      x = iv2
      l = list.sort { |a, b| AtlasPca::V2JS.compare_utf8(a, b) }
      ep = { 'instance_id' => 'ana', 'grant_ref' => x.session_revocation_scope(c['session']), 'epoch' => l.length, 'set_size' => l.length,
             'root' => x.revset_root(l), 'issued_at' => c['now'] - 10_000, 'not_after' => c['now'] + 300_000,
             'guardian' => AtlasPca.b64e(rev_key.raw_public_key) }
      body = x::EPOCH_FIELDS.to_h { |k| [k, ep[k]] }
      ep['sig'] = AtlasPca.b64e(rev_key.sign(nil, x.dmsg(x::REVEPOCH_DOMAIN, body)))
      { 'epoch' => ep, 'revoked' => l }
    end

    def rev_fixture = (@rev_fixture ||= begin
      a = "pca-intent:session:caf\u00e9"
      b = "pca-intent:map:\u00fcber"
      { one: rev_ev([a]), two: rev_ev([a, b]), a: a, b: b }
    end)

    def csr(ev, ids, last: absent, session: rev_base['session'])
      c = rev_base
      iv2.check_session_revocation(ev, session: session, authority: ev['epoch']['guardian'], ids: ids, now: c['now'], max_age_ms: c['maxAge'], last: last)
    end

    def revocation_checks
      f = rev_fixture
      ok = { 'ok' => true }
      [
        ['guardian is the fixture authority', AtlasPca.b64e(rev_key.raw_public_key) == AtlasPca.parse_json_text(rev_base['authority'])],
        ['non-ascii unrevoked', csr(f[:one], ['pca-intent:session:other']) == ok],
        ['non-ascii revoked', csr(f[:one], [f[:a]]) == { 'ok' => false, 'reason' => "'#{f[:a]}' is revoked" }],
        ['non-ascii revoked (binary id)', csr(f[:one], [f[:a].b])['ok'] == false],
        # append-only against the tracked last epoch: every id of `last` must still be listed (compared as strings)
        ['append-only kept', csr(f[:two], ['x'], last: f[:one]) == ok],
        ['append-only dropped', csr(f[:one], ['x'], last: f[:two])['ok'] == false],
        # an internal error is the fail-closed shape {ok: false, reason: "session revocation check error (fail closed): ..."}
        ['internal error shape', csr(f[:one], ['x'], session: BasicObject.new).then { |r| r.keys == %w[ok reason] && r['ok'] == false && r['reason'].start_with?('session revocation check error (fail closed): ') }]
      ]
    end

    # ---- committed-map pieces on edge inputs (intent-map-commit.ts mapLeafHash / mapRootFromPath / mapCellOf) ----
    def map_checks
      salt = "\x07".b * 32
      lh = ->(sl, leaf = { 'verb' => 'v' }) { strict_msg { iv2.map_leaf_hash('header', sl, leaf) } }
      salt_msg = 'mapLeafHash: the salt is 32 bytes'
      h = iv2.map_leaf_hash('header', salt, { 'verb' => 'v' })
      # a 32-byte salt that is a (valid, non-ASCII) UTF-8 String and a non-ASCII leaf: the hash is over the bytes
      u8salt = "\u00e9" * 16
      hu = iv2.map_leaf_hash('cell', u8salt, { 'v' => "\u00fc" })
      hdr = { 'verb' => 'v', 'first' => 1, 'cells' => 3,
              'dims' => [{ 'kind' => 'cat', 'path' => 'action.resource',
                           'values' => [{ 'kind' => 'exact', 'value' => "caf\u00e9" }, { 'kind' => 'prefix', 'value' => "\u00fc" }, { 'kind' => 'other', 'value' => '*' }] }] }
      cell = ->(r) { iv2.map_cell_of(hdr, r, absent)['cell'] }
      [
        ['salt 31', lh.call("\x07".b * 31) == salt_msg], ['salt 33', lh.call("\x07".b * 33) == salt_msg],
        ['salt nil', lh.call(nil) == salt_msg], ['salt number', lh.call(5) == salt_msg], ['salt array', lh.call([1] * 32) == salt_msg],
        ['salt ok', h.is_a?(String) && h.bytesize == 32],
        ['utf-8 salt bytes', hu == iv2.map_leaf_hash('cell', u8salt.b, { 'v' => "\u00fc" }) && hu.bytesize == 32],
        ['path negative index', iv2.map_root_from_path(-1, 2, h, [h]).nil? && iv2.map_root_from_path(-2, 4, h, [h, h]).nil?],
        ['path index = size', iv2.map_root_from_path(2, 2, h, [h]).nil?],
        ['path ok', iv2.map_root_from_path(0, 2, h, [h]) == iv2.map_node_hash(h, h)],
        # string dimensions compare bytes: an exact non-ASCII value, a non-ASCII prefix, the other bucket
        ['cell exact non-ascii', cell.call("caf\u00e9") == [0]],
        ['cell exact non-ascii (binary)', cell.call("caf\u00e9".b) == [0]],
        ['cell prefix non-ascii', cell.call("\u00fcber") == [1]],
        ['cell prefix non-ascii (binary)', cell.call("\u00fcber".b) == [1]],
        ['cell other', cell.call('zzz') == [2]]
      ]
    end

    # ---- grant_session_caveat / verify_session_root edges ----
    def grant_checks
      g = ->(x) { AtlasPca.grant_session_caveat(x) }
      cav = { 'type' => 'intent_session', 'session' => 's' }
      [
        ['grant number', g.call(5).nil?], ['grant array', g.call([1]).nil?], ['grant nil', g.call(nil).nil?], ['grant string', g.call('caveats').nil?],
        ['caveats not array', g.call({ 'caveats' => 'x' }).nil? && g.call({ 'caveats' => { 'type' => 'intent_session' } }).nil?],
        ['no caveats', g.call({}).nil?],
        ['non-object caveats skipped', g.call({ 'caveats' => [5, nil, 'intent_session', ['intent_session'], cav] }).equal?(cav)]
      ]
    end

    def root_pin_checks
      c = KillSession.data['root'].find { |x| x['name'] == 'pq-first-principal' }
      s = n(c['arg'])
      pins = n(c['pins'])
      signer = s['signer']
      need = "session root suite '#{s['alg']}' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it"
      v = ->(pp) { iv2.verify_session_root(s, pp) }
      [
        ['pinned ok', v.call(pins) == { 'ok' => true }],
        ['pin number', v.call({ signer => 5 }) == { 'ok' => false, 'reason' => need }],
        ['pin true', v.call({ signer => true }) == { 'ok' => false, 'reason' => need }],
        ['pin array', v.call({ signer => [pins[signer]] }) == { 'ok' => false, 'reason' => need }],
        ['pins for another key', v.call({ "#{signer}x" => pins[signer] }) == { 'ok' => false, 'reason' => need }],
        ['no pins', v.call(nil) == { 'ok' => false, 'reason' => need } && v.call('x') == { 'ok' => false, 'reason' => need }]
      ]
    end

    # ---- action schema / session root / misc edges (the helpers' own refusals; exact messages) ----
    def schema_doc = (@schema_doc ||= AtlasPca.parse_json_text(ActionSchemaDiff.data['shape'].find { |c| c['name'] == 'shape/base' }['doc']))

    def edge_checks
      x = AtlasPca
      doc = schema_doc
      shape = ->(d) { x.action_schema_shape_error(d) }
      verb0 = doc['verbs'][0]
      with_verb = ->(h) { doc.merge('verbs' => [verb0.merge(h)]) }
      undecl = "Cannot convert undefined or null to object"
      root = n(KillSession.data['root'].find { |c| c['name'] == 'base' }['arg'])
      unsigned = root.reject { |k, _| %w[signer sig alg pq_pk pq_sig].include?(k) }
      task_ok = root.dig('layers', 'task')
      [
        ['schema base', shape.call(doc).nil?],
        # verbs that are not an array are refused by the verbs rule (never reach a later method call)
        ['verbs number', shape.call(doc.merge('verbs' => 5)) == 'verbs must be 1..256 entries'],
        ['verbs string', shape.call(doc.merge('verbs' => 'x')) == 'verbs must be 1..256 entries'],
        ['verbs object', shape.call(doc.merge('verbs' => { 'a' => 1 })) == 'verbs must be 1..256 entries'],
        # mcp / openapi are exactly one member: an extra "" member is not absorbed by the key join
        ['mcp ok', shape.call(with_verb.call('mcp' => { 'tool' => 't' })).nil?],
        ['mcp extra empty key', shape.call(with_verb.call('mcp' => { '' => 'x', 'tool' => 't' })) == "verb 'a.b': mcp must be {tool}"],
        ['openapi ok', shape.call(with_verb.call('openapi' => { 'operationId' => 'o' })).nil?],
        ['openapi extra empty key', shape.call(with_verb.call('openapi' => { '' => 'x', 'operationId' => 'o' })) == "verb 'a.b': openapi must be {operationId}"],
        # schema_verb: a null entry raises like `v.verb` on null; non-objects never match (even against the absent marker)
        ['verb null entry', strict_msg { x.schema_verb({ 'verbs' => [nil] }, 'a') } == "Cannot read properties of null (reading 'verb')"],
        ['verb non-objects skipped', x.schema_verb({ 'verbs' => [5, 'a', [], { 'verb' => 'a' }] }, 'a') == { 'verb' => 'a' }],
        ['verb absent never matches a non-object', x.schema_verb({ 'verbs' => [5, 'a', true] }, absent).nil?],
        # decl on a non-object declaration raises the TS TypeError text
        ['decl number', strict_msg { x.param_value_violation(5, 'x') } == "Cannot read properties of 5 (reading 'max_len')"],
        ['decl null', strict_msg { x.param_value_violation(nil, 'x') } == "Cannot read properties of null (reading 'max_len')"],
        ['decl string', strict_msg { x.param_value_violation('d', 'x') } == "Cannot read properties of d (reading 'max_len')"],
        # conform_action / accumulation_params on a verb whose params is not an object
        ['conform params not object', strict_msg { x.conform_action({ 'verbs' => [{ 'verb' => 'a', 'params' => 5 }] }, 'a', {}) } == undecl],
        ['conform ok verb', x.conform_action(doc, 'a.b', { 'total' => 5 }) == { 'ok' => true, 'verb' => verb0 }],
        ['acc params not object', strict_msg { x.accumulation_params({ 'params' => 5 }, 'u') } == undecl],
        ['acc params absent', strict_msg { x.accumulation_params({}, 'u') } == undecl],
        ['acc accumulates_into not array',
         strict_msg { x.accumulation_params({ 'params' => { 'action.params.n' => { 'type' => 'integer', 'accumulates_into' => 'u' } } }, 'u') } == 'accumulates_into must be an array'],
        ['acc ok', x.accumulation_params({ 'params' => { 'action.params.n' => { 'type' => 'integer', 'accumulates_into' => ['u'] } } }, 'u') == ['action.params.n']],
        # calendar_date? is a boolean (false, not nil) for every refusal
        ['date shape', x.calendar_date?('2024-1-01').equal?(false) && x.calendar_date?(5).equal?(false)],
        ['date range', x.calendar_date?('2024-13-01').equal?(false) && x.calendar_date?('0000-01-01').equal?(false) && x.calendar_date?('2024-01-00').equal?(false)],
        ['date ok', x.calendar_date?('2024-02-29') == true && x.calendar_date?('2023-02-29') == false],
        # session root: the unsigned shape does not ask for the signature members; layers.task is exactly {map_digest}
        ['root base', x.session_root_shape_error(root).nil?],
        ['root unsigned', x.session_root_shape_error(unsigned, signed: false).nil? && !x.session_root_shape_error(unsigned).nil?],
        ['root task extra empty key', task_ok.nil? || x.session_root_shape_error(root.merge('layers' => root['layers'].merge('task' => { '' => 1 }.merge(task_ok)))) == 'layers.task must be {map_digest}'],
        # the revocation epoch check refuses a non-object epoch as unsigned, even when asked with the absent marker as guardian
        ['epoch non-object', [5, nil, 'x', []].all? { |e| x.check_revocation_epoch(e, absent, 1) == { 'ok' => false, 'reason' => 'revocation epoch not signed by the pinned guardian' } }]
      ]
    end

    # ---- decide_intent_v2 around the W-B checks: an internal W-B error is a failed facts check; a W-B deny adds no env ----
    def decide_checks
      now = 1_800_000_000_000
      d = AtlasPca.b64e("\x01".b * 32)
      dec = ->(is) { AtlasPca.decide_intent_v2({ 'intent_session' => is }, {}, nil, now) }
      err = dec.call(5)['checks'].find { |c| c['name'] == 'facts' }
      deny = dec.call({ 'session' => d, 'facts' => [d] })
      admit = dec.call({ 'session' => d })
      [
        ['W-B error is a failed facts check', err.is_a?(Hash) && err.keys == %w[name ok reason] && err['ok'] == false && err['reason'].start_with?('W-B error (fail closed): ')],
        ['W-B deny', deny['checks'].last == { 'name' => 'facts', 'ok' => false, 'reason' => 'facts: a committed fact was not supplied (or is malformed)' }],
        ['W-B deny adds no env', !deny.key?('env')],
        ['W-B admit merges its (empty) env', admit['env'] == {} && admit['checks'].none? { |c| %w[facts provenance classes].include?(c['name']) }]
      ]
    end

    # ---- policy.acc ages are seconds (x 1000 ms), inclusive: the k042-intentv2-cases `vec/acc-receipt` decision (a passing
    # sequenced receipt) re-run at a later clock under a tighter policy. Only the accumulators check is compared. ----
    def acc_age_checks
      c = IntentV2Diff.cases.find { |x| x['name'] == 'vec/acc-receipt' }
      p = AtlasPca.parse_json_text(c['p'])
      g = AtlasPca.parse_json_text(c['grant'])
      ctx = AtlasPca.parse_json_text(c['ctx'])
      ctx = ctx.merge('params' => AtlasPca.parse_json_text(c['wp'])) if c.key?('wp')
      r = ctx['acc']['receipts'][0]
      ks = ctx['acc']['sequencer_keys'][0]
      acc = lambda do |pol, now|
        out = iv2.decide_intent_v2(p, g, ctx.merge('policy' => { 'acc' => pol }), now)
        out['checks'].find { |x| x['name'] == 'accumulators' }
      end
      unsigned = "is not signed by a key the session sequencer's root-signed key set lists for its issue time"
      expired = 'has expired'
      [
        ['fixture passes', acc.call({}, c['now'])['ok'] == true],
        ['receipt age edge', acc.call({ 'max_receipt_age_s' => 600 }, r['issued_at'] + 600_000)['reason'].to_s.end_with?(expired)],
        ['receipt age over', acc.call({ 'max_receipt_age_s' => 600 }, r['issued_at'] + 600_001)['reason'].to_s.end_with?(unsigned)],
        ['key set age edge', acc.call({ 'max_keyset_age_s' => 600, 'max_receipt_age_s' => 100_000 }, ks['issued_at'] + 600_000)['reason'].to_s.end_with?(expired)],
        ['key set age over', acc.call({ 'max_keyset_age_s' => 600, 'max_receipt_age_s' => 100_000 }, ks['issued_at'] + 600_001)['reason'].to_s.end_with?(unsigned)]
      ]
    end

    # ---- internal errors fail closed (false), never open: a PQ key set without pq_pk, a disclosed entry that cannot be hashed ----
    def closed_checks
      k = n(holder_case['keySets'][0])
      root = holder_case['holder']['root']
      salt = AtlasPca.b64e("\x07".b * 32)
      leaf = { 'verb' => 'v' }
      h = iv2.map_leaf_hash('header', "\x07".b * 32, leaf)
      commit = iv2.map_commit_of(1, h)
      e = { 'index' => 0, 'salt' => salt, 'leaf' => leaf, 'path' => [] }
      [
        ['key set ok', iv2.verify_sequencer_key_set(k, root) == true],
        ['PQ key set without pq_pk', iv2.verify_sequencer_key_set(k.merge('alg' => 'ml-dsa-65'), root) == false],
        ['PQ key set without pq_pk (public)', AtlasPca.verify_sequencer_key_set(k.merge('alg' => 'hybrid-ed25519-ml-dsa-65'), root) == false],
        ['entry opens', iv2.map_opens?('header', e, 1, commit) == true],
        ['entry other commit', iv2.map_opens?('header', e, 1, iv2.map_commit_of(2, h)) == false],
        ['entry bad salt', iv2.map_opens?('header', e.merge('salt' => 'AAAA'), 1, commit) == false],
        ['entry non-canonical leaf', iv2.map_opens?('header', e.merge('leaf' => { 'x' => 1.5 }), 1, commit) == false],
        ['entry bad path', iv2.map_opens?('header', e.merge('path' => ['x']), 1, commit) == false]
      ]
    end

    def first_bad(checks)
      checks.call.each { |name, ok| return name unless ok == true }
      nil
    rescue StandardError, SystemStackError => e
      "raised #{e.class}: #{e.message[0, 120]}"
    end
  end

  # the signed revocation fixture is built here, by the unmutated library
  V2Targeted.rev_fixture

  [['receipt against holder: min_keyset_version / key sets', -> { V2Targeted.holder_checks }],
   ['verify_pinned_suite', -> { V2Targeted.pinned_checks }],
   ['revocation ids / scopes / goals', -> { V2Targeted.id_checks }],
   ['map commitment of malformed leaf lists', -> { V2Targeted.commit_checks }],
   ['session revocation: non-ASCII ids, append-only, error shape', -> { V2Targeted.revocation_checks }],
   ['committed map pieces: salts, paths, non-ASCII cells', -> { V2Targeted.map_checks }],
   ['grant session caveat on non-objects', -> { V2Targeted.grant_checks }],
   ['session root PQ pin', -> { V2Targeted.root_pin_checks }],
   ['schema / session root / epoch edges', -> { V2Targeted.edge_checks }],
   ['decision around the W-B checks', -> { V2Targeted.decide_checks }],
   ['accumulator receipt / key set age policy (seconds)', -> { V2Targeted.acc_age_checks }],
   ['internal errors fail closed', -> { V2Targeted.closed_checks }]].each do |label, checks|
    t("intent v2 targeted: #{label}") do
      next true if DiffUtil.skip?('intent_v2.rb')

      bad = V2Targeted.first_bad(checks)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
