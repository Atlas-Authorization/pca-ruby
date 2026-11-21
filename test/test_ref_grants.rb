# frozen_string_literal: true

# Replays the TS-reference oracle of the operational plane (test-data/ref-grants.json.gz): signing, bundles, decision log and replay,
# shadow rollout, list-authorized, the grant service and its HTTP binding, lease HTTP and renewal, blueprint group kill and admission,
# freshness helpers. Stateful cases are scenarios (spec in, JSON out). A secret key is a label; its seed is
# sha256("atlas-pca-conformance/" + label). In specs "$key:LABEL" is that key's public key and {"$sign": {kind, label, fields}} the signed record.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/grants'
require_relative '../lib/atlas_pca/grants_list'
require_relative '../lib/atlas_pca/grants_service'
require_relative '../lib/atlas_pca/grants_shadow'
require 'digest'
require 'minitest/autorun'

class TestRefGrants < Minitest::Test
  G = AtlasPca::Grants
  L = AtlasPca::GrantsList
  GS = AtlasPca::GrantsService
  S = AtlasPca::GrantsShadow
  BY_FN = Ref.load('grants')
  T0 = 1_800_000_000_000
  KEYS = {}
  SIGNERS = { 'lease' => :sign_lease, 'leaseOver' => :sign_lease_unsafe_over_cap, 'revocation' => :sign_lease_revocation,
              'blueprint' => :sign_blueprint, 'breakglass' => :sign_break_glass, 'review' => :sign_break_glass_review }.freeze

  def self.seed(label) = Digest::SHA256.digest("atlas-pca-conformance/#{label}")
  def self.sk(label) = (KEYS[label] ||= AtlasPca::KeyPair.new(seed(label)))
  def self.pub(label) = sk(label).public

  def self.resolve(v)
    case v
    when String then v.start_with?('$key:') ? pub(v[5..]) : v
    when Array then v.map { |x| resolve(x) }
    when Hash
      if v.key?('$sign')
        s = v['$sign']
        G.send(SIGNERS.fetch(s['kind']), sk(s['label']), resolve(s['fields']))
      else
        v.transform_values { |x| resolve(x) }
      end
    else v
    end
  end

  def self.err_code(e) = { '$err' => e.respond_to?(:code) && e.code.is_a?(String) ? e.code : 'x' }

  # the reference's JSON round trip drops an undefined member
  def self.strip_nil(v)
    case v
    when Array then v.map { |x| strip_nil(x) }
    when Hash then v.reject { |_, x| x.nil? }.transform_values { |x| strip_nil(x) }
    else v
    end
  end

  def self.safely(fallback = { '$err' => true })
    yield
  rescue StandardError
    fallback
  end

  LOG = lambda do |spec|
    log = G::DecisionLog.new(sk(spec['label']), spec['mask'] || [])
    recs = spec['records'].map { |r| log.append(r) }
    signer = pub(spec['label'])
    head = log.head(spec['now'])
    out = { 'recs' => recs, 'head' => head, 'size' => log.size }
    proofs = (spec['proofs'] || []).map { |i| safely { log.proof(i) } }
    out['proofs'] = proofs
    out['incl'] = (spec['proofs'] || []).zip(proofs).map { |i, p| p['$err'] ? { '$err' => true } : AtlasPca.verify_record_inclusion(recs[i], p, head, signer) }
    out['batches'] = (spec['batches'] || []).map do |b|
      safely do
        bt = G.next_batch(log, b['from'], b['max'], spec['now'])
        st = { 'next' => b['from'], 'lastCommit' => b['from'].zero? ? '' : AtlasPca.record_commit(recs[b['from'] - 1]) }
        tampered = bt['records'].empty? ? bt : bt.merge('records' => [bt['records'][0].merge('at' => 1), *bt['records'][1..]])
        { 'bt' => bt, 'verdict' => AtlasPca.verify_batch(bt, st, signer), 'tampered' => AtlasPca.verify_batch(tampered, st, signer),
          'wrong' => AtlasPca.verify_batch(bt, st, pub('zz')) }
      end
    end
    out
  end

  REPLAY = lambda do |spec|
    dec = ->(t) { ->(i) { t[i] } }
    diff = G.semantic_diff(spec['cases'], dec.call(spec['oldT']), dec.call(spec['newT']))
    audit = G.audit_replay(spec['records'], spec['cases'], ->(i, rev) { spec['revT']["#{i}@#{rev}"] })
    { 'diff' => strip_nil(diff), 'audit' => audit }
  end

  FRESH = lambda do |spec|
    iss = G::FreshAtIssuer.new(sk(spec['label']), spec['scope'], spec['init'])
    last = nil
    spec['steps'].map do |s|
      safely do
        case s['op']
        when 'advance' then last = iss.advance(s['patch'], s['now'])
        when 'check' then iss.check(s['token'] == 'last' ? last : s['token'], s['now'], s['maxAge'])
        when 'current' then iss.current
        when 'tamper' then iss.check(last.merge('policy_revision' => last['policy_revision'] + 1), s['now'])
        end
      end
    end
  end

  SHADOW = lambda do |spec|
    log = S::ShadowLog.new(sk(spec['label']))
    t_of = lambda do |t|
      lambda do |i|
        d = t[i]
        raise 'boom' if d == 'throw'

        d == 'junk' ? 'weird' : d
      end
    end
    out = { 'runs' => [], 'diffs' => {} }
    spec['obs'].each do |ob|
      r = S.run_shadow(ob['input'], t_of.call(spec['enforcedT']), spec['cands'].map { |c| { 'digest' => c['digest'], 'decide' => t_of.call(c['T']) } })
      out['runs'] << { 'decision' => r['decision'], 'shadow' => r['shadow'] }
      r['shadow'].each { |oc| log.observe(spec['enforcedDigest'], ob['action_digest'], r['decision'], oc, ob['at']) }
    end
    out['stats'] = spec['cands'].to_h { |c| [c['digest'], log.stats(c['digest'])] }
    spec['cands'].each { |c| out['diffs'][c['digest']] = log.diffs(c['digest']) }
    out['verify'] = out['diffs'].values.flatten(1).map do |d|
      [S.verify_shadow_diff(d, log.signer), S.verify_shadow_diff(d), S.verify_shadow_diff(d, pub('zz')),
       S.verify_shadow_diff(d.merge('sig' => d['sig'][1..] + 'A'), log.signer), S.verify_shadow_diff(d.merge('at' => d['at'] + 1))]
    end
    out['signer'] = log.signer
    if (g = spec['gate'])
      principals = (g['principals'] || []).map { |p| pub(p) }
      explanations = (g['explain'] || []).map do |e|
        S.sign_widening_explanation(sk(e['label']), { 'shadow_digest' => e['shadow_digest'], 'action_digest' => e['action_digest'], 'reason_digest' => e['reason_digest'] })
      end
      approval = nil
      if g['approval']
        a = g['approval']
        approval = S.sign_promotion_approval(sk(a['label']), { 'shadow_digest' => a['shadow_digest'], 'enforced_digest' => a['enforced_digest'], 'at' => a['at'] })
      end
      out['explanations'] = explanations
      out['approval'] = approval
      opts = g['options'] || {}
      o = opts.merge('principals' => opts['principals'].nil? ? principals : opts['principals'],
                     'explanations' => opts['explanations'].nil? ? explanations : opts['explanations'])
      o['approval'] = approval unless approval.nil?
      out['gate'] = S.promotion_gate(log, o)
      if (p = spec['promote'])
        out['promoted'] = safely do
          gate = p['useGate'] == false ? { 'ok' => false, 'code' => 'bad_input', 'reason' => 'x' } : out['gate']
          S.promote_shadow(p['enforced'], p['candidate'], gate, p['now'])
        end
      end
    end
    out
  end

  LIST = lambda do |spec|
    acc = L::WindowReadAccumulator.new(spec['cap'], spec['windowMs'])
    universe = spec['universe']
    page_of = lambda do |lst, q|
      idx = q.key?('cursor') ? q['cursor'].to_i : 0
      o = { 'objects' => lst[idx, q['limit'] + (spec['overfetch'] ? 3 : 0)] || [] }
      if idx + q['limit'] < lst.length then o['next'] = (idx + q['limit']).to_s
      elsif spec['emptyNext'] then o['next'] = ''
      end
      o
    end
    cand = Object.new
    cand.define_singleton_method(:page) { |q| page_of.call(universe, q) }
    rs = spec['relation']
    allowed = (rs && rs['allowed']) || []
    rel = Object.new
    rel.define_singleton_method(:check) { |q| allowed.include?(q['object']) }
    rel.define_singleton_method(:list_objects) { |q| page_of.call(rs['listed'].nil? ? universe : rs['listed'], q) } if rs && rs['useList']
    permitted = spec['permitted']
    out = []
    cursor = nil
    spec['pages'].times do |p|
      t = spec['tamper'] && p == spec['tamper']['page'] ? spec['tamper'] : nil
      tg = ->(k, d) { t && t.key?(k) ? t[k] : d }
      begin
        cands = rs && rs['asCandidates'] ? L.candidates_from_relation(rel, spec['subject'], rs['name']) : cand
        page = { 'limit' => tg.call('limit', spec['limit']) }
        page['cursor'] = tg.call('cursor', cursor) unless (t && t['dropCursor']) || cursor.nil?
        kw = {}
        kw[:max_scan] = spec['maxScan'] unless spec['maxScan'].nil?
        kw[:relation] = { 'source' => rel, 'relation' => tg.call('relation', rs['name']) } if rs
        r = L.list_authorized(subject: tg.call('subject', spec['subject']), resource_type: spec['type'], permits: ->(x) { permitted.nil? || permitted.include?(x) },
                              candidates: cands, filter_id: tg.call('filterId', spec['filterId']), policy_digest: spec['policyDigest'],
                              fresh_at_digest: spec['freshAt'], page: page, reads: acc,
                              now: T0 + (p * (spec['nowStep'].nil? ? 1 : spec['nowStep'])), signing_key: sk(tg.call('label', spec['label'])), **kw)
        out << r
        cursor = r['next_cursor']
      rescue StandardError => e
        out << { '$err' => (e.respond_to?(:code) && e.code) || 'x' }
        break unless t
      end
    end
    out
  end

  WINDOW = lambda do |cap, win, ops|
    a = L::WindowReadAccumulator.new(cap, win)
    ops.map { |x| a.charge(x['key'], x['units'], x['now']) }
  end

  GRANT = lambda do |spec|
    store = GS::MemoryGrantStore.new
    events = []
    ctr = { 'grant' => 0, 'need' => 0 }
    new_id = lambda do |kind|
      ctr[kind] += 1
      "#{kind == 'grant' ? 'g' : 'n'}_#{ctr[kind]}"
    end
    providers = spec['providers'] ? { 'usage' => ->(g) { { 'rev' => g['rev'] } }, 'remaining_budget' => ->(_g) { { 'left' => 5 } }, 'residual' => ->(g) { { 'id' => g['id'] } } } : nil
    svc = GS::GrantService.new(
      store, -> { T0 }, new_id, providers: providers,
      verify_step_up: spec['stepUp'] ? ->(ref, _g) { ref == 'ok-step' } : nil,
      on_revoke: ->(ids, scope, root) { events << { 'revoked' => ids, 'scope' => scope, 'root' => root['id'] } },
      on_change: ->(kind, g) { events << { 'change' => kind, 'id' => g['id'], 'rev' => g['rev'] } },
      validate_need: spec['validateNeed'] ? ->(nd) { nd['verb'] == 'forbidden' ? 'verb not allowed' : nil } : nil
    )
    handler = GS.grant_resource_handler(svc, ->(req) { req['who'] })
    sec = ->(by) { { 'principal' => sk('$P'), 'holder' => sk('$A'), 'wrongkey' => sk('$X') }.fetch(by) }
    steps = spec['steps'].map do |raw|
      s = resolve(raw)
      begin
        case s['op']
        when 'register' then svc.register(s['grant'])
        when 'list' then svc.list(s['filter'] || {})
        when 'inspect' then svc.inspect(s['id'])
        when 'amend'
          g = svc.inspect(s['id'])
          req = { 'action' => s['action'], 'authority' => s['authority'] }
          unless s['by'] == 'none'
            req['signed_by'] = s['signed_by'] || (s['by'] == 'holder' ? 'holder' : 'principal')
            req['sig'] = GS.sign_grant_body(AtlasPca::GRANT_AMEND_DOMAIN, AtlasPca.amend_message(g, s['action'], s['authority']), sec.call(s['by']))
          end
          req['step_up_ref'] = s['stepUp'] if s['stepUp']
          svc.amend(s['id'], req)
        when 'revoke'
          g = svc.inspect(s['id'])
          auth = if s['by'] == 'admin' then { 'admin' => true }
                 elsif s['by'] == 'noauth' then {}
                 else { 'sig' => GS.sign_grant_body(AtlasPca::GRANT_REVOKE_DOMAIN, AtlasPca.grant_revoke_message(g['id'], s['scope']), sec.call(s['by'])) }
                 end
          svc.revoke(s['id'], s['scope'], auth)
        when 'needs' then svc.request_needs(s['id'], s['needs'])
        when 'approve'
          nid = svc.need_grant_id(s['needId'])
          g = svc.inspect(nid)
          sig = GS.sign_grant_body(AtlasPca::NEED_APPROVE_DOMAIN, AtlasPca.need_approve_message({ 'id' => s['needId'], 'grant_id' => nid }, g['rev'], s['approved']), sec.call(s['by']))
          svc.approve_needs(s['needId'], s['approved'], sig, s['stepUp'])
        when 'deny' then svc.deny_needs(s['needId'])
        when 'http' then handler.call(s.slice('method', 'path', 'query', 'body', 'who'))
        else raise ArgumentError, 'bad op'
        end
      rescue StandardError => e
        err_code(e)
      end
    end
    { 'steps' => steps, 'events' => events, 'grants' => store.list.sort_by { |g| AtlasPca.utf16_key(g['id']) } }
  end

  def self.strip_msg(x) = x.is_a?(Hash) ? x.reject { |k, _| %w[reason message].include?(k) } : x

  LEASE = lambda do |spec|
    reg = AtlasPca::LeaseRegistry.new({ 'authorities' => [pub('auth')] }.merge(spec['policy'] || {}), AtlasPca::MemoryAtomicKv.new, shards: spec['shards'] || 4, clock: -> { T0 })
    handler = GS.lease_resource_handler(reg, ->(req) { req['who'] }, -> { T0 })
    spec['steps'].map do |raw|
      s = resolve(raw)
      begin
        case s['op']
        when 'accept' then strip_msg(reg.accept(s['lease'], s['chain'] || []))
        when 'revoke' then reg.revoke(s['rev'])
        when 'get' then reg.get(s['id'])
        when 'history' then reg.history(s['id'])
        when 'shardRevs' then reg.shard_revocations(s['i'])
        when 'renew'
          veto = s['vetoSeq'].nil? ? nil : ->(c) { c['seq'] >= s['vetoSeq'] }
          r = G.renew_lease(sk(s['label'] || 'auth'), reg, s['id'], s['now'], s['increment'], s['just'], approvers: s['approvers'], veto: veto, chain: s['chain'])
          r['ok'] ? r : { 'ok' => false, 'code' => r['code'] }
        when 'check' then AtlasPca.check_lease(s['lease'], reg, s['now'])
        when 'http'
          res = handler.call(s.slice('method', 'path', 'query', 'body', 'who'))
          { 'status' => res['status'], 'body' => strip_msg(res['body']) }
        else raise ArgumentError, 'bad op'
        end
      rescue StandardError => e
        err_code(e)
      end
    end
  end

  BLUEPRINT = lambda do |spec|
    reg = AtlasPca::BlueprintRegistry.new([pub('op')], AtlasPca::MemoryAtomicKv.new)
    adm = G::AdmissionRegistry.new
    revoked = []
    revoker = Object.new
    revoker.define_singleton_method(:revoke) { |i| revoked << i }
    fresh = G::FreshAtIssuer.new(sk('iss'), 'scope', { 'revocation_epoch' => 0, 'ledger_tree_size' => 0, 'budget_version' => 0, 'policy_revision' => 0, 'policy_digest' => 'pd' })
    spec['steps'].map do |raw|
      s = resolve(raw)
      begin
        case s['op']
        when 'accept' then reg.accept(s['bp'])
        when 'epoch' then reg.epoch
        when 'kill'
          reason = s['reason']
          G.group_kill(sk(s['label'] || 'op'), reg, s['key'], s['now'], reason: reason.nil? || reason == '' ? nil : reason,
                                                                       revocation: s['revoker'] ? revoker : nil, fresh_at: s['fresh'] ? fresh : nil)
        when 'revoked' then revoked.dup
        when 'admit'
          adm.admit(s['instance'], reg.get(s['key']), s['until'])
          true
        when 'admitRevoke' then adm.revoke(s['instance'], s['key'])
        when 'admitCheck' then adm.checker(s['now']).call(s['instance'], reg.get(s['key']))
        else raise ArgumentError, 'bad op'
        end
      rescue StandardError => e
        err_code(e)
      end
    end
  end

  ADMIT = lambda do |bp, e|
    G.admit_with_evidence(bp, lambda {
      raise TypeError, 'boom' if e.is_a?(Hash) && e['$throw']

      e
    })
  end

  MAP = {
    'signerOf' => ->(label) { G.signer_of(sk(label)) },
    'signBody' => ->(dom, body, label) { G.sign_body(dom, body, sk(label)) },
    'verifyBody' => ->(dom, body, signer, sig) { G.verify_domain_body(dom, body, signer, sig) },
    'signLease' => ->(label, r) { G.sign_lease(sk(label), r) },
    'signLeaseUnsafeOverCap' => ->(label, r) { G.sign_lease_unsafe_over_cap(sk(label), r) },
    'signLeaseRevocation' => ->(label, r) { G.sign_lease_revocation(sk(label), r) },
    'signBlueprint' => ->(label, r) { G.sign_blueprint(sk(label), r) },
    'signBreakGlass' => ->(label, r) { G.sign_break_glass(sk(label), r) },
    'signBreakGlassReview' => ->(label, r) { G.sign_break_glass_review(sk(label), r) },
    'signBundle' => ->(body, label) { G.sign_bundle(body, sk(label)) },
    'assembleBundle' => ->(body, sigs) { G.assemble_bundle(body, sigs) },
    'maskRecord' => ->(r, mask) { G.mask_record(r, mask) },
    'mergeFreshAt' => ->(a, b) { G.merge_fresh_at(a, b) },
    'gateDecision' => ->(d, v) { G.gate_decision(d, v) },
    'logScenario' => LOG, 'replayScenario' => REPLAY, 'freshScenario' => FRESH, 'shadowScenario' => SHADOW, 'listScenario' => LIST,
    'windowAcc' => WINDOW, 'grantScenario' => GRANT, 'leaseScenario' => LEASE, 'blueprintScenario' => BLUEPRINT, 'admitWithEvidence' => ADMIT
  }.freeze


  def test_sign_domain_body_is_sign_body_over_a_key_or_a_seed
    seed = "\x05".b * 32
    k = AtlasPca::KeyPair.new(seed)
    want = G.sign_body('d', { 'a' => 1 }, k)
    assert_equal want, G.sign_domain_body('d', { 'a' => 1 }, k)
    assert_equal want, G.sign_domain_body('d', { 'a' => 1 }, seed)
    assert G.verify_domain_body('d', { 'a' => 1 }, k.public, want)
  end

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  def test_lease_store_conformance_over_memory_kv
    passed = G.run_lease_store_conformance(-> { AtlasPca::MemoryAtomicKv.new }, reopen: ->(kv) { kv })
    assert_includes passed, 'spread'
    assert_includes passed, 'pruning bounds revocations'
  end

  def test_grant_client_folds_only_newer_tokens
    sk = self.class.sk('c')
    iss = G::FreshAtIssuer.new(sk, 'scope', { 'revocation_epoch' => 1, 'ledger_tree_size' => 1, 'budget_version' => 1, 'policy_revision' => 1, 'policy_digest' => 'pd' })
    t1 = iss.advance({ 'revocation_epoch' => 2 }, T0)
    sent = []
    toks = [t1, t1.merge('revocation_epoch' => 0), t1.merge('sig' => 'x')]
    fetch = lambda do |req|
      sent << req
      { 'status' => 200, 'headers' => { 'Pca-Fresh-At' => JSON.generate(toks.shift) }, 'body' => '{"grants":[]}' }
    end
    c = GS.create_grant_client('https://as.example/', fetch, sk.public)
    c.list({ 'status' => 'active', 'limit' => 5 })
    assert_equal 'https://as.example/pca/grants?status=active&limit=5', sent[0]['url']
    assert_equal 2, c.fresh_at['revocation_epoch']
    c.inspect('a/b')
    c.inspect('a/b')
    assert_equal t1, c.fresh_at
    assert sent[1]['url'].end_with?('/pca/grants/a%2Fb')
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2767, BY_FN.values.sum(&:length), 'grants'
  end

end
