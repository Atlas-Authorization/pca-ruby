# frozen_string_literal: true

# Runs one producer vector case (producer-vectors.json and producer-pq-vectors.json format) through this gem's producers.
#
# Shared by the producer tests and the cross-language driver: ProducerOps.run(case, keys, pq_keys) returns the produced
# artifact, shaped like the case's `expect` (the reference's member names), or raises what the producer raised. `keys` maps a
# key name to an Ed25519 KeyPair, `pq_keys` is a ProducerOps::PqKeys over the file's PQ seed entries. An op this gem does not
# know raises ProducerOps::NotProduced.
require_relative '../../lib/atlas_pca'
require 'json'

module ProducerOps
  # The op names an artifact this gem does not produce.
  class NotProduced < StandardError; end

  # The reference names PQ families in lower case.
  FAMILIES = { 'ml-dsa-65' => 'ML-DSA-65', 'ml-dsa-87' => 'ML-DSA-87', 'slh-dsa-sha2-128f' => 'SLH-DSA-SHA2-128f',
               'slh-dsa-sha2-256s' => 'SLH-DSA-SHA2-256s', 'fn-dsa-512' => 'FN-DSA-512', 'fn-dsa-1024' => 'FN-DSA-1024' }.freeze

  # Seeded PQ key pairs by name (`<role>/<family>`), derived once.
  class PqKeys
    def initialize(entries)
      @entries = entries || {}
      @cache = {}
    end

    def [](name)
      return nil if name.nil?

      @cache[name] ||= ProducerOps.pq_key(@entries.fetch(name))
    end
  end

  module_function

  def keys_of(doc_keys) = doc_keys.transform_values { |k| AtlasPca::KeyPair.from_seed_b64u(k['seed']) }

  # A seed entry {family, seed}: a family this gem cannot sign answers unsupported_suite, never a different key.
  def pq_key(entry)
    fam = entry['family']
    prim = FAMILIES.fetch(fam, fam)
    raise AtlasPca::UnsupportedSigner, "unsupported_suite: #{fam}" unless AtlasPca::PQ_SEED_BYTES.key?(prim)

    AtlasPca::PqKeyPair.from_seed(prim, AtlasPca.b64d(entry['seed']) || raise(ArgumentError, 'a PQ seed is canonical base64url'))
  end

  def parts(sig, pq_sig) = pq_sig.nil? ? { 'sig' => sig } : { 'sig' => sig, 'pq_sig' => pq_sig }

  def facade_act(a, k)
    rec = k.(a['recorder_key'])
    h = AtlasPca.create_agent(principal: k.(a['principal']), goal: a['goal'], permissions: a['permissions'], limits: a['limits'],
                              holder: k.(a['holder']), aud: a['aud'], now: a['now'], goal_salt: a['goal_salt'],
                              provenance: { key: rec, session: a['session'], now: -> { a['now'] } })
    grant = h.grant
    h = h.sub_agent(holder: k.(a['sub_agent']['holder']), added_caveats: a['sub_agent']['added_caveats']) if a['sub_agent']
    (a['principal_messages'] || []).each { |t| h.provenance.principal(t) }
    act = a['act']
    r = h.act(act['verb'], act['resource'], act['params'], counter: act['counter'], now: act['now'], nonce: act['nonce'])
    { 'grant' => grant, 'goal_commit' => grant['caveats'][0]['goal_commit'], 'chain' => h.chain, 'pcactn' => r['pcactn'],
      'encoded' => r['encoded'], 'provenance' => r['provenance'] }
  end

  def prov_recorder(a, k)
    clock = a['clock'].dup
    r = AtlasPca::ProvenanceRecorder.new(mediator: a['mediator'], kid: a['kid'], key: k.(a['key']), session: a['session'],
                                         now: -> { clock.shift })
    outs = a['steps'].map do |s|
      case s['kind']
      when 'principal' then r.principal(s['text'])
      when 'tool' then r.tool(s['name'], s['output'])
      when 'web' then r.web(s['url'], s['content'])
      when 'retrieval' then r.retrieval(s['source'], s['content'])
      else r.for_action(s['op'])
      end
    end
    { 'pin' => r.pin, 'receipts' => outs[0...-1], 'bundle' => outs[-1] }
  end

  def act(a, k)
    extra = %w[nonce caution rationale_commitment tool_binding fresh_at].to_h { |n| [n, a[n]] }
    p = AtlasPca.build_pcactn(grant: a['grant'], chain: a['chain'], plan: a['plan'], node_id: a['node_id'], counter: a['counter'],
                              signer: k.(a['signer']), aud: a['aud'], params: a['params'], iat: a['iat'], exp: a['exp'], extra: extra)
    { 'pcactn' => p, 'header' => AtlasPca.pca_headers(p)['PCA-Action'] }
  end

  def artifact_suite(a, k, pq)
    b = a['body']
    if a['kind'] == 'escalation_answer'
      return AtlasPca.sign_escalation_answer(k.(a['signer']), b, b['decision'], b['iat'], b['expires_at'], nonce: b['nonce'], alg: a['alg'],
                                                                                                         pq: pq[a['pq']])
    end
    AtlasPca.sign_revocation_epoch(k.(a['signer']), b, alg: a['alg'], pq: pq[a['pq']])
  end

  # The artifact `c['op']` produces from `c['args']`.
  def run(c, keys, pq = PqKeys.new(nil))
    a = c['args']
    k = ->(n) { keys.fetch(n) }
    hpq = ->(n) { n.nil? ? nil : pq[n].public }
    case c['op']
    # ---- producer-vectors.json: Ed25519 -------------------------------------------------------------------------------
    when 'ed25519_sign'
      kp = AtlasPca::KeyPair.from_seed_b64u(a['seed'])
      { 'public' => kp.public, 'sig' => AtlasPca.b64e(kp.sign(a['message_utf8'].b)) }
    when 'goal_commit' then { 'commit' => AtlasPca.goal_commit_of(a['goal'], a['salt']) }
    when 'params_digest' then { 'digest' => AtlasPca.params_digest(a['params']) }
    when 'plan_commit' then AtlasPca.commit_plan(a['nodes'])
    when 'mint_grant' then AtlasPca.mint_grant(k.(a['principal']), k.(a['holder']).public, a['envelope'], a['goal'], salt: a['salt'])
    when 'delegate'
      AtlasPca.delegate_cap(a['parent'], k.(a['signer']), to_holder: a['to_holder'] && k.(a['to_holder']).public, added: a['added_caveats'])
    when 'act' then act(a, k)
    when 'fresh_at' then AtlasPca.sign_fresh_at(k.(a['signer']), a['scope'], a['state'], a['issued_at'])
    when 'escalation_digests'
      { 'policy_digest' => AtlasPca.escalation_policy_digest(a['grant']), 'action_digest' => AtlasPca.escalation_action_digest(a['pcactn']),
        'history_head' => AtlasPca.escalation_history_head(a['last_counter']) }
    when 'sign_escalation_answer'
      b = a['body']
      AtlasPca.sign_escalation_answer(k.(a['signer']), b, b['decision'], b['iat'], b['expires_at'], nonce: b['nonce'])
    when 'sign_discharge'
      b = a['body']
      AtlasPca.sign_discharge(k.(a['signer']), b['caveat_id'], b['issuer'], b['cap_hash'], b['claims'], b['iat'], b['not_after'],
                              bind: b['bind'], action_digest: b['action_digest'], nonce: b['nonce'])
    when 'discharge_digest' then { 'digest' => AtlasPca.discharge_digest(a['discharge']) }
    when 'sign_narrow'
      b = a['body']
      AtlasPca.sign_narrow(k.(a['signer']), b['cap_hash'], b['caveats'], b['iat'], b['not_after'], action_digest: b['action_digest'], nonce: b['nonce'])
    when 'sign_passport'
      pp = AtlasPca.issue_passport(a['identity'])
      { 'passport' => pp, 'signed' => AtlasPca.sign_passport(pp, k.(a['issuer']), k.(a['subject']).public, a['exp']) }
    when 'sign_workflow' then AtlasPca.sign_workflow(k.(a['signer']), a['body'])
    when 'sign_step_receipt'
      AtlasPca.sign_step_receipt(k.(a['signer']), a['workflow'], a['step'], a['outcome'], a['params_digest'], a['outputs'], a['issued_at'], prev: a['prev'])
    when 'sign_read_grant' then AtlasPca.sign_read_grant(k.(a['signer']), a['body'])
    when 'sign_aggregate_grant' then AtlasPca.sign_aggregate_grant(k.(a['signer']), a['body'])
    when 'sign_revocation_epoch' then AtlasPca.sign_revocation_epoch(k.(a['signer']), a['body'])
    when 'sign_undo_token' then AtlasPca.sign_undo_token(a['record'], k.(a['signer']))
    when 'sign_undo_receipt' then AtlasPca.sign_undo_receipt(a['body'], k.(a['signer']))
    when 'sign_contract' then AtlasPca::Contracts.sign_contract(a['contract'], k.(a['signer']))
    when 'sign_contract_reset' then { 'sig' => AtlasPca::Contracts.sign_contract_reset(k.(a['signer']), a['contract_id'], a['seq']) }
    when 'sign_constitution' then AtlasPca::Prohibitions.sign_constitution(a['constitution'], k.(a['signer']))
    when 'sign_safety_evidence' then AtlasPca::Prohibitions.sign_safety_evidence(a['evidence'], k.(a['signer']))
    when 'sign_threshold_share'
      AtlasPca.sign_threshold_share(a['role'], k.(a['signer']), AtlasPca.b64d(a['message']), a['signer_set'], a['t'])
    when 'sign_prepared_share' then AtlasPca.sign_prepared_share(a['role'], k.(a['signer']), AtlasPca.b64d(a['prepared']))
    when 'sign_pq_binding' then AtlasPca.sign_pq_binding(k.(a['signer']), a['pq_pk'], a['epoch'], a['aud'])
    when 'sign_caution' then AtlasPca.sign_caution(a['body'], k.(a['signer']))
    when 'sign_heartbeat' then AtlasPca.sign_heartbeat(a['body'], k.(a['signer']))
    when 'prov_recorder' then prov_recorder(a, k)
    when 'sign_mesh_action' then { 'sig' => AtlasPca.sign_mesh_action(a['chain'], a['action'], k.(a['signer'])) }
    when 'sign_session_root' then AtlasPca.sign_session_root(a['body'], k.(a['signer']))
    when 'mint_session_grant'
      AtlasPca.mint_session_grant(k.(a['principal']), k.(a['holder']).public, session: a['session'], seq: a['seq'], root: a['root'],
                                                                              map_digest: a['map_digest'], predicates: a['predicates'], prev: a['prev'],
                                                                              map_form: a['map_form'], caveats: a['caveats'], salt: a['salt'])
    when 'sign_action_schema' then AtlasPca.sign_action_schema(a['doc'], a['kid'], k.(a['signer']))
    when 'sign_intent_required' then AtlasPca.sign_intent_required(a['body'], a['kid'], k.(a['signer']))
    when 'sign_labels' then AtlasPca.sign_labels(a['body'], k.(a['signer']))
    when 'sign_fact' then AtlasPca.sign_fact(a['body'], k.(a['signer']))
    when 'sign_offer_set' then AtlasPca.sign_offer_set(a['body'], k.(a['signer']))
    when 'sign_progress_step' then AtlasPca.sign_progress_step(a['step'], k.(a['signer']))
    when 'sign_read_receipt'
      AtlasPca.sign_read_receipt(k.(a['signer']), a['grant'], a['verb'], a['resource'], a['purpose'], a['fields'], a['labels'], a['issued_at'],
                                 prev: a['prev'])
    when 'sign_template' then AtlasPca.sign_template(a['def'], k.(a['signer']))
    when 'sign_tighten' then AtlasPca.sign_tighten(a['overlay'], k.(a['signer']))
    when 'parse_limit' then AtlasPca.parse_limit(a['limit'])
    when 'compile_policy'
      AtlasPca.compile_policy(a['permissions'], a['limits'], budget_model: a['budget_model'], now: a['now']).reject { |n, _| %w[actions inputLimits].include?(n) }
    when 'facade_act' then facade_act(a, k)
    # ---- producer-pq-vectors.json: every suite ------------------------------------------------------------------------------
    when 'pq_keygen' then { 'public' => pq_key(a).public }
    when 'suite_sign' then parts(*AtlasPca.sign_with_suite(a['alg'], a['ed'] && k.(a['ed']), pq[a['pq']], a['message_utf8'].b))
    when 'mint_root_suite'
      AtlasPca.mint_root(k.(a['principal']), k.(a['holder']).public, a['caveats'], holder_pq: hpq.(a['holder_pq']), alg: a['alg'], pq: pq[a['pq']])
    when 'delegate_suite'
      AtlasPca.delegate_cap(a['parent'], k.(a['signer']), to_holder: a['to_holder'] && k.(a['to_holder']).public, added: a['added_caveats'],
                                                          holder_pq: hpq.(a['holder_pq']), alg: a['alg'], pq: pq[a['pq']])
    when 'sign_pcactn_suite' then { 'pcactn' => AtlasPca.sign_pcactn(a['body'], k.(a['signer']), alg: a['alg'], pq: pq[a['pq']]) }
    when 'sign_artifact_suite' then artifact_suite(a, k, pq)
    else raise NotProduced, c['op']
    end
  end

  # ---- replays shared by the producer tests and the mutation-kill registry (keys passed in, built at call time) -------------

  def jsonify(v) = JSON.parse(JSON.generate(v))

  # Names of the producer-vectors.json cases this gem does not reproduce exactly (a refusal must carry the reference's text).
  def v1_problems(doc, keys)
    doc['cases'].filter_map do |c|
      want = c['op'] == 'act' ? c['expect'].reject { |k, _| k == 'threshold_message' } : c['expect']
      refusal = want.keys == ['error']
      begin
        got = run(c, keys)
      rescue StandardError => e
        # the canonical profile's wording is per-language: a reference canonicalize refusal only has to refuse
        next refusal && (e.message == want['error'] || want['error'].start_with?('canonicalize: ')) ? nil : "#{c['name']}: #{e.class}: #{e.message}"
      end
      next "#{c['name']}: signed what the reference refuses" if refusal

      jsonify(got) == jsonify(want) ? nil : c['name']
    end
  end

  # The PQ primitive a producer-pq-vectors.json case needs (nil: Ed25519 only).
  def pq_family_of(c)
    a = c['args']
    return FAMILIES.fetch(a['family'], a['family']) if c['op'] == 'pq_keygen'

    AtlasPca::SIG_SUITES.fetch(a['alg'], [])[3]
  end

  # producer-pq-vectors.json: every case that lists this gem in `exact` byte for byte (and signing twice gives the same bytes);
  # a suite outside this gem (FN-DSA) is refused with unsupported_suite, never signed differently. `required`: a case whose PQ
  # primitive this runtime lacks is a problem, not a skip. Returns {problems, refused (case names), ran}.
  def pq_replay(doc, required)
    ed = keys_of(doc['ed_keys'])
    pq = PqKeys.new(doc['pq_keys'])
    bad = []
    refused = []
    ran = 0
    doc['cases'].each do |c|
      unless c['exact'].include?('ruby')
        begin
          run(c, ed, pq)
          bad << "#{c['name']}: signed a suite outside this gem"
        rescue AtlasPca::UnsupportedSigner => e
          refused << c['name']
          bad << "#{c['name']}: #{e.message}" unless e.message.start_with?('unsupported_suite: ')
        end
        next
      end
      prim = pq_family_of(c)
      unless prim.nil? || AtlasPca.pq_prim_available?(prim)
        bad << "#{c['name']}: #{prim} signing is required" if required
        next
      end
      got = jsonify(run(c, ed, pq))
      ran += 1
      if got != c['expect']
        bad << c['name']
      elsif c['op'] == 'suite_sign' && jsonify(run(c, ed, pq)) != got
        bad << "#{c['name']}: signing twice gave different bytes"
      end
    end
    want_refused = doc['cases'].reject { |c| c['exact'].include?('ruby') }.map { |c| c['name'] }.sort
    bad << "refused #{refused.sort} != #{want_refused}" unless refused.sort == want_refused
    { 'problems' => bad, 'refused' => refused, 'ran' => ran }
  end

  # ---- natives -> reference: this gem's own signed artifacts for the reference verifier ---------------------------------------

  NATIVE_AUD = 'rs-ruby-producer'
  NATIVE_NOW = 1_800_000_000_000 + 1000

  def vector_args(doc, name) = doc['cases'].find { |c| c['name'] == name }.fetch('args')

  def pins(key, pq = nil, **extra)
    p = extra.transform_keys(&:to_s).merge('pk' => key.public)
    p['pq_pk'] = pq.public if pq
    p
  end

  # One PCActn per suite this runtime signs (and one from a delegated sub-agent under each), one facade act with params, and
  # each artifact kind under Ed25519 and, when available, a hybrid ML-DSA suite. `doc` is producer-vectors.json, `keys` its keys.
  def native_cases(doc, keys)
    t0 = NATIVE_NOW - 1000
    principal = keys['principal']
    agent_key = keys['agent']
    env = { 'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }], 'caveats' => [], 'agent_binding' => {},
            'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY }
    cases = []
    suites = AtlasPca::SIG_SUITES.select { |a, s| a == 'ed25519' || (AtlasPca::PQ_SEED_BYTES.key?(s[3]) && AtlasPca.pq_prim_available?(s[3])) }.keys.sort
    suites.each_with_index do |alg, i|
      prim = AtlasPca::SIG_SUITES[alg][3]
      pq = prim && AtlasPca::PqKeyPair.from_seed(prim, [i + 1].pack('C') * AtlasPca::PQ_SEED_BYTES[prim])
      grant = AtlasPca.mint_grant(principal, agent_key.public, env, 'refund an order', salt: 's', holder_pq: pq&.public)['grant']
      a = AtlasPca::Agent.new(agent_key, grant, NATIVE_AUD, clock: -> { t0 }, alg: prim && alg, pq: pq)
      cases << { 'kind' => 'pcactn', 'alg' => alg, 'grant' => grant, 'pcactn' => a.act('refund', 'orders/1', { 'amount' => 5 }).pcactn }
      sub = a.delegate(keys['subagent'], [{ 'type' => 'budget_alloc', 'limit' => 5 }])
      cases << { 'kind' => 'pcactn', 'alg' => alg, 'grant' => grant, 'pcactn' => sub.act('refund', 'orders/2', { 'amount' => 1 }).pcactn }
    end
    h = AtlasPca.create_agent(principal: principal, goal: 'refund order 1', permissions: { 'stripe' => ['refund'] },
                              limits: { 'refund' => '$500/day' }, holder: agent_key, aud: NATIVE_AUD, now: t0)
    h.provenance.principal('refund order 1')
    cases << { 'kind' => 'pcactn', 'alg' => 'ed25519', 'grant' => h.grant,
               'pcactn' => h.act('stripe.refund', 'charge:ch_1', { 'amount' => 42, 'currency' => 'usd' }, now: t0)['pcactn'] }

    variants = [['ed25519', nil, nil]]
    if AtlasPca.pq_prim_available?('ML-DSA-65')
      variants << ['hybrid-ed25519-ml-dsa-65', AtlasPca::PqKeyPair.from_seed('ML-DSA-65', "\x2a".b * 32),
                   AtlasPca::PqKeyPair.from_seed('ML-DSA-65', "\x2b".b * 32)]
    end
    site = keys['site']
    variants.each do |alg, pq, pq2|
      a = alg == 'ed25519' ? nil : alg
      b = vector_args(doc, 'escalation-answer-allow')['body']
      cases << { 'kind' => 'escalation_answer', 'alg' => alg, 'pins' => pins(principal, pq),
                 'artifact' => AtlasPca.sign_escalation_answer(principal, b, b['decision'], b['iat'], b['expires_at'], nonce: b['nonce'], alg: a, pq: pq) }
      cases << { 'kind' => 'revocation_epoch', 'alg' => alg, 'pins' => pins(keys['guardian'], pq2),
                 'artifact' => AtlasPca.sign_revocation_epoch(keys['guardian'], vector_args(doc, 'revocation-epoch')['body'], alg: a, pq: pq2) }
      cases << { 'kind' => 'session_root', 'alg' => alg, 'pins' => pins(principal, pq),
                 'artifact' => AtlasPca.sign_session_root(vector_args(doc, 'session-root')['body'], principal, alg: a, pq: pq) }
      cases << { 'kind' => 'action_schema', 'alg' => alg, 'pins' => pins(site, pq2, kid: 'site-k1', alg: alg),
                 'artifact' => AtlasPca.sign_action_schema(vector_args(doc, 'action-schema')['doc'], 'site-k1', site, alg: a, pq: pq2) }
      cases << { 'kind' => 'intent_required', 'alg' => alg, 'pins' => pins(site, pq2, kid: 'site-k1', alg: alg),
                 'artifact' => AtlasPca.sign_intent_required(vector_args(doc, 'intent-required')['body'], 'site-k1', site, alg: a, pq: pq2) }
      lb = vector_args(doc, 'labels')['body']
      cases << { 'kind' => 'labels', 'alg' => alg, 'pins' => pins(site, pq2, kid: lb['kid'], site: lb['site']),
                 'artifact' => AtlasPca.sign_labels(lb, site, alg: a, pq: pq2) }
      cases << { 'kind' => 'fact', 'alg' => alg, 'pins' => pins(keys['oracle'], pq),
                 'artifact' => AtlasPca.sign_fact(vector_args(doc, 'fact-integer')['body'], keys['oracle'], alg: a, pq: pq) }
    end
    cases << { 'kind' => 'caution', 'alg' => 'ed25519', 'pins' => pins(agent_key),
               'artifact' => AtlasPca.sign_caution(vector_args(doc, 'caution-reason')['body'], agent_key) }
    cases << { 'kind' => 'pq_binding', 'alg' => 'ed25519', 'pins' => pins(agent_key),
               'artifact' => AtlasPca.sign_pq_binding(agent_key, vector_args(doc, 'pq-binding')['pq_pk'], 1, NATIVE_AUD) }
    { 'lang' => 'ruby', 'aud' => NATIVE_AUD, 'now' => NATIVE_NOW, 'cases' => cases }
  end

  # This gem's own verifier for each kind (the reference checks the same file).
  def native_ok?(c, out)
    a = c['artifact']
    p = c['pins'] || {}
    pq_pins = p.key?('pq_pk') ? { p['pk'] => p['pq_pk'] } : {}
    pin = p.slice('pk', 'pq_pk')
    undef_ = AtlasPca::V2JS::UNDEF
    case c['kind']
    when 'pcactn'
      AtlasPca.verify_pcactn(c['pcactn'], c['grant'], now: out['now'], audience: out['aud'], insecure_skip_plan_root_check: true).allow == true
    when 'escalation_answer'
      AtlasPca.verify_escalation_answer(a, [pin], a.slice('policy_digest', 'action_digest', 'history_head'), out['now'])[:ok] == true
    when 'revocation_epoch' then AtlasPca.check_revocation_epoch(a, p['pk'], out['now'], undef_, pq_pins)['ok'] == true
    when 'session_root' then AtlasPca.verify_session_root(a, pq_pins)['ok'] == true
    when 'action_schema' then AtlasPca.verify_action_schema(a, [p.slice('kid', 'alg', 'pk', 'pq_pk')])['ok'] == true
    when 'intent_required' # no verifier in this gem (host / wallet tooling): the site signature under the pinned key, the expiry
      msg = AtlasPca::INTENT_REQUIRED_DOMAIN.b + AtlasPca.strict_bytes(a.reject { |k, _| k == 'sig' })
      s = a['sig']
      s['kid'] == p['kid'] && s['alg'] == p['alg'] && out['now'] <= a['expires_at'] &&
        AtlasPca::IntentV2.verify_pinned_suite(p['alg'], p['pk'], p.fetch('pq_pk', undef_), msg, s['value'], s.fetch('pq_value', undef_), pq_pins) == true
    when 'labels' then AtlasPca.verify_labels(a, [pin.merge(p.slice('site', 'kid'))]).nil?
    when 'fact' then AtlasPca.validate_fact_wire(a).nil? && AtlasPca.wb_verify_artifact_sig(AtlasPca::FACT_DOMAIN, a, pin) == true
    when 'caution'
      a['holder'] == p['pk'] &&
        AtlasPca.verify_b64u(p['pk'], AtlasPca.domain_body_bytes(AtlasPca::CAUTION_DOMAIN, a.reject { |k, _| k == 'sig' }), a['sig']) == true
    when 'pq_binding' then !AtlasPca.pq_pin_for(a, out['aud']).nil?
    else false
    end
  end

  def flip(s) = s[10] == 'A' ? "#{s[0, 10]}B#{s[11..]}" : "#{s[0, 10]}A#{s[11..]}"

  # The same case with one signature character changed: the PQ half when present, else the classical one.
  def tamper(c)
    x = jsonify(c)
    if c['kind'] == 'pcactn'
      f = x['pcactn'].key?('pq_sig') ? 'pq_sig' : 'sig'
      x['pcactn'][f] = flip(x['pcactn'][f])
    elsif %w[action_schema intent_required].include?(c['kind'])
      f = x['artifact']['sig'].key?('pq_value') ? 'pq_value' : 'value'
      x['artifact']['sig'][f] = flip(x['artifact']['sig'][f])
    else
      f = x['artifact'].key?('pq_sig') ? 'pq_sig' : 'sig'
      x['artifact'][f] = flip(x['artifact'][f])
    end
    x
  end

  NATIVE_KINDS = %w[action_schema caution escalation_answer fact intent_required labels pcactn pq_binding revocation_epoch session_root].freeze

  # Everything wrong with a native producer document: a missing kind, an artifact this gem does not verify, a tampered one it
  # does, a sub-agent that is not a delegated hop, a PQ sub-agent signing with its parent's key or an uncommitted one, the facade
  # act's node and params digest. `required`: the hybrid and SLH-DSA suites must be present.
  def native_problems(out, required)
    cs = out['cases']
    bad = []
    bad << "kinds #{cs.map { |c| c['kind'] }.uniq.sort}" unless cs.map { |c| c['kind'] }.uniq.sort == NATIVE_KINDS
    cs.each { |c| bad << "#{c['kind']} #{c['alg']}" unless native_ok?(c, out) }
    cs.each { |c| bad << "tampered #{c['kind']} #{c['alg']} verified" if native_ok?(tamper(c), out) }
    pcs = cs.select { |c| c['kind'] == 'pcactn' }
    subs = pcs.select { |c| c['pcactn']['cap_chain'].length == 2 }
    bad << "#{subs.length} sub-agent actions of #{pcs.length}" unless subs.length == (pcs.length - 1) / 2
    subs.each do |c|
      next if c['alg'] == 'ed25519'

      parent = pcs[pcs.index(c) - 1]
      bad << "#{c['alg']} sub-agent pq key not committed" unless AtlasPca.holder_pq_commitment(c['pcactn']['pq_pk']) == c['pcactn']['cap_chain'][-1]['holder_pq']
      bad << "#{c['alg']} sub-agent signs with the parent's pq key" if parent['pcactn']['pq_pk'] == c['pcactn']['pq_pk']
    end
    f = pcs.last['pcactn']
    unless [f['plan']['node_id'], f['action']['params_digest']] == ['n0', AtlasPca.params_digest({ 'amount' => 42, 'currency' => 'usd' })]
      bad << 'facade act node / params digest'
    end
    algs = cs.map { |c| c['alg'] }
    bad << 'hybrid and SLH-DSA suites missing' if required && !(algs.include?('hybrid-ed25519-ml-dsa-65') && algs.include?('slh-dsa-sha2-256s'))
    bad
  end
end
