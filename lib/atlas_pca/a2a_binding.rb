# frozen_string_literal: true

# The rest of the A2A binding (TypeScript reference @atlasauth/pca-a2a): proof-carrying tasks and messages, the AUTH_REQUIRED
# mapping, per-hop delegation, the extension declaration, the AP2 payment-mandate envelope, signed task-update receipts and the
# extended Agent Card. a2a.rb holds the needs / chain / push / receipt-chain core this builds on. Hashes use String keys; option
# Hashes take the reference's camelCase names or the snake_case spellings. Where the reference awaits, these are synchronous.
require 'set'
require_relative '../atlas_pca'
require_relative 'a2a'
require_relative 'acp'
require_relative 'agentcard'
require_relative 'agentcard_card'
require_relative 'js_compat'
require_relative 'actions'

module AtlasPca
  module A2aBinding
    UNDEFINED = AgentcardCard::UNDEFINED
    PCA_A2A_EXTENSION_URI = 'https://atlasauth.net/a2a/ext/pca/v2'
    TASK_STATE_AUTH_REQUIRED = 'TASK_STATE_AUTH_REQUIRED'
    TASK_STATE_INPUT_REQUIRED = 'TASK_STATE_INPUT_REQUIRED'
    NEED_KEY = "#{PCA_A2A_EXTENSION_URI}#need"
    RECEIPT_KEY = "#{PCA_A2A_EXTENSION_URI}#receipt"
    A2A_RECEIPT_DOMAIN = AtlasPca::A2A_RECEIPT_DOMAIN
    A2A_AP2_CONTEXT = %w[https://www.w3.org/2018/credentials/v1 https://ap2-protocol.org/context/v0.2].freeze
    PARAM_KEYS = %w[aud suites grants policy_digest].freeze
    # The stateless required checks (server verify DEFAULT_REQUIRED_CHECKS): without a revocation hook a task is refused.
    DEFAULT_REQUIRED_CHECKS = %w[counter_format revocation plan_root_authorized audience validity grant_ref_bound].freeze
    NEED_MAX_ENCODED = 2048
    PREFIX = 'pca-verb:'
    JS_WS = Actions::SvfJS::JS_WS

    # A verifier configured without any authority (grant or expectedRootIssuer): a chain is never its own authority.
    class AuthorityError < StandardError
      def code = 'authority_required'

      def initialize
        super('pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority')
      end
    end

    module_function

    def undef?(v) = v.equal?(UNDEFINED)
    def spread(v) = AgentcardCard.spread(v)
    def get(o, k) = AgentcardCard.get(o, k)
    def member(o, k) = AgentcardCard.member(o, k)
    def nullish(v, default) = AgentcardCard.nullish(v, default)
    def defined(v) = undef?(v) ? nil : v
    def truthy?(v) = !undef?(v) && Js.truthy?(v)
    def obj?(x) = x.is_a?(Hash)
    def u16len(s) = AgentcardCard.u16key(s).bytesize / 2

    # o.camel, else o.snake, else undefined
    def opt(o, camel, snake = camel)
      return UNDEFINED unless o.is_a?(Hash)

      o.key?(camel) ? o[camel] : (o.key?(snake) ? o[snake] : UNDEFINED)
    end

    # JavaScript === on JSON values (containers compare by reference).
    def same(a, b)
      return a.equal?(b) if a.is_a?(Hash) || a.is_a?(Array) || b.is_a?(Hash) || b.is_a?(Array)
      return a.equal?(b) if a.nil? || b.nil? || undef?(a) || undef?(b)
      return a == b if [true, false].include?(a) && [true, false].include?(b)
      return false if [true, false].include?(a) || [true, false].include?(b)
      return a.is_a?(String) && b.is_a?(String) && a == b if a.is_a?(String) || b.is_a?(String)

      a.is_a?(Numeric) && b.is_a?(Numeric) && a == b
    end

    def uint?(n) = AtlasPca.k3_int?(n) && !(n.is_a?(Float) && n.zero? && (1.0 / n).negative?)
    def neg_zero?(v) = v.is_a?(Float) && v.zero? && (1.0 / v).negative?

    def safe_int?(v)
      return false unless v.is_a?(Integer) || v.is_a?(Float)

      v.is_a?(Float) ? (v.finite? && v.abs <= 9_007_199_254_740_991 && v == v.floor) : v.abs <= 9_007_199_254_740_991
    end

    def iso_from_ms(now) = Acp.iso_from_ms(now)
    def now_ms = (Time.now.to_f * 1000).to_i

    # ---- needs ----

    def validate_need(x)
      code = AtlasPca.a2a_need_error(x)
      code ? { 'ok' => false, 'code' => code } : { 'ok' => true, 'need' => x }
    end

    def decode_need(value)
      need, code = AtlasPca.decode_a2a_need(value)
      code ? { 'ok' => false, 'code' => code } : { 'ok' => true, 'need' => need }
    end

    def need_digest(need) = AtlasPca.a2a_need_digest(need)

    def chain_extends(prev, nxt)
      nxt.length >= prev.length && prev.each_with_index.all? { |id, k| same(nxt[k], id) }
    end

    def check_chain_extension(chains)
      prev = nil
      chains.each_with_index do |ids, i|
        return { 'ok' => false, 'failedHop' => i, 'reason' => 'no_chain' } unless ids.is_a?(Array) && !ids.empty?
        return { 'ok' => false, 'failedHop' => i, 'reason' => 'chain_does_not_extend_previous_hop' } if prev && !chain_extends(prev, ids)

        prev = ids
      end
      { 'ok' => true }
    end

    # ---- proof-carrying tasks ----

    def with_pca(metadata, pca)
      out = spread(nullish(metadata, {}))
      out[PCA_A2A_EXTENSION_URI] = pca
      out
    end

    def read_pca(metadata)
      v = metadata.is_a?(Hash) ? metadata[PCA_A2A_EXTENSION_URI] : nil
      v.is_a?(Hash) ? v : nil
    end

    # A copy of the task with the PCActn on its metadata (the input is not mutated).
    def attach_pca_to_a2a_task(task, pca)
      out = spread(task)
      out['metadata'] = with_pca(get(task, 'metadata'), pca)
      out
    end

    def attach_pca_to_a2a_message(message, pca) = attach_pca_to_a2a_task(message, pca)

    # The PCActn a task carries: its metadata, then the status message, then the most recent history message; nil if none.
    def extract_pca(task)
      return nil unless task.is_a?(Hash)

      on_task = read_pca(task['metadata'])
      return on_task unless on_task.nil?

      status = task['status']
      msg = status.is_a?(Hash) ? status['message'] : nil
      on_status = msg.is_a?(Hash) ? read_pca(msg['metadata']) : nil
      return on_status unless on_status.nil?

      history = task['history']
      if history.is_a?(Array)
        history.reverse_each do |m|
          on_msg = m.is_a?(Hash) ? read_pca(m['metadata']) : nil
          return on_msg unless on_msg.nil?
        end
      end
      nil
    end

    def extract_pca_from_message(message) = message.is_a?(Hash) ? read_pca(message['metadata']) : nil

    def assert_authority(opts)
      grant = opt(opts, 'grant')
      issuer = opt(opts, 'expectedRootIssuer', 'expected_root_issuer')
      return if grant.is_a?(Hash) || grant.is_a?(Array) || (issuer.is_a?(String) && !issuer.empty?)

      raise AuthorityError
    end

    # The default verdict source: the core PCActn verifier. Replay, revocation and budget state belong to the caller's hooks.
    def core_verifier(p, grant, opts, context, pq_pins)
      plan = context.is_a?(Hash) && context['plan'].is_a?(Hash) ? context['plan'] : {}
      authorized = context.is_a?(Hash) && (context['planAuthorized'] == true || context['plan_authorized'] == true)
      roots = authorized && plan['root'].is_a?(String) ? [plan['root']] : []
      suites = defined(opt(opts, 'allowedSuites', 'allowed_suites'))
      v = AtlasPca.verify_pcactn(p, grant, now: opts.key?('now') && !opts['now'].nil? ? opts['now'] : now_ms, audience: opts['aud'],
                                           allowed_suites: suites, authorized_plan_roots: roots, pq_pins: pq_pins)
      checks = v.checks.dup
      hooks = opts['hooks'].is_a?(Hash) ? opts['hooks'] : {}
      rev = hooks['revocation']
      reasons = v.reasons && !v.reasons.empty? ? v.reasons.dup : (v.reason && !v.reason.empty? ? [v.reason] : [])
      allow = v.allow ? true : false
      res = begin
        rev.respond_to?(:call) ? rev.call({ 'pcactn' => p, 'grant' => grant, 'context' => context }) : nil
      rescue StandardError => e
        { 'enforced' => true, 'ok' => false, 'reason' => "revocation hook failed: #{e.message}" }
      end
      if res.is_a?(Hash) && res['enforced'] == true
        checks['revocation'] = res['ok'] == true ? 'pass' : 'fail'
        if res['ok'] != true
          allow = false
          reasons << (Js.truthy?(res['reason']) ? res['reason'].to_s : 'rejected')
        end
      else
        checks['revocation'] = 'not-enforced'
      end
      params = context.is_a?(Hash) ? context['params'] : nil
      action = p.is_a?(Hash) ? p['action'] : nil
      if params.is_a?(Hash) && action.is_a?(Hash)
        checks['params_digest'] = begin
          AtlasPca.params_digest(params) == action['params_digest']
        rescue StandardError
          false
        end
      end
      { 'allow' => allow, 'checks' => checks, 'reasons' => reasons }
    end

    # PCActn authorization shared by the task and payment-mandate surfaces, under a known authority: the stored grant, or the
    # chain root only when its issuer is the expected principal. opts['verify'] replaces the default core verifier.
    def verify_pca(p, opts, extra_required = [])
      assert_authority(opts)
      return { 'ok' => false, 'reason' => 'PCActn is not an object' } unless p.is_a?(Hash) || p.is_a?(Array)

      chain = get(p, 'cap_chain')
      root = chain.is_a?(Array) && !chain.empty? ? chain[0] : UNDEFINED
      return { 'ok' => false, 'reason' => 'PCActn carries no capability chain', 'pcActn' => p } unless truthy?(root)

      expected = opt(opts, 'expectedRootIssuer', 'expected_root_issuer')
      if !undef?(expected) && !same(get(root, 'issuer'), expected)
        return { 'ok' => false, 'reason' => 'chain root issuer does not match the expected principal', 'pcActn' => p }
      end

      stored = opt(opts, 'grant')
      grant = nullish(stored, root) # without a stored grant the root is admitted only under the pinned principal
      pins = opt(opts, 'pqPins', 'pq_pins')
      pq_pins = undef?(stored) ? (truthy?(defined(pins)) ? pins : {}) : defined(pins)
      ctx = opts['context']
      context = nullish(ctx.respond_to?(:call) ? ctx.call(p) : ctx, {})
      hook = opts['verify']
      verdict = hook.respond_to?(:call) ? hook.call(p, grant, opts, context) : core_verifier(p, grant, opts, context, pq_pins)
      require_checks = opt(opts, 'requireChecks', 'require_checks')
      names = undef?(require_checks) || require_checks.nil? ? DEFAULT_REQUIRED_CHECKS.dup : require_checks.dup
      extra_required.each { |n| names << n unless names.include?(n) }
      checks = verdict['checks'] || {}
      allow = (Js.truthy?(verdict['allow']) && names.all? { |n| [true, 'pass'].include?(checks[n]) })
      reasons = (verdict['reasons'] || []).select { |r| Js.truthy?(r) }
      reason = allow ? nil : (reasons.empty? ? 'PCActn verification failed' : reasons.join('; '))
      result = verdict.merge('allow' => allow)
      result['reason'] = reason unless reason.nil?
      allow ? { 'ok' => true, 'result' => result, 'pcActn' => p } : { 'ok' => false, 'reason' => reason, 'result' => result, 'pcActn' => p }
    end

    # Verify the proof-carrying action on a task. Fail closed: no PCActn, or one that does not verify, is refused.
    def verify_a2a_task(task, opts)
      assert_authority(opts)
      p = extract_pca(task)
      return { 'ok' => false, 'reason' => 'no proof-carrying action attached to this task' } if p.nil?

      verify_pca(p, opts)
    end

    # A per-task guard. require (default true): a task with no proof is refused; with false it passes, but a task that DOES carry a
    # proof must still verify.
    def pca_a2a_middleware(opts)
      assert_authority(opts)
      req = nullish(opts['require'], true)
      lambda do |task|
        p = extract_pca(task)
        if p.nil?
          next Js.truthy?(req) ? { 'ok' => false, 'reason' => 'proof-carrying action required but none attached to task' } : { 'ok' => true }
        end

        verify_pca(p, opts)
      end
    end

    # ---- extension declaration ----

    def pca_extension_declaration(params, required = true)
      { 'uri' => PCA_A2A_EXTENSION_URI, 'description' => 'Per-action proofs of authority (PCActn) on tasks and messages',
        'required' => required, 'params' => params }
    end

    # Read and validate the PCA extension from an Agent Card. A malformed declaration is a refusal, never a guess.
    def read_pca_extension(card)
      caps = obj?(card) ? card['capabilities'] : nil
      exts = obj?(caps) ? caps['extensions'] : nil
      return { 'ok' => false, 'code' => 'not_declared' } unless exts.is_a?(Array)

      found = exts.select { |e| obj?(e) && e['uri'] == PCA_A2A_EXTENSION_URI }
      return { 'ok' => false, 'code' => 'not_declared' } if found.empty?
      return { 'ok' => false, 'code' => 'bad_declaration' } if found.length > 1

      e = found[0]
      return { 'ok' => false, 'code' => 'bad_declaration' } if e.key?('required') && ![true, false].include?(e['required'])

      p = e['params']
      bad = { 'ok' => false, 'code' => 'bad_params' }
      return bad unless obj?(p) && p.keys.all? { |k| PARAM_KEYS.include?(k) } && p['aud'].is_a?(String) && u16len(p['aud']).between?(1, 512)
      if p.key?('suites') && !(p['suites'].is_a?(Array) && p['suites'].length <= 16 && p['suites'].all? { |s| s.is_a?(String) && u16len(s).between?(1, 64) })
        return bad
      end
      return bad if p.key?('policy_digest') && !(p['policy_digest'].is_a?(String) && u16len(p['policy_digest']).between?(1, 128))

      grants = []
      if p.key?('grants')
        details, code = AtlasPca.parse_pca_grant_details(p['grants'])
        return { 'ok' => false, 'code' => 'bad_grants' } if code

        grants = details
      end
      { 'ok' => true, 'required' => e['required'] == true, 'params' => p, 'grants' => grants }
    end

    # True iff the A2A-Extensions service parameter lists the PCA extension (exact URI in a comma-separated list).
    def client_opts_into_pca(header)
      header.is_a?(String) && header.split(',', -1).any? { |u| u.gsub(/\A[#{JS_WS}]+|[#{JS_WS}]+\z/o, '') == PCA_A2A_EXTENSION_URI }
    end

    # ---- AUTH_REQUIRED mapping ----

    def auth_required?(state) = state.is_a?(String) && [TASK_STATE_AUTH_REQUIRED, 'auth-required'].include?(state)

    # The unpadded base64url of a need's strict canonical JSON. Raises on a malformed need or an over-long value.
    def encode_pca_need(need)
      v = validate_need(need)
      raise ArgumentError, "encodePcaNeed: malformed need (#{v['code']})" unless v['ok']

      enc = AtlasPca.b64e(AtlasPca.strict_bytes(need))
      raise ArgumentError, 'encodePcaNeed: the need is too large for a header' if enc.length > NEED_MAX_ENCODED

      enc
    end

    # The TaskStatus an agent sets to ask for authority: AUTH_REQUIRED plus a message carrying the typed need.
    def auth_required_status(need, o)
      enc = encode_pca_need(need)
      text = opt(o, 'text')
      stamp = iso_from_ms(opt(o, 'now'))
      mid = opt(o, 'messageId', 'message_id')
      msg = { 'role' => 'agent',
              'parts' => [{ 'kind' => 'text', 'text' => text.nil? || undef?(text) ? "Authority needed: #{need['verb']} on #{need['resource']}" : text }],
              'extensions' => [PCA_A2A_EXTENSION_URI], 'metadata' => { NEED_KEY => enc } }
      msg['messageId'] = mid unless undef?(mid)
      { 'state' => TASK_STATE_AUTH_REQUIRED, 'timestamp' => stamp, 'message' => msg }
    end

    # The need parked in a task status message, decoded (nil when there is none).
    def read_auth_required_need(task)
      status = obj?(task) ? task['status'] : nil
      msg = obj?(status) ? status['message'] : nil
      md = obj?(msg) ? msg['metadata'] : nil
      return nil unless obj?(md) && md.key?(NEED_KEY)

      decode_need(md[NEED_KEY])
    end

    # The answer message: a PCActn for exactly the parked need, plus the need's digest.
    def answer_message(need, pca, message_id)
      { 'role' => 'user', 'messageId' => message_id, 'parts' => [{ 'kind' => 'text', 'text' => 'authority provided' }],
        'metadata' => { PCA_A2A_EXTENSION_URI => pca, NEED_KEY => need_digest(need) } }
    end

    # resume_gate over the reference's option object {state, needEncoded, answerNeedDigest, proofAction}: an absent proofAction is
    # no proof, a null one raises (as the reference does).
    def resume_gate_obj(o)
      return 'task_not_auth_required' unless auth_required?(o['state'])

      need = o.key?('needEncoded') ? decode_need(o['needEncoded']) : nil
      return 'no_valid_need' if need.nil? || !need['ok']
      return 'answer_not_bound_to_need' unless same(o.key?('answerNeedDigest') ? o['answerNeedDigest'] : UNDEFINED, need_digest(need['need']))
      return 'no_proof' unless o.key?('proofAction')

      action = o['proofAction']
      raise TypeError, "Cannot read properties of null (reading 'verb')" if action.nil?
      return 'action_mismatch' if !same(get(action, 'verb'), need['need']['verb']) || !same(get(action, 'resource'), need['need']['resource'])

      nil
    end

    # Resume a Task parked in AUTH_REQUIRED: only when its status carries a decodable need, the answer cites that need's digest, the
    # answer carries a PCActn for the need's exact verb and resource, and that PCActn passes the verifier for THIS agent.
    def resume_auth_required(task, answer, opts)
      status = obj?(task) ? task['status'] : nil
      smsg = obj?(status) ? status['message'] : nil
      status_md = obj?(smsg) && obj?(smsg['metadata']) ? smsg['metadata'] : {}
      md = obj?(answer) && obj?(answer['metadata']) ? answer['metadata'] : {}
      p = extract_pca_from_message(answer)
      gate = {}
      gate['state'] = status['state'] if obj?(status) && status.key?('state')
      gate['needEncoded'] = status_md[NEED_KEY] if status_md.key?(NEED_KEY)
      gate['answerNeedDigest'] = md[NEED_KEY] if md.key?(NEED_KEY)
      gate['proofAction'] = p['action'] if !p.nil? && p.key?('action')
      refusal = resume_gate_obj(gate)
      return { 'ok' => false, 'reason' => refusal } unless refusal.nil?

      v = verify_a2a_task({ 'id' => task['id'], 'status' => { 'state' => 'TASK_STATE_WORKING' }, 'metadata' => { PCA_A2A_EXTENSION_URI => p } }, opts)
      v['ok'] ? { 'ok' => true, 'verification' => v } : { 'ok' => false, 'reason' => Js.truthy?(v['reason']) ? v['reason'] : 'proof_rejected' }
    end

    # ---- per-hop delegation ----

    # Verify a chain of delegated tasks, one per A2A hop; the capability chain must EXTEND the previous hop's. Stops at the first
    # failure; empty input is refused.
    def verify_a2a_delegation(hops)
      chains = []
      return { 'ok' => false, 'reason' => 'no_hops', 'chains' => chains } if hops.empty?

      hops.each_with_index do |h, i|
        v = verify_a2a_task(h['task'], h['opts'])
        return { 'ok' => false, 'failedHop' => i, 'reason' => Js.truthy?(v['reason']) ? v['reason'] : 'rejected', 'chains' => chains } unless v['ok']

        p = extract_pca(h['task'])
        ids = !p.nil? && p['cap_chain'].is_a?(Array) ? p['cap_chain'].map { |c| get(c, 'id') } : nil
        return { 'ok' => false, 'failedHop' => i, 'reason' => 'no_chain', 'chains' => chains } if ids.nil?
        if !chains.empty? && !chain_extends(chains[-1], ids)
          return { 'ok' => false, 'failedHop' => i, 'reason' => 'chain_does_not_extend_previous_hop', 'chains' => chains }
        end

        chains << ids
      end
      { 'ok' => true, 'chains' => chains }
    end

    # ---- push notifications and anti-enumeration ----

    # The per-task push token. Raises on a salt shorter than 16 characters.
    def pca_push_token(task_id, chain_ids, salt)
      t = AtlasPca.a2a_push_token(task_id, chain_ids, salt)
      raise ArgumentError, 'pcaPushToken: the salt must be a secret of at least 16 characters' if t.nil?

      t
    end

    # Receiver-side check of a delivered push notification: the token must be the one recomputed from the task, the chain and the
    # salt, and the payload must be about that task. Raises on a salt shorter than 16 characters.
    def check_push_notification(expected, delivered)
      token = delivered['token']
      return { 'ok' => false, 'reason' => 'no_token' } unless token.is_a?(String) && !token.empty?

      want = pca_push_token(expected['taskId'], expected['chainIds'], expected['salt'])
      unless token.bytesize == want.bytesize && OpenSSL.fixed_length_secure_compare(token.b, want.b)
        return { 'ok' => false, 'reason' => 'token_mismatch' }
      end

      p = obj?(delivered['payload']) ? delivered['payload'] : {}
      found = UNDEFINED
      [%w[task id], %w[statusUpdate taskId], %w[artifactUpdate taskId]].each do |key, field|
        c = p[key]
        v = obj?(c) ? c[field] : nil
        unless v.nil?
          found = v
          break
        end
      end
      same(found, expected['taskId']) ? { 'ok' => true } : { 'ok' => false, 'reason' => 'task_mismatch' }
    end

    # The one error servers return for "no such task" and "not yours" alike (no existence leak).
    def uniform_task_not_found = { 'code' => 'TaskNotFoundError', 'message' => 'task not found' }

    # ---- payment mandate envelope ----

    # True only when the PCActn's threshold shares verify at t=3 (agent, guardian and principal) under signer_set. The agent role may
    # be satisfied by the leaf signature only for an Ed25519 leaf and an Ed25519-only agent registration. Never raises.
    def human_present?(p, signer_set)
      reg = AtlasPca.signer_registry(signer_set)
      return false if reg.nil? || reg.keys.sort != AtlasPca::THRESHOLD_ROLES.sort || !p.is_a?(Hash)

      msg = AtlasPca.threshold_message(p)
      shares = p['threshold'].is_a?(Hash) && p['threshold']['shares'].is_a?(Array) ? p['threshold']['shares'] : []
      ok_roles = Set.new
      shares.each do |sh|
        next unless sh.is_a?(Hash)

        entry = { 'role' => sh['role'], 't' => 3, 'share' => sh, 'threshold_message' => AtlasPca.b64e(msg), 'signer_set' => signer_set }
        ok_roles << sh['role'] if AtlasPca.verify_threshold_share(entry)
      end
      if !ok_roles.include?('agent') && reg['agent'][1].nil? && [nil, 'ed25519'].include?(p['alg'])
        chain = p['cap_chain']
        leaf = chain.is_a?(Array) && !chain.empty? ? chain[-1] : nil
        if leaf.is_a?(Hash) && leaf['holder'] == reg['agent'][0] && p['sig'].is_a?(String) && AtlasPca.verify_leaf_suite(p, leaf['holder'], msg)
          ok_roles << 'agent'
        end
      end
      ok_roles == Set.new(AtlasPca::THRESHOLD_ROLES)
    rescue StandardError
      false
    end

    # Map a PCActn to an AP2 payment-mandate envelope whose authority is carried BY REFERENCE (x_pca.pcactn_digest). opts: amount
    # (integer minor units), paymentMethod, merchant, humanPresent, humanSignerSet, issuerPublic, now. Raises on anything the
    # envelope cannot honestly carry.
    def a2a_payment_mandate_from_pca(pca, opts)
      chain = get(pca, 'cap_chain')
      leaf_obj = chain.is_a?(Array) && !chain.empty? ? chain[-1] : UNDEFINED
      leaf = leaf_obj.nil? || undef?(leaf_obj) ? UNDEFINED : get(leaf_obj, 'holder')
      issuer = nullish(opt(opts, 'issuerPublic', 'issuer_public'), leaf)
      raise ArgumentError, 'a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain' if undef?(issuer)

      amount = get(opts, 'amount')
      value = get(amount, 'value')
      raise ArgumentError, 'a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units' if !safe_int?(value) || value.negative?

      hp = opt(opts, 'humanPresent', 'human_present')
      signer_set = opt(opts, 'humanSignerSet', 'human_signer_set')
      hp = truthy?(defined(signer_set)) ? human_present?(pca, signer_set) : false if hp.nil? || undef?(hp)
      now = nullish(opt(opts, 'now'), now_ms)
      action = get(pca, 'action')
      x_pca = { 'pcactn_digest' => AtlasPca.hash_canonical(pca) }
      [['aud', get(pca, 'aud')], ['verb', get(action, 'verb')], ['resource', get(action, 'resource')],
       ['params_digest', get(action, 'params_digest')], ['grant_ref', get(pca, 'grant_ref')]].each { |k, v| x_pca[k] = v unless undef?(v) }
      x_pca['leaf_holder'] = nullish(leaf, issuer)
      contents = { 'amount' => spread(amount), 'payment_method' => spread(defined(opt(opts, 'paymentMethod', 'payment_method'))), 'human_present' => hp }
      merchant = opt(opts, 'merchant')
      contents['merchant'] = merchant unless undef?(merchant)
      contents['x_pca'] = x_pca
      { '@context' => A2A_AP2_CONTEXT.dup, 'type' => %w[VerifiableCredential PaymentMandate], 'issuer' => issuer,
        'issuanceDate' => iso_from_ms(now), 'credentialSubject' => contents }
    end

    # The PCA binding read back out of a payment mandate (the round trip of x_pca).
    def pca_binding_from_a2a_payment_mandate(mandate) = spread(get(get(mandate, 'credentialSubject'), 'x_pca'))

    def own?(o, k) = o.is_a?(Hash) && o.key?(k)

    def mandate_binding_error(m, p, params, opts)
      x = get(m, 'x_pca')
      return 'payment mandate carries no x_pca binding' unless obj?(x)

      chain = get(p, 'cap_chain')
      leaf = chain.is_a?(Array) && !chain.empty? ? chain[-1] : nil
      action = get(p, 'action')
      act = ->(k) { action.nil? || undef?(action) ? UNDEFINED : get(action, k) }
      bound = [['aud', get(p, 'aud')], ['verb', act.call('verb')], ['resource', act.call('resource')], ['params_digest', act.call('params_digest')],
               ['grant_ref', get(p, 'grant_ref')], ['leaf_holder', obj?(leaf) && leaf.key?('holder') ? leaf['holder'] : UNDEFINED]]
      bound.each do |k, v|
        return "payment mandate x_pca.#{k} is not the PCActn's" if !own?(x, k) || !x[k].is_a?(String) || !same(x[k], v)
      end
      amt = obj?(m) && m.key?('amount') ? m['amount'] : UNDEFINED
      if !obj?(amt) || !safe_int?(amt['value']) || amt['value'].negative? || neg_zero?(amt['value']) || !amt['currency'].is_a?(String)
        return 'payment mandate amount is malformed (value must be a non-negative integer in minor units)'
      end
      if !own?(params, 'amount') || !safe_int?(params['amount']) || params['amount'].negative? || neg_zero?(params['amount'])
        return 'the PCActn params carry no integer minor-unit amount to bind the mandate amount to'
      end
      return 'the PCActn params carry no currency to bind the mandate currency to' if !own?(params, 'currency') || !params['currency'].is_a?(String)
      if amt['value'] != params['amount'] || amt['currency'] != params['currency']
        return 'payment mandate amount / currency differ from the authorized PCActn params'
      end

      merchant = own?(m, 'merchant') ? m['merchant'] : UNDEFINED
      p_merchant = own?(params, 'merchant') ? params['merchant'] : UNDEFINED
      return 'payment mandate merchant differs from the authorized PCActn params' unless same(merchant, p_merchant)

      if own?(params, 'payment_method')
        same_pm = begin
          AtlasPca.hash_canonical(m.key?('payment_method') ? m['payment_method'] : nil) == AtlasPca.hash_canonical(params['payment_method'])
        rescue StandardError
          false
        end
        return 'payment mandate payment_method differs from the authorized PCActn params' unless same_pm
      end
      hp = obj?(m) && m.key?('human_present') ? m['human_present'] : UNDEFINED
      return 'payment mandate human_present must be a boolean' unless [true, false].include?(hp)

      hs = opt(opts, 'humanSignerSet', 'human_signer_set')
      return 'payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)' if hp && !(hs.is_a?(Array) && human_present?(p, hs))

      nil
    end

    # Verify a payment mandate against the PCActn it references. The mandate is NOT signed: every field a payer acts on must be
    # authorized by the PCActn, and the PCActn itself must verify, with params_digest required.
    def verify_a2a_payment_mandate(mandate, pca, opts)
      assert_authority(opts)
      begin
        bound = get(get(get(mandate, 'credentialSubject'), 'x_pca'), 'pcactn_digest')
        digest = AtlasPca.hash_canonical(pca)
      rescue StandardError => e
        return { 'ok' => false, 'reason' => "malformed payment mandate or PCActn: #{e.message}" }
      end
      return { 'ok' => false, 'reason' => 'payment mandate is not bound to this PCActn (pcactn_digest mismatch)', 'pcActn' => pca } unless same(bound, digest)
      return { 'ok' => false, 'reason' => 'PCActn is not an object' } unless pca.is_a?(Hash) || pca.is_a?(Array)

      ctx = opts['context']
      context = nullish(ctx.respond_to?(:call) ? ctx.call(pca) : ctx, {})
      params = get(context, 'params')
      unless obj?(params)
        return { 'ok' => false, 'reason' => 'context.params (the PCActn params plaintext) is required to bind the payment mandate', 'pcActn' => pca }
      end

      why = mandate_binding_error(mandate['credentialSubject'], pca, params, opts)
      return { 'ok' => false, 'reason' => why, 'pcActn' => pca } unless why.nil?

      verify_pca(pca, opts.merge('context' => context), ['params_digest'])
    end

    # ---- signed task-update receipts ----

    # Sign a receipt with an Ed25519 seed (32 bytes). o: taskId, state, chainIds, issuedAt, optional prev (the previous receipt of
    # the same task). Raises on malformed input, a prev of another task or one already terminal.
    def sign_task_receipt(secret, o)
      task_id = o['taskId']
      state = o['state']
      issued = o['issuedAt']
      ids = o['chainIds']
      if !task_id.is_a?(String) || task_id.empty? || u16len(task_id) > 256 || !AtlasPca::A2A_STATES.include?(state) || !uint?(issued) || ids.empty?
        raise ArgumentError, 'signTaskReceipt: malformed input'
      end

      prev = o['prev']
      if truthy?(prev) && (get(prev, 'task_id') != task_id || AtlasPca::A2A_TERMINAL.include?(get(prev, 'state')))
        raise ArgumentError, 'signTaskReceipt: prev is for another task or already terminal'
      end

      key = AtlasPca::KeyPair.new(secret)
      base = { 'v' => 1, 'task_id' => task_id, 'state' => state, 'seq' => truthy?(prev) ? prev['seq'] + 1 : 0,
               'prev' => truthy?(prev) ? AtlasPca.a2a_receipt_digest(prev) : nil, 'chain' => AtlasPca.pca_grant_chain_digest(ids),
               'issued_at' => issued, 'signer' => key.public }
      base.merge('sig' => AtlasPca.b64e(key.sign(A2A_RECEIPT_DOMAIN + AtlasPca.strict_bytes(base))))
    end

    # check_a2a_receipt_chain with the reference's result shape: on success the last receipt itself (last) and terminal.
    def check_receipt_chain_result(receipts, signer, task_id, chain_ids)
      r = AtlasPca.check_a2a_receipt_chain(receipts, signer, task_id, chain_ids)
      return r unless r['ok']

      { 'ok' => true, 'last' => receipts[-1], 'terminal' => r['terminal'] }
    end

    # A copy of a status update or message with the receipt on its metadata.
    def attach_receipt(carrier, receipt)
      out = spread(carrier)
      md = spread(nullish(get(carrier, 'metadata'), {}))
      md[RECEIPT_KEY] = receipt
      out['metadata'] = md
      out
    end

    # The (unverified) receipt a push or stream payload carries (statusUpdate, task or message metadata), else nil.
    def receipt_of_payload(payload)
      return nil unless obj?(payload)

      %w[statusUpdate task message].each do |k|
        c = payload[k]
        md = obj?(c) ? c['metadata'] : nil
        return md[RECEIPT_KEY] if obj?(md) && md.key?(RECEIPT_KEY)
      end
      nil
    end

    # ---- extended Agent Card ----

    # SameValueZero identity of a JSON value (for maps keyed by it).
    def key_of(v)
      return [:u] if undef?(v)
      return [:z] if v.nil?
      return [:b, v] if [true, false].include?(v)
      return [:n, v.to_f] if v.is_a?(Numeric)
      return [:s, v] if v.is_a?(String)

      [:o, v.object_id]
    end

    def default_verb_of(s)
      tags = member(s, 'tags')
      tags = [] if tags.nil? || undef?(tags)
      raise TypeError, 'tags.find is not a function' unless tags.is_a?(Array)

      tags.each { |t| return t[PREFIX.length..] if t.is_a?(String) && t.start_with?(PREFIX) }
      UNDEFINED
    end

    # The card a caller may see after authenticating: hidden skills are revealed only when their verb's envelope is autonomous or
    # needs-approval; all envelopes must come from one policy (its digest is recorded in the PCA extension params). o: authenticated,
    # hiddenSkills, envelopes, optional verbOf. The result is unsigned; discovery only.
    def extended_agent_card(public_card, o)
      raise ArgumentError, 'extendedAgentCard: the caller must be authenticated (A2A 13.3)' unless o['authenticated'] == true

      envs = o['envelopes']
      digests = {}
      envs.each { |e| digests[key_of(member(e, 'policyDigest'))] = member(e, 'policyDigest') unless digests.key?(key_of(member(e, 'policyDigest'))) }
      raise ArgumentError, 'extendedAgentCard: envelopes were computed against different policies' if digests.length > 1

      by_verb = {}
      envs.each { |e| by_verb[key_of(member(e, 'verb'))] = e }
      verb_of = o['verbOf'].respond_to?(:call) ? o['verbOf'] : method(:default_verb_of)
      revealed = []
      o['hiddenSkills'].each do |s|
        verb = verb_of.call(s)
        env = verb.nil? || undef?(verb) ? UNDEFINED : by_verb.fetch(key_of(verb), UNDEFINED)
        next if undef?(env) || member(env, 'status') == 'denied'

        tags = member(s, 'tags')
        sk = spread(s)
        sk['tags'] = (tags.is_a?(Array) ? tags.dup : []) + [member(env, 'status') == 'autonomous' ? 'pca:autonomous' : 'pca:needs-approval']
        revealed << sk
      end
      raise TypeError, "Cannot destructure 'publicCard' as it is null." if public_card.nil?

      rest = spread(public_card).reject { |k, _| k == 'signatures' }
      caps_raw = rest['capabilities']
      caps = spread(caps_raw.nil? ? {} : caps_raw)
      exts_raw = caps_raw.nil? ? UNDEFINED : member(caps_raw, 'extensions')
      exts = exts_raw.is_a?(Array) ? exts_raw : []
      policy_digest = digests.empty? ? UNDEFINED : digests.values.first
      next_exts =
        if undef?(policy_digest)
          exts
        else
          exts.map do |e|
            next e unless member(e, 'uri') == PCA_A2A_EXTENSION_URI

            ne = spread(e)
            params = spread(member(e, 'params'))
            params['policy_digest'] = policy_digest
            ne['params'] = params
            ne
          end
        end
      skills = rest['skills'].is_a?(Array) ? rest['skills'] : []
      caps['extensions'] = next_exts
      out = rest.dup
      out['capabilities'] = caps
      out['skills'] = skills + revealed
      out
    end

    # Validate a card against its signature(s) (A2A flavour: the result carries passportRef and passport only).
    def verify_agent_card(card, opts)
      return { 'ok' => false, 'reason' => 'agent card is not an object' } unless card.is_a?(Hash) || card.is_a?(Array)

      signatures = card.is_a?(Hash) ? card['signatures'] : nil
      return { 'ok' => false, 'reason' => 'agent card carries no signatures' } unless signatures.is_a?(Array) && !signatures.empty?

      if opts['schema'] == 'a2a-1.0'
        problems = AgentcardCard.validate_agent_card1(card)
        return { 'ok' => false, 'reason' => "agent card does not match the A2A 1.0 schema: #{problems.join('; ')}" } unless problems.empty?
      end
      resolved = Agentcard.resolve_verify_key(opts)
      return { 'ok' => false, 'reason' => resolved['error'] } if resolved.key?('error')

      payload = begin
        AgentcardCard.card_bytes(card)
      rescue TypeError => e
        return { 'ok' => false, 'reason' => "agent card has no canonical form: #{e.message}" }
      end
      ref_out = nil
      signatures.each_with_index do |sig, i|
        unless sig.is_a?(Hash) && sig['protected'].is_a?(String) && sig['signature'].is_a?(String)
          return { 'ok' => false, 'reason' => "signature #{i} is malformed" }
        end

        res = Agentcard.verify_detached(payload, sig, resolved)
        return { 'ok' => false, 'reason' => "signature #{i} did not verify: #{res['reason']}" } unless res['ok']

        ref = res['protectedHeader'][AgentcardCard::PCA_PASSPORT_HEADER]
        ref_out = ref if ref.is_a?(String) && ref_out.nil?
      end
      out = { 'ok' => true }
      out['passportRef'] = ref_out unless ref_out.nil?
      out['passport'] = card['pcaPassport'] if card.is_a?(Hash) && Js.truthy?(card['pcaPassport'])
      out
    end
  end
end
