# frozen_string_literal: true

module AtlasPca
  # Small public helpers of the reference that sit next to larger Ruby modules: the receipt chain (the principal's own tamper-evident log of
  # what their agents did), assurance refresh, caveat predicates, the signature-suite verify seam, and the revocation / policy-VM helpers.
  # All data is JSON-shaped (String-keyed Hashes); every function is total unless it says otherwise.
  module_function

  # ---- receipts: a hash-chained client-side log of verified actions ----------------------------------------------------------------
  def pcactn_digest(p) = hash_canonical(p)

  # a member the receipt lacks is `undefined` in the reference, which the canonicalizer refuses: so does this
  def receipt_body(r)
    missing = %w[seq at actionDigest verb resource outcome prev].find { |k| !(r.is_a?(Hash) && r.key?(k)) }
    raise ArgumentError, "canonicalize: unsupported type undefined (#{missing})" if missing

    { 'd' => 'atlas-pca/receipt/v1', 'seq' => r['seq'], 'at' => r['at'], 'actionDigest' => r['actionDigest'], 'verb' => r['verb'], 'resource' => r['resource'],
      'outcome' => r['outcome'], 'checks' => r['checks'], 'prev' => r['prev'] }
  end

  # The next receipt in a chain for a verified action; `verify` carries {'allow', 'checks'?}.
  def receipt_for(prev_hash, seq, p, verify, at = nil)
    body = { 'seq' => seq, 'at' => at.nil? ? p['iat'] : at, 'actionDigest' => pcactn_digest(p), 'verb' => p['action']['verb'], 'resource' => p['action']['resource'],
             'outcome' => verify['allow'] ? 'allow' : 'deny' }
    body['checks'] = verify['checks'] if verify['checks']
    body['prev'] = prev_hash
    body.merge('hash' => hash_canonical(receipt_body(body)))
  end

  # Append a verified action to a receipt log, chaining to the last entry (returns a new log).
  def append_receipt(log, p, verify, at = nil)
    last = log.last
    log + [receipt_for(last ? last['hash'] : '', last ? last['seq'] + 1 : 0, p, verify, at)]
  end

  # The head hash of a log: one value that commits to the entire history.
  def receipt_head(log) = log.empty? ? '' : log.last['hash']

  # Verify a receipt log is an intact hash chain (sequential, correctly linked, each hash matches): {'ok' => true} or
  # {'ok' => false, 'brokenAt', 'reason'}.
  def verify_receipt_chain(log)
    prev = ''
    log.each_with_index do |r0, i|
      r = r0.is_a?(Hash) ? r0 : {} # JS reads members of a non-object as undefined
      seq = r['seq']
      seq_s = if !r.key?('seq') then 'undefined'
              elsif seq.nil? then 'null'
              elsif seq.is_a?(Numeric) then Predicates.js_number_string(seq.to_f)
              else seq.to_s
              end
      broken = ->(why) { { 'ok' => false, 'brokenAt' => (seq if r.key?('seq')), 'reason' => why }.compact }
      return broken.call("seq #{seq_s} out of order (expected #{i})") if seq != i
      return broken.call("prev link mismatch at seq #{seq_s}") if r['prev'] != prev
      return broken.call("hash mismatch at seq #{seq_s} (tampered body)") if hash_canonical(receipt_body(r.reject { |k, _| k == 'hash' })) != r['hash']

      prev = r['hash']
    end
    { 'ok' => true }
  end

  # ---- assurance, caveats, suites ----------------------------------------------------------------------------------------------
  # Refresh a report after more checks were decided: a check that is no longer `pass` loses its level, a new check is added, `unsupported`
  # stays. Mutates and returns the report.
  def refresh_assurance(report, checks)
    checks.each do |name, status|
      was = report[name]
      next if was && was['outcome'] == 'unsupported'

      if status != 'pass' then report[name] = { 'outcome' => status }
      elsif was.nil? || was['outcome'] != 'pass' then report[name] = { 'outcome' => 'pass' }
      end
    end
    report
  end

  # A well-formed budget_alloc caveat (a finite limit >= 0).
  def budget_alloc_caveat?(cv) = cv.is_a?(Hash) && cv['type'] == 'budget_alloc' && Js.num?(cv['limit']) && (!cv['limit'].is_a?(Float) || cv['limit'].finite?) && cv['limit'] >= 0

  # One of the five K1 caveat types (needs_discharge, sealed, max_uses, derive, spiffe_bound).
  def k1_caveat?(c) = c.is_a?(Hash) && c['type'].is_a?(String) && K1_CAVEAT_TYPES.include?(c['type'])

  # Verify a suite signature over `msg`: the agility seam every surface verifies through. `keys`: {'ed_pub' => b64u, 'pq' => PinnedPq}; `s`:
  # {'sig', 'pq_sig'?}. FAIL CLOSED: an unknown alg, a missing component or key, a PQ key not minted by resolve_pq_key, or any invalid
  # component is false; a hybrid requires BOTH, the Ed25519 half first. Never raises.
  def verify_with_suite(alg, keys, msg, s)
    pq = keys.is_a?(Hash) ? keys['pq'] : nil
    return false unless pq.nil? || pq.is_a?(PinnedPq)

    p = { 'sig' => s.is_a?(Hash) ? s['sig'] : nil, 'pq_sig' => s.is_a?(Hash) ? s['pq_sig'] : nil }
    p['alg'] = alg unless alg.nil?
    verify_suite(p, keys.is_a?(Hash) ? keys['ed_pub'] : nil, msg, pq)
  rescue StandardError
    false
  end

  # ---- policy VM, decisions, revocation ------------------------------------------------------------------------------------------
  # The denial wording that names the unmet limit, or nil when none is in scope.
  def named_unmet_limit_reason(predicates, ctx)
    limit = Predicates.first_unmet_limit(predicates, ctx)
    return nil if limit.nil?

    a = ctx.is_a?(Hash) ? ctx['action'] : nil
    "#{limit} not satisfied for #{a.is_a?(Hash) ? a['verb'] : 'undefined'} on #{a.is_a?(Hash) ? a['resource'] : 'undefined'}"
  rescue StandardError
    nil
  end

  # The ordered reason list of a verdict: the core's own reason(s), then one `<check>: <reason>` for EVERY failing check the v2 pipeline
  # reported ({'name', 'ok', 'reason'?}) that is not already listed. A failing check without a reason contributes nothing.
  def fold_v2_reasons(base, v2)
    out = base.dup
    v2.each do |c|
      next if c['ok'] || c['reason'].nil?

      line = "#{c['name']}: #{c['reason']}"
      out << line unless out.include?(line)
    end
    out
  end

  # The caveat context extended with the action and the tool call derived from it (applied LAST: a caller-supplied context can never
  # substitute a different action or tool call).
  def agent_caveat_context(base, action)
    a = action.is_a?(Hash) ? action['action'] : nil
    params = a.is_a?(Hash) ? a['params'] : nil
    call = { 'tool' => a.is_a?(Hash) && a['verb'].is_a?(String) ? a['verb'] : '', 'args' => params.is_a?(Hash) ? params : {} }
    call['toolSignatureDigest'] = action['toolBinding'] if action.is_a?(Hash) && action['toolBinding'].is_a?(String)
    base.merge('action' => action, 'toolCall' => call)
  end

  # THE reversibility class of an action: its own class, else the class of the plan node it is bound to (`node_id`, the SIGNED plan node id),
  # else nil (which no `reversibility_max` caveat accepts and which is not fast-path eligible: fail closed).
  def resolve_reversibility_class(action, plan, node_id)
    own = action.is_a?(Hash) && action['action'].is_a?(Hash) ? action['action']['reversibility_class'] : nil
    return own unless own.nil?
    return nil unless node_id.is_a?(String)

    plan.is_a?(Array) ? plan.find { |n| n.is_a?(Hash) && n['id'] == node_id }&.fetch('reversibility_class', nil) : nil
  end

  # The server's risk inputs for a money-moving operation: {'blastRadius' => amount / kappa clamped to [0, 1]} from the verified
  # `params[amount_field]` and the grant's own risk policy; nil when there is no numeric amount (the verifier then prices the missing
  # inputs at the worst case).
  def amount_risk(grant, params, amount_field: 'amount')
    amount = params.is_a?(Hash) ? params[amount_field] : nil
    kappa = read_envelope(grant)&.dig('risk_policy', 'kappa')
    return nil unless Js.num?(amount) && (!amount.is_a?(Float) || amount.finite?) && Js.num?(kappa) && (!kappa.is_a?(Float) || kappa.finite?) && kappa.positive?

    { 'blastRadius' => [1, [0, amount / kappa.to_f].max].min }
  end

  # Throws ArgumentError on a malformed staleness policy (a RevocationStaleness or a Hash of its options): a configuration error.
  def validate_revocation_staleness(p)
    return p if p.is_a?(RevocationStaleness)

    RevocationStaleness.new(**p.to_h { |k, v| [k.to_sym, v] })
  end

  # True when the policy turns the staleness check on (any age option set).
  def staleness_policy_on?(p)
    h = p.respond_to?(:to_h) ? p.to_h.transform_keys(&:to_s) : {}
    !h['max_revocation_age_ms'].nil? || !h['staleness'].nil?
  end

  # Verify `id` IS in the set: inclusion against the size-bound root (canonical base64url siblings of exactly 32 bytes).
  def verify_membership(root, proof, id)
    return false unless proof.is_a?(Hash)

    mesh_leaf_ok?(root, proof['size'], id, proof)
  rescue StandardError
    false
  end

  # The hash of a policy template reference.
  def link_digest(ref) = hash_canonical(ref)

  # A ref to the shared SafeRegex cache and runner under the reference's names: `compile_safe_regex_cached(src)` -> compiled or nil,
  # `run_safe_regex(compiled, subject)` -> true / false, or nil when the work budget would be exceeded.
  def compile_safe_regex_cached(src) = SafeRegex.compile_cached(src)
  def run_safe_regex(re, subject) = SafeRegex.run(re, subject)

  # ---- small helpers of the satellite packages ----------------------------------------------------------------------------------
  # The error of the remote agent client: `code` is one of no_plan, unknown_node, no_secret, network, bad_response, build_failed.
  class PcaAgentError < StandardError
    attr_reader :code, :http_status

    def initialize(code, message, http_status = nil)
      @code = code
      @http_status = http_status
      super(message)
    end
  end

  # First check (in evaluation order) whose status is 'fail', or nil when none failed.
  def first_failed_check(checks) = checks.each { |name, status| return name if status == 'fail' } && nil

  # A plain JSON object (a Hash).
  def plain_object?(v) = v.is_a?(Hash)

  # The single-process reference ChargeBudgetStore for tests (production needs a durable store with a conditional write):
  # get(key) -> {'budget', 'version'} | nil, compare_and_set(key, expected_version | nil, budget) -> bool.
  class MemoryChargeBudgetStore
    def initialize
      @m = {}
      @lock = Mutex.new
    end

    def get(key) = @lock.synchronize { (r = @m[key]).nil? ? nil : Marshal.load(Marshal.dump(r)) }

    def compare_and_set(key, expected, budget)
      @lock.synchronize do
        next false if (@m[key]&.fetch('version')) != expected

        @m[key] = { 'budget' => Marshal.load(Marshal.dump(budget)), 'version' => (expected || 0) + 1 }
        true
      end
    end
  end

  DEFAULT_SHARD_DEFS = 512

  # Shard names are the resource family (`resource.type` first segment) of the defs, split in order into chunks of `max`:
  # [{'name', 'defs'}].
  def shard_defs(defs, max = DEFAULT_SHARD_DEFS)
    raise Actions::ActionKitError.new('bad_shard_size', 'the shard size must be a positive integer') unless max.is_a?(Integer) && max >= 1

    fam = {}
    defs.each { |d| (fam[d['resource']['type'].split('.', -1)[0]] ||= []) << d }
    out = []
    fam.keys.sort_by { |k| Predicates.units(k).pack('n*') }.each do |f|
      l = fam[f]
      n = 1
      (0...l.length).step(max) do |i|
        out << { 'name' => l.length > max ? "#{f}-#{n}" : f, 'defs' => l[i, max] }
        n += 1
      end
    end
    out
  end

  # ---- intent goal strings ------------------------------------------------------------------------------------------------------
  # Parse an intent goal string: {'intentRef', 'mapDigest'?} or nil when it is not one.
  def parse_intent_goal(goal)
    return nil unless goal.is_a?(String) && goal.start_with?(INTENT_GOAL_PREFIX)

    ref, map, *rest = goal[INTENT_GOAL_PREFIX.length..].split(':', -1)
    return nil if ref.nil? || ref.empty? || !rest.empty?

    map.nil? || map.empty? ? { 'intentRef' => ref } : { 'intentRef' => ref, 'mapDigest' => map }
  end

  # Ask the judge panel (an object with #verdicts(input)) and attest (the hook form): {'att', 'verdicts'}. `verify` is the injected threshold
  # verifier of intent_conformance_attestation.
  def check_intent_conformance(panel, input, opts, verify)
    verdicts = panel.verdicts(input)
    { 'att' => IntentRuntime.intent_conformance_attestation(input, verdicts, opts, verify), 'verdicts' => verdicts }
  end
end
