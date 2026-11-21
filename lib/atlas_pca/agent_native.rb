# frozen_string_literal: true

require 'securerandom'

module AtlasPca
  # Agent-native authority primitives (the reference's `agentNative` namespace): uncertainty attestation, rationale binding, the
  # semantic firewall (tool-schema caveats), capability introspection and the authority lease.
  #
  #   claim = AtlasPca::AgentNative.sign_caution({ 'action_digest' => d, 'caution' => 0.4, 'holder' => key.public }, key)
  #   AtlasPca::AgentNative.combine_signed_caution(claim, d, 0.2, key.public) # {"effectiveRisk"=>0.4, "honoured"=>true, ...}
  #
  # Pure and deterministic: no clocks (callers pass `now`) and no randomness except the default rationale salt. The verifiers and
  # evaluators are total and fail closed (they never raise on malformed input); the AUTHORING helpers (sign_caution, bind_rationale,
  # tool_schema_caveat, grant_lease) raise on invalid input, so a bad artefact is never minted. Values are the reference's JSON:
  # Hashes with String keys, Arrays, Strings, numbers (a finite Integer or Float; true/false are never numbers) and nil. The
  # member names are the reference's (effectiveRisk, hasEnvelope, remainingBudgetHints, ...).
  #
  # `renew_capability_lease` is the reference's pure renewLease(lease, heartbeat, now); AtlasPca::Lease's renew_lease is the grants
  # LeaseRegistry renewal, a different feature.
  module AgentNative
    CAVEAT_ENVELOPE = 'envelope'
    CAVEAT_EXPIRES = 'expires'
    CAVEAT_NOT_BEFORE = 'not_before'
    CAVEAT_RATE = 'rate'
    CAVEAT_MAX_BLAST_RADIUS = 'max_blast_radius'
    CAVEAT_REVERSIBILITY_MAX = 'reversibility_max'
    CAVEAT_DELEGATION_DEPTH = 'delegation_depth'
    CAVEAT_PREDICATES = 'predicates'
    CAVEAT_TOOL_SCHEMA = 'tool_schema'
    CAVEAT_MAX_SPEND = 'max_spend'

    MAX_CAUTION_REASON_LEN = AtlasPca::MAX_CAUTION_REASON_LEN
    MIN_SALT_BYTES = 16
    MIN_SALT_DISTINCT_BYTES = 8
    MAX_RATIONALE_LEN = 8192
    MAX_SCHEMA_DEPTH = AtlasPca::MAX_SCHEMA_DEPTH
    MAX_SCHEMA_NODES = AtlasPca::MAX_SCHEMA_NODES
    MAX_OBJECT_PROPS = AtlasPca::MAX_OBJECT_PROPS
    MAX_ENUM_VALUES = AtlasPca::MAX_ENUM_VALUES
    DEFAULT_MAX_ARRAY_ITEMS = AtlasPca::DEFAULT_MAX_ARRAY_ITEMS
    ABSOLUTE_MAX_ARRAY_ITEMS = AtlasPca::ABSOLUTE_MAX_ARRAY_ITEMS
    DEFAULT_MAX_STRING_LEN = AtlasPca::DEFAULT_MAX_STRING_LEN
    ABSOLUTE_MAX_STRING_LEN = AtlasPca::ABSOLUTE_MAX_STRING_LEN
    MAX_VALUE_NODES = AtlasPca::MAX_VALUE_NODES
    HEARTBEAT_SKEW_MS = 30_000
    MAX_LEASE_TTL_MS = 7 * 24 * 3_600_000

    SAFE_INT = (2**53) - 1
    ABSENT = Object.new.freeze
    SALT_RE = /\A[A-Za-z0-9_-]+\z/
    CAUTION_KEYS = %w[action_digest caution reason holder sig].freeze
    HB_KEYS = %w[cap_id seq at holder lease_issued_at sig].freeze

    module_function

    # ---- JS-shaped helpers ----------------------------------------------------------------------------------------------

    def fin(x) = AtlasPca.finite_num(x)
    def fin?(x) = !fin(x).nil?

    # Number.isInteger
    def int?(x)
      f = fin(x)
      !f.nil? && f == f.floor
    end

    def neg0?(x) = x.is_a?(Float) && x.zero? && (1.0 / x).negative?
    def str?(x) = x.is_a?(String)
    def non_empty?(x) = x.is_a?(String) && !x.empty?
    def js_len(s) = SafeRegex.utf16_len(s)

    # A computed double as the caller's number: an integral value inside the safe range is an Integer (no -0).
    def nz(x)
      x.is_a?(Float) && x.finite? && x == x.floor && x.abs <= SAFE_INT ? x.to_i : x
    end

    def clamp01(x) = [1.0, [0.0, x.to_f].max].min

    def only_keys?(o, allowed) = o.keys.all? { |k| allowed.include?(k) }

    # JavaScript === for the scalars compared here (a bool is not a number).
    def strict_eq?(a, b)
      fa = fin(a)
      fb = fin(b)
      return !fa.nil? && !fb.nil? && fa == fb if !fa.nil? || !fb.nil?

      a.is_a?(String) && b.is_a?(String) && a == b
    end

    def truthy?(x)
      !(x.nil? || x == false || x == '' || (x.is_a?(Numeric) && (x.zero? || (x.is_a?(Float) && x.nan?))))
    end

    # JavaScript `o.k`: nil for a missing member or a non-object (a TypeError for null).
    def prop(o, k)
      raise TypeError, 'cannot read property of null' if o.nil?

      o.is_a?(Hash) ? o[k] : nil
    end

    # UTF-8 byte order of Strings (== code point order), as the reference's compareUtf8
    def sort_utf8(list) = list.sort_by(&:b)
    def sorted_unique(list) = sort_utf8(list.uniq)

    # JSON.parse(canonicalize(x)) for a value with a Number-only vocabulary: a deep copy where -0 becomes 0 and a non-finite
    # number raises (the lenient canonical form of the reference).
    def clone_lenient(x)
      case x
      when Hash then x.to_h { |k, v| [k.to_s, clone_lenient(v)] }
      when Array then x.map { |v| clone_lenient(v) }
      when Float
        raise AtlasPca::Malformed, 'canonicalize: non-finite number' unless x.finite?

        x.zero? ? 0 : x
      when String, Integer, true, false, nil then x
      else raise AtlasPca::Malformed, "unsupported type #{x.class}"
      end
    end

    # ---- 1. uncertainty attestation --------------------------------------------------------------------------------------

    def sign_caution(body, holder) = AtlasPca.sign_caution(body, holder)

    def caution_error(b)
      return 'not an object' unless b.is_a?(Hash)
      return 'action_digest required' unless non_empty?(b['action_digest'])
      return 'holder required' unless non_empty?(b['holder'])

      c = fin(b['caution'])
      return 'caution must be a finite number in [0,1]' if c.nil? || c.negative? || c > 1
      return nil unless b.key?('reason')

      r = b['reason']
      return 'invalid reason' unless r.is_a?(String) && r.valid_encoding? && js_len(r) <= MAX_CAUTION_REASON_LEN && AtlasPca::CAUTION_REASON_RE.match?(r)

      nil
    end

    # The shared verifier; `digest` / `holder` are the expected values, or ABSENT.
    def verify_caution_with(claim, digest, holder)
      return false unless claim.is_a?(Hash) && claim['sig'].is_a?(String) && only_keys?(claim, CAUTION_KEYS)
      return false unless caution_error(claim).nil?
      return false if digest != ABSENT && claim['action_digest'] != digest
      return false if holder != ABSENT && claim['holder'] != holder

      body = claim.reject { |k, _| k == 'sig' }
      AtlasPca.verify_b64u(claim['holder'], AtlasPca.domain_body_bytes(AtlasPca::CAUTION_DOMAIN, body), claim['sig'])
    rescue StandardError, SystemStackError
      false
    end

    # Verify a caution claim: strict shape (no smuggled member), caution in [0,1], a valid signature by claim['holder'], bound to
    # `expected_action_digest` (when given) and signed by `expected_holder` (when given: production callers MUST pass the PCActn's
    # holder, otherwise any key may attest). nil = not given. Total.
    def verify_caution(claim, expected_action_digest = nil, expected_holder = nil)
      verify_caution_with(claim, expected_action_digest.nil? ? ABSENT : expected_action_digest, expected_holder.nil? ? ABSENT : expected_holder)
    end

    # max(declared, server_risk) clamped to [0,1]: never below the server's figure, non-decreasing in the declaration; an unusable
    # declaration is ignored and an unusable server risk fails closed to 1.
    def combine_caution(agent_declared_caution, server_risk)
      s = fin?(server_risk) ? clamp01(fin(server_risk)) : 1.0
      return s unless fin?(agent_declared_caution)

      [clamp01(fin(agent_declared_caution)), s].max
    end

    # The same, taking a signed claim: only a valid claim bound to THIS action (and, when given, THIS holder) is honoured.
    def combine_signed_caution(claim, action_digest, server_risk, expected_holder = nil)
      s = fin?(server_risk) ? clamp01(fin(server_risk)) : 1.0
      ok = !claim.nil? && !action_digest.nil? && verify_caution_with(claim, action_digest, expected_holder.nil? ? ABSENT : expected_holder)
      eff = combine_caution(ok ? claim['caution'] : nil, s)
      { 'effectiveRisk' => eff, 'honoured' => ok, 'escalated' => eff > s }
    end

    # Exhaustive-grid check of the monotonicity property (non-finite and non-number entries are dropped).
    def check_caution_monotone(grid)
      g = grid.select { |x| fin?(x) }
      g.each do |s|
        g.each do |d|
          e = combine_caution(d, s)
          return { 'ok' => false, 'counterexample' => [d, s] } if e < clamp01(fin(s))

          g.each do |d2|
            return { 'ok' => false, 'counterexample' => [d2, s] } if fin(d2) >= fin(d) && combine_caution(d2, s) < e
          end
        end
      end
      { 'ok' => true }
    end

    # ---- 2. rationale binding --------------------------------------------------------------------------------------------

    # Entropy floor of a commitment salt: base64url of >= 16 bytes with >= 8 distinct byte values (at most 256 characters).
    def strong_salt?(salt)
      return false unless salt.is_a?(String) && salt.valid_encoding? && salt.length <= 256 && SALT_RE.match?(salt)

      b = AtlasPca.b64d(salt)
      !b.nil? && b.bytesize >= MIN_SALT_BYTES && b.bytes.uniq.length >= MIN_SALT_DISTINCT_BYTES
    end

    def commit_digest(action_digest, salt, rationale)
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/rationale/v1', 'a' => action_digest, 's' => salt, 'r' => rationale })
    end

    # The agent commits to its stated reason: publish `commitment`, KEEP `reveal`. `salt` (b64u, >= 16 bytes with >= 8 distinct
    # values) defaults to 32 random bytes. Raises on a weak salt, a non-string or oversized rationale or an action that cannot be
    # canonicalized.
    def bind_rationale(action, rationale, salt = ABSENT)
      salt = AtlasPca.b64e(SecureRandom.random_bytes(32)) if salt.equal?(ABSENT)
      raise TypeError, 'bindRationale: rationale must be a string' unless rationale.is_a?(String)
      raise RangeError, 'bindRationale: rationale too long' if js_len(rationale) > MAX_RATIONALE_LEN
      unless strong_salt?(salt)
        raise RangeError, "bindRationale: salt must be b64u of >=#{MIN_SALT_BYTES} bytes with >=#{MIN_SALT_DISTINCT_BYTES} distinct values"
      end

      action_digest = AtlasPca.hash_canonical(action)
      { 'commitment' => { 'v' => 1, 'action_digest' => action_digest, 'commitment' => commit_digest(action_digest, salt, rationale) },
        'reveal' => { 'rationale' => rationale, 'salt' => salt } }
    end

    def commitment_ok?(c)
      c.is_a?(Hash) && fin(c['v']) == 1 && non_empty?(c['action_digest']) && non_empty?(c['commitment'])
    end

    # Does the revealed rationale open the commitment (and, when `action` is given, for that very action)? A salt below the entropy
    # floor is refused even if it hashes correctly. Total.
    def verify_rationale(commitment, reveal, action = ABSENT)
      return false unless commitment.is_a?(Hash) && reveal.is_a?(Hash) && commitment_ok?(commitment)
      return false unless reveal['rationale'].is_a?(String) && js_len(reveal['rationale']) <= MAX_RATIONALE_LEN && strong_salt?(reveal['salt'])
      return false if !action.equal?(ABSENT) && AtlasPca.hash_canonical(action) != commitment['action_digest']

      commit_digest(commitment['action_digest'], reveal['salt'], reveal['rationale']) == commitment['commitment']
    rescue StandardError, SystemStackError
      false
    end

    # After-the-fact audit with an auditor-supplied judge (a callable (rationale, action) -> true | other). Failing to open the
    # commitment, or a rationale that opens and is judged false, is slashable; a malformed commitment, the wrong action or a
    # throwing judge is not. Total.
    def audit_rationale(commitment, action, reveal, judge)
      plain = commitment.is_a?(Hash)
      evidence = { 'commitment' => plain && commitment['commitment'].is_a?(String) ? commitment['commitment'] : '',
                   'action_digest' => plain && commitment['action_digest'].is_a?(String) ? commitment['action_digest'] : '' }
      return { 'verdict' => 'malformed', 'slashable' => false, 'evidence' => evidence } unless commitment_ok?(commitment)
      return { 'verdict' => 'wrong_action', 'slashable' => false, 'evidence' => evidence } if AtlasPca.hash_canonical(action) != commitment['action_digest']
      return { 'verdict' => 'unopened', 'slashable' => true, 'evidence' => evidence } unless truthy?(reveal) && verify_rationale(commitment, reveal, action)

      begin
        good = judge.call(reveal['rationale'], action).equal?(true)
      rescue StandardError, SystemStackError
        return { 'verdict' => 'judge_error', 'slashable' => false, 'evidence' => evidence.merge('rationale' => reveal['rationale']) }
      end
      { 'verdict' => good ? 'consistent' : 'false_rationale', 'slashable' => !good, 'evidence' => evidence.merge('rationale' => reveal['rationale']) }
    rescue StandardError, SystemStackError
      { 'verdict' => 'malformed', 'slashable' => false, 'evidence' => evidence }
    end

    # ---- 3. semantic firewall --------------------------------------------------------------------------------------------

    def validate_arg_schema(schema) = AtlasPca.validate_arg_schema(schema)

    def binding_of(tool, signature_digest, schema)
      AtlasPca.hash_canonical({ 'tool' => tool, 'signature_digest' => signature_digest, 'schema' => schema })
    end

    # Build a `tool_schema` caveat: authority for exactly this tool + signature + closed argument schema. Raises when the signature
    # has no tool name, the schema is invalid or anything is not canonicalizable. The schema is deep-cloned.
    def tool_schema_caveat(tool_signature, arg_schema)
      tool = if tool_signature.is_a?(String) then tool_signature
             elsif tool_signature.is_a?(Hash) && tool_signature['name'].is_a?(String) then tool_signature['name']
             else ''
             end
      raise TypeError, 'toolSchemaCaveat: tool name required' if tool.empty?

      err = validate_arg_schema(arg_schema)
      raise TypeError, "toolSchemaCaveat: #{err}" if err

      schema = clone_lenient(arg_schema)
      signature_digest = AtlasPca.hash_canonical(tool_signature)
      { 'type' => 'tool_schema', 'tool' => tool, 'signature_digest' => signature_digest, 'schema' => schema,
        'schema_digest' => AtlasPca.hash_canonical(schema), 'binding_digest' => binding_of(tool, signature_digest, schema) }
    end

    # Evaluate a tool call {'tool', 'args', 'toolSignature'?, 'toolSignatureDigest'?} against a `tool_schema` caveat:
    # {'ok' => true} or {'ok' => false, 'reason' => ...}. Fails closed, never raises.
    def evaluate_tool_schema(caveat, call)
      ok, reason = AtlasPca.evaluate_tool_schema(caveat, call)
      ok ? { 'ok' => true } : { 'ok' => false, 'reason' => reason }
    end

    # The caveat-evaluator hook for `tool_schema`: ctx = {'toolCall' => {...}}; other caveat types are unsatisfied here.
    def tool_schema_evaluator(caveat, ctx)
      return false unless ctx.is_a?(Hash) && ctx['toolCall'].is_a?(Hash)

      evaluate_tool_schema(caveat, ctx['toolCall'])['ok']
    end

    # The delegated-narrowing caveat {'type' => 'predicates', 'allow' => [...]} (deep-cloned canonical form).
    def predicates_caveat(allow) = { 'type' => CAVEAT_PREDICATES, 'allow' => clone_lenient(allow) }

    # The action's spend in USD as `max_spend` reads it: the own action['action']['params']['amount'] (finite, >= 0) whose own
    # `currency`, when present, is "usd" or "USD". nil = no readable spend. (AtlasPca.action_spend_usd takes the inner action.)
    def action_spend_usd(action)
      return nil unless action.is_a?(Hash) && action['action'].is_a?(Hash)

      params = action['action']['params']
      return nil unless params.is_a?(Hash) && params.key?('amount')

      amount = params['amount']
      f = fin(amount)
      return nil if f.nil? || f.negative?
      return nil if params.key?('currency') && params['currency'] != 'usd' && params['currency'] != 'USD'

      amount
    end

    def max_spend_satisfied?(caveat, ctx)
      lim = fin(caveat['usd'])
      spend = action_spend_usd(ctx['action'])
      !lim.nil? && !spend.nil? && fin(spend) <= lim
    end

    STOCK_CTX = { 'now' => 'now', 'blastRadius' => 'blast_radius', 'reversibilityClass' => 'reversibility_class',
                  'delegationDepth' => 'delegation_depth', 'recentActionTimes' => 'recent_action_times' }.freeze

    # Superset of the stock envelope caveat evaluator: adds `predicates` (needs ctx['action']), `max_spend` (needs ctx['action']) and
    # `tool_schema` (needs ctx['toolCall']). ctx is the reference's: now, blastRadius, reversibilityClass, delegationDepth,
    # recentActionTimes, action, toolCall. Anything else defers to the stock types and fails closed. Total.
    def agent_native_caveat_evaluator(caveat, ctx)
      return false unless caveat.is_a?(Hash) && ctx.is_a?(Hash)

      case caveat['type']
      when CAVEAT_TOOL_SCHEMA then tool_schema_evaluator(caveat, ctx)
      when CAVEAT_PREDICATES
        a = ctx['action']
        return false unless a.is_a?(Hash) && caveat['allow'].is_a?(Array)

        caveat['allow'].any? { |p| AtlasPca.predicate_matches(p, a) }
      when CAVEAT_MAX_SPEND then max_spend_satisfied?(caveat, ctx)
      else
        stock = {}
        STOCK_CTX.each { |src, dst| stock[dst] = ctx[src] if ctx.key?(src) }
        AtlasPca.caveat_satisfied?(caveat, stock)
      end
    rescue StandardError, SystemStackError
      false
    end

    # ---- 4. capability introspection -------------------------------------------------------------------------------------

    def intersect_verbs(a, b)
      return sorted_unique(b) if a.include?('*')
      return sorted_unique(a) if b.include?('*')

      sorted_unique(a.select { |x| b.include?(x) })
    end

    # Intersect two resource patterns: the pattern, nil = empty, :opaque = cannot decide symbolically (regex).
    def inter_res(a, b)
      return a if a == b
      return :opaque if a.start_with?('re:') || b.start_with?('re:')
      return b if a == '*'
      return a if b == '*'

      ap = a.end_with?('*')
      bp = b.end_with?('*')
      if ap && bp
        pa = a[0...-1]
        pb = b[0...-1]
        return pb.start_with?(pa) ? b : (pa.start_with?(pb) ? a : nil)
      end
      return b.start_with?(a[0...-1]) ? b : nil if ap
      return a.start_with?(b[0...-1]) ? a : nil if bp

      nil
    end

    # Collapse a conjunction of resource patterns; nil = unsatisfiable.
    def collapse_resources(list)
      lit = nil
      res = []
      list.each do |p|
        if p.start_with?('re:')
          res << p unless res.include?(p)
          next
        end
        if lit.nil?
          lit = p
        else
          r = inter_res(lit, p)
          return nil if r.nil? || r == :opaque

          lit = r
        end
      end
      out = (!lit.nil? && lit != '*' ? [lit] : []) + sort_utf8(res)
      out.empty? ? ['*'] : out
    end

    def scope_of_predicate(p)
      return nil unless p.is_a?(Hash)

      v = p['verb']
      verbs = if v.is_a?(String) then [v]
              elsif v.is_a?(Array) && v.all?(String) then v.dup
              end
      return nil if verbs.nil?
      return nil if p.key?('resource') && !p['resource'].is_a?(String)

      where = p.key?('where') ? p['where'] : []
      return nil unless where.is_a?(Array)

      { 'verbs' => sorted_unique(verbs), 'resources' => [p.key?('resource') ? p['resource'] : '*'], 'where' => where }
    end

    def intersect_scopes(a, b)
      out = {}
      a.each do |x|
        b.each do |y|
          verbs = intersect_verbs(x['verbs'], y['verbs'])
          next if verbs.empty?

          resources = collapse_resources(x['resources'] + y['resources'])
          next if resources.nil?

          s = { 'verbs' => verbs, 'resources' => resources, 'where' => x['where'] + y['where'] }
          out[AtlasPca.hash_canonical(s)] = s
        end
      end
      out.keys.sort.map { |k| out[k] }
    end

    def scope_matches?(s, verb, resource, params)
      return false if !s['verbs'].include?('*') && !s['verbs'].include?(verb)

      action = { 'verb' => verb, 'resource' => resource }
      action['params'] = params if truthy?(params)
      ctx = { 'action' => action }
      s['resources'].each { |r| return false unless AtlasPca.predicate_matches({ 'verb' => '*', 'resource' => r }, ctx) }
      return AtlasPca.predicate_matches({ 'verb' => '*', 'where' => s['where'] }, ctx) if !params.nil? && !s['where'].empty?

      true
    end

    def well_formed_caveat?(cv)
      case cv['type']
      when CAVEAT_EXPIRES, CAVEAT_NOT_BEFORE then fin?(cv['at'])
      when CAVEAT_RATE then fin?(cv['max']) && fin?(cv['per_secs']) && fin(cv['per_secs']).positive?
      when CAVEAT_MAX_BLAST_RADIUS, CAVEAT_DELEGATION_DEPTH then fin?(cv['max'])
      when CAVEAT_REVERSIBILITY_MAX then cv['class'].is_a?(String) && AtlasPca::REVERSIBILITY_ORDER.include?(cv['class'])
      when CAVEAT_PREDICATES then cv['allow'].is_a?(Array) && cv['allow'].all? { |p| !scope_of_predicate(p).nil? }
      when CAVEAT_TOOL_SCHEMA then non_empty?(cv['tool'])
      when 'budget_alloc' then fin?(cv['limit']) && fin(cv['limit']) >= 0
      when CAVEAT_MAX_SPEND then fin?(cv['usd']) && fin(cv['usd']) >= 0
      else false
      end
    end

    def empty_envelope
      { 'ok' => false, 'hasEnvelope' => false, 'scopes' => [], 'verbs' => [], 'resources' => [], 'opaqueResourceConstraints' => [],
        'tools' => [], 'toolSchemas' => [], 'unsatisfiable' => [], 'caveats' => [], 'remainingBudgetHints' => {} }
    end

    # What an attenuated chain permits NOW: the conjunction of the root `envelope` predicates and every appended caveat, derived
    # with the verifier's own vocabulary (never wider than reality). A chain that does not verify, or one carrying a caveat the
    # verifier cannot satisfy, permits nothing. Deterministic (`now` supplied) and total. `policy` takes allowedSuites, pqPins and
    # trustedRoot.
    def describe_envelope(chain, now = nil, expected_root_issuer = nil, policy = nil)
      pol = policy.is_a?(Hash) ? policy : {}
      reason, ok = AtlasPca.verify_chain(chain, expected_root_issuer, !expected_root_issuer.nil?, pol['allowedSuites'], pol['pqPins'], pol['trustedRoot'])
      return empty_envelope.merge('reason' => reason) unless ok

      root = chain[0]
      leaf = chain[-1]
      env0 = AtlasPca.read_envelope(root)
      env = empty_envelope.merge('ok' => true, 'hasEnvelope' => !env0.nil?, 'caveats' => leaf['caveats'])
      h = env['remainingBudgetHints']
      bad = []
      scopes = nil
      tools = nil
      seen_envelope = false
      everything = [{ 'verbs' => ['*'], 'resources' => ['*'], 'where' => [] }]
      if env0
        base = env0['predicates'].map { |p| scope_of_predicate(p) }
        bad << 'envelope.predicates' if base.any?(&:nil?)
        scopes = intersect_scopes(base.compact, everything)
      end

      fold = lambda do |cv, in_envelope|
        unless cv.is_a?(Hash) && cv['type'].is_a?(String)
          bad << '<malformed>'
          next
        end
        t = cv['type']
        if t == CAVEAT_ENVELOPE
          bad << CAVEAT_ENVELOPE if seen_envelope || in_envelope
          seen_envelope = true
          next
        end
        unless well_formed_caveat?(cv)
          bad << t
          next
        end
        case t
        when CAVEAT_PREDICATES
          scopes = intersect_scopes(scopes || everything, cv['allow'].map { |p| scope_of_predicate(p) })
        when CAVEAT_TOOL_SCHEMA
          env['toolSchemas'] << cv
          sig = cv.key?('signature_digest') ? Predicates.js_string(cv['signature_digest']) : 'undefined'
          consistent = validate_arg_schema(cv['schema']).nil? && AtlasPca.hash_canonical(cv['schema']) == cv['schema_digest'] &&
                       binding_of(cv['tool'], sig, cv['schema']) == cv['binding_digest']
          if consistent
            tools = tools.nil? ? [cv['tool']] : tools.select { |x| x == cv['tool'] }
          else
            tools = []
            bad << CAVEAT_TOOL_SCHEMA
          end
        when CAVEAT_EXPIRES then h['expiresAt'] = h.key?('expiresAt') ? [h['expiresAt'], cv['at']].min : cv['at']
        when CAVEAT_NOT_BEFORE then h['notBefore'] = h.key?('notBefore') ? [h['notBefore'], cv['at']].max : cv['at']
        when CAVEAT_RATE
          m = fin(cv['max'])
          p = fin(cv['per_secs'])
          cur = h['maxRate']
          cm = cur && fin(cur['max'])
          cp = cur && fin(cur['per_secs'])
          h['maxRate'] = { 'max' => cv['max'], 'per_secs' => cv['per_secs'] } if cur.nil? || m / p < cm / cp || (m / p == cm / cp && m < cm)
        when CAVEAT_MAX_BLAST_RADIUS then h['maxBlastRadius'] = h.key?('maxBlastRadius') ? [h['maxBlastRadius'], cv['max']].min : cv['max']
        when CAVEAT_REVERSIBILITY_MAX
          rev = AtlasPca::REVERSIBILITY_ORDER
          i = rev.index(cv['class'])
          j = h.key?('reversibilityMax') ? rev.index(h['reversibilityMax']) : rev.length
          h['reversibilityMax'] = rev[i] if i < j
        when CAVEAT_DELEGATION_DEPTH
          rem = nz(fin(cv['max']) - (chain.length - 1))
          h['delegationDepthRemaining'] = h.key?('delegationDepthRemaining') ? [h['delegationDepthRemaining'], rem].min : rem
        when 'budget_alloc' then h['budgetAlloc'] = h.key?('budgetAlloc') ? [h['budgetAlloc'], cv['limit']].min : cv['limit']
        when CAVEAT_MAX_SPEND then h['maxSpendUsd'] = h.key?('maxSpendUsd') ? [h['maxSpendUsd'], cv['usd']].min : cv['usd']
        end
      end

      env0['caveats'].each { |cv| fold.call(cv, true) } if env0
      leaf['caveats'].each { |cv| fold.call(cv, false) }

      env['scopes'] = scopes
      opaque = []
      if scopes
        vs = []
        rs = []
        scopes.each do |s|
          vs.concat(s['verbs'])
          s['resources'].each do |r|
            rs << r
            opaque << r if r.start_with?('re:')
          end
        end
        env['verbs'] = sorted_unique(vs)
        env['resources'] = sorted_unique(rs)
      else
        env['verbs'] = nil
        env['resources'] = nil
      end
      env['opaqueResourceConstraints'] = sorted_unique(opaque)
      env['tools'] = tools.nil? ? nil : sorted_unique(tools)
      env['unsatisfiable'] = sorted_unique(bad)
      unless env['unsatisfiable'].empty?
        env['scopes'] = []
        env['verbs'] = []
        env['resources'] = []
        env['tools'] = []
        env['reason'] = "unsatisfiable caveat(s): #{env['unsatisfiable'].join(', ')}"
      end
      h['expiresIn'] = nz(fin(h['expiresAt']) - fin(now)) if h.key?('expiresAt') && fin?(now)
      env
    rescue StandardError, SystemStackError
      empty_envelope.merge('reason' => 'introspection error (fail closed)')
    end

    # Cheap pre-flight an agent can run before attempting. false is DEFINITIVE (the verifier will refuse); true means the symbolic
    # envelope allows it. With `params` the `where` conditions are evaluated too (fail closed); without, a conditional scope counts
    # as "may permit". Total.
    def envelope_permits?(env, verb, resource, now = nil, params = nil)
      return false if !truthy?(env['ok']) || !env['unsatisfiable'].empty?
      return false if !env['scopes'].nil? && env['scopes'].none? { |s| scope_matches?(s, verb, resource, params) }

      h = env['remainingBudgetHints']
      return false if h.key?('delegationDepthRemaining') && !(fin?(h['delegationDepthRemaining']) && h['delegationDepthRemaining'] >= 0)

      if h.key?('maxSpendUsd') && !params.nil?
        spend = action_spend_usd({ 'action' => { 'params' => params } })
        ms = h['maxSpendUsd']
        return false if spend.nil? || !(fin(spend) <= (ms.is_a?(Numeric) ? ms : fin(ms)))
      end
      unless now.nil?
        return false unless fin?(now)
        # a bound that is not a finite number never admits (NaN compares false, an infinite bound would admit every clock)
        ea = h['expiresAt']
        nb = h['notBefore']
        return false if h.key?('expiresAt') && !(fin?(ea) && fin(now) < ea)
        return false if h.key?('notBefore') && !(fin?(nb) && fin(now) >= nb)
      end
      true
    rescue StandardError, SystemStackError
      false
    end

    # Pre-flight for a tool call: the tool must be in env['tools'] and satisfy EVERY `tool_schema` caveat. Total.
    def envelope_permits_tool_call(env, call)
      if !truthy?(env['ok']) || !env['unsatisfiable'].empty?
        return { 'ok' => false, 'reason' => env['reason'].nil? ? 'envelope not usable' : env['reason'] }
      end

      unless env['tools'].nil? # the reference reads call.tool only here (a null call is a TypeError, rescued below)
        tool = prop(call, 'tool')
        unless env['tools'].include?(tool)
          shown = call.is_a?(Hash) && call.key?('tool') ? Predicates.js_string(tool) : 'undefined'
          return { 'ok' => false, 'reason' => "tool #{AtlasPca::ToolSchema.show(shown)} not authorized" }
        end
      end

      env['toolSchemas'].each do |tc|
        r = evaluate_tool_schema(tc, call)
        return r unless r['ok']
      end
      { 'ok' => true }
    rescue StandardError, SystemStackError
      { 'ok' => false, 'reason' => 'evaluation error (fail closed)' }
    end

    # ---- 5. authority lease ----------------------------------------------------------------------------------------------

    # Issue a lease {'cap_id', 'holder', 'now', 'ttl_ms', 'hard_expires_at'?, 'max_renewals'?}. Raises unless the ids are
    # non-empty, `now` is finite, 0 < ttl_ms <= MAX_LEASE_TTL_MS, hard_expires_at (when present) is finite and after `now` and
    # max_renewals (when present) is a non-negative integer.
    def grant_lease(args)
      raise TypeError, 'grantLease: cap_id and holder required' unless non_empty?(args['cap_id']) && non_empty?(args['holder'])

      now = fin(args['now'])
      ttl = fin(args['ttl_ms'])
      raise RangeError, 'grantLease: invalid now/ttl_ms' if now.nil? || ttl.nil? || ttl <= 0 || ttl > MAX_LEASE_TTL_MS

      hard = args.key?('hard_expires_at') ? fin(args['hard_expires_at']) : ABSENT
      if !hard.equal?(ABSENT) && (hard.nil? || hard <= now)
        raise RangeError, 'grantLease: hard_expires_at must be finite and in the future'
      end
      mr = args.key?('max_renewals') ? args['max_renewals'] : ABSENT
      raise RangeError, 'grantLease: invalid max_renewals' if !mr.equal?(ABSENT) && !(int?(mr) && fin(mr) >= 0 && !neg0?(mr))

      exp = now + ttl
      exp = [exp, hard].min unless hard.equal?(ABSENT)
      lease = { 'cap_id' => args['cap_id'], 'holder' => args['holder'], 'issued_at' => nz(now), 'renewed_at' => nz(now),
                'ttl_ms' => nz(ttl), 'renewals' => 0, 'last_seq' => 0, 'expires_at' => nz(exp) }
      lease['hard_expires_at'] = nz(hard) unless hard.equal?(ABSENT)
      lease['max_renewals'] = nz(fin(mr)) unless mr.equal?(ABSENT)
      lease
    end

    def lease_error(l)
      return 'malformed lease' unless l.is_a?(Hash) && non_empty?(l['cap_id']) && non_empty?(l['holder'])
      return 'malformed lease' unless %w[issued_at renewed_at ttl_ms expires_at].all? { |k| fin?(l[k]) }

      ttl = fin(l['ttl_ms'])
      return 'malformed lease' if ttl <= 0 || ttl > MAX_LEASE_TTL_MS

      %w[renewals last_seq].each do |k|
        return 'malformed lease' unless int?(l[k]) && fin(l[k]) >= 0 && !neg0?(l[k])
      end
      return 'malformed lease' if l.key?('max_renewals') && !(int?(l['max_renewals']) && fin(l['max_renewals']) >= 0 && !neg0?(l['max_renewals']))

      if l.key?('hard_expires_at')
        return 'malformed lease' unless fin?(l['hard_expires_at'])
        return 'lease exceeds hard expiry' if fin(l['expires_at']) > fin(l['hard_expires_at'])
      end
      # a lease can never outlive one ttl past its last renewal: anything else is corruption or tampering
      return 'malformed lease' if fin(l['expires_at']) > fin(l['renewed_at']) + ttl

      nil
    end

    # Live iff the record is well-formed, the clock has not run back more than the skew window past the last renewal and
    # now < expires_at. Anything else is dead with a 'reason' and 'expiresIn' 0 (fail closed).
    def lease_state(lease, now)
      dead = ->(reason) { { 'live' => false, 'expiresIn' => 0, 'reason' => reason } }
      return dead.call('invalid clock') unless fin?(now)

      e = lease_error(lease)
      return dead.call(e) if e
      return dead.call('clock before last renewal') if fin(now) < fin(lease['renewed_at']) - HEARTBEAT_SKEW_MS

      expires_in = fin(lease['expires_at']) - fin(now)
      return dead.call('lease lapsed') if expires_in <= 0

      { 'live' => true, 'expiresIn' => nz(expires_in) }
    end

    def sign_heartbeat(body, holder) = AtlasPca.sign_heartbeat(body, holder)

    # The reference's pure renewLease: renew on a valid, fresh, in-order heartbeat signed by the lease holder for THIS lease grant.
    # A lease that has lapsed (or is malformed or clock-anomalous) is dead for good. Renewal never passes hard_expires_at, never
    # shortens the lease and spends the renewal budget. Returns {'ok' => true, 'lease' => ...} or {'ok' => false, 'reason' => ...};
    # total. (AtlasPca::Lease's renew_lease is the grants registry's renewal, not this.)
    def renew_capability_lease(lease, hb, now)
      st = lease_state(lease, now)
      unless st['live']
        return { 'ok' => false, 'reason' => st['reason'] == 'lease lapsed' ? 'lease lapsed' : "lease not live: #{st['reason']}" }
      end
      return { 'ok' => false, 'reason' => 'malformed heartbeat' } unless hb.is_a?(Hash) && only_keys?(hb, HB_KEYS) && hb['sig'].is_a?(String)

      unless strict_eq?(hb['cap_id'], lease['cap_id']) && strict_eq?(hb['holder'], lease['holder']) &&
             strict_eq?(hb['lease_issued_at'], lease['issued_at'])
        return { 'ok' => false, 'reason' => 'heartbeat not for this lease' }
      end
      seq = fin(hb['seq'])
      if seq.nil? || seq != seq.floor || seq.abs > SAFE_INT || seq <= fin(lease['last_seq'])
        return { 'ok' => false, 'reason' => 'stale or replayed heartbeat' }
      end
      at = fin(hb['at'])
      return { 'ok' => false, 'reason' => 'heartbeat outside skew window' } if at.nil? || (at - fin(now)).abs > HEARTBEAT_SKEW_MS

      body = hb.reject { |k, _| k == 'sig' }
      unless AtlasPca.verify_b64u(lease['holder'], AtlasPca.domain_body_bytes(AtlasPca::HEARTBEAT_DOMAIN, body), hb['sig'])
        return { 'ok' => false, 'reason' => 'bad heartbeat signature' }
      end
      if lease.key?('max_renewals') && fin(lease['renewals']) >= fin(lease['max_renewals'])
        return { 'ok' => false, 'reason' => 'renewal budget exhausted' }
      end

      exp = fin(now) + fin(lease['ttl_ms'])
      exp = [exp, fin(lease['hard_expires_at'])].min if lease.key?('hard_expires_at')
      return { 'ok' => false, 'reason' => 'malformed lease' } unless exp.finite?

      { 'ok' => true,
        'lease' => lease.merge('renewals' => nz(fin(lease['renewals']) + 1), 'last_seq' => hb['seq'],
                               'renewed_at' => nz([fin(now), fin(lease['renewed_at'])].max),
                               'expires_at' => nz([exp, fin(lease['expires_at'])].max)) }
    rescue StandardError, SystemStackError
      { 'ok' => false, 'reason' => 'malformed heartbeat' }
    end
  end
end
