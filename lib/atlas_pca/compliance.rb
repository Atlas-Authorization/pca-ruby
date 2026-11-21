# frozen_string_literal: true

require_relative '../atlas_pca'
require_relative 'explain_js'
require_relative 'predicates'
require_relative 'js_compat'

# Auditor-ready compliance evidence from PCA proofs and decision records, pre-mapped to the control language auditors use: EU AI Act
# Art. 12 / Art. 50, ISO/IEC 42001 clauses and SOC 2 CC6, plus the console-activity framework report (EU AI Act, SOC 2, GDPR).
# Port of the TypeScript reference (@atlasauth/pca-compliance). Everything is pure and read-only, and total where the reference is:
# a malformed record degrades to a best-effort one. HONEST SCOPE: an evidence mapping, not a legal certification; `satisfied` means
# the cryptographic evidence a control asks for is present in the supplied records. Inputs and outputs are the reference's JSON
# shapes (String-keyed Hashes / Arrays); property reads follow JavaScript semantics (a missing member is `undefined`, reading
# through null raises) so reports match the reference text for text.
module AtlasPca
  module Compliance
    X = ExplainJs
    UNDEF = X::UNDEF
    UNSET = Object.new.freeze # "argument omitted"
    COMPLIANCE_FRAMEWORKS = %w[eu-ai-act iso-42001 soc2].freeze
    FRAMEWORK_IDS = %w[eu-ai-act soc2 gdpr].freeze
    STATUS_GLYPH = { 'satisfied' => '✓', 'partial' => '◐', 'not-evidenced' => '·' }.freeze

    module_function

    # ---- JavaScript semantics ------------------------------------------------------------------------------------------

    def own(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    def nullish?(v) = v.nil? || v.equal?(UNDEF)

    # `o.k`: raises when `o` is null / undefined
    def prop(o, k)
      raise TypeError, "Cannot read properties of #{o.nil? ? 'null' : 'undefined'} (reading '#{k}')" if nullish?(o)

      own(o, k)
    end

    # `o?.k`
    def qprop(o, k) = nullish?(o) ? UNDEF : own(o, k)

    def truthy?(v) = X.truthy?(v)
    def fin?(v) = X.fin?(v)
    def num?(v) = X.num?(v)
    def num(v) = X.to_num(v)
    def gt(a, b) = X.gt(a, b)
    def tpl(v) = X.js_string(v)
    def num_str(v) = Predicates.js_number_string(v)

    # `v.length` for a string (UTF-16 units) or an array; undefined for any other value; raises on null / undefined
    def length(v)
      raise TypeError, "Cannot read properties of #{v.nil? ? 'null' : 'undefined'} (reading 'length')" if nullish?(v)

      return X.len16(v) if v.is_a?(String)

      v.is_a?(Array) ? v.length : UNDEF
    end

    # `Math.round`: halves round toward +Infinity
    def js_round(v)
      return v unless v.finite? # Math.round leaves NaN and the infinities as they are

      r = v.floor
      v - r >= 0.5 ? r + 1 : r
    end

    def integer?(v) = fin?(v) && v == v.floor

    # a `Set` with SameValueZero identity: primitives by value, objects each distinct
    class JsSet
      def initialize
        @keys = {}
        @n = 0
      end

      def add(v)
        k = if v == true || v == false then [:b, v]
            elsif v.is_a?(Integer) || v.is_a?(Float) then [:n, v.is_a?(Float) && v.nan? ? :nan : v.to_f + 0.0]
            elsif v.is_a?(String) then [:s, v.b]
            elsif v.nil? || v.equal?(UNDEF) then [:z, v.nil?]
            else [:o, (@n += 1)]
            end
        @keys[k] = true
      end

      def size = @keys.size
    end

    def json_str(s) = Js.json_string(s)

    # JSON.stringify(v) (compact; JS key order and number formatting)
    def stringify(v)
      case v
      when nil then 'null'
      when true then 'true'
      when false then 'false'
      when String then json_str(v)
      when Integer, Float then v.is_a?(Float) && !v.finite? ? 'null' : num_str(v)
      when Array then "[#{v.map { |x| x.equal?(UNDEF) ? 'null' : stringify(x) }.join(',')}]"
      when Hash then "{#{Js.js_keys(v).reject { |k| v[k].equal?(UNDEF) }.map { |k| "#{json_str(k)}:#{stringify(v[k])}" }.join(',')}}"
      else raise TypeError, "stringify: unsupported type #{v.class}"
      end
    end

    # JSON.stringify(v, null, 2)
    def pretty(v, base = '')
      if v.is_a?(Array)
        return '[]' if v.empty?

        ind = "#{base}  "
        "[\n#{v.map { |x| ind + (x.equal?(UNDEF) ? 'null' : pretty(x, ind)) }.join(",\n")}\n#{base}]"
      elsif v.is_a?(Hash)
        keys = Js.js_keys(v).reject { |k| v[k].equal?(UNDEF) }
        return '{}' if keys.empty?

        ind = "#{base}  "
        "{\n#{keys.map { |k| "#{ind}#{json_str(k)}: #{pretty(v[k], ind)}" }.join(",\n")}\n#{base}}"
      else
        stringify(v)
      end
    end

    # (year, month, day) of a day count since 1970-01-01 (proleptic Gregorian)
    def civil(days)
      z = days + 719_468
      era = z.div(146_097)
      doe = z - (era * 146_097)
      yoe = (doe - doe.div(1460) + doe.div(36_524) - doe.div(146_096)).div(365)
      y = yoe + (era * 400)
      doy = doe - ((365 * yoe) + yoe.div(4) - yoe.div(100))
      mp = ((5 * doy) + 2).div(153)
      d = doy - ((153 * mp) + 2).div(5) + 1
      m = mp < 10 ? mp + 3 : mp - 9
      [m <= 2 ? y + 1 : y, m, d]
    end

    # `new Date(ms).toISOString()`; raises ArgumentError for an invalid / unrepresentable time (a RangeError there)
    def iso_string(ms)
      raise ArgumentError, 'Invalid time value' if !num?(ms) || !fin?(ms) || ms.abs > 8.64e15

      days, rem = ms.to_i.divmod(86_400_000)
      y, mo, d = civil(days)
      ys = y >= 0 && y <= 9999 ? format('%04d', y) : (y.positive? ? '+' : '-') + format('%06d', y.abs)
      format('%s-%02d-%02dT%02d:%02d:%02d.%03dZ', ys, mo, d, rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000)
    end

    def iso(ms)
      return '(unknown time)' unless fin?(ms)

      iso_string(ms)
    rescue ArgumentError
      '(unrepresentable time)'
    end

    def ts(ms) = { 'epochMs' => ms, 'iso' => iso(ms) }
    def now_ms = (Time.now.to_f * 1000).to_i

    # abbreviate a long key for display (UTF-16 units, like the reference)
    def short(key, n = 12)
      return '(none)' unless key.is_a?(String) && !key.empty?
      return key if X.len16(key) <= n + 1

      "#{X.slice16(key, 0, n)}…"
    end

    def numstr(x)
      return X.js_string(x) unless fin?(x)
      return num_str(x) if integer?(x)

      num_str(js_round(x.to_f * 1e4) / 1e4)
    end

    # ---- AuditEvent ----------------------------------------------------------------------------------------------------

    def budget_alloc?(cv)
      cv.is_a?(Hash) && cv['type'] == 'budget_alloc' && fin?(cv['limit']) && cv['limit'] >= 0
    end

    # a bounded, human-readable rendering of one caveat
    def describe_caveat(cv)
      return '(malformed caveat)' unless cv.is_a?(Hash) && cv['type'].is_a?(String)

      if cv['type'] == 'envelope'
        preds = cv['predicates']
        inner = cv['caveats']
        return format('policy envelope (%d predicate(s), %d caveat(s))', preds.is_a?(Array) ? preds.length : 0, inner.is_a?(Array) ? inner.length : 0)
      end
      return "budget allocation ≤ #{numstr(cv['limit'])}" if budget_alloc?(cv)

      parts = []
      Js.js_keys(cv).first(8).each do |k|
        next if k == 'type'

        v = cv[k]
        parts << "#{k}=#{v.is_a?(Hash) || v.is_a?(Array) ? stringify(v) : numstr(v)}"
      end
      parts.empty? ? cv['type'] : "#{cv['type']}(#{parts.join(', ')})"
    end

    # the delegation hops: issuer -> holder and the caveats each hop ADDED (append-only diff against its parent)
    def build_delegation_hops(chain)
      safe = chain.is_a?(Array) ? chain : []
      hops = []
      safe.each_with_index do |cap, i|
        next unless truthy?(cap)

        is_root = i.zero?
        parent = i.positive? ? safe[i - 1] : nil
        pcv = truthy?(parent) ? own(parent, 'caveats') : UNDEF
        parent_len = pcv.is_a?(Array) ? pcv.length : 0
        own_cv = own(cap, 'caveats')
        mine = own_cv.is_a?(Array) ? own_cv : []
        added = if is_root then mine
                else mine.length >= parent_len ? mine[parent_len..] : []
                end
        scope = added.map { |c| describe_caveat(c) }
        budget_cv = added.find { |c| budget_alloc?(c) }
        issuer = own(cap, 'issuer')
        holder = own(cap, 'holder')
        joined = scope.join('; ')
        narrative = if is_root
                      "Principal #{short(issuer)} granted authority to #{short(holder)}#{scope.empty? ? '' : " under: #{joined}"}."
                    else
                      "#{short(issuer)} delegated to #{short(holder)}#{scope.empty? ? ' (rebind only, no new constraints)' : ", narrowing scope: #{joined}"}."
                    end
        hop = { 'index' => i, 'isRoot' => is_root, 'scope' => scope, 'caveats' => added, 'narrative' => narrative }
        hop['issuer'] = issuer unless issuer.equal?(UNDEF)
        hop['holder'] = holder unless holder.equal?(UNDEF)
        hop['budgetAlloc'] = budget_cv['limit'] unless budget_cv.nil?
        hops << hop
      end
      hops
    end

    # the signed co-signature (human override) of a PCActn's threshold signature, if any
    def build_human_override(threshold, required_tier, threshold_check)
      sh = truthy?(threshold) ? own(threshold, 'shares') : UNDEF
      shares = sh.is_a?(Array) ? sh : []
      return nil if shares.empty?

      # `threshold` is outside the signed body: never report a signed approval (or name approvers) from unverified shares.
      if threshold_check != 'pass'
        return { 'humanApproved' => false, 'approvers' => [], 'guardianCosigners' => [], 'roles' => [], 'requiredTier' => required_tier,
                 'narrative' => "#{shares.length} co-signature share(s) were presented but NOT verified (threshold check: " \
                                "#{nullish?(threshold_check) ? 'absent' : tpl(threshold_check)}); no human approval is recorded." }
      end

      approvers = []
      guardians = []
      roles = []
      shares.each do |s|
        next if !truthy?(s) || !own(s, 'role').is_a?(String)

        roles << s['role']
        pk = s['publicKey']
        approvers << pk if s['role'] == 'principal' && pk.is_a?(String)
        guardians << pk if s['role'] == 'guardian' && pk.is_a?(String)
      end
      approved = !approvers.empty?
      narrative = if approved
                    "Step-up approved by a signed human co-signature from principal #{short(approvers[0])}" \
                      "#{guardians.empty? ? '' : " (plus #{guardians.length} guardian co-sign)"} at tier t=#{tpl(required_tier)}."
                  else
                    "Co-signed by #{guardians.length} guardian share(s) at tier t=#{tpl(required_tier)} (no human principal signature present)."
                  end
      { 'humanApproved' => approved, 'approvers' => approvers, 'guardianCosigners' => guardians, 'roles' => roles,
        'requiredTier' => required_tier, 'narrative' => narrative }
    end

    def first_reason_or(decision, fallback)
      rs = own(decision, 'reasons')
      rs = rs.is_a?(Array) ? rs : []
      rs.length.positive? && rs[0].is_a?(String) ? rs[0] : fallback
    end

    # the auditor-facing outcome from the proof's verification and the Policy-VM decision
    def resolve_outcome(verify, decision)
      if !truthy?(verify) || !own(verify, 'allow').equal?(true)
        r = qprop(verify, 'reason')
        return { 'outcome' => 'deny', 'reason' => nullish?(r) ? 'proof failed verification' : r }
      end
      return { 'outcome' => 'allow', 'reason' => 'proof verified; no policy decision supplied' } unless truthy?(decision)

      if truthy?(own(decision, 'admit'))
        { 'outcome' => 'allow', 'reason' => first_reason_or(decision, 'auto-admitted within policy and budget') }
      elsif truthy?(own(decision, 'releaseGuardianShare'))
        { 'outcome' => 'step-up', 'reason' => first_reason_or(decision, 'policy satisfied but a co-signature is required') }
      else
        { 'outcome' => 'deny', 'reason' => first_reason_or(decision, 'policy did not release authority (default-deny)') }
      end
    end

    def safe_digest(p)
      return '(undigestible)' if p.equal?(UNDEF)

      AtlasPca.hash_canonical(p)
    rescue StandardError
      '(undigestible)'
    end

    # a normalized AuditEvent from a PCActn, the core verifier's result and the Policy-VM decision. `inp` is
    # {pcactn, verify, decision?, now?, session?}; `now` (epoch ms) defaults to the clock.
    def to_audit_event(inp)
      p = prop(inp, 'pcactn')
      verify = own(inp, 'verify')
      verify = { 'allow' => false, 'checks' => {} } if nullish?(verify)
      decision = own(inp, 'decision')
      now = own(inp, 'now')
      now = now_ms if nullish?(now)
      cc = qprop(p, 'cap_chain')
      chain = cc.is_a?(Array) ? cc : nil
      hops = build_delegation_hops(chain)
      leaf = chain && !chain.empty? ? chain[-1] : UNDEF
      root = chain && !chain.empty? ? chain[0] : UNDEF
      res = resolve_outcome(verify, decision)
      outcome = res['outcome']
      reason = res['reason']
      tier = qprop(qprop(decision, 'requiredThreshold'), 't')
      required_tier = nullish?(tier) ? 1 : tier
      checks_raw = own(verify, 'checks')
      human = build_human_override(qprop(p, 'threshold'), required_tier, qprop(checks_raw, 'threshold'))
      checks = nullish?(checks_raw) ? {} : checks_raw
      crypto_ok = own(checks, 'wire') == 'pass' && own(checks, 'leaf_signature') == 'pass'

      action = qprop(p, 'action')
      verb_v = qprop(action, 'verb')
      res_v = qprop(action, 'resource')
      verb = verb_v.is_a?(String) ? verb_v : '(unknown verb)'
      resource = res_v.is_a?(String) ? res_v : '(unknown resource)'
      gr = qprop(p, 'grant_ref')
      grant_ref = gr.is_a?(String) ? gr : '(none)'
      sig = qprop(p, 'sig')
      alg = qprop(p, 'alg')
      plan_root = qprop(qprop(p, 'plan'), 'root')
      pd = qprop(action, 'params_digest')
      counter = qprop(p, 'counter')
      nonce = qprop(p, 'nonce')
      evidence = {
        'pcactnDigest' => safe_digest(p),
        'leafSignature' => sig.is_a?(String) ? sig : '(unsigned)',
        'signatureSuite' => alg.is_a?(String) ? alg : 'ed25519',
        'planRoot' => plan_root.is_a?(String) ? plan_root : '(none)',
        'paramsDigest' => pd.is_a?(String) ? pd : '(none)',
        'grantRef' => grant_ref,
        'counter' => num?(counter) ? counter : -1,
        'cryptographicallyVerifiable' => crypto_ok
      }
      evidence['nonce'] = nonce if nonce.is_a?(String)

      risk = {}
      if truthy?(decision)
        rt = own(decision, 'requiredThreshold')
        { 'r' => own(decision, 'r'), 'tier' => qprop(rt, 't'), 'proof' => qprop(rt, 'proof'), 'budget' => own(decision, 'budget') }.each do |key, val|
          risk[key] = val unless val.equal?(UNDEF)
        end
      end

      word = outcome == 'allow' ? 'ALLOWED' : outcome == 'deny' ? 'DENIED' : 'STEP-UP'
      narrative = "Agent #{short(qprop(leaf, 'holder'))} #{word} to #{verb} on #{resource} (#{hops.length}-hop chain rooted at principal " \
                  "#{short(qprop(root, 'issuer'))}; #{crypto_ok ? 'cryptographically verifiable proof' : 'proof not cryptographically verifiable'}" \
                  "#{human && human['humanApproved'] ? '; human-signed step-up' : ''}). #{tpl(reason)}"

      holder = qprop(leaf, 'holder')
      principal = qprop(root, 'issuer')
      sess = own(inp, 'session')
      rc = qprop(action, 'reversibility_class')
      iat = qprop(p, 'iat')
      exp = qprop(p, 'exp')
      agent = { 'holder' => holder.is_a?(String) ? holder : '(none)', 'session' => nullish?(sess) ? grant_ref : sess }
      agent['principal'] = principal if principal.is_a?(String)
      event = {
        'schema' => 'atlas-pca/audit-event/v1',
        'recordedAt' => ts(now),
        'agent' => agent,
        'delegation' => { 'depth' => [0, hops.length - 1].max, 'hops' => hops },
        'action' => { 'verb' => verb, 'resource' => resource, 'paramsDigest' => evidence['paramsDigest'],
                      'reversibilityClass' => rc.is_a?(String) ? rc : '(unknown)', 'summary' => "#{verb} on #{resource}" },
        'decision' => { 'outcome' => outcome, 'reason' => reason, 'proofVerified' => own(verify, 'allow').equal?(true), 'checks' => checks },
        'risk' => risk,
        'timestamps' => { 'issuedAt' => ts(num?(iat) ? iat : Float::NAN), 'expiresAt' => ts(num?(exp) ? exp : Float::NAN) },
        'evidence' => evidence,
        'narrative' => narrative
      }
      event['humanOverride'] = human unless human.nil?
      event
    end

    # ---- control mappings ----------------------------------------------------------------------------------------------

    CONTROL_MAPPINGS = [
      {
        'framework' => 'eu-ai-act',
        'controlId' => 'eu-ai-act:art-12',
        'controlTitle' => 'Record-keeping — automatic, traceable logging of events',
        'clause' => 'EU AI Act, Article 12',
        'requirement' => 'High-risk AI systems must automatically record events ("logs") over their lifetime, enabling traceability of the system\'s functioning.',
        'pcaEvidence' => 'Every action is a signed PCActn; each log entry CITES its proof (the PCActn digest + the verifying leaf signature), so the record is tamper-evident and cannot be back-dated or fabricated.',
        'evidenceFields' => ['evidence.pcactnDigest', 'evidence.leafSignature', 'evidence.cryptographicallyVerifiable', 'timestamps.issuedAt']
      },
      {
        'framework' => 'eu-ai-act',
        'controlId' => 'eu-ai-act:art-50',
        'controlTitle' => 'Transparency — disclosure of automated decisions and the acting agent',
        'clause' => 'EU AI Act, Article 50',
        'requirement' => 'Providers/deployers must ensure natural persons are informed that they are interacting with / affected by an AI system; interactions and automated decisions must be disclosed.',
        'pcaEvidence' => 'Each entry discloses the acting AGENT identity (leaf holder), the PRINCIPAL it acts for (root issuer), the exact action, and the automated decision outcome + reason — a complete, attributable disclosure per action.',
        'evidenceFields' => ['agent.holder', 'agent.principal', 'action.summary', 'decision.outcome', 'decision.reason']
      },
      {
        'framework' => 'iso-42001',
        'controlId' => 'iso-42001:A.6.2.8',
        'controlTitle' => 'Reasoning trace — AI system event logging',
        'clause' => 'ISO/IEC 42001 Annex A.6.2.8 (AI system event logs / recording)',
        'requirement' => 'The organization shall record events produced by the AI system so that its decisions can be examined and explained after the fact.',
        'pcaEvidence' => 'Each entry carries the Policy-VM decision with its decisive reason, the risk score r, the required tier and the trust-budget state — a complete, machine-checked reasoning trace, not a free-text note.',
        'evidenceFields' => ['decision.reason', 'risk.r', 'risk.tier', 'risk.budget', 'decision.checks']
      },
      {
        'framework' => 'iso-42001',
        'controlId' => 'iso-42001:A.9.2',
        'controlTitle' => 'Delegation & authorization chain',
        'clause' => 'ISO/IEC 42001 Annex A.9.2 (authorization / responsible use of AI systems)',
        'requirement' => 'Use of the AI system must be authorized; the authority under which an automated action is taken must be identifiable and bounded.',
        'pcaEvidence' => 'The delegation chain is EXPLICIT: each hop records issuer → holder and the scope (caveats) it narrowed, rooted at the principal — authority is attenuated and provable, never ambient.',
        'evidenceFields' => ['delegation.hops', 'delegation.depth', 'agent.principal', 'delegation.hops[].scope']
      },
      {
        'framework' => 'iso-42001',
        'controlId' => 'iso-42001:A.9.3',
        'controlTitle' => 'Human oversight of AI systems',
        'clause' => 'ISO/IEC 42001 Annex A.9.3 (human oversight)',
        'requirement' => 'Mechanisms for human oversight of the AI system must exist and be exercised for higher-impact decisions.',
        'pcaEvidence' => 'Human oversight is a SIGNED CO-SIGNATURE: a step-up is approved by a principal threshold share naming the human approver (cryptographic, not a free-text "approved by"); denials and step-up requirements show the oversight boundary being enforced.',
        'evidenceFields' => ['humanOverride.humanApproved', 'humanOverride.approvers', 'decision.outcome', 'risk.tier']
      },
      {
        'framework' => 'iso-42001',
        'controlId' => 'iso-42001:A.6.2.2',
        'controlTitle' => 'Intended use — action bound to a committed plan',
        'clause' => 'ISO/IEC 42001 Annex A.6.2.2 (AI system requirements / intended purpose)',
        'requirement' => 'The AI system must operate within its intended purpose; actions outside the specified scope must be prevented.',
        'pcaEvidence' => 'Every action proves inclusion in a committed plan (the signed plan root): an off-plan action fails verification. The plan root in each entry binds the action to its intended, pre-committed purpose.',
        'evidenceFields' => ['evidence.planRoot', 'action.verb', 'action.resource', 'decision.checks']
      },
      {
        'framework' => 'soc2',
        'controlId' => 'soc2:CC6.1',
        'controlTitle' => 'Logical access security — least privilege',
        'clause' => 'SOC 2 CC6.1',
        'requirement' => 'The entity implements logical access controls to protect against unauthorized access, enforcing least privilege.',
        'pcaEvidence' => 'Access is deny-by-default: actions are constrained by signed predicates and capability attenuation. Denied entries evidence the control actively refusing out-of-scope access.',
        'evidenceFields' => ['decision.outcome', 'delegation.hops[].scope', 'decision.checks', 'evidence.cryptographicallyVerifiable']
      },
      {
        'framework' => 'soc2',
        'controlId' => 'soc2:CC6.2',
        'controlTitle' => 'Registration & authorization of credentials / identities',
        'clause' => 'SOC 2 CC6.2',
        'requirement' => 'Prior to issuing access, the entity registers and authorizes new identities; access is traceable to an authorizing principal.',
        'pcaEvidence' => 'Each agent identity (leaf holder) is bound into a delegation chain rooted at an authorizing principal, with every hop signed — access is always traceable to who authorized it.',
        'evidenceFields' => ['agent.principal', 'agent.holder', 'delegation.hops', 'evidence.grantRef']
      },
      {
        'framework' => 'soc2',
        'controlId' => 'soc2:CC6.3',
        'controlTitle' => 'Access modification & removal (attenuation / revocation)',
        'clause' => 'SOC 2 CC6.3',
        'requirement' => 'The entity modifies and removes access based on roles/need; access rights are narrowed or withdrawn appropriately.',
        'pcaEvidence' => 'Delegation is append-only attenuation: a child hop can only narrow scope, never widen it. Narrowing caveats per hop (and denied actions) evidence access being bounded and withdrawn.',
        'evidenceFields' => ['delegation.hops[].scope', 'delegation.hops[].budgetAlloc', 'decision.outcome']
      },
    ].freeze

    def assert_framework(framework)
      return if framework.is_a?(String) && COMPLIANCE_FRAMEWORKS.include?(framework)

      raise ArgumentError, "pca-compliance: unknown framework '#{tpl(framework)}' (have: #{COMPLIANCE_FRAMEWORKS.join(', ')})"
    end

    # the control mappings for a framework (the whole table when none is given)
    def control_mappings(framework = UNSET)
      return CONTROL_MAPPINGS.dup if framework.equal?(UNSET)

      assert_framework(framework)
      CONTROL_MAPPINGS.select { |m| m['framework'] == framework }
    end

    # ---- ComplianceReport ----------------------------------------------------------------------------------------------

    def compute_stats(events)
      agents = JsSet.new
      principals = JsSet.new
      sample = UNDEF
      verifiable = denied = step_up = allowed = human = with_chain = with_plan = 0
      max_depth = 0
      events.each do |e|
        next unless truthy?(e)

        verifiable += 1 if truthy?(prop(prop(e, 'evidence'), 'cryptographicallyVerifiable'))
        outcome = prop(prop(e, 'decision'), 'outcome')
        if outcome == 'deny' then denied += 1
        elsif outcome == 'step-up' then step_up += 1
        else allowed += 1
        end
        human += 1 if truthy?(qprop(own(e, 'humanOverride'), 'humanApproved'))
        hops_len = length(prop(prop(e, 'delegation'), 'hops'))
        with_chain += 1 if hops_len.is_a?(Integer) && hops_len.positive?
        with_plan += 1 if prop(prop(e, 'evidence'), 'planRoot') != '(none)'
        depth = prop(prop(e, 'delegation'), 'depth')
        max_depth = depth if gt(depth, max_depth)
        agents.add(prop(prop(e, 'agent'), 'holder'))
        principal = prop(prop(e, 'agent'), 'principal')
        principals.add(principal) unless principal.equal?(UNDEF)
        digest = prop(prop(e, 'evidence'), 'pcactnDigest')
        sample = digest if sample.equal?(UNDEF) && digest != '(undigestible)'
      end
      { 'total' => events.length, 'verifiable' => verifiable, 'denied' => denied, 'stepUp' => step_up, 'allowed' => allowed,
        'humanOverrides' => human, 'withChain' => with_chain, 'withPlanRoot' => with_plan, 'maxDepth' => max_depth,
        'agents' => agents.size, 'principals' => principals.size, 'sampleDigest' => sample }
    end

    def status_of(count, total) = count == total ? 'satisfied' : count.positive? ? 'partial' : 'not-evidenced'

    def evaluate_control(control_id, s)
      findings = []
      total = s['total']
      digest_note = s['sampleDigest'].equal?(UNDEF) ? '' : " (e.g. #{short(s['sampleDigest'], 16)})"
      if total.zero?
        return { 'status' => 'not-evidenced', 'evidence' => 'no actions in the reporting period', 'findings' => ['no events supplied — nothing to evidence'] }
      end

      case control_id
      when 'eu-ai-act:art-12'
        status = s['verifiable'] == total ? 'satisfied' : 'partial'
        findings << "#{total - s['verifiable']} of #{total} entries are not cryptographically verifiable" if s['verifiable'] < total
        { 'status' => status, 'evidence' => "#{total} actions logged; #{s['verifiable']}/#{total} cite a cryptographically verifiable proof#{digest_note}",
          'findings' => findings }
      when 'eu-ai-act:art-50'
        { 'status' => 'satisfied',
          'evidence' => "#{total} actions each disclose the acting agent, the principal (#{s['principals']} distinct) and the automated decision outcome",
          'findings' => findings }
      when 'iso-42001:A.6.2.8'
        { 'status' => 'satisfied', 'evidence' => "#{total} actions each carry a decision reason + risk/tier/budget reasoning trace", 'findings' => findings }
      when 'iso-42001:A.9.2'
        wc = s['withChain']
        findings << "#{total - wc} entries have no delegation chain" if wc < total
        { 'status' => status_of(wc, total),
          'evidence' => "#{wc}/#{total} actions carry an explicit delegation chain (max depth #{tpl(s['maxDepth'])}, #{s['principals']} authorizing principal(s))",
          'findings' => findings }
      when 'iso-42001:A.9.3'
        if s['humanOverrides'].positive?
          status = 'satisfied'
          evidence = "#{s['humanOverrides']} step-up(s) approved by a signed human co-signature; #{s['stepUp']} step-up(s) and #{s['denied']} denial(s) show oversight enforced"
        elsif s['stepUp'].positive? || s['denied'].positive?
          status = 'partial'
          evidence = "oversight boundary enforced (#{s['stepUp']} step-up(s), #{s['denied']} denial(s)) but no signed human co-signature observed in the period"
          findings << 'no human step-up co-signature was exercised in this period'
        else
          status = 'partial'
          evidence = 'all actions were auto-admitted within policy; no oversight event was triggered in the period'
          findings << 'no higher-impact action required human oversight in this period'
        end
        { 'status' => status, 'evidence' => evidence, 'findings' => findings }
      when 'iso-42001:A.6.2.2'
        wp = s['withPlanRoot']
        findings << "#{total - wp} entries are not bound to a committed plan root" if wp < total
        { 'status' => status_of(wp, total), 'evidence' => "#{wp}/#{total} actions are bound to a committed plan root (intended-use binding)",
          'findings' => findings }
      when 'soc2:CC6.1'
        findings << "#{s['denied']} out-of-scope action(s) denied — access control actively enforced" if s['denied'].positive?
        { 'status' => 'satisfied',
          'evidence' => "deny-by-default access over #{total} actions (#{s['allowed']} allowed, #{s['stepUp']} step-up, #{s['denied']} denied); " \
                        'all gated by signed predicates + attenuation',
          'findings' => findings }
      when 'soc2:CC6.2'
        wc = s['withChain']
        findings << "#{total - wc} entries are not traceable to an authorizing principal" if wc < total
        { 'status' => status_of(wc, total),
          'evidence' => "#{s['agents']} agent identit(ies) traceable to #{s['principals']} authorizing principal(s) via signed delegation chains",
          'findings' => findings }
      when 'soc2:CC6.3'
        narrowed = num(s['maxDepth']) >= 1
        findings << 'no attenuating hop or denial observed in the period' if !narrowed && s['denied'].zero?
        { 'status' => narrowed || s['denied'].positive? ? 'satisfied' : 'partial',
          'evidence' => "access narrowed by attenuation (max delegation depth #{tpl(s['maxDepth'])}) and #{s['denied']} denied action(s)",
          'findings' => findings }
      else
        { 'status' => 'not-evidenced', 'evidence' => 'no evaluator for this control', 'findings' => ['unmapped control'] }
      end
    end

    # a structured ComplianceReport for opts['framework'] from AuditEvents: per-control status + evidence, the PCA-unique
    # assurances and a coverage summary. opts['now'] (epoch ms) defaults to the clock.
    def to_compliance_report(events, opts)
      framework = prop(opts, 'framework')
      assert_framework(framework)
      lst = events.is_a?(Array) ? events.select { |e| truthy?(e) } : []
      now = own(opts, 'now')
      now = now_ms if nullish?(now)
      s = compute_stats(lst)
      items = []
      CONTROL_MAPPINGS.each do |m|
        next if m['framework'] != framework

        r = evaluate_control(m['controlId'], s)
        items << { 'controlId' => m['controlId'], 'controlTitle' => m['controlTitle'], 'clause' => m['clause'], 'framework' => m['framework'],
                   'status' => r['status'], 'pcaEvidence' => m['pcaEvidence'], 'evidence' => r['evidence'], 'findings' => r['findings'] }
      end
      satisfied = items.count { |i| i['status'] == 'satisfied' }
      partial = items.count { |i| i['status'] == 'partial' }
      not_evidenced = items.count { |i| i['status'] == 'not-evidenced' }
      total = items.length
      fraction = total.positive? ? satisfied.to_f / total : 0
      iats = lst.map { |e| prop(prop(prop(e, 'timestamps'), 'issuedAt'), 'epochMs') }.select { |x| fin?(x) }
      frm = iats.empty? ? 0 : iats.min
      to = iats.empty? ? 0 : iats.max
      st = s['total']
      assurances = {
        'cryptographicallyVerifiable' => st.positive? && s['verifiable'] == st,
        'explicitDelegationChain' => st.positive? && s['withChain'] == st,
        'signedHumanOverrides' => s['humanOverrides'].positive?,
        'narrative' => if st.zero?
                         'No events in scope.'
                       else
                         "#{s['verifiable']}/#{st} entries cite a cryptographically verifiable proof; #{s['withChain']}/#{st} carry an explicit " \
                           "delegation chain; #{s['humanOverrides']} step-up(s) carry a signed human co-signature."
                       end
      }
      summary = "#{framework}: #{satisfied}/#{total} controls satisfied#{partial.positive? ? ", #{partial} partial" : ''}" \
                "#{not_evidenced.positive? ? ", #{not_evidenced} not evidenced" : ''} over #{st} action(s)."
      {
        'schema' => 'atlas-pca/compliance-report/v1',
        'framework' => framework,
        'generatedAt' => ts(now),
        'period' => { 'from' => ts(frm), 'to' => ts(to) },
        'eventCount' => st,
        'assurances' => assurances,
        'items' => items,
        'coverage' => { 'total' => total, 'satisfied' => satisfied, 'partial' => partial, 'notEvidenced' => not_evidenced,
                        'satisfiedFraction' => fraction, 'satisfiedPercent' => js_round(fraction * 100) },
        'summary' => summary
      }
    end

    # ---- renderers -----------------------------------------------------------------------------------------------------

    # the report as stable, pretty JSON (JSON.stringify(report, null, 2))
    def render_json(report) = pretty(report)

    def upper(v)
      raise TypeError, 'toUpperCase is not a function' unless v.is_a?(String)

      v.upcase
    end

    def glyph(status) = status.is_a?(String) && STATUS_GLYPH.key?(status) ? STATUS_GLYPH[status] : 'undefined'

    def walk(o, path) = path.reduce(o) { |acc, k| prop(acc, k) }

    # the report as an auditor-facing Markdown document (admissibility assurances, coverage, control table and detail)
    def render_markdown(report)
      r = report
      g = ->(*path) { walk(r, path) }
      lines = []
      lines << "# PCA compliance evidence — #{tpl(g.('framework'))}"
      lines << ''
      lines << "Generated #{tpl(g.('generatedAt', 'iso'))} · #{tpl(g.('eventCount'))} action(s) · coverage: " \
               "#{tpl(g.('coverage', 'satisfied'))}/#{tpl(g.('coverage', 'total'))} satisfied (#{tpl(g.('coverage', 'satisfiedPercent'))}%)"
      if gt(g.('eventCount'), 0)
        lines << ''
        lines << "Reporting period: #{tpl(g.('period', 'from', 'iso'))} → #{tpl(g.('period', 'to', 'iso'))}"
      end
      lines << ''
      lines << '## Why this trail is admissible (what PCA uniquely provides)'
      lines << ''
      lines << "- **Cryptographically verifiable** — #{truthy?(g.('assurances', 'cryptographicallyVerifiable')) ? 'YES' : 'PARTIAL'}: every log entry " \
               'cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated.'
      lines << "- **Explicit delegation chain** — #{truthy?(g.('assurances', 'explicitDelegationChain')) ? 'YES' : 'PARTIAL'}: each action records " \
               'who authorized what scope, hop by hop, rooted at a principal.'
      lines << "- **Signed human-overrides** — #{truthy?(g.('assurances', 'signedHumanOverrides')) ? 'YES' : 'none in period'}: a step-up approval " \
               'is a principal threshold co-signature naming the human approver, not a free-text note.'
      lines << ''
      lines << "> #{tpl(g.('assurances', 'narrative'))}"
      lines << ''
      lines << '## Coverage summary'
      lines << ''
      lines << '| Satisfied | Partial | Not evidenced | Total |'
      lines << '| --- | --- | --- | --- |'
      lines << "| #{tpl(g.('coverage', 'satisfied'))} | #{tpl(g.('coverage', 'partial'))} | #{tpl(g.('coverage', 'notEvidenced'))} | #{tpl(g.('coverage', 'total'))} |"
      lines << ''
      lines << '## Controls'
      lines << ''
      lines << '| Control | Clause | Status | Evidence in period |'
      lines << '| --- | --- | --- | --- |'
      items = g.('items')
      raise TypeError, 'items is not iterable' unless items.is_a?(Array)

      items.each do |i|
        lines << "| #{tpl(prop(i, 'controlTitle'))} (`#{tpl(prop(i, 'controlId'))}`) | #{tpl(prop(i, 'clause'))} | " \
                 "#{glyph(prop(i, 'status'))} #{upper(prop(i, 'status'))} | #{tpl(prop(i, 'evidence'))} |"
      end
      lines << ''
      lines << '## Control detail'
      lines << ''
      items.each do |i|
        lines << "### #{tpl(prop(i, 'controlId'))} — #{tpl(prop(i, 'controlTitle'))}"
        lines << ''
        lines << "- Clause: #{tpl(prop(i, 'clause'))}"
        lines << "- Status: #{glyph(prop(i, 'status'))} #{upper(prop(i, 'status'))}"
        lines << "- PCA evidence basis: #{tpl(prop(i, 'pcaEvidence'))}"
        lines << "- Evidence in period: #{tpl(prop(i, 'evidence'))}"
        n = length(prop(i, 'findings'))
        if n.is_a?(Integer) && n.positive?
          lines << '- Findings:'
          X.iter(prop(i, 'findings')).each { |f| lines << "  - #{tpl(f)}" }
        end
        lines << ''
      end
      lines << '---'
      lines << ''
      lines << '_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for ' \
               'is present in the supplied records._'
      lines.join("\n")
    end

    # ---- framework report (console activity stream) --------------------------------------------------------------------

    def safety_bound(p)
      kappa = prop(p, 'kappa')
      b_max = prop(p, 'bMax')
      return 0 unless gt(kappa, 0)

      b = num(b_max)
      (b.nan? ? Float::NAN : [0.0, b].max) / num(kappa)
    end

    def base_summary(inp)
      events = prop(inp, 'events')
      raise TypeError, 'e.filter is not a function' unless events.is_a?(Array)

      p = prop(prop(inp, 'policy'), 'riskPolicy')
      decisions = qprop(inp, 'decisions')
      dlen = nullish?(decisions) ? 0 : length(decisions)
      taint = 0.0
      events.each do |x|
        t = prop(x, 'taint')
        v = t.equal?(UNDEF) ? 0.0 : fin?(t) ? t.to_f : Float::INFINITY
        taint = v if v > taint
      end
      agents = JsSet.new
      events.each { |x| agents.add(prop(x, 'agent')) }
      {
        'totalActions' => events.length,
        'autonomous' => events.count { |x| %w[auto executed].include?(prop(x, 'outcome')) },
        'humanOverseen' => events.count { |x| prop(x, 'outcome') == 'step_up' } + (dlen.equal?(UNDEF) ? 0 : dlen),
        'denied' => events.count { |x| prop(x, 'outcome') == 'deny' },
        'attributableAgents' => agents.size,
        'autonomousBound' => safety_bound(p) * num(prop(p, 'kappa')),
        'maxTaintObserved' => taint
      }
    end

    def period(events)
      ats = events.map { |e| prop(e, 'at') }.select { |a| fin?(a) }
      { 'from' => ats.empty? ? 0 : ats.min, 'to' => ats.empty? ? 0 : ats.max }
    end

    def ctl(cid, name, status, evidence) = { 'id' => cid, 'name' => name, 'status' => status, 'evidence' => evidence }

    def eu_ai_act_controls(inp, s)
      logged = s['totalActions'].positive?
      bound = s['autonomousBound']
      oversight = s['humanOverseen'].positive? || fin?(bound)
      goal = truthy?(own(inp, 'hasGoalCommitment'))
      [
        ctl('art12-record-keeping', 'Automatic logging of events', logged ? 'pass' : 'warn', "#{s['totalActions']} attributable actions recorded"),
        ctl('art14-human-oversight', 'Human oversight', oversight ? 'pass' : 'warn',
            "#{s['humanOverseen']} human-reviewed actions; autonomous bound #{num_str(bound)}"),
        ctl('art15-robustness', 'Bounded autonomy (accuracy/robustness)', fin?(bound) ? 'pass' : 'fail',
            "machine-checked safety bound = #{num_str(bound)} between human co-signs"),
        ctl('art13-transparency', 'Transparency / traceability', goal ? 'pass' : 'warn',
            goal ? 'every action binds to a signed goal commitment (lineage)' : 'no goal commitment supplied')
      ]
    end

    def soc2_controls(inp, s)
      preds = qprop(own(inp, 'policy'), 'predicates')
      constrained = preds.is_a?(Array) && !preds.empty?
      [
        ctl('cc6.1-access', 'Logical access — least privilege', constrained ? 'pass' : 'warn',
            constrained ? 'actions constrained by signed predicates + capability attenuation (deny by default)' : 'the supplied policy lists no predicates'),
        ctl('cc7.2-monitoring', 'Monitoring of anomalies', s['totalActions'].positive? ? 'pass' : 'warn',
            "#{s['denied']} denied + #{s['humanOverseen']} escalated actions captured"),
        ctl('cc7.3-audit-trail', 'Audit trail', s['totalActions'].positive? ? 'pass' : 'warn',
            "#{s['totalActions']} content-addressed actions across #{s['attributableAgents']} agents"),
        ctl('cc8.1-change', 'Change management (policy integrity)', constrained ? 'pass' : 'warn',
            constrained ? 'policy is signed into the grant; tampering breaks verification' : 'the supplied policy lists no predicates')
      ]
    end

    def gdpr_controls(inp, s)
      goal = truthy?(own(inp, 'hasGoalCommitment'))
      erasure = truthy?(own(inp, 'erasureSupported'))
      [
        ctl('art5-purpose', 'Purpose limitation', goal ? 'pass' : 'warn', goal ? 'actions bound to a committed goal/purpose' : 'no goal commitment supplied'),
        ctl('art5-minimization', 'Data minimisation', s['totalActions'].positive? ? 'pass' : 'warn',
            "taint-gated data flows; max taint observed = #{num_str(s['maxTaintObserved'])}"),
        ctl('art5-accountability', 'Accountability', s['attributableAgents'].positive? ? 'pass' : 'warn',
            "#{s['attributableAgents']} attributable agent identities"),
        ctl('art17-erasure', 'Right to erasure', erasure ? 'pass' : 'warn', erasure ? 'erasure path wired' : 'erasure path not asserted')
      ]
    end

    # a compliance evidence report for a framework from the console activity stream: inp is
    # {policy, events, decisions?, hasGoalCommitment?, erasureSupported?}. `now` (epoch ms) defaults to the clock when omitted.
    def framework_report(framework, inp, now = UNSET)
      summary = base_summary(inp)
      unless framework.is_a?(String) && FRAMEWORK_IDS.include?(framework)
        raise ArgumentError, "frameworkReport: unknown framework '#{tpl(framework)}' (have: #{FRAMEWORK_IDS.join(', ')})"
      end

      controls = case framework
                 when 'eu-ai-act' then eu_ai_act_controls(inp, summary)
                 when 'soc2' then soc2_controls(inp, summary)
                 else gdpr_controls(inp, summary)
                 end
      { 'framework' => framework, 'generatedAt' => now.equal?(UNSET) ? now_ms : now, 'period' => period(inp['events']), 'summary' => summary,
        'controls' => controls, 'pass' => controls.all? { |c| c['status'] != 'fail' } }
    end

    # `new Date(v).toISOString()` for a number (null is the epoch); raises for an invalid time
    def date_iso(v)
      iso_string(v.nil? ? 0 : v == true ? 1 : v == false ? 0 : v)
    end

    # a short Markdown block of a framework report, for an audit package
    def framework_report_to_markdown(r)
      summary = prop(r, 'summary')
      controls = prop(r, 'controls')
      raise TypeError, 'r.controls.map is not a function' unless controls.is_a?(Array)

      [
        "# PCA compliance evidence — #{tpl(prop(r, 'framework'))}",
        '',
        "Generated #{date_iso(prop(r, 'generatedAt'))} · #{tpl(prop(summary, 'totalActions'))} actions · " \
        "#{tpl(prop(summary, 'attributableAgents'))} agents · overall: #{truthy?(prop(r, 'pass')) ? 'PASS' : 'FAIL'}",
        '',
        '| Control | Status | Evidence |',
        '| --- | --- | --- |',
        *controls.map { |c| "| #{tpl(prop(c, 'name'))} (#{tpl(prop(c, 'id'))}) | #{upper(prop(c, 'status'))} | #{tpl(prop(c, 'evidence'))} |" },
        '',
        '_Evidence mapping, not a legal certification._'
      ].join("\n")
    end
  end
end
