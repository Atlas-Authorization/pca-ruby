# frozen_string_literal: true

require_relative 'js_compat'
require 'net/http'
require 'uri'

module AtlasPca
  # SIEM export of PCA authorization decisions: OCSF 1.x Authorize Session, ArcSight CEF and Elastic Common Schema events plus
  # fail-safe sinks. Mirrors the TypeScript reference (@atlasauth/pca-siem); outputs are byte-identical, including the JavaScript
  # string / number / Date quirks (UTF-16 lengths, number formatting, toISOString). Shipping an event never raises into the caller.
  module Siem
    OCSF_SCHEMA_VERSION = '1.1.0'
    ECS_VERSION = '8.11.0'
    SECURITY_CHECKS = %w[wire version audience validity cap_chain plan_inclusion leaf_signature counter_format replay].freeze
    UNDEF = Object.new.freeze # JS `undefined` (nil is JSON null)

    SEV_INFO = [1, 'Informational', 1].freeze
    SEV_LOW = [2, 'Low', 3].freeze
    SEV_MEDIUM = [3, 'Medium', 5].freeze
    SEV_HIGH = [4, 'High', 8].freeze # OCSF id, OCSF label, CEF / ECS 0-10 scale

    # The JavaScript \s class, and an ASCII-only (?a) context: JS non-unicode regexes fold case ASCII-only, so letters are spelled
    # as explicit [Aa] classes instead of the i flag (which would also fold U+212A to k).
    WS = "\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"

    # UTF-16 code-unit view of a (possibly WTF-8, lone-surrogate-carrying) string. A lone surrogate rides through regexes as a
    # private-use stand-in (plane 15, one codepoint per surrogate value).
    module U16
      module_function

      def to_pua(s)
        s = s.dup.force_encoding(Encoding::UTF_8)
        return s if s.valid_encoding?

        s.b.gsub(/\xED[\xA0-\xBF][\x80-\xBF]/n) do |m|
          b = m.bytes
          u = ((b[0] & 0x0f) << 12) | ((b[1] & 0x3f) << 6) | (b[2] & 0x3f)
          [0xF0000 + (u - 0xD800)].pack('U').b
        end.force_encoding(Encoding::UTF_8)
      end

      def from_pua(s)
        s.b.gsub(/\xF3\xB0[\x80-\x9F][\x80-\xBF]/n) do |m|
          u = 0xD800 + (m.force_encoding(Encoding::UTF_8).ord - 0xF0000)
          [0xE0 | (u >> 12), 0x80 | ((u >> 6) & 0x3f), 0x80 | (u & 0x3f)].pack('C*')
        end.force_encoding(Encoding::UTF_8)
      end

      # run a text transform with lone surrogates preserved
      def safe(s)
        t = to_pua(s)
        from_pua(yield(t))
      end

      def units(s)
        to_pua(s).each_codepoint.flat_map do |c|
          if c >= 0xF0000 && c <= 0xF07FF then [c - 0xF0000 + 0xD800]
          elsif c > 0xFFFF then [0xD800 + ((c - 0x10000) >> 10), 0xDC00 + ((c - 0x10000) & 0x3FF)]
          else [c]
          end
        end
      end

      def from_units(us)
        cps = []
        i = 0
        while i < us.length
          u = us[i]
          if u >= 0xD800 && u <= 0xDBFF && i + 1 < us.length && us[i + 1] >= 0xDC00 && us[i + 1] <= 0xDFFF
            cps << (0x10000 + ((u - 0xD800) << 10) + (us[i + 1] - 0xDC00))
            i += 2
          else
            cps << (u >= 0xD800 && u <= 0xDFFF ? 0xF0000 + (u - 0xD800) : u)
            i += 1
          end
        end
        from_pua(cps.pack('U*'))
      end

      def len(s) = units(s).length
      def slice(s, n) = from_units(units(s).first(n))
    end

    module_function

    # ---- JS helpers
    def get(o, k) = o.is_a?(Hash) ? o.fetch(k, UNDEF) : UNDEF
    def nullish?(v) = v.nil? || v.equal?(UNDEF)
    def truthy?(v) = !v.equal?(UNDEF) && Js.truthy?(v)
    def str_or(v, fallback) = v.is_a?(String) && !v.empty? ? v : fallback
    def finite(v) = (v.is_a?(Integer) || (v.is_a?(Float) && v.finite?)) ? v : UNDEF
    def num_s(v) = Predicates.js_number_string(v)

    # Object.entries over any JSON value
    def entries(x)
      case x
      when Hash then Js.js_keys(x).map { |k| [k.to_s, x[k]] }
      when Array then x.each_with_index.map { |v, i| [i.to_s, v] }
      when String then U16.units(x).each_with_index.map { |u, i| [i.to_s, U16.from_units([u])] }
      else []
      end
    end

    # new Date(ms).toISOString(), or the epoch when ms is not a valid time value
    def iso(ms)
      return '1970-01-01T00:00:00.000Z' unless (ms.is_a?(Integer) || (ms.is_a?(Float) && ms.finite?)) && ms.abs <= 8.64e15

      t = ms.to_i
      days, rem = t.divmod(86_400_000)
      z = days + 719_468
      era = z.div(146_097)
      doe = z - (era * 146_097)
      yoe = (doe - (doe / 1460) + (doe / 36_524) - (doe / 146_096)) / 365
      y = yoe + (era * 400)
      doy = doe - ((365 * yoe) + (yoe / 4) - (yoe / 100))
      mp = ((5 * doy) + 2) / 153
      d = doy - (((153 * mp) + 2) / 5) + 1
      m = mp < 10 ? mp + 3 : mp - 9
      y += 1 if m <= 2
      ys = y.between?(0, 9999) ? format('%04d', y) : "#{y.negative? ? '-' : '+'}#{format('%06d', y.abs)}"
      h, rem = rem.divmod(3_600_000)
      mi, rem = rem.divmod(60_000)
      s, milli = rem.divmod(1000)
      format('%s-%02d-%02dT%02d:%02d:%02d.%03dZ', ys, m, d, h, mi, s, milli)
    end

    def now_ms(now)
      return now.call if now.respond_to?(:call)
      return now if now.is_a?(Integer) || now.is_a?(Float)

      (Time.now.to_f * 1000).to_i
    end

    def prune(h) = h.reject { |_, v| v.equal?(UNDEF) }

    def short_key(key, n = 12)
      return '(none)' unless key.is_a?(String) && !key.empty?

      U16.len(key) <= n + 1 ? key : "#{U16.slice(key, n)}…"
    end

    def safe_digest(p)
      return '(undigestible)' if p.equal?(UNDEF)

      AtlasPca.hash_canonical(p)
    rescue StandardError # an out-of-profile body has no digest
      '(undigestible)'
    end

    # ---- normalization
    def first_reason_or(decision, fallback)
      rs = get(decision, 'reasons')
      first = rs.is_a?(Array) && !rs.empty? ? rs[0] : UNDEF
      first.is_a?(String) && !first.empty? ? first : fallback
    end

    def resolve_outcome(verify, decision)
      return ['deny', str_or(get(verify, 'reason'), 'proof failed verification')] if !truthy?(verify) || get(verify, 'allow') != true
      return ['allow', 'proof verified; no policy decision supplied'] unless truthy?(decision)
      return ['allow', first_reason_or(decision, 'auto-admitted within policy and budget')] if truthy?(get(decision, 'admit'))
      return ['step-up', first_reason_or(decision, 'policy satisfied but a co-signature is required')] if truthy?(get(decision, 'releaseGuardianShare'))

      ['deny', first_reason_or(decision, 'policy did not release authority (default-deny)')]
    end

    def build_hops(chain)
      hops = []
      chain.each_with_index do |cap, i|
        next unless truthy?(cap)

        parent = i.positive? ? chain[i - 1] : UNDEF
        pc = truthy?(parent) ? get(parent, 'caveats') : UNDEF
        parent_len = pc.is_a?(Array) ? pc.length : 0
        oc = get(cap, 'caveats')
        own_len = oc.is_a?(Array) ? oc.length : 0
        added = i.zero? ? own_len : [0, own_len - parent_len].max
        hops << { 'index' => i, 'isRoot' => i.zero?, 'issuer' => str_or(get(cap, 'issuer'), '(none)'),
                  'holder' => str_or(get(cap, 'holder'), '(none)'), 'addedCaveats' => added }
      end
      hops
    end

    def read_override(threshold, threshold_check)
      shares = truthy?(threshold) ? get(threshold, 'shares') : UNDEF
      shares = [] unless shares.is_a?(Array)
      # threshold sits outside the signed body: its shares prove nothing until a threshold verifier passed
      return { 'humanApproved' => false, 'approvers' => [], 'guardianCosigners' => [], 'roles' => [] } unless threshold_check == 'pass'

      approvers = []
      guardians = []
      roles = []
      shares.each do |s|
        role = get(s, 'role')
        next if !truthy?(s) || !role.is_a?(String)

        roles << role
        pk = get(s, 'publicKey')
        approvers << pk if role == 'principal' && pk.is_a?(String)
        guardians << pk if role == 'guardian' && pk.is_a?(String)
      end
      { 'humanApproved' => !approvers.empty?, 'approvers' => approvers, 'guardianCosigners' => guardians, 'roles' => roles }
    end

    def severity_for(outcome, checks, tier)
      return(SECURITY_CHECKS.any? { |k| get(checks, k) == 'fail' } ? SEV_HIGH : SEV_MEDIUM) if outcome == 'deny'
      return SEV_MEDIUM if outcome == 'step-up'

      if tier.is_a?(Numeric) && tier == 3 then SEV_MEDIUM
      elsif tier.is_a?(Numeric) && tier == 2 then SEV_LOW
      else SEV_INFO
      end
    end

    def shown_signature(sig, mode)
      return sig if mode == 'full'
      return '(omitted)' if mode == 'omit'

      U16.len(sig) <= 16 ? sig : "#{U16.slice(sig, 16)}…"
    end

    def normalize(record, opts, now)
      raise TypeError, 'record is required' if record.nil?

      p = get(record, 'pcactn')
      v = get(record, 'verify')
      verify = nullish?(v) ? { 'allow' => false, 'checks' => {} } : v
      c = get(verify, 'checks')
      checks = nullish?(c) ? {} : c
      n_now = finite(get(record, 'now'))
      n_now = now_ms(now) if n_now.equal?(UNDEF)
      cc = get(p, 'cap_chain')
      chain = cc.is_a?(Array) ? cc : []
      hops = build_hops(chain)
      leaf = chain.empty? ? UNDEF : chain[-1]
      root = chain.empty? ? UNDEF : chain[0]

      decision = get(record, 'decision')
      outcome, reason = resolve_outcome(verify, decision)
      rt = get(decision, 'requiredThreshold')
      tier = get(rt, 't')
      override = read_override(get(p, 'threshold'), get(checks, 'threshold'))

      grant_ref = str_or(get(p, 'grant_ref'), '(none)')
      agent_holder = str_or(get(leaf, 'holder'), '(none)')
      ri = get(root, 'issuer')
      principal = ri.is_a?(String) && !ri.empty? ? ri : nil
      chain_string = ([principal.nil? ? '(principal?)' : principal] + hops.map { |h| h['holder'] }).map { |k| short_key(k) }.join(' -> ')

      action = get(p, 'action')
      nonce = get(p, 'nonce')
      bond = get(p, 'bond_ref')
      {
        'now' => n_now, 'outcome' => outcome, 'reason' => reason,
        'cryptographicallyVerifiable' => get(checks, 'wire') == 'pass' && get(checks, 'leaf_signature') == 'pass',
        'checks' => checks, 'agentHolder' => agent_holder, 'principal' => principal,
        'session' => str_or(get(record, 'session'), grant_ref), 'hops' => hops, 'depth' => hops.empty? ? 0 : hops.length - 1,
        'chainString' => chain_string,
        'verb' => str_or(get(action, 'verb'), '(unknown verb)'),
        'resource' => str_or(get(action, 'resource'), '(unknown resource)'),
        'paramsDigest' => str_or(get(action, 'params_digest'), '(none)'),
        'reversibilityClass' => str_or(get(action, 'reversibility_class'), '(unknown)'),
        'grantRef' => grant_ref,
        'counter' => finite(get(p, 'counter')).equal?(UNDEF) ? -1 : get(p, 'counter'),
        'nonce' => nonce.is_a?(String) ? nonce : UNDEF,
        'planRoot' => str_or(get(get(p, 'plan'), 'root'), '(none)'),
        'signatureSuite' => str_or(get(p, 'alg'), 'ed25519'),
        'leafSignature' => shown_signature(str_or(get(p, 'sig'), '(unsigned)'), get(opts, 'signature')),
        'proofDigest' => safe_digest(p),
        'riskScore' => finite(get(decision, 'r')), 'tier' => tier, 'proofStrength' => get(rt, 'proof'),
        'caution' => finite(get(p, 'caution')), 'bondRef' => bond.is_a?(String) ? bond : UNDEF,
        'humanApproved' => override['humanApproved'], 'approvers' => override['approvers'],
        'guardianCosigners' => override['guardianCosigners'], 'roles' => override['roles'],
        'severity' => severity_for(outcome, checks, tier),
        'iat' => finite(get(p, 'iat')).equal?(UNDEF) ? n_now : get(p, 'iat'),
        'exp' => finite(get(p, 'exp')).equal?(UNDEF) ? n_now : get(p, 'exp')
      }
    end

    def hop_wire(h)
      { 'index' => h['index'], 'is_root' => h['isRoot'], 'issuer' => h['issuer'], 'holder' => h['holder'], 'added_caveats' => h['addedCaveats'] }
    end

    def human_override(n)
      return UNDEF unless n['humanApproved']

      { 'human_approved' => true, 'approvers' => n['approvers'], 'guardian_cosigners' => n['guardianCosigners'], 'roles' => n['roles'] }
    end

    def pca_extensions(n)
      prune({
        'proof_digest' => n['proofDigest'], 'leaf_signature' => n['leafSignature'], 'signature_suite' => n['signatureSuite'],
        'cryptographically_verifiable' => n['cryptographicallyVerifiable'], 'plan_root' => n['planRoot'],
        'params_digest' => n['paramsDigest'], 'grant_ref' => n['grantRef'], 'counter' => n['counter'], 'nonce' => n['nonce'],
        'reversibility_class' => n['reversibilityClass'], 'risk_score' => n['riskScore'], 'risk_tier' => n['tier'],
        'required_proof' => n['proofStrength'], 'caution' => n['caution'], 'bond_ref' => n['bondRef'],
        'delegation_depth' => n['depth'], 'delegation_chain' => n['hops'].map { |h| hop_wire(h) }, 'checks' => n['checks'],
        'human_override' => human_override(n)
      })
    end

    def narrative(n)
      word = { 'allow' => 'ALLOWED', 'deny' => 'DENIED' }.fetch(n['outcome'], 'STEP-UP')
      verifiable = n['cryptographicallyVerifiable'] ? 'cryptographically verifiable proof' : 'proof not cryptographically verifiable'
      "Agent #{short_key(n['agentHolder'])} #{word} to #{n['verb']} on #{n['resource']} (#{n['hops'].length}-hop chain rooted at " \
        "principal #{short_key(n['principal'])}; #{verifiable}#{n['humanApproved'] ? '; human-signed step-up' : ''}). #{n['reason']}"
    end

    # ---- OCSF
    OCSF_ACTIVITY = { 'allow' => [1, 'Allow'], 'deny' => [2, 'Deny'], 'step-up' => [3, 'Step-Up'] }.freeze
    OCSF_ACTION = { 'allow' => [1, 'Allowed'], 'deny' => [2, 'Denied'], 'step-up' => [99, 'Other'] }.freeze

    # OCSF 1.x Authorize Session (category 3, class 3003); `unmapped` carries the proof digest, tier and delegation chain
    def to_ocsf_event(record, opts = nil, now = nil)
      n = normalize(record, opts, now)
      aid, aname = OCSF_ACTIVITY[n['outcome']]
      actid, actname = OCSF_ACTION[n['outcome']]
      status = case n['outcome']
               when 'allow' then [1, 'Success', n['reason']]
               when 'deny' then [2, 'Failure', n['reason']]
               else [99, 'Other', "step-up / co-signature required: #{n['reason']}"]
               end
      class_name = 'Authorize Session'
      principal = n['principal'].nil? ? '(none)' : n['principal']
      {
        'activity_id' => aid, 'activity_name' => aname, 'category_uid' => 3, 'category_name' => 'Identity & Access Management',
        'class_uid' => 3003, 'class_name' => class_name, 'type_uid' => (3003 * 100) + aid, 'type_name' => "#{class_name}: #{aname}",
        'action_id' => actid, 'action' => actname, 'severity_id' => n['severity'][0], 'severity' => n['severity'][1],
        'status_id' => status[0], 'status' => status[1], 'status_detail' => status[2], 'time' => n['iat'],
        'actor' => {
          'user' => { 'type_id' => 99, 'type' => 'Agent', 'uid' => n['agentHolder'], 'name' => short_key(n['agentHolder']) },
          'invoked_by' => principal,
          'session' => prune({ 'uid' => n['session'], 'issuer' => n['principal'].nil? ? UNDEF : n['principal'] }),
          'app_name' => 'PCA'
        },
        'user' => { 'type_id' => 1, 'type' => 'User', 'uid' => principal, 'name' => short_key(n['principal']) },
        'resources' => [{ 'type' => 'pca.resource', 'name' => n['resource'], 'uid' => n['resource'] }],
        'api' => { 'operation' => n['verb'], 'service' => { 'name' => 'PCA' } },
        'metadata' => {
          'version' => OCSF_SCHEMA_VERSION, 'product' => { 'name' => 'PCA', 'vendor_name' => 'Atlas', 'version' => OCSF_SCHEMA_VERSION },
          'logged_time' => n['now'], 'uid' => n['proofDigest'],
          'labels' => ['pca', "outcome:#{n['outcome']}", "suite:#{n['signatureSuite']}"]
        },
        'observables' => [
          { 'name' => 'actor.user.uid', 'type' => 'User Name', 'type_id' => 4, 'value' => n['agentHolder'] },
          { 'name' => 'pca.proof.digest', 'type' => 'Hash', 'type_id' => 8, 'value' => n['proofDigest'] },
          { 'name' => 'resources.uid', 'type' => 'Resource UID', 'type_id' => 10, 'value' => n['resource'] }
        ],
        'count' => 1, 'message' => narrative(n), 'unmapped' => pca_extensions(n)
      }
    end

    # ---- CEF
    def cef_header_escape(s)
      U16.safe(s) { |t| t.gsub('\\') { '\\\\' }.gsub('|') { '\\|' }.gsub(/[\r\n]+/, ' ') }
    end

    def cef_ext_value_escape(s)
      U16.safe(s) { |t| t.gsub('\\') { '\\\\' }.gsub('=') { '\\=' }.gsub(/\r\n|\r|\n/) { '\\n' } }
    end

    def cef_str(v) = Js.string(v)

    # One ArcSight CEF line: standard keys where they fit, the proof digest in cs1 and the delegation chain in cs2
    def to_cef(record, opts = nil, now = nil)
      n = normalize(record, opts, now)
      wire_ver = finite(get(get(record, 'pcactn'), 'ver'))
      device_version = wire_ver.equal?(UNDEF) ? '2' : num_s(wire_ver)
      header = ['CEF:0', cef_header_escape('Atlas'), cef_header_escape('PCA'), cef_header_escape(device_version),
                cef_header_escape("pca-authz-#{n['outcome']}"),
                cef_header_escape("PCA authorization #{n['outcome']}: #{n['verb']} on #{n['resource']}"),
                n['severity'][2].to_s].join('|')
      principal = n['principal'].nil? ? '(none)' : n['principal']
      pairs = [
        ['act', n['outcome']], ['outcome', n['outcome']], ['suser', principal], ['suid', principal],
        ['duser', n['agentHolder']], ['duid', n['agentHolder']], ['destinationServiceName', n['verb']],
        ['rt', n['now']], ['start', n['iat']], ['end', n['exp']],
        ['externalId', n['nonce'].equal?(UNDEF) ? num_s(n['counter']) : n['nonce']],
        ['request', n['resource']], ['requestMethod', n['verb']],
        %w[cs1Label pcaProofDigest], ['cs1', n['proofDigest']],
        %w[cs2Label pcaDelegationChain], ['cs2', n['chainString']],
        %w[cs3Label pcaProofStrength], ['cs3', nullish?(n['proofStrength']) ? 'n/a' : n['proofStrength']],
        %w[cs4Label pcaSignatureSuite], ['cs4', n['signatureSuite']],
        %w[cs5Label pcaVerifyChecks], ['cs5', entries(n['checks']).map { |k, v| "#{k}:#{cef_str(v)}" }.join(';')],
        %w[cs6Label pcaGrantRef], ['cs6', n['grantRef']],
        %w[cn1Label pcaRiskScore], ['cn1', n['riskScore'].equal?(UNDEF) ? '' : n['riskScore']],
        %w[cn2Label pcaDelegationDepth], ['cn2', n['depth']],
        %w[cn3Label pcaRiskTier], ['cn3', nullish?(n['tier']) ? '' : n['tier']],
        %w[flexString1Label pcaHumanApproved], ['flexString1', n['humanApproved'] ? 'true' : 'false'],
        %w[cat authorization], ['msg', n['reason']]
      ]
      ext = pairs.map { |k, v| "#{k}=#{cef_ext_value_escape(cef_str(v))}" }.join(' ')
      "#{header}|#{ext}"
    end

    # ---- ECS
    ECS_EVENT_TYPE = { 'allow' => ['allowed'], 'deny' => ['denied'], 'step-up' => ['info'] }.freeze
    ECS_OUTCOME = { 'allow' => 'success', 'deny' => 'failure', 'step-up' => 'unknown' }.freeze

    # Elastic Common Schema event; the PCA edge lives under `pca.*`
    def to_ecs(record, opts = nil, now = nil)
      n = normalize(record, opts, now)
      related_users = ([n['agentHolder']] + (truthy?(n['principal']) ? [n['principal']] : []) + n['approvers']).uniq
      related_hashes = [n['proofDigest'], n['leafSignature']].uniq
      event = {
        'kind' => 'event', 'category' => ['iam'], 'type' => ECS_EVENT_TYPE[n['outcome']], 'action' => n['verb'],
        'outcome' => ECS_OUTCOME[n['outcome']], 'module' => 'pca', 'dataset' => 'pca.authorization', 'provider' => 'pca',
        'id' => n['proofDigest'], 'severity' => n['severity'][2], 'reason' => n['reason']
      }
      event['risk_score'] = n['riskScore'] unless n['riskScore'].equal?(UNDEF)
      principal = n['principal'].nil? ? '(none)' : n['principal']
      {
        '@timestamp' => iso(n['iat']), 'ecs.version' => ECS_VERSION, 'event' => event,
        'user' => { 'id' => n['agentHolder'], 'name' => short_key(n['agentHolder']), 'roles' => ['agent'],
                    'effective' => { 'id' => principal, 'name' => short_key(n['principal']) } },
        'service' => { 'name' => 'pca', 'type' => 'authorization' },
        'related' => { 'user' => related_users, 'hash' => related_hashes },
        'message' => narrative(n),
        'pca' => prune({
          'outcome' => n['outcome'],
          'proof' => prune({ 'digest' => n['proofDigest'], 'leaf_signature' => n['leafSignature'], 'signature_suite' => n['signatureSuite'],
                             'cryptographically_verifiable' => n['cryptographicallyVerifiable'], 'plan_root' => n['planRoot'],
                             'params_digest' => n['paramsDigest'] }),
          'risk' => prune({ 'score' => n['riskScore'], 'tier' => n['tier'], 'required_proof' => n['proofStrength'], 'caution' => n['caution'] }),
          'delegation' => { 'depth' => n['depth'], 'chain' => n['chainString'], 'hops' => n['hops'] },
          'grant_ref' => n['grantRef'], 'counter' => n['counter'], 'nonce' => n['nonce'],
          'reversibility_class' => n['reversibilityClass'], 'bond_ref' => n['bondRef'], 'checks' => n['checks'],
          'human_override' => human_override(n)
        })
      }
    end

    # ---- sinks
    CONTENT_TYPE = { 'ocsf' => 'application/x-ndjson', 'ecs' => 'application/x-ndjson', 'cef' => 'text/plain; charset=utf-8' }.freeze

    def ci(word) = word.chars.map { |c| c =~ /[A-Za-z]/ ? "[#{c.downcase}#{c.upcase}]" : Regexp.escape(c) }.join
    def ci_alt(*words) = "(?:#{words.map { |w| ci(w) }.join('|')})"
    SECRET_NAMES = ci_alt('token', 'secret', 'password', 'passwd', 'pwd', 'dd-api-key', 'key', 'signature', 'sig', 'credential').sub(
      '(?:', "(?:#{ci('api')}[_-]?#{ci('key')}|"
    )
    SCRUB = [
      [Regexp.new("(?a)([A-Za-z][A-Za-z0-9+.-]*://)[^#{WS}/@]*:[^#{WS}/@]*@"), '\1[redacted]@'],
      [Regexp.new("(?a)\\b(#{ci('authorization')}[\"']?[#{WS}]*[:=][#{WS}]*)[^\\n\"']*"), '\1[redacted]'],
      [Regexp.new("(?a)\\b(#{ci_alt('Bearer', 'Basic', 'Splunk', 'Token')})[#{WS}]+[\\w.~+/=-]{6,}"), '\1 [redacted]'],
      [Regexp.new("(?a)\\b(#{SECRET_NAMES}[\"']?[#{WS}]*[:=][#{WS}]*)(\"[^\"]*\"|'[^']*'|[^#{WS}\"'&,;]+)"), '\1[redacted]'],
      [/[A-Za-z0-9_-]{32,}/, '[redacted]']
    ].freeze

    # Remove credentials from an error message: URL userinfo, token= style pairs, bearer credentials, long token-like runs
    def scrub_error(message)
      t = message.is_a?(String) ? message : Js.string(message)
      t = U16.safe(t) { |u| SCRUB.reduce(u) { |acc, (rx, rep)| acc.gsub(rx, rep) } }
      U16.len(t) > 300 ? "#{U16.slice(t, 300)}..." : t
    end

    # A SIEM destination: `format` is the schema it expects, deliver(events) -> { 'ok' => bool, 'error' => str }
    class SiemSink
      attr_reader :name, :format, :deliver

      def initialize(name, format, deliver)
        @name = name
        @format = format
        @deliver = deliver
      end
    end

    # a minimal stand-in for AbortSignal handed to the fetch callable
    class Signal
      def initialize = @q = Thread::Queue.new
      def set = @q.push(true)
      def wait(secs) = @q.pop(timeout: secs)
    end

    # {format, object?, line}: CEF is a bare line; any format other than cef / ocsf yields ECS
    def format_decision(record, fmt, opts = nil, now = nil)
      return { 'format' => fmt, 'line' => to_cef(record, opts, now) } if fmt == 'cef'

      obj = fmt == 'ocsf' ? to_ocsf_event(record, opts, now) : to_ecs(record, opts, now)
      { 'format' => fmt, 'object' => obj, 'line' => Js.json(obj) }
    end

    def err_text(e) = e.message.to_s.empty? ? e.class.name : e.message

    def default_fetch(url, init)
      uri = URI(url)
      t = init['timeout']
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: t, read_timeout: t) do |http|
        req = Net::HTTP::Post.new(uri, init['headers'])
        req.body = init['body']
        http.request(req)
      end
      { 'ok' => res.code.to_i.between?(200, 299), 'status' => res.code.to_i, 'statusText' => res.message }
    end

    def resp(res, k)
      return res[k] if res.is_a?(Hash)

      res.respond_to?(k) ? res.public_send(k) : nil
    end

    # One POST per batch: NDJSON for OCSF / ECS, raw CEF lines for CEF. fetch.(url, init) returns {ok, status, statusText?};
    # init carries method / headers / body, an AbortSignal-like `signal` set on timeout and `timeout` seconds. Delivery never raises.
    def http_sink(url, fmt, headers: nil, fetch: nil, content_type: nil, name: nil, timeout_ms: nil)
      deliver = lambda do |events|
        do_fetch = fetch || method(:default_fetch)
        body = events.map { |e| e['line'] }.join("\n")
        hdrs = {}
        ct = content_type.nil? ? CONTENT_TYPE[fmt] : content_type
        hdrs['content-type'] = ct unless ct.nil?
        hdrs.merge!(headers || {})
        tm = timeout_ms.nil? ? 10_000 : timeout_ms
        secs = ((tm.is_a?(Integer) || (tm.is_a?(Float) && tm.finite?)) && tm.positive? ? tm : 10_000) / 1000.0
        signal = Signal.new
        box = {}
        th = Thread.new do
          Thread.current.report_on_exception = false
          begin
            box[:res] = do_fetch.call(url, { 'method' => 'POST', 'headers' => hdrs, 'body' => body, 'signal' => signal, 'timeout' => secs })
          rescue Exception => e # rubocop:disable Lint/RescueException -- reported as a delivery failure
            box[:err] = e
          end
        end
        if th.join(secs).nil?
          signal.set
          next({ 'ok' => false, 'error' => 'delivery timed out' })
        end
        raise box[:err] if box.key?(:err)

        res = box[:res]
        next({ 'ok' => true }) if truthy?(resp(res, 'ok'))

        st = resp(res, 'statusText')
        { 'ok' => false, 'error' => scrub_error("HTTP #{Js.string(resp(res, 'status'))}#{truthy?(st) ? " #{st}" : ''}") }
      rescue StandardError => e
        { 'ok' => false, 'error' => scrub_error(err_text(e)) }
      end
      SiemSink.new(name.nil? ? "http:#{fmt}" : name, fmt, deliver)
    end

    # Writes each event's serialized line to a logger (default puts). Never raises.
    def console_sink(fmt = nil, logger = nil, name = nil)
      f = fmt.nil? ? 'ocsf' : fmt
      log = logger || ->(l) { puts l }
      deliver = lambda do |events|
        events.each { |e| log.call(e['line']) }
        { 'ok' => true }
      rescue StandardError => e
        { 'ok' => false, 'error' => scrub_error(err_text(e)) }
      end
      SiemSink.new(name.nil? ? "console:#{f}" : name, f, deliver)
    end

    # ---- export
    def safe_on_error(on_error, error, sink, count)
      return if on_error.nil?

      on_error.call(error, { 'sink' => sink, 'count' => count })
    rescue StandardError # an on_error that raises must never reach the auth path
      nil
    end

    # Export decisions in ONE delivery. Fail-safe: any serialization or delivery error is scrubbed, reported through
    # on_error.(error, {sink, count}) and returned as {ok: false, error}; nothing is raised.
    def export_batch(records, sink, on_error = nil, serialize = nil, now = nil)
      fmt = sink.respond_to?(:format) ? sink.format : nil
      count = 0
      begin
        events = []
        skipped = 0
        records.each do |r|
          events << format_decision(r, fmt, serialize, now)
        rescue StandardError => e # one bad record must not take the others' audit trail
          skipped += 1
          safe_on_error(on_error, StandardError.new(scrub_error("record could not be serialized: #{err_text(e)}")), sink.name, 1)
        end
        count = events.length
        return { 'ok' => false, 'delivered' => 0, 'format' => fmt, 'error' => 'no record could be serialized', 'skipped' => skipped } if events.empty? && skipped.positive?

        res = sink.deliver.call(events)
        extra = skipped.positive? ? { 'skipped' => skipped } : {}
        return { 'ok' => true, 'delivered' => events.length, 'format' => fmt }.merge(extra) if truthy?(resp(res, 'ok'))

        er = resp(res, 'error')
        err = StandardError.new(scrub_error(nullish?(er) ? 'sink reported a delivery failure' : er))
        safe_on_error(on_error, err, sink.name, events.length)
        { 'ok' => false, 'delivered' => 0, 'format' => fmt, 'error' => err.message }.merge(extra)
      rescue StandardError => e
        err = StandardError.new(scrub_error(err_text(e)))
        safe_on_error(on_error, err, sink.respond_to?(:name) ? sink.name : '(unknown sink)', count)
        { 'ok' => false, 'delivered' => 0, 'format' => fmt, 'error' => err.message }
      end
    end

    def export_decision(record, sink, on_error = nil, serialize = nil, now = nil) = export_batch([record], sink, on_error, serialize, now)
  end
end
