# frozen_string_literal: true

require_relative '../atlas_pca'
require_relative 'explain_js'
require_relative 'risk'

# Self-explaining PCA decisions: the verifier's per-check result, the Policy VM decision and a delegation chain become precise,
# human-readable explanations plus renderers (port of the TypeScript reference @atlasauth/pca-explain). Everything is pure and
# read-only; explanations are String-keyed Hashes with exactly the members of the reference's objects (an absent member is a JS
# `undefined`). Inputs are JSON values; the reference's JavaScript value semantics are reproduced where an untrusted field reaches
# them, so a hostile shape gives the same text or the same refusal (an exception). `now` and the decision context keep the
# reference's camelCase keys (`blastRadius`, `delegationDepth`, ...).
module AtlasPca
  module Explain
    X = ExplainJs
    UNDEF = X::UNDEF

    MAX_TEXT = 400
    PCACTN_VERSION = 2
    PCACTN_MAX_LIFETIME_MS = AtlasPca::MAX_LIFETIME_MS
    PCACTN_MAX_SKEW_MS = AtlasPca::MAX_SKEW_MS

    VERIFY_CHECK_ORDER = %w[wire version audience validity cap_chain grant_ref_bound plan_inclusion leaf_signature counter_format].freeze

    CHECK_TITLE = {
      'wire' => 'wire format', 'version' => 'version', 'audience' => 'audience binding', 'validity' => 'freshness window',
      'cap_chain' => 'capability chain', 'grant_ref_bound' => 'grant reference binding', 'plan_inclusion' => 'plan inclusion',
      'leaf_signature' => 'leaf signature', 'counter_format' => 'counter format', 'counter' => 'counter format', 'replay' => 'replay',
      'plan_root_authorized' => 'plan-root authorization', 'taint_gate' => 'taint gate', 'attestation' => 'agent attestation',
      'threshold' => 'threshold signature', 'revocation' => 'revocation', 'zk_compliance' => 'zk compliance', 'bond' => 'bond',
      'malformed' => 'structure'
    }.freeze

    OPTS = Object.new.freeze # "argument omitted": the reference defaults it to {}, while an explicit null stays null

    # PUA stand-ins for lone surrogates so the credential patterns run on a valid string
    PUA_BASE = 0x10F000

    # ASCII-only case folding (a JS regex without /u): [Bb][Ee]...
    def self.ci(word) = word.gsub(/[A-Za-z]/) { |c| "[#{c.downcase}#{c.upcase}]" }

    W = 'A-Za-z0-9_'
    WS = X::WS_CLASS
    RE_JWT = /(?<![#{W}])eyJ[#{W}\-]{5,}\.[#{W}\-]{5,}\.[#{W}\-]*/
    RE_BEARER = /(?<![#{W}])(#{ci('Bearer')}|#{ci('Basic')}|#{ci('Token')})[#{WS}]+[#{W}.~+\/=\-]{6,}/
    RE_USERINFO = %r{([A-Za-z][A-Za-z0-9+.\-]*://)[^#{WS}/@]*:[^#{WS}/@]*@}
    PAIR_KEYS = ['token', 'secret', 'password', 'passwd', 'pwd', 'api[_-]?key', 'key', 'signature', 'sig', 'credential', 'authorization',
                 'auth'].map { |k| k.gsub(/[A-Za-z]+/) { |w| ci(w) } }.join('|')
    RE_PAIR = /(?<![#{W}])((?:#{PAIR_KEYS})["']?[#{WS}]*[:=][#{WS}]*)("[^"]*"|'[^']*'|[^#{WS}"'&,;]+)/
    RE_RUN = /[#{W}\-]{40,}/

    module_function

    def to_pua(s)
      return s if s.valid_encoding?

      s.b.gsub(/\xED[\xA0-\xBF][\x80-\xBF]/n) do |m|
        b = m.bytes
        [PUA_BASE + (((b[0] & 0x0f) << 12) | ((b[1] & 0x3f) << 6) | (b[2] & 0x3f)) - 0xD800].pack('U').b
      end.force_encoding(Encoding::UTF_8)
    end

    def from_pua(s)
      return s unless s.each_char.any? { |c| c.ord >= PUA_BASE && c.ord < PUA_BASE + 0x800 }

      X.from_units(s.each_char.flat_map do |c|
        o = c.ord
        if o >= PUA_BASE && o < PUA_BASE + 0x800 then [o - PUA_BASE + 0xD800]
        elsif o > 0xFFFF then [0xD800 + ((o - 0x10000) >> 10), 0xDC00 + ((o - 0x10000) & 0x3ff)]
        else [o]
        end
      end)
    end

    # Remove what looks like a credential from text built out of untrusted fields (JWTs, bearer credentials, URL userinfo,
    # `token=` style pairs, long unbroken token runs); the result is cut to 400 characters. A net, not a proof.
    def clean_text(text)
      t = to_pua(X.js_string(text))
      t = t.gsub(RE_JWT, '[redacted]')
      t = t.gsub(RE_BEARER) { "#{Regexp.last_match(1)} [redacted]" }
      t = t.gsub(RE_USERINFO) { "#{Regexp.last_match(1)}[redacted]@" }
      t = t.gsub(RE_PAIR) { "#{Regexp.last_match(1)}[redacted]" }
      t = from_pua(t.gsub(RE_RUN, '[redacted]'))
      X.len16(t) > MAX_TEXT ? "#{X.slice16(t, 0, MAX_TEXT)}..." : t
    end

    # ---- shared helpers ------------------------------------------------------------------------------------------------

    # Abbreviate a long b64u key for display: the first `n` characters and an ellipsis.
    def short(key, n = 10)
      return '<none>' unless key.is_a?(String) && !key.empty?

      X.len16(key) <= n + 1 ? key : "#{X.slice16(key, 0, n)}…"
    end

    def round_js(y)
      return y unless y.finite?

      f = y.floor.to_f
      y - f >= 0.5 ? f + 1 : f
    end

    # Compact number: integers stay integers, fractions round to 4 dp; anything else prints as String(x).
    def num(x)
      return X.js_string(x) unless X.fin?(x)
      return X.numstr(x) if x.to_f == x.to_f.floor

      X.numstr(round_js(x * 1e4) / 1e4)
    end

    def value_summary(rest)
      X.keys(rest).first(6).map { |k| "#{k}=#{X.obj?(rest[k]) ? Js.json(rest[k]) : num(rest[k])}" }.join(', ')
    end

    def caveat_type(cv)
      t = X.opt(cv, 'type')
      t.is_a?(String) ? t : '<malformed>'
    end

    def caveat_rest(cv)
      rest = {}
      X.keys(cv).each { |k| rest[k] = X.get(cv, k) unless k == 'type' } if X.obj?(cv)
      rest
    end

    def cond_to_text(c, depth = 0)
      return '<malformed>' unless X.obj?(c)
      return '…' if depth > 6

      if c.is_a?(Hash)
        return "(#{c['all_of'].map { |x| cond_to_text(x, depth + 1) }.join(' AND ')})" if c.key?('all_of') && c['all_of'].is_a?(Array)
        return "(#{c['any_of'].map { |x| cond_to_text(x, depth + 1) }.join(' OR ')})" if c.key?('any_of') && c['any_of'].is_a?(Array)
        return "NOT #{cond_to_text(c['not'], depth + 1)}" if c.key?('not')
      end
      ref = X.get(c, 'ref')
      operand = if !ref.equal?(UNDEF) then "→#{X.js_string(ref)}"
                elsif c.is_a?(Hash) && c.key?('value') then num(c['value'])
                else ''
                end
      X.trim("#{X.js_string(X.get(c, 'field'))} #{X.js_string(X.get(c, 'op'))} #{operand}")
    end

    def where_summary(where)
      return 'any (no where-bound)' if !where.is_a?(Array) || where.empty?

      where.map { |c| cond_to_text(c) }.join(' AND ')
    end

    # ---- explainVerification -------------------------------------------------------------------------------------------

    def reason_tail(name, verify_result)
      r = X.get(verify_result, 'reason')
      return nil unless r.is_a?(String)

      pre = "#{name}: "
      r.b.start_with?(pre.b) ? r.byteslice(pre.bytesize..).force_encoding(Encoding::UTF_8) : nil
    end

    def validity_pinpoint(p, now)
      exp = X.get(p, 'exp')
      iat = X.get(p, 'iat')
      lifetime = X.to_num(exp) - X.to_num(iat)
      unless X.gt(exp, iat)
        return { 'detail' => "exp #{X.js_string(exp)} ≤ iat #{X.js_string(iat)}: empty validity window",
                 'remedy' => 'set exp strictly greater than iat.' }
      end
      if lifetime > PCACTN_MAX_LIFETIME_MS
        return { 'detail' => "lifetime #{X.numstr(lifetime)}ms exceeds the #{PCACTN_MAX_LIFETIME_MS}ms maximum",
                 'remedy' => "shorten the window to ≤ #{PCACTN_MAX_LIFETIME_MS}ms (buildPCActn ttlMs)." }
      end
      unless now.equal?(UNDEF)
        unless X.le(iat, X.add(now, PCACTN_MAX_SKEW_MS))
          return { 'detail' => "iat #{X.js_string(iat)} is #{X.numstr(X.to_num(iat) - X.to_num(now))}ms in the future " \
                               "(> #{PCACTN_MAX_SKEW_MS}ms clock-skew allowance)",
                   'remedy' => 'fix the signer clock; do not pre-date actions.' }
        end
        unless X.le(now, exp)
          return { 'detail' => "expired #{X.numstr(X.to_num(now) - X.to_num(exp))}ms ago (exp #{X.js_string(exp)}, now #{X.js_string(now)})",
                   'remedy' => 'build a fresh action — a PCActn lifetime is short by design.' }
        end
      end
      { 'detail' => 'validity window invalid', 'remedy' => 'build a fresh action with a valid iat/exp window.' }
    end

    # the reference's words for the core verifier's reasons
    def chain_reason(why)
      why.is_a?(String) && (m = why.match(/\Achain longer than ([0-9]+) capabilities\z/)) ? "chain too long (max #{m[1]} hops)" : why
    end

    def cap_chain_pinpoint(p)
      chain = X.get(p, 'cap_chain')
      if chain.is_a?(Array)
        why, ok = AtlasPca.verify_chain(chain, nil, false)
        reason = ok ? 'chain root is not the grant this verifier expects' : X.nn(chain_reason(why), 'capability chain invalid')
      else
        reason = 'cap_chain is not an array'
      end
      m = reason.b.match(/hop ([0-9]+)/n)
      remedy = 'rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats.'
      if reason.include?('root issuer') || reason.include?('not the grant')
        remedy = 'root the chain at the principal key that minted the grant.'
      elsif reason.include?('widens')
        remedy = 'a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation.'
      elsif reason.include?('caveat')
        remedy = 'attenuation is append-only: never drop, reorder or edit a parent caveat.'
      elsif reason.include?('signature')
        remedy = 're-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite).'
      end
      out = { 'detail' => reason, 'remedy' => remedy }
      out['hop'] = m[1].to_i if m
      out
    end

    def leaf_sig_pinpoint(p)
      chain = X.get(p, 'cap_chain')
      idx = chain.is_a?(Array) ? chain.length - 1 : -1
      leaf = idx >= 0 ? chain[idx] : UNDEF
      alg = X.nn(X.get(p, 'alg'), 'ed25519')
      remedy = 'sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to ' \
               'match the holder.'
      unless X.truthy?(leaf)
        return { 'detail' => 'no leaf capability to check the signature against (empty/invalid chain)', 'remedy' => remedy }
      end

      out = { 'detail' => "leaf hop ##{idx} signature (holder #{short(X.get(leaf, 'holder'))}, suite #{X.js_string(alg)}) does not verify",
              'remedy' => remedy }
      out['hop'] = idx if idx >= 0
      out
    end

    def nn_str(tail, default) = tail.nil? ? default : tail

    # The decisive (first failing) check with a concrete detail and remedy.
    def pinpoint(name, p, verify_result, now)
      tail = reason_tail(name, verify_result)
      action = X.opt(p, 'action')
      plan = X.opt(p, 'plan')
      case name
      when 'wire'
        { 'detail' => nn_str(tail, 'wire structure / strict-canonical-form check failed'),
          'remedy' => 'do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK.' }
      when 'version'
        { 'detail' => nn_str(tail, "unsupported ver #{num(X.get(p, 'ver'))} (verifier requires #{PCACTN_VERSION})"),
          'remedy' => "re-mint the action at wire version #{PCACTN_VERSION}." }
      when 'audience'
        { 'detail' => nn_str(tail, "aud #{X.jstr(X.get(p, 'aud'))} does not match this resource server / instance"),
          'remedy' => 'build the action with aud = this verifier’s instance id (or verify with audience:null to accept any).' }
      when 'validity'
        v = validity_pinpoint(p, now)
        { 'detail' => nn_str(tail, v['detail']), 'remedy' => v['remedy'] }
      when 'cap_chain'
        c = cap_chain_pinpoint(p)
        out = { 'detail' => nn_str(tail, c['detail']), 'remedy' => c['remedy'] }
        out['hop'] = c['hop'] if c.key?('hop')
        out
      when 'grant_ref_bound'
        { 'detail' => nn_str(tail, "grant_ref #{short(X.get(p, 'grant_ref'))} is not the id of the root capability in cap_chain"),
          'remedy' => 'set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant.' }
      when 'plan_inclusion'
        { 'detail' => nn_str(tail, "action (verb #{X.jstr(X.opt(action, 'verb'))} on #{X.jstr(X.opt(action, 'resource'))}) is not node " \
                                   "#{X.jstr(X.opt(plan, 'node_id'))} of committed plan #{short(X.opt(plan, 'root'))}"),
          'remedy' => 'rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn).' }
      when 'leaf_signature'
        l = leaf_sig_pinpoint(p)
        out = { 'detail' => nn_str(tail, l['detail']), 'remedy' => l['remedy'] }
        out['hop'] = l['hop'] if l.key?('hop')
        out
      when 'counter', 'counter_format'
        { 'detail' => nn_str(tail, "counter #{num(X.get(p, 'counter'))} is missing or not a non-negative safe integer"),
          'remedy' => 'use a strictly increasing per-holder counter; a repeated counter is a replay.' }
      when 'malformed'
        { 'detail' => nn_str(tail, 'the PCActn is structurally malformed'),
          'remedy' => 'rebuild the action with the SDK; do not construct the wire object by hand.' }
      else
        { 'detail' => nn_str(tail, "#{name} check failed"),
          'remedy' => "satisfy the #{name} requirement (supply the corresponding verifier hook / proof)." }
      end
    end

    # What held, for a pass.
    def pass_detail(name, p)
      case name
      when 'wire' then 'wire structure + strict canonical form valid'
      when 'version' then "ver #{num(X.get(p, 'ver'))} supported"
      when 'audience' then "aud #{X.jstr(X.get(p, 'aud'))} matches this resource server"
      when 'validity' then "fresh: iat/exp window valid (lifetime #{num((X.to_num(X.get(p, 'exp')) - X.to_num(X.get(p, 'iat'))) / 1000)}s)"
      when 'cap_chain'
        chain = X.get(p, 'cap_chain')
        n = chain.is_a?(Array) ? chain.length : 0
        root = n.positive? ? chain[0] : UNDEF
        "#{n}-hop chain verifies; root issuer #{short(X.opt(root, 'issuer'))}"
      when 'grant_ref_bound' then "grant_ref #{short(X.get(p, 'grant_ref'))} is the id of the chain root"
      when 'plan_inclusion'
        plan = X.opt(p, 'plan')
        "action is node #{X.jstr(X.opt(plan, 'node_id'))} of committed plan #{short(X.opt(plan, 'root'))}"
      when 'leaf_signature'
        chain = X.get(p, 'cap_chain')
        leaf = chain.is_a?(Array) && !chain.empty? ? chain[-1] : UNDEF
        "leaf holder #{short(X.opt(leaf, 'holder'))} signature valid (suite #{X.js_string(X.nn(X.get(p, 'alg'), 'ed25519'))})"
      when 'counter', 'counter_format' then "counter #{num(X.get(p, 'counter'))} well-formed"
      else 'ok'
      end
    end

    def clean_check(c) = c.merge('detail' => clean_text(c['detail']))

    def verification(verdict, allow, checks, decisive, summary)
      out = {
        'kind' => 'verification', 'verdict' => verdict, 'allow' => allow, 'checks' => checks,
        'passed' => checks.select { |c| c['status'] == 'pass' }.map { |c| c['name'] },
        'failed' => checks.select { |c| c['status'] == 'fail' }.map { |c| c['name'] },
        'notEnforced' => checks.select { |c| c['status'] == 'not-enforced' }.map { |c| c['name'] }
      }
      out['decisive'] = decisive unless decisive.nil?
      out['summary'] = summary
      out
    end

    def denied_verification(why)
      e = { 'name' => 'malformed', 'status' => 'fail', 'title' => CHECK_TITLE['malformed'], 'detail' => why,
            'remedy' => 'pass the PCActn and the verifier result you verified.', 'decisive' => true }
      verification('deny', false, [e], e, "Denied: #{why}")
    end

    # Walk the normative checks of an offline verification in order: summarize what held for each pass and pinpoint the first
    # failing check with a concrete remedy. `opts` may carry `now` (epoch ms) to tell "expired" from "clock skew" precisely.
    def explain_verification(pca_actn, verify_result, opts = OPTS)
      return denied_verification('the PCActn or the verifier result is missing') unless X.obj?(pca_actn) && X.obj?(verify_result)

      begin
        explain_verification_inner(pca_actn, verify_result, opts.equal?(OPTS) ? {} : opts)
      rescue StandardError, SystemStackError # never throws: a malformed input is a denial
        denied_verification('the PCActn or the verifier result is malformed')
      end
    end

    def explain_verification_inner(p, vr, opts)
      statuses = X.nn(X.get(vr, 'checks'), {})
      ordered = VERIFY_CHECK_ORDER.dup
      X.keys(statuses).each { |n| ordered << n unless ordered.include?(n) } # later-milestone / extra checks appended
      decisive_name = ordered.find { |n| X.get(statuses, n) == 'fail' }
      checks = []
      decisive = nil
      ordered.each do |name|
        status = X.nn(X.get(statuses, name), 'skipped')
        title = CHECK_TITLE.fetch(name, name)
        remedy = nil
        hop = nil
        if status == 'fail'
          pin = pinpoint(name, p, vr, X.rd(opts, 'now'))
          detail = pin['detail']
          remedy = pin['remedy']
          hop = pin['hop']
        elsif status == 'pass' then detail = pass_detail(name, p)
        elsif status == 'not-enforced' then detail = 'not enforced by this verifier (no hook / opt-out)'
        elsif status == 'unsupported' then detail = 'the PCActn carries a feature this verifier does not implement (never a pass)'
        else detail = 'not reached (a terminal earlier check stopped evaluation)'
        end
        entry = { 'name' => name, 'status' => status, 'title' => title, 'detail' => detail }
        entry['remedy'] = remedy unless remedy.nil?
        entry['hop'] = hop unless hop.nil?
        if name == decisive_name
          entry['decisive'] = true
          decisive = entry
        end
        checks << entry
      end

      # Allow only on an explicit `allow: true` that no check contradicts and that carries per-check statuses.
      has_checks = X.get(vr, 'checks').is_a?(Hash)
      allow_claimed = X.get(vr, 'allow') == true
      claimed = allow_claimed && has_checks
      contradicted = claimed && !decisive_name.nil?
      verdict = claimed && !contradicted ? 'allow' : 'deny'
      summary = if verdict == 'allow'
                  "All #{checks.count { |c| c['status'] == 'pass' }} evaluated checks passed (no check failed)."
                elsif allow_claimed && !has_checks
                  'Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial).'
                elsif contradicted
                  "Denied: the verifier result says allow but the \"#{decisive.nil? ? decisive_name : decisive['title']}\" check failed " \
                    '(inconsistent result, treated as a denial).'
                elsif !decisive.nil?
                  "Denied at the \"#{decisive['title']}\" check: #{decisive['detail']}"
                else
                  reason = X.get(vr, 'reason')
                  "Denied: #{reason.is_a?(String) ? reason : 'a check failed'}"
                end
      verification(verdict, verdict == 'allow', checks.map { |c| clean_check(c) }, decisive.nil? ? nil : clean_check(decisive),
                   clean_text(summary))
    end

    GLYPH = { 'pass' => '✓', 'fail' => '✗', 'not-enforced' => '·', 'unsupported' => '?', 'skipped' => '–' }.freeze

    def verification_to_text(e)
      lines = ["PCA verification — #{X.js_string(e['verdict']).upcase}", X.js_string(e['summary']), '']
      e['checks'].each do |c|
        mark = X.truthy?(X.get(c, 'decisive')) ? ' ◀ DECISIVE' : ''
        st = c['status']
        glyph = st.is_a?(String) ? GLYPH.fetch(st, 'undefined') : 'undefined'
        lines << "  #{glyph} #{X.pad_end(X.js_string(c['name']), 16)} #{X.js_string(c['detail'])}#{mark}"
        lines << "      ↳ fix: #{X.js_string(c['remedy'])}" if X.truthy?(X.get(c, 'decisive')) && X.truthy?(X.get(c, 'remedy'))
      end
      lines.join("\n")
    end

    # ---- explainDecision -----------------------------------------------------------------------------------------------

    def caveat_remedy(type, rest)
      g = ->(k) { X.hget(rest, k) }
      case type
      when 'expires' then "the grant expired at #{num(g.('at'))} (epoch ms); obtain a fresh grant or re-mint with a later 'expires'."
      when 'not_before' then "the grant is not valid until #{num(g.('at'))} (epoch ms); retry after that time."
      when 'rate'
        "rate limit #{num(g.('max'))}/#{num(g.('per_secs'))}s reached; wait for the window to clear or raise the 'rate' caveat."
      when 'max_blast_radius'
        "the action's blast radius exceeds the caveat max #{num(g.('max'))}; narrow the action or raise 'max_blast_radius'."
      when 'reversibility_max'
        "the action is more severe than the allowed class '#{X.js_string(g.('class'))}'; only that class or lower is permitted."
      when 'delegation_depth'
        "delegation depth exceeds max #{num(g.('max'))}; act from a shallower hop or raise 'delegation_depth'."
      else "caveat '#{type}' is not satisfied; check its parameters against the action/context."
      end
    end

    def caveat_detail(type, rest, satisfied)
      bound = value_summary(rest)
      verb = X.truthy?(satisfied) ? 'held' : 'NARROWED/DENIED'
      bound.empty? ? "#{type} #{verb}" : "#{type}(#{bound}) #{verb}"
    end

    # JS `/caveat\(s\) not satisfied: (.+)$/`: `.` stops at a line terminator, `$` is the end of the text
    FAILED_CAVEATS = /caveat\(s\) not satisfied: ([^\n\r\u2028\u2029]+)\z/

    def failed_caveat_types(reasons)
      out = []
      reasons.each do |r|
        m = to_pua(X.js_string(r)).match(FAILED_CAVEATS)
        next unless m

        m[1].split(',', -1).each do |t|
          tt = X.trim(from_pua(t))
          out << tt unless tt.empty? || out.include?(tt)
        end
      end
      out
    end

    def risk_band(r, theta1, theta2, tier)
      return "effective tier t=#{X.js_string(tier)}" if theta1.equal?(UNDEF) || theta2.equal?(UNDEF)
      return "r #{num(r)} ≤ θ1 #{num(theta1)} → claim band (t=1)" if X.le(r, theta1)
      return "θ1 #{num(theta1)} < r #{num(r)} ≤ θ2 #{num(theta2)} → standard band (t=2)" if X.le(r, theta2)

      "r #{num(r)} > θ2 #{num(theta2)} → strong band (t=3)"
    end

    def no_decision(reason)
      { 'admit' => false, 'needStepUp' => false, 'releaseGuardianShare' => false, 'r' => 1,
        'requiredThreshold' => { 't' => 3, 'proof' => 'human', 'optimisticAllowed' => false },
        'budget' => { 'B' => 0, 'tau' => 0, 'asOf' => 0 }, 'reasons' => [reason] }
    end

    # Explain a Policy-VM decision: which predicate granted the (verb, resource) and under what `where` bound, which caveat
    # narrowed or denied, the risk band and the admission path; for anything short of auto-admit the single decisive reason and
    # remedy. A missing or malformed decision is a denial, never an allow.
    def explain_decision(pca_actn, decision, opts = OPTS)
      o = opts.equal?(OPTS) ? {} : opts
      unless X.obj?(decision) && X.obj?(X.get(decision, 'requiredThreshold'))
        return explain_decision_inner(no_decision('no policy decision supplied (default-deny)'), o)
      end

      begin
        explain_decision_inner(decision, o)
      rescue StandardError, SystemStackError
        explain_decision_inner(no_decision('the policy decision could not be explained (default-deny)'), {})
      end
    end

    def includes?(r, needle)
      raise TypeError, 'includes is not a function' unless r.is_a?(String)

      r.b.include?(needle.b)
    end

    def length_of(v) = v.is_a?(Array) ? v.length : v.is_a?(String) ? X.len16(v) : UNDEF

    # evaluateAgentCaveats([cv], caveatCtx, actionCtx).ok: the reference's camelCase context mapped onto this evaluator's
    def eval_caveat(cv, caveat_ctx, action_ctx)
      inner = X.get(action_ctx, 'action')
      inner = {} unless inner.is_a?(Hash)
      c = {}
      { 'now' => 'now', 'delegationDepth' => 'delegation_depth', 'blastRadius' => 'blast_radius',
        'reversibilityClass' => 'reversibility_class', 'recentActionTimes' => 'recent_action_times' }.each do |src, dst|
        v = X.get(caveat_ctx, src)
        c[dst] = v unless v.equal?(UNDEF)
      end
      c['action'] = inner
      verb = X.get(inner, 'verb')
      params = X.get(inner, 'params')
      binding = X.get(action_ctx, 'toolBinding')
      tool = { 'tool' => verb.is_a?(String) ? verb : '', 'args' => params.is_a?(Hash) ? params : {} }
      tool['tool_signature_digest'] = binding if binding.is_a?(String)
      AtlasPca.evaluate_agent_caveats([cv], c, action_ctx.is_a?(Hash) ? action_ctx : {}, tool)[0]
    end

    def explain_decision_inner(decision, opts)
      env = X.rd(opts, 'envelope')
      ctx = X.nn(X.get(opts, 'context'), {})
      reasons_raw = X.get(decision, 'reasons')
      reasons = reasons_raw.is_a?(Array) ? reasons_raw : []

      admitted = X.get(decision, 'admit') == true # strict: a truthy non-boolean is not an admission
      rgs = X.get(decision, 'releaseGuardianShare')
      disposition = admitted ? 'auto-admit' : (rgs == true ? 'step-up' : 'denied')
      verdict = admitted ? 'allow' : 'deny'

      # authority: the granting predicate
      grant = {}
      X.put(grant, 'granted', rgs)
      chain = X.get(ctx, 'chain')
      root_cap = X.opt(chain, '0')
      X.put(grant, 'capabilityId', X.get(root_cap, 'id')) if X.truthy?(root_cap)
      ctx_action = X.get(ctx, 'action')
      ctx_caveat = X.get(ctx, 'caveat')
      has_env = X.truthy?(env)
      if has_env && X.truthy?(ctx_action)
        preds = X.get(env, 'predicates')
        pr = AtlasPca.evaluate_predicates(preds.is_a?(Array) ? preds : nil, ctx_action)
        if pr['allowed'] && !pr['matched'].nil?
          matched = pr['matched']
          grant['granted'] = true
          grant['predicate'] = matched
          grant['predicateIndex'] = preds.index { |x| x.equal?(matched) }
          grant['where'] = where_summary(X.get(matched, 'where'))
        else
          grant['granted'] = false
          grant['reason'] = X.nn(pr['reason'], 'no predicate permits this action')
        end
      elsif !X.truthy?(rgs)
        reasons.each do |r|
          if includes?(r, 'predicate') || includes?(r, 'not permitted')
            grant['reason'] = r
            break
          end
        end
      end

      # caveats: per-caveat outcome
      caveats = []
      failed_from_reasons = failed_caveat_types(reasons)
      can_eval = !env.equal?(UNDEF) && !ctx_caveat.equal?(UNDEF) && !ctx_action.equal?(UNDEF)
      grant_caveats = X.nn(X.opt(env, 'caveats'), [])
      chain0 = X.opt(chain, '0')
      root_count = 0
      unless chain0.equal?(UNDEF) || chain0.nil?
        cv0 = X.rd(chain0, 'caveats')
        raise TypeError, "cannot read 'length' of undefined" if cv0.equal?(UNDEF) || cv0.nil?

        n0 = length_of(cv0)
        root_count = n0.equal?(UNDEF) ? 0 : n0
      end
      delegated = []
      delegated = X.slice_from(X.nn(X.opt(chain[-1], 'caveats'), []), root_count) if chain.is_a?(Array) && chain.length > 1
      classify = lambda do |cv, is_delegated|
        type = caveat_type(cv)
        rest = caveat_rest(cv)
        satisfied = if can_eval && X.truthy?(ctx_caveat) && X.truthy?(ctx_action)
                      eval_caveat(cv, ctx_caveat, ctx_action)
                    else
                      failed_from_reasons.include?(type) ? false : rgs
                    end
        out = { 'type' => type }
        X.put(out, 'satisfied', satisfied)
        out['value'] = rest
        out['detail'] = caveat_detail(type, rest, satisfied)
        out['delegated'] = is_delegated
        out['remedy'] = caveat_remedy(type, rest) unless X.truthy?(satisfied)
        out
      end
      X.iter(grant_caveats).each { |cv| caveats << classify.call(cv, false) }
      X.iter(delegated).each { |cv| caveats << classify.call(cv, true) }

      # risk / tier
      rt = X.get(decision, 'requiredThreshold')
      r = X.get(decision, 'r')
      env_nn = !env.equal?(UNDEF) && !env.nil?
      risk_policy = UNDEF
      if env_nn
        risk_policy = X.rd(env, 'risk_policy')
        raise TypeError, 'cannot read properties of undefined' if risk_policy.equal?(UNDEF) || risk_policy.nil?
      end
      theta1 = X.opt(risk_policy, 'theta1')
      theta2 = X.opt(risk_policy, 'theta2')
      tier = X.get(rt, 't')
      proof = X.get(rt, 'proof')
      optimistic = X.get(rt, 'optimisticAllowed')
      risk = {}
      X.put(risk, 'r', r)
      X.put(risk, 'tier', tier)
      X.put(risk, 'proof', proof)
      X.put(risk, 'optimisticAllowed', optimistic)
      risk['band'] = risk_band(r, theta1, theta2, tier)
      if has_env
        X.put(risk, 'theta1', theta1)
        X.put(risk, 'theta2', theta2)
      end

      # admission / budget
      kappa = env_nn ? X.get(risk_policy, 'kappa') : UNDEF
      cost_val = kappa.equal?(UNDEF) ? nil : Risk.cost(r.equal?(UNDEF) ? nil : r, kappa)
      budget_depleted = reasons.any? { |x| includes?(x, 'budget depleted') }
      path = if admitted then "auto-admitted at t=#{X.js_string(tier)} (#{X.js_string(proof)}); metered"
             elsif !X.truthy?(rgs) then 'guardian share withheld — policy not satisfied (no autonomous or guardian path)'
             elsif budget_depleted then 'trust budget cannot cover the cost — step-up to t=3 (human recharge) required'
             else "step-up to t=#{X.js_string(tier)} (#{X.js_string(proof)}) co-signature required"
             end
      admission = { 'admit' => admitted }
      X.put(admission, 'needStepUp', X.get(decision, 'needStepUp'))
      X.put(admission, 'releaseGuardianShare', rgs)
      X.put(admission, 'budget', X.get(decision, 'budget'))
      admission['path'] = path
      admission['cost'] = cost_val unless cost_val.nil?
      admission['kappa'] = kappa unless kappa.equal?(UNDEF)

      # the single decisive reason
      decisive = nil
      unless admitted
        if !X.truthy?(X.hget(grant, 'granted'))
          decisive = { 'reason' => X.nn(X.hget(grant, 'reason'), 'action not permitted by the envelope predicates (default-deny)'),
                       'remedy' => 'grant a predicate that permits this verb+resource (and satisfies its where bound).' }
        else
          first_failed = caveats.find { |c| !X.truthy?(X.hget(c, 'satisfied')) }
          if !first_failed.nil?
            decisive = { 'reason' => "caveat '#{first_failed['type']}' narrowed the authority away: #{first_failed['detail']}" }
            decisive['remedy'] = first_failed['remedy'] if X.truthy?(X.hget(first_failed, 'remedy'))
          elsif budget_depleted
            decisive = { 'reason' => "risk #{num(r)} is admissible but the trust budget cannot cover cost κ·r#{cost_val.nil? ? '' : "=#{num(cost_val)}"}",
                         'remedy' => 'recharge the budget with a human co-sign, or lower the action risk.' }
          else
            decisive = { 'reason' => "risk #{num(r)} exceeds the auto threshold → step-up to t=#{X.js_string(tier)} (#{X.js_string(proof)})",
                         'remedy' => X.num?(tier) && tier == 3 ? 'obtain a human step-up co-signature.' : 'obtain the guardian/principal co-signature for this tier.' }
          end
        end
      end

      summary = if admitted
                  who = X.truthy?(X.hget(grant, 'predicate')) ? "predicate ##{X.js_string(X.hget(grant, 'predicateIndex'))}" : 'policy'
                  "Auto-admitted: #{who} grants it, all caveats held, risk r=#{num(r)} is in the t=#{X.js_string(tier)} band and the budget covers it."
                elsif !decisive.nil?
                  "#{verdict == 'deny' && disposition == 'denied' ? 'Denied' : 'Needs step-up'}: #{X.js_string(decisive['reason'])}"
                else
                  "Not auto-admitted (t=#{X.js_string(tier)})."
                end

      cleaned_caveats = caveats.map { |c| c.merge('detail' => clean_text(c['detail'])) }
      cleaned_decisive = decisive.nil? ? nil : decisive.merge('reason' => clean_text(decisive['reason']))
      out = { 'kind' => 'decision', 'verdict' => verdict, 'disposition' => disposition, 'grant' => grant, 'caveats' => cleaned_caveats,
              'risk' => risk, 'admission' => admission }
      out['decisive'] = cleaned_decisive unless cleaned_decisive.nil?
      out['reasons'] = reasons.map { |x| clean_text(x) }
      out['summary'] = clean_text(summary)
      out
    end

    def decision_to_text(e)
      lines = ["PCA decision — #{X.js_string(e['verdict']).upcase} (#{X.js_string(e['disposition'])})", X.js_string(e['summary']), '']
      gr = e['grant']
      pred = X.get(gr, 'predicate')
      if X.truthy?(X.get(gr, 'granted')) && X.truthy?(pred)
        pv = X.get(pred, 'verb')
        verbs = pv.is_a?(Array) ? pv.map { |x| x.nil? ? '' : X.js_string(x) }.join('|') : X.js_string(pv)
        lines << "  authority : predicate ##{X.js_string(X.get(gr, 'predicateIndex'))} of grant #{short(X.get(gr, 'capabilityId'))} " \
                 "grants #{verbs} on #{X.js_string(X.nn(X.get(pred, 'resource'), '*'))}"
        lines << "              where #{X.js_string(X.get(gr, 'where'))}"
      else
        lines << "  authority : NOT granted — #{X.js_string(X.nn(X.get(gr, 'reason'), 'no predicate permits this action'))}"
      end
      if e['caveats'].empty?
        lines << '  caveats   : none'
      else
        e['caveats'].each do |c|
          mark = X.truthy?(X.get(c, 'satisfied')) ? '✓' : '✗'
          src = X.truthy?(X.get(c, 'delegated')) ? ' [delegated]' : ''
          lines << "  caveat #{mark}  : #{X.js_string(c['detail'])}#{src}"
          lines << "              ↳ fix: #{X.js_string(c['remedy'])}" if !X.truthy?(X.get(c, 'satisfied')) && X.truthy?(X.get(c, 'remedy'))
        end
      end
      risk = e['risk']
      lines << "  risk      : #{X.js_string(X.get(risk, 'band'))}; proof=#{X.js_string(X.get(risk, 'proof'))}, " \
               "optimistic=#{X.js_string(X.get(risk, 'optimisticAllowed'))}"
      a = e['admission']
      cost = X.get(a, 'cost')
      cost_str = cost.equal?(UNDEF) ? '' : ", cost κ·r=#{num(cost)} (κ=#{num(X.get(a, 'kappa'))})"
      lines << "  budget    : #{X.js_string(X.get(a, 'path'))}#{cost_str}; B after=#{num(X.rd(X.get(a, 'budget'), 'B'))}"
      dec = X.get(e, 'decisive')
      if X.truthy?(dec)
        lines << ''
        lines << "  ◀ DECISIVE: #{X.js_string(X.get(dec, 'reason'))}"
        lines << "      ↳ fix: #{X.js_string(X.get(dec, 'remedy'))}" if X.truthy?(X.get(dec, 'remedy'))
      end
      lines.join("\n")
    end

    # ---- explainChain --------------------------------------------------------------------------------------------------

    def budget_alloc?(cv)
      return false unless X.obj?(cv) && X.get(cv, 'type') == 'budget_alloc'

      lim = X.get(cv, 'limit')
      X.fin?(lim) && lim >= 0
    end

    # The per-node budget subtree carried by a chain: one node per well-formed `budget_alloc` caveat, in delegation order. Reads the
    # append-only caveat lineage; it does not verify signatures.
    def budget_alloc_nodes(chain)
      out = []
      return out unless chain.is_a?(Array) && !chain.empty?

      leaf_cvs = X.rd(chain[-1], 'caveats')
      return out unless leaf_cvs.is_a?(Array)

      hop = 0
      leaf_cvs.each_with_index do |cv, ci|
        while hop < chain.length - 1
          n = length_of(X.rd(chain[hop], 'caveats'))
          if (n.equal?(UNDEF) ? 0 : n) <= ci then hop += 1
          else break
          end
        end
        next unless budget_alloc?(cv)

        introducing = chain[hop]
        cap_id = X.rd(introducing, 'id')
        raise TypeError, 'canonicalize: undefined member' if cap_id.equal?(UNDEF)

        node = { 'nodePath' => AtlasPca.hash_canonical({ 'd' => 'atlas-pca/budget-node/v1', 'cap' => cap_id, 'i' => ci }) }
        X.put(node, 'capId', cap_id)
        X.put(node, 'holder', X.rd(introducing, 'holder'))
        node['depth'] = hop
        node['caveatIndex'] = ci
        node['limit'] = cv['limit']
        out << node
      end
      out
    end

    def hop_narrowed_summary(is_root, added)
      bits = []
      added.each do |cv|
        type = caveat_type(cv)
        rest = caveat_rest(cv)
        if type == 'envelope'
          preds = rest['predicates']
          inner = rest['caveats']
          bits << "envelope (#{preds.is_a?(Array) ? preds.length : 0} predicate(s), #{inner.is_a?(Array) ? inner.length : 0} caveat(s))"
        elsif budget_alloc?(cv)
          bits << "budget_alloc(B_sub=#{num(cv['limit'])})"
        else
          bound = value_summary(rest)
          bits << (bound.empty? ? "+#{type}" : "+#{type}(#{bound})")
        end
      end
      return is_root ? 'root grant (no caveats)' : 'rebind only (no new caveats)' if bits.empty?

      (is_root ? 'grants ' : 'narrows: ') + bits.join(', ')
    end

    def explain_chain_inner(chain)
      safe = chain.is_a?(Array) ? chain : []
      hops = []
      safe.each_with_index do |cap, i|
        next unless X.truthy?(cap)

        is_root = i.zero?
        parent = i.positive? ? safe[i - 1] : UNDEF
        pc = X.truthy?(parent) ? X.get(parent, 'caveats') : UNDEF
        parent_len = pc.is_a?(Array) ? pc.length : 0
        oc = X.get(cap, 'caveats')
        own = oc.is_a?(Array) ? oc : []
        added = is_root ? own : (own.length >= parent_len ? own[parent_len..] : [])
        budget_cv = added.find { |cv| budget_alloc?(cv) }
        hop = { 'index' => i, 'isRoot' => is_root }
        X.put(hop, 'issuer', X.get(cap, 'issuer'))
        X.put(hop, 'holder', X.get(cap, 'holder'))
        hop['issuerShort'] = short(X.get(cap, 'issuer'))
        hop['holderShort'] = short(X.get(cap, 'holder'))
        hop['alg'] = X.nn(X.get(cap, 'alg'), 'ed25519')
        hop['addedCaveats'] = added.dup
        hop['addedCaveatTypes'] = added.map { |cv| caveat_type(cv) }
        hop['narrowed'] = clean_text(hop_narrowed_summary(is_root, added))
        hop['budgetAlloc'] = budget_cv['limit'] unless budget_cv.nil?
        hops << hop
      end
      root = safe.empty? ? UNDEF : safe[0]
      leaf = safe.empty? ? UNDEF : safe[-1]
      nodes = budget_alloc_nodes(safe)
      summary = if safe.empty? then 'empty chain (no authority)'
                else "#{short(X.opt(root, 'issuer'))} (principal) delegated through #{safe.length - 1} hop(s) to the acting holder " \
                     "#{short(X.opt(leaf, 'holder'))}; #{nodes.length} budget node(s)."
                end
      out = { 'kind' => 'chain', 'depth' => safe.length, 'hops' => hops }
      X.put(out, 'rootIssuer', X.opt(root, 'issuer'))
      X.put(out, 'leafHolder', X.opt(leaf, 'holder'))
      out['budgetNodes'] = nodes
      out['summary'] = summary
      out
    end

    # Render a delegation chain as an ordered attenuation trace. With `opts["verify"] == true` the chain is also checked
    # (`opts["expectedRootIssuer"]` pins the root issuer); otherwise the trace shows only what the chain claims.
    def explain_chain(chain, opts = OPTS)
      o = opts.equal?(OPTS) ? {} : opts
      out = explain_chain_inner(chain)
      return out unless X.rd(o, 'verify') == true

      ok = false
      reason = 'chain is not an array'
      begin
        if chain.is_a?(Array)
          exp = X.get(o, 'expectedRootIssuer')
          have = !(exp.equal?(UNDEF) || exp.nil?)
          why, ok = AtlasPca.verify_chain(chain, have ? exp : nil, have)
          reason = ok ? nil : chain_reason(why)
        end
      rescue StandardError
        ok = false
        reason = 'chain could not be verified'
      end
      v = { 'ok' => ok ? true : false }
      v['reason'] = clean_text(reason) unless reason.nil?
      out.merge('verification' => v)
    end

    def chain_to_text(e)
      lines = ["PCA delegation chain — #{X.js_string(e['depth'])} hop(s) (attenuation trace)"]
      v = X.get(e, 'verification')
      if v.equal?(UNDEF)
        lines << 'UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.'
      elsif v['ok'] == true
        lines << 'verified: signatures, links and caveat rules hold.'
      else
        lines << "NOT VALID: #{X.js_string(X.nn(X.get(v, 'reason'), 'the chain failed verification'))}"
      end
      lines << X.js_string(e['summary'])
      lines << ''
      e['hops'].each do |h|
        tag = h['isRoot'] ? 'root ' : 'deleg'
        lines << "  ##{X.js_string(h['index'])} #{tag} #{X.js_string(h['issuerShort'])} ──▶ #{X.js_string(h['holderShort'])}   #{X.js_string(h['narrowed'])}"
      end
      unless e['budgetNodes'].empty?
        tree = e['budgetNodes'].map { |n| "depth #{X.js_string(n['depth'])} B_sub=#{num(n['limit'])}" }.join(' → ')
        lines << ''
        lines << "  budget subtree: #{tree}"
      end
      lines.join("\n")
    end
  end
end
