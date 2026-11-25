# frozen_string_literal: true

module AtlasPca
  # The approval half of natural-language policy authoring (the reference's `nl`): a model completion is parsed strictly and grounded in the catalog
  # (`IntentCompilers.parse_nl_policy`), the draft is content-addressed and bound to the instruction, the model and the prompt, a reviewer signs it, and
  # only a verified, unexpired approval compiles into an agent. The model is an injected `complete` callable (prompt -> text): no model dependency.
  # Catalogs are an Array of action specs (the built-ins by default) or a facade catalog. Records are String-keyed Hashes.
  module NlApproval
    UNDEF = IntentV2::UNDEF
    NL_APPROVAL_DOMAIN = "atlas-pca/nl-approval/v1\0"
    NL_APPROVAL_DOMAIN_V2 = "atlas-pca/nl-approval/v2\0"
    MAX_NL_OUTPUT_BYTES = 16_384
    MAX_NL_APPROVAL_TTL_MS = 24 * 3_600_000
    DEFAULT_NL_APPROVAL_TTL_MS = 3_600_000
    REJECTIONS = %w[no_reviewers_pinned not_a_draft catalog_mismatch tampered_draft goal_mismatch unknown_verbs empty_permissions analyzer_error
                    malformed_approval digest_mismatch reviewer_not_pinned ttl_too_long not_yet_valid expired bad_signature].freeze

    module_function

    def pm(h, k) = h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF
    def nullish?(x) = x.nil? || UNDEF.equal?(x)
    def specs(catalog) = IntentCompilers.specs_of(catalog)
    def lenient_hash(v) = ActionsImportCommon.hash_canonical_lenient(v)
    def lenient_bytes(v) = ActionsImportCommon.lenient(v).dup.force_encoding('UTF-8').b
    def u16(s) = IntentCompilers.u16key(Attestation.jstr(s))

    # sha256 over the lenient canonical rows [verb, reversibility, amountField|null] sorted by verb (NOT the catalog module's digest)
    def catalog_digest(catalog)
      rows = specs(catalog).map { |s| [s['verb'], s['reversibility'], nullish?(pm(s, 'amountField')) ? nil : s['amountField']] }.sort_by { |r| u16(r[0]) }
      lenient_hash({ 'v' => 1, 'rows' => rows })
    end

    # {instruction_digest, model, prompt_digest}: the instruction, the model name (null when none) and the grounding prompt the draft is bound to
    def draft_binding(instruction, catalog, model = nil)
      { 'instruction_digest' => lenient_hash({ 'd' => 'atlas-pca/nl-instruction/v1', 'text' => instruction }), 'model' => model.nil? ? nil : model,
        'prompt_digest' => lenient_hash({ 'd' => 'atlas-pca/nl-prompt/v1', 'text' => IntentCompilers.nl_prompt(instruction, catalog) }) }
    end

    # the elements of `[...x]` (an Array, or a String by characters); anything else is not iterable
    def spread(x)
      return x.dup if x.is_a?(Array)
      return x.chars if x.is_a?(String)

      raise TypeError, 'not iterable'
    end

    # permissions with the connector names and each action list sorted (so the digest does not depend on order)
    def sorted_permissions(permissions)
      keys = Mcp.keys_of(permissions).sort_by { |k| u16(k) }
      keys.to_h { |c| [c, spread(Mcp.get_key(permissions, c)).sort_by { |a| u16(a) }] }
    end

    def draft_digest_v2(permissions, limits, catalog_digest, binding)
      lenient_hash({ 'v' => 2, 'permissions' => sorted_permissions(permissions), 'limits' => limits, 'catalog_digest' => catalog_digest,
                     'instruction_digest' => pm(binding, 'instruction_digest'), 'model' => pm(binding, 'model'), 'prompt_digest' => pm(binding, 'prompt_digest') })
    end

    def draft_digest(permissions, limits, catalog_digest)
      lenient_hash({ 'v' => 1, 'permissions' => sorted_permissions(permissions), 'limits' => limits, 'catalog_digest' => catalog_digest })
    end

    def lints_of(permissions, limits, catalog)
      return [] if Mcp.keys_of(permissions).empty?

      PolicySim.lint_policy(AtlasPca.compile_policy(permissions, limits, catalog: specs(catalog)), catalog: specs(catalog))
    end

    # The model's policy for an instruction, parsed and linted: {permissions, limits, unknownVerbs, droppedLimits, raw, lints}.
    def policy_from_nl(instruction, complete, catalog = nil)
      raw = complete.call(IntentCompilers.nl_prompt(instruction, catalog))
      parsed = IntentCompilers.parse_nl_policy(raw, catalog)
      lints = parsed['permissions'].empty? ? [] : lints_of(parsed['permissions'], parsed['limits'], catalog)
      parsed.merge('raw' => raw, 'lints' => lints)
    end

    # A content-addressed draft bound to the instruction, the model and the prompt. Raises on a completion that is not a string or exceeds the
    # output cap, or when the model fails.
    def draft_policy_from_nl(instruction, complete, catalog = nil, model = nil)
      raw = complete.call(IntentCompilers.nl_prompt(instruction, catalog))
      raise "draftPolicyFromNL: model output exceeds #{MAX_NL_OUTPUT_BYTES} bytes or is not a string" if !raw.is_a?(String) || raw.b.length > MAX_NL_OUTPUT_BYTES

      p = IntentCompilers.parse_nl_policy(raw, catalog)
      lints = lints_of(p['permissions'], p['limits'], catalog)
      cd = catalog_digest(catalog)
      binding = draft_binding(instruction, catalog, model)
      { 'status' => 'draft', 'instruction' => instruction, 'permissions' => p['permissions'], 'limits' => p['limits'], 'catalog_digest' => cd,
        'binding' => binding, 'digest' => draft_digest_v2(p['permissions'], p['limits'], cd, binding), 'unknownVerbs' => p['unknownVerbs'],
        'droppedLimits' => p['droppedLimits'], 'lints' => lints,
        'analyzerOk' => !p['permissions'].empty? && lints.none? { |l| l['level'] == 'error' } }
    end

    def approval_message(a)
      v = pm(a, 'v')
      (v == 2 ? NL_APPROVAL_DOMAIN_V2 : NL_APPROVAL_DOMAIN).b +
        lenient_bytes(%w[v digest catalog_digest reviewer approved_at expires_at].to_h { |k| [k, pm(a, k)] })
    end

    def sign_approval(body, secret) = body.merge('sig' => AtlasPca.b64e(secret.sign(approval_message(body))))

    def reviewer_key(secret) = secret.is_a?(AtlasPca::KeyPair) ? secret : AtlasPca::KeyPair.new(secret)

    # A reviewer's v2 approval of a draft: raises for a draft that did not pass the analyzer, proposes unknown verbs, or an invalid time / ttl (opts
    # {'now', 'ttlMs'}; the ttl is capped).
    def approve_draft(draft, reviewer_secret, opts = nil)
      raise 'approveDraft: the draft did not pass the static analyzer' unless Attestation.truthy?(pm(draft, 'analyzerOk'))
      raise 'approveDraft: the draft proposed verbs that are not in the catalog' if Array(pm(draft, 'unknownVerbs')).length.positive?

      o = opts.nil? ? {} : opts
      now = nullish?(pm(o, 'now')) ? (Time.now.to_f * 1000).to_i : o['now']
      ttl = nullish?(pm(o, 'ttlMs')) ? DEFAULT_NL_APPROVAL_TTL_MS : o['ttlMs']
      raise 'approveDraft: invalid time or ttl' if !Attestation.finite?(now) || !Attestation.finite?(ttl) || ttl <= 0 || ttl > MAX_NL_APPROVAL_TTL_MS

      key = reviewer_key(reviewer_secret)
      sign_approval({ 'v' => 2, 'digest' => draft['digest'], 'catalog_digest' => draft['catalog_digest'], 'reviewer' => key.public, 'approved_at' => now,
                      'expires_at' => now + ttl }, key)
    end

    # The v1 (instruction-unbound) form of an approval, kept to load drafts approved before the binding existed.
    def approve_draft_legacy_v1(draft, reviewer_secret, opts = nil)
      v2 = approve_draft(draft, reviewer_secret, opts)
      sign_approval({ 'v' => 1, 'digest' => draft_digest(draft['permissions'], draft['limits'], draft['catalog_digest']), 'catalog_digest' => draft['catalog_digest'],
                      'reviewer' => v2['reviewer'], 'approved_at' => v2['approved_at'], 'expires_at' => v2['expires_at'] }, reviewer_key(reviewer_secret))
    end

    def rejected(reason) = { 'ok' => false, 'reason' => reason }

    def safe_int?(x) = IntentArtifacts.safe_int?(x)

    def object?(x) = x.is_a?(Hash) || x.is_a?(Array)

    # Load an approved draft: {ok: true, permissions, limits, reviewer, instruction, legacy_unbound_instruction} or {ok: false, reason} (the reason a
    # NLRejection code). `opts`: 'reviewers' (the pinned reviewer keys), 'catalog'?, 'now'?. Never raises.
    def load_approved_policy(draft, approval, opts)
      catalog = pm(opts, 'catalog')
      catalog = nil if nullish?(catalog)
      now = nullish?(pm(opts, 'now')) ? (Time.now.to_f * 1000).to_i : opts['now']
      reviewers = pm(opts, 'reviewers')
      return rejected('no_reviewers_pinned') if !reviewers.is_a?(Array) || reviewers.empty?
      unless draft.is_a?(Hash) && draft['status'] == 'draft' && object?(pm(draft, 'permissions')) && object?(pm(draft, 'limits'))
        return rejected('not_a_draft')
      end

      cd = catalog_digest(catalog)
      return rejected('catalog_mismatch') unless Attestation.js_eq(pm(draft, 'catalog_digest'), cd)
      return rejected('not_a_draft') unless draft['instruction'].is_a?(String)

      legacy_draft = !draft.key?('binding')
      return rejected('not_a_draft') if !legacy_draft && !object?(draft['binding'])

      if legacy_draft
        return rejected('tampered_draft') unless Attestation.js_eq(pm(draft, 'digest'), draft_digest(draft['permissions'], draft['limits'], cd))
      else
        b = draft['binding']
        model = pm(b, 'model')
        binding = draft_binding(draft['instruction'], catalog, model.is_a?(String) ? model : nil)
        unless Attestation.js_eq(pm(b, 'instruction_digest'), binding['instruction_digest']) && Attestation.js_eq(pm(b, 'prompt_digest'), binding['prompt_digest']) &&
               (model.nil? ? binding['model'].nil? : Attestation.js_eq(model, binding['model']))
          return rejected('tampered_draft')
        end
        return rejected('tampered_draft') unless Attestation.js_eq(pm(draft, 'digest'), draft_digest_v2(draft['permissions'], draft['limits'], cd, binding))
      end
      cat = IntentCompilers.cat_of(catalog)
      Mcp.keys_of(draft['permissions']).each do |c|
        acts = Mcp.get_key(draft['permissions'], c)
        return rejected('unknown_verbs') if !acts.is_a?(Array) || acts.any? { |a| !a.is_a?(String) || cat.get("#{c}.#{a}").nil? }
      end
      uv = pm(draft, 'unknownVerbs')
      return rejected('unknown_verbs') if uv.is_a?(Array) && !uv.empty?
      return rejected('empty_permissions') if Mcp.keys_of(draft['permissions']).empty?
      return rejected('analyzer_error') if lints_of(draft['permissions'], draft['limits'], catalog).any? { |l| l['level'] == 'error' }

      a = approval
      unless a.is_a?(Hash) && [1, 2].any? { |x| Attestation.js_eq(pm(a, 'v'), x) } && %w[sig reviewer digest catalog_digest].all? { |k| a[k].is_a?(String) } &&
             safe_int?(a['approved_at']) && safe_int?(a['expires_at'])
        return rejected('malformed_approval')
      end

      legacy = a['v'] == 1
      return rejected('digest_mismatch') if legacy_draft && !legacy

      want = legacy ? draft_digest(draft['permissions'], draft['limits'], cd) : draft['digest']
      return rejected('digest_mismatch') if !Attestation.js_eq(a['digest'], want) || a['catalog_digest'] != cd
      return rejected('reviewer_not_pinned') unless reviewers.any? { |r| Attestation.js_eq(r, a['reviewer']) }

      life = a['expires_at'] - a['approved_at']
      return rejected('ttl_too_long') if life <= 0 || life > MAX_NL_APPROVAL_TTL_MS
      # JS compares against the clock after coercion: a numeric string is its number, any other text is NaN (every comparison false)
      clock = now.is_a?(String) ? (Float(now.strip, exception: false) || Float::NAN) : now
      return rejected('not_yet_valid') unless a['approved_at'] <= clock
      return rejected('expired') unless clock < a['expires_at']
      return rejected('bad_signature') unless AtlasPca.verify_b64u(a['reviewer'], approval_message(a), a['sig'])

      { 'ok' => true, 'permissions' => draft['permissions'], 'limits' => draft['limits'], 'reviewer' => a['reviewer'], 'instruction' => draft['instruction'],
        'legacy_unbound_instruction' => legacy }
    rescue StandardError, SystemStackError
      rejected('malformed_approval')
    end

    # An agent from an approved draft: raises `agentFromApprovedNL: <code>` for a rejected approval or a goal that is not the approved instruction
    # (a legacy, instruction-unbound approval takes any goal). `req`: 'draft', 'approval', 'reviewers', 'catalog'?, 'now'?, 'principal' (a KeyPair),
    # 'goal', 'aud'?, 'holder'?. Returns {'agent' => the handle, 'reviewer', 'legacy_unbound_instruction'}.
    def agent_from_approved_nl(req)
      loaded = load_approved_policy(req['draft'], req['approval'], req)
      raise "agentFromApprovedNL: #{loaded['reason']}" unless loaded['ok']
      raise 'agentFromApprovedNL: goal_mismatch' if !loaded['legacy_unbound_instruction'] && req['goal'] != loaded['instruction']

      kw = { principal: req['principal'], goal: req['goal'], permissions: loaded['permissions'], limits: loaded['limits'] }
      kw[:catalog] = specs(req['catalog']) unless nullish?(pm(req, 'catalog'))
      kw[:aud] = req['aud'] unless nullish?(pm(req, 'aud'))
      kw[:holder] = req['holder'] unless nullish?(pm(req, 'holder'))
      kw[:now] = req['now'] unless nullish?(pm(req, 'now'))
      { 'agent' => AtlasPca.create_agent(**kw), 'reviewer' => loaded['reviewer'], 'legacy_unbound_instruction' => loaded['legacy_unbound_instruction'] }
    end
  end
end
