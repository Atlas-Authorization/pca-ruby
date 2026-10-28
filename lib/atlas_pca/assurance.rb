# frozen_string_literal: true

# Assurance labels (T8 / B7).
#
# A check's status (pass / fail / not-enforced / unsupported) says WHETHER it held; the assurance report says WHAT a pass
# rests on: software or hardware attestation, a SNARK proof or an attested-VM statement, a post-quantum or an Ed25519
# signature, independent multisig shares or a FROST (awaiting audit) aggregate. It also names features the verifier does not
# implement (`unsupported`), which are reported and never count as a pass.
#
# Labels come from the VERIFIER'S configuration, never from the presented evidence: a software attestation verifier is
# `software` whatever the document claims, a SNARK backend is the system it was built for, a threshold verifier is the
# scheme the server declared. A hook or backend without a label is `unknown`, which satisfies no requirement.
#
# `require_assurance:` on AtlasPca.authorize turns the report into a gate: when the evidence is weaker, missing, failed
# (invalid or expired), unlabelled, awaiting-audit or unsupported, the `assurance` check fails and the request is denied before
# any replay state is written.
module AtlasPca
  # Attestation levels, weakest first. `unknown` = an unlabelled verifier (satisfies nothing).
  ASSURANCE_ATT_RANK = { 'unknown' => 0, 'software' => 1, 'hardware' => 2, 'multi_root' => 3 }.freeze
  ASSURANCE_ZK_RANK = { 'unknown' => 0, 'attested_vm' => 1, 'attested_vm_hw' => 1, 'stark' => 2, 'zkvm' => 2, 'groth16' => 3,
                        'policyvm_snark' => 3 }.freeze
  ASSURANCE_ZK_NEED = { 'attested_vm' => 1, 'attested_vm_hardware' => 1, 'proof' => 2, 'snark' => 3 }.freeze
  ASSURANCE_AWAITING_AUDIT_SCHEMES = %w[frost frost_dkg mpc].freeze
  ASSURANCE_KEYS = %w[attestation zk signature threshold allow_awaiting_audit allowAwaitingAudit allowPreview allow_preview].freeze
  # The reference names the chain check `cap_chain`, this SDK's verdict `chain`.
  ASSURANCE_CHAIN_NAMES = %w[cap_chain chain].freeze
  LEGACY_POLARITY_DEGRADED = "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)"

  # WeakKeyMap: weak keys, STRONG values (a WeakMap also drops the label hash on GC, so a labelled hook read back as unlabelled).
  ASSURANCE_LABELS = ObjectSpace::WeakKeyMap.new
  private_constant :ASSURANCE_LABELS

  module_function

  # Attach an assurance label to a verifier hook (a lambda, an object), a hardware verifier or a SNARK-like backend.
  # Returns `target`.
  #   level     attestation: software | hardware | multi_root; zk: groth16 | policyvm_snark | stark | zkvm | attested_vm |
  #             attested_vm_hw; threshold: multisig | frost | frost_dkg | mpc
  #   vendor    a vendor or root id, e.g. 'amd-sev-snp'
  #   awaiting_audit   crypto awaiting audit (not production): FROST, DKG, MPC
  #   ceremony  SNARK backends: 'single-party' | 'multi-party'
  def set_assurance_label(target, level, vendor: nil, awaiting_audit: nil, ceremony: nil)
    label = { 'level' => level }
    { 'vendor' => vendor, 'awaiting_audit' => awaiting_audit, 'ceremony' => ceremony }.each { |k, v| label[k] = v unless v.nil? }
    ASSURANCE_LABELS[target] = label.freeze
    target
  end

  # The label attached to `target` by set_assurance_label, if any.
  def assurance_label_of(target)
    return nil if target.nil? || target.is_a?(Symbol) || target.is_a?(Integer)

    lab = ASSURANCE_LABELS[target]
    lab.is_a?(Hash) && lab['level'].is_a?(String) ? lab : nil
  end

  # True for the threshold schemes awaiting audit (FROST, DKG, MPC).
  def awaiting_audit_scheme?(scheme)
    ASSURANCE_AWAITING_AUDIT_SCHEMES.include?(scheme)
  end

  # The attestation level a multi-root N-of-M policy guarantees: the fewest hardware roots any accepted subset can contain
  # (all required roots, filled up to `threshold` with the weakest optional ones). Two or more => 'multi_root', one =>
  # 'hardware', none => the weakest level among the roots that could make up the quorum. Each root is
  # {'verifier' => <labelled hook>, 'required' => bool?}.
  def multi_root_level(roots, threshold)
    rank = lambda do |r|
      lab = assurance_label_of(r['verifier'])
      ASSURANCE_ATT_RANK.fetch(lab ? lab['level'] : 'unknown', 0)
    end
    req = roots.select { |r| r['required'] == true }
    opt = roots.reject { |r| r['required'] == true }.each_with_index.sort_by { |r, i| [rank.call(r), i] }.map(&:first) # stable
    chosen = req + opt.first([threshold.to_i - req.length, 0].max)
    hw = chosen.count { |r| rank.call(r) >= ASSURANCE_ATT_RANK['hardware'] }
    return 'multi_root' if hw >= 2
    return 'hardware' if hw == 1

    (chosen.map { |r| rank.call(r) }.min || ASSURANCE_ATT_RANK['software']) >= ASSURANCE_ATT_RANK['software'] ? 'software' : 'unknown'
  end

  # Classify one signature suite (absent = Ed25519): 'ed25519', 'hybrid' (Ed25519 + a PQ suite), 'pq' (PQ only), or
  # 'unknown' for an unregistered suite.
  def signature_level(alg)
    a = alg.nil? ? 'ed25519' : alg
    return 'ed25519' if a == 'ed25519'
    return 'unknown' unless a.is_a?(String) && REGISTERED_SUITES.include?(a)

    a.start_with?('hybrid-') ? 'hybrid' : 'pq'
  end

  def assurance_weakest(levels)
    %w[unknown ed25519 hybrid].each { |lv| return lv if levels.include?(lv) }
    levels.empty? ? 'unknown' : 'pq'
  end

  # A registered suite whose backend this runtime lacks.
  def assurance_unavailable?(alg)
    a = alg.nil? ? 'ed25519' : alg
    a.is_a?(String) && REGISTERED_SUITES.include?(a) && !supported_suites.include?(a)
  end

  # What each check rests on. `degraded` maps a check name to why a PASSING check rests on a compatibility mode (it is then
  # reported `degraded` and refused by any high-assurance policy). Signature checks carry their suites and level; a carried
  # `bond_ref` is `unsupported` (never a pass).
  #
  #   hooks             the verifier's labelled hooks {'attestation', 'zk', 'threshold', 'revocation'} (see
  #                     set_assurance_label): a passing check reports the hook's level, vendor, awaiting-audit flag and (zk)
  #                     ceremony; an unlabelled hook reports 'unknown'. `attestation_hook` (the verifier actually used) wins
  #                     over hooks['attestation']; `threshold_t` is the `t` the threshold hook enforced;
  #                     `allow_unbound_pq` reports a PQ suite that was not pinned as 'unbound_pq'.
  #
  # Without `hooks` (the authorize path: this SDK verifies no zk proof, attestation or threshold co-signature there) a failed
  # attestation, a carried zk_compliance / threshold and a registered suite whose backend is missing here are also
  # reported `unsupported`.
  def assurance_report(p, checks, degraded = nil, hooks: nil, attestation_hook: nil, threshold_t: nil, allow_unbound_pq: false)
    out = {}
    have_p = p.is_a?(Hash)
    pp = have_p ? p : {}
    hk = hooks.is_a?(Hash) ? hooks.transform_keys(&:to_s) : {}
    chain = pp['cap_chain'].is_a?(Array) ? pp['cap_chain'] : []
    hop_algs = chain.map { |c| c.is_a?(Hash) ? c['alg'] : nil }
    checks.each do |name, st|
      e = { 'outcome' => st }
      e['reason'] = "#{name} is not implemented by this verifier" if st == 'unsupported'
      if st == 'pass'
        hook = case name
               when 'attestation' then attestation_hook.nil? ? hk['attestation'] : attestation_hook
               when 'zk_compliance' then hk['zk']
               when 'threshold' then hk['threshold']
               when 'revocation' then hk['revocation']
               end
        label = hook.nil? ? nil : assurance_label_of(hook)
        if %w[attestation zk_compliance].include?(name) || (name == 'threshold' && !hook.nil?)
          e['level'] = label ? label['level'] : 'unknown'
          e['vendor'] = label['vendor'] if label&.key?('vendor')
          e['ceremony'] = label['ceremony'] if name == 'zk_compliance' && label&.key?('ceremony')
          e['awaiting_audit'] = true if label&.dig('awaiting_audit') == true || (name == 'threshold' && awaiting_audit_scheme?(e['level']))
          e['t'] = threshold_t if name == 'threshold' && (threshold_t.is_a?(Integer) || threshold_t.is_a?(Float))
        elsif label
          e['level'] = label['level']
          e['vendor'] = label['vendor'] if label.key?('vendor')
          e['awaiting_audit'] = true if label['awaiting_audit'] == true
        end
        if name == 'leaf_signature' && have_p
          alg = pp['alg'].nil? ? 'ed25519' : pp['alg']
          e['suites'] = [alg.to_s]
          e['level'] = allow_unbound_pq && alg != 'ed25519' ? 'unbound_pq' : signature_level(alg)
        end
        if ASSURANCE_CHAIN_NAMES.include?(name) && have_p && pp['cap_chain'].is_a?(Array)
          algs = hop_algs.map { |a| a.nil? ? 'ed25519' : a }
          e['suites'] = algs.map(&:to_s)
          e['level'] = allow_unbound_pq && algs.any? { |a| a != 'ed25519' } ? 'unbound_pq' : assurance_weakest(algs.map { |a| signature_level(a) })
        end
      end
      out[name] = e
    end
    unsupported = ->(name, why) { out[name] = { 'outcome' => 'unsupported', 'reason' => why } }
    if hooks.nil?
      if out.dig('leaf_signature', 'outcome') == 'fail' && assurance_unavailable?(pp['alg'])
        unsupported.call('leaf_signature', "signature suite '#{pp['alg']}' has no backend in this runtime")
      end
      if out.dig('chain', 'outcome') == 'fail' && hop_algs.any? { |a| assurance_unavailable?(a) }
        unsupported.call('chain', 'a capability suite has no backend in this runtime')
      end
      unsupported.call('zk_compliance', 'zk compliance verification is not implemented by this SDK') if pp.key?('zk_compliance')
      if out.dig('attestation', 'outcome') == 'fail'
        unsupported.call('attestation', 'attestation verification is not implemented by this SDK')
      end
      unsupported.call('threshold', 'threshold co-signatures are not verified by this SDK') if pp.key?('threshold')
    end
    # a bond is never verified here: reported, never a pass
    unsupported.call('bond', 'bond verification is not implemented by this verifier') if pp.key?('bond_ref')
    (degraded || {}).each do |name, why|
      out[name] = out[name].merge('degraded' => true, 'reason' => why) if out.dig(name, 'outcome') == 'pass'
    end
    out
  end

  # The reason (prefixed 'assurance: ') of the first unmet dimension of `req` (attestation: software < hardware <
  # multi_root; zk: attested_vm | attested_vm_hardware | proof | snark; signature: 'pq'; threshold: [schemes]; allowAwaitingAudit),
  # or nil. Missing, failed, not-enforced, unlabelled, weaker, awaiting-audit, degraded and unsupported evidence never meets a
  # requirement. An unknown requirement key or value is refused (fail closed).
  def unmet_assurance(report, req)
    report.each do |name, e|
      if e['outcome'] == 'unsupported'
        return "assurance: unsupported: #{name} (#{V2JS.truthy?(e['reason']) ? e['reason'] : 'not implemented'}); a high-assurance policy never accepts it"
      end
    end
    report.each do |name, e|
      if e['outcome'] == 'pass' && e['degraded'] == true
        return "assurance: #{name} rests on a degraded compatibility mode (#{V2JS.truthy?(e['reason']) ? e['reason'] : 'degraded'}); " \
               'a high-assurance policy never accepts it'
      end
    end
    return 'assurance: unknown assurance requirement(s): invalid (fail closed)' unless req.is_a?(Hash)

    r = req.transform_keys(&:to_s)
    unknown = r.keys - ASSURANCE_KEYS
    return "assurance: unknown assurance requirement(s): #{unknown.sort.join(', ')} (fail closed)" unless unknown.empty?

    att = r['attestation']
    zk = r['zk']
    sig = r['signature']
    thr = r['threshold']
    allow_awaiting_audit = [r['allowAwaitingAudit'], r['allow_awaiting_audit'], r['allowPreview'], r['allow_preview']].include?(true)
    return "assurance: unknown attestation requirement #{att.inspect} (fail closed)" if !att.nil? && !%w[software hardware multi_root].include?(att)
    return "assurance: unknown zk requirement #{zk.inspect} (fail closed)" if !zk.nil? && !ASSURANCE_ZK_NEED.key?(zk)
    return "assurance: unknown signature requirement #{sig.inspect} (fail closed)" if !sig.nil? && sig != 'pq'
    return "assurance: unknown threshold requirement #{thr.inspect} (fail closed)" if !thr.nil? && !(thr.is_a?(Array) && thr.all?(String))

    need = lambda do |name, what|
      e = report[name]
      next "assurance: #{what} required but there is no #{name} evidence" if e.nil?
      next "assurance: #{what} required but the #{name} check is #{e['outcome']}" if e['outcome'] != 'pass'

      e
    end

    unless att.nil?
      e = need.call('attestation', "#{att} attestation")
      return e if e.is_a?(String)
      if ASSURANCE_ATT_RANK.fetch(e['level'] || 'unknown', 0) < ASSURANCE_ATT_RANK[att]
        return "assurance: #{att} attestation required but the evidence is #{e['level'] || 'unknown'}"
      end
    end
    unless zk.nil?
      e = need.call('zk_compliance', "zk compliance (#{zk})")
      return e if e.is_a?(String)
      if zk == 'attested_vm_hardware' && ['attested_vm', 'unknown', nil].include?(e['level'])
        return "assurance: zk compliance (#{zk}) required but the prover key is not bound to hardware evidence"
      end
      if ASSURANCE_ZK_RANK.fetch(e['level'] || 'unknown', 0) < ASSURANCE_ZK_NEED[zk]
        return "assurance: zk compliance (#{zk}) required but the evidence is #{e['level'] || 'unknown'}"
      end
    end
    if sig == 'pq'
      ['leaf_signature', ASSURANCE_CHAIN_NAMES.find { |n| report.key?(n) } || 'cap_chain'].each do |name|
        e = need.call(name, 'post-quantum signatures')
        return e if e.is_a?(String)
        return "assurance: post-quantum signatures required but #{name} is #{e['level'] || 'unknown'}" unless %w[pq hybrid].include?(e['level'])
      end
    end
    unless thr.nil?
      names = thr.join(' | ')
      e = need.call('threshold', "threshold (#{names})")
      return e if e.is_a?(String)
      return "assurance: threshold (#{names}) required but no threshold verifier enforced it" if e['level'].nil?
      return "assurance: threshold (#{names}) required but the scheme is #{e['level']}" unless thr.include?(e['level'])
    end
    unless allow_awaiting_audit
      report.each do |name, e|
        next if e['outcome'] != 'pass' || e['awaiting_audit'] != true && e['preview'] != true
        next if name == 'threshold' && !thr.nil? && thr.include?(e['level'] || '')

        return "assurance: #{name} rests on crypto awaiting audit (#{e['level'] || 'unknown'}); set allowAwaitingAudit or list the scheme to accept it"
      end
    end
    nil
  end
end
