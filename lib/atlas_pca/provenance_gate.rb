# frozen_string_literal: true

# Build provenance as a K1 discharge (track K9): a port of packages/pca/src/provenance-gate.ts (contracts C-520..C-526).
# The policy half of a Sigstore / SLSA provenance check: RFC 9162 inclusion, provenance_gate (facts against the verifier's
# pinned signer-builder pairs) and provenance_caveat (`needs_discharge` with issuer_class "artifact").
#
# Inputs are String-keyed Hashes shaped like the TypeScript interfaces. provenance_gate returns { ok: true, level:, claims: }
# or { ok: false, code: } (symbol keys, like the caveat_lang results); the claims keep the String keys of the wire.
# Every function is total: malformed input is a refusal, never an exception.
module AtlasPca
  module_function

  SLSA_PROVENANCE_V1 = 'https://slsa.dev/provenance/v1'
  INTOTO_STATEMENT_V1 = 'https://in-toto.io/Statement/v1'
  PROV_HEX = { 'sha256' => /\A[0-9a-f]{64}\z/, 'sha512' => /\A[0-9a-f]{128}\z/ }.freeze

  # RFC 9162 section 2.1.1: SHA-256(0x00 || data).
  def rfc9162_leaf_hash(data) = Digest::SHA256.digest("\x00".b + data.b)

  def prov_b32?(v) = v.is_a?(String) && v.bytesize == 32

  # RFC 9162 section 2.1.3.2. `proof` runs from the leaf level up. False on any malformed input.
  def verify_rfc9162_inclusion(leaf_hash, index, size, proof, root)
    return false unless wb_safe_int?(index) && wb_safe_int?(size) && index >= 0 && size >= 1 && index < size
    return false unless prov_b32?(leaf_hash) && prov_b32?(root)
    return false unless proof.is_a?(Array) && proof.length <= 64 && proof.all? { |p| prov_b32?(p) }

    fn = wb_int(index)
    sn = wb_int(size) - 1
    r = leaf_hash.b
    proof.each do |p|
      return false if sn.zero?

      if fn.odd? || fn == sn
        r = Digest::SHA256.digest("\x01".b + p.b + r)
        if fn.even?
          while fn.even? && fn != 0
            fn >>= 1
            sn >>= 1
          end
        end
      else
        r = Digest::SHA256.digest("\x01".b + r + p.b)
      end
      fn >>= 1
      sn >>= 1
    end
    sn.zero? && r == root.b
  rescue StandardError
    false
  end

  def prov_str?(v) = wb_bounded?(v, 2048)
  def prov_level?(v) = wb_safe_int?(v) && [1, 2, 3].include?(v)

  # JS String.length (UTF-16 code units).
  def prov_utf16_len(s)
    s.encode('UTF-16LE').bytesize / 2
  rescue StandardError
    0
  end

  def prov_subject_error?(s)
    return true unless s.is_a?(Hash) && wb_closed_members(s, %w[alg digest]).nil?

    re = PROV_HEX[s['alg']]
    !(re && s['digest'].is_a?(String) && re.match?(s['digest']))
  end

  # nil when well-formed (closed members, bounded strings).
  def provenance_facts_error(f)
    return 'facts must be an object' unless f.is_a?(Hash)

    e = wb_closed_members(f, %w[v predicate_type build_type builder_id subjects identity oidc_issuer integrated_time rekor_log_index],
                          %w[source_repo source_ref source_digest provenance_source], 'facts')
    return e if e
    return 'facts.v must be 1' unless wb_safe_int?(f['v']) && f['v'] == 1

    %w[predicate_type build_type builder_id identity oidc_issuer].each { |k| return "facts.#{k} must be a non-empty string" unless prov_str?(f[k]) }
    %w[source_repo source_ref source_digest].each { |k| return "facts.#{k} must be a non-empty string" if f.key?(k) && !prov_str?(f[k]) }
    s = f['subjects']
    return 'facts.subjects must be 1..64 {alg, digest}' unless s.is_a?(Array) && s.length.between?(1, 64) && s.none? { |x| prov_subject_error?(x) }
    return 'facts.integrated_time must be a non-negative integer' unless wb_safe_int?(f['integrated_time']) && f['integrated_time'] >= 0
    return 'facts.rekor_log_index must be a non-negative integer' unless wb_safe_int?(f['rekor_log_index']) && f['rekor_log_index'] >= 0

    if f.key?('provenance_source')
      p = f['provenance_source']
      unless p.is_a?(Hash) && wb_closed_members(p, ['uri'], ['git_commit']).nil? && prov_str?(p['uri']) && (!p.key?('git_commit') || prov_str?(p['git_commit']))
        return 'facts.provenance_source is malformed'
      end
    end
    nil
  end

  # nil when well-formed.
  def provenance_policy_error(p)
    return 'policy must be an object' unless p.is_a?(Hash)

    e = wb_closed_members(p, %w[roots min_level], %w[source_repo source_ref source_ref_prefix build_types max_age_s require_runtime], 'policy')
    return e if e
    return 'policy.roots must hold 1..32 pairs' unless p['roots'].is_a?(Array) && p['roots'].length.between?(1, 32)

    p['roots'].each do |r|
      return 'policy root is malformed' unless r.is_a?(Hash) && wb_closed_members(r, %w[oidc_issuer builder_id level], %w[identity identity_prefix]).nil?
      return 'policy root needs oidc_issuer and builder_id' unless prov_str?(r['oidc_issuer']) && prov_str?(r['builder_id'])
      return 'policy root needs exactly one of identity and identity_prefix' if r.key?('identity') == r.key?('identity_prefix')
      return 'policy root identity is malformed' if r.key?('identity') && !prov_str?(r['identity'])
      # a prefix must at least name a scheme and a host; an empty-ish prefix would pin nothing
      if r.key?('identity_prefix') && !(prov_str?(r['identity_prefix']) && prov_utf16_len(r['identity_prefix']) >= 10)
        return 'policy root identity_prefix must be at least 10 characters'
      end
      return 'policy root level must be 1, 2 or 3' unless prov_level?(r['level'])
    end
    return 'policy.min_level must be 1, 2 or 3' unless prov_level?(p['min_level'])
    return 'policy.source_repo is malformed' if p.key?('source_repo') && !prov_str?(p['source_repo'])
    return 'policy takes source_ref or source_ref_prefix, not both' if p.key?('source_ref') && p.key?('source_ref_prefix')
    return 'policy.source_ref is malformed' if p.key?('source_ref') && !prov_str?(p['source_ref'])
    return 'policy.source_ref_prefix is malformed' if p.key?('source_ref_prefix') && !prov_str?(p['source_ref_prefix'])
    if p.key?('build_types') && !(p['build_types'].is_a?(Array) && p['build_types'].length.between?(1, 16) && p['build_types'].all? { |b| prov_str?(b) })
      return 'policy.build_types must hold 1..16 strings'
    end
    return 'policy.max_age_s must be a positive integer' if p.key?('max_age_s') && !(wb_safe_int?(p['max_age_s']) && p['max_age_s'] >= 1)
    return 'policy.require_runtime must be a boolean' if p.key?('require_runtime') && ![true, false].include?(p['require_runtime'])

    nil
  end

  # The provenance gates in the reference order. Total.
  def provenance_gate(input)
    no = ->(code) { { ok: false, code: code } }
    return no.call('malformed_facts') unless input.is_a?(Hash)

    f = input['facts']
    p = input['policy']
    now = input['now']
    return no.call('malformed_policy') unless provenance_policy_error(p).nil?
    return no.call('malformed_facts') unless provenance_facts_error(f).nil?
    return no.call('malformed_facts') unless wb_safe_int?(now) && now >= 0

    has_rt = input.key?('runtime')
    rt = input['runtime']
    return no.call('malformed_runtime') if has_rt && prov_subject_error?(rt)
    return no.call('predicate_type') if f['predicate_type'] != SLSA_PROVENANCE_V1
    return no.call('future') if f['integrated_time'] > now
    return no.call('stale') if p.key?('max_age_s') && now - f['integrated_time'] > p['max_age_s']

    level = 0
    p['roots'].each do |r|
      next if r['oidc_issuer'] != f['oidc_issuer'] || r['builder_id'] != f['builder_id']
      next if r.key?('identity') ? r['identity'] != f['identity'] : !f['identity'].start_with?(r['identity_prefix'])

      level = [level, wb_int(r['level'])].max
    end
    return no.call('no_root') if level.zero?
    return no.call('level') if level < p['min_level']

    if f.key?('provenance_source')
      ps = f['provenance_source']
      return no.call('source_mismatch') if ps.key?('git_commit') && f.key?('source_digest') && ps['git_commit'] != f['source_digest']
      if f.key?('source_repo') && !(ps['uri'] == "git+#{f['source_repo']}" || ps['uri'].start_with?("git+#{f['source_repo']}@"))
        return no.call('source_mismatch')
      end
    end
    return no.call('source_repo') if p.key?('source_repo') && f['source_repo'] != p['source_repo']
    return no.call('source_ref') if p.key?('source_ref') && f['source_ref'] != p['source_ref']
    return no.call('source_ref') if p.key?('source_ref_prefix') && !(f.key?('source_ref') && f['source_ref'].start_with?(p['source_ref_prefix']))
    return no.call('build_type') if p.key?('build_types') && !p['build_types'].include?(f['build_type'])

    bound = false
    if has_rt
      subject = f['subjects'].find { |s| s['alg'] == rt['alg'] && s['digest'] == rt['digest'] }
      return no.call('runtime_mismatch') if subject.nil?

      bound = true
    else
      return no.call('runtime_required') if p['require_runtime'] == true
      return no.call('subject_ambiguous') if f['subjects'].length != 1

      subject = f['subjects'][0]
    end
    claims = { 'subject_alg' => subject['alg'], 'subject_digest' => subject['digest'], 'slsa_level' => level, 'builder_id' => f['builder_id'],
               'build_type' => f['build_type'], 'oidc_issuer' => f['oidc_issuer'], 'identity' => f['identity'] }
    %w[source_repo source_ref source_digest].each { |k| claims[k] = f[k] if f.key?(k) }
    claims['rekor_log_index'] = wb_int(f['rekor_log_index'])
    claims['runtime_bound'] = bound
    return no.call('claim_too_long') if claims.values.any? { |v| v.is_a?(String) && v.bytesize > 256 }

    { ok: true, level: level, claims: claims }
  rescue StandardError
    no.call('malformed_facts')
  end

  # A `needs_discharge` caveat (String-keyed, wire shape) that asks the pinned `artifact` verifier for provenance claims.
  def provenance_caveat(issuer:, min_level:, id: nil, source_repo: nil, builder_ids: nil, oidc_issuer: nil, require_runtime: true, bind: nil, ttl_ms: nil)
    req = [{ 'claim' => 'slsa_level', 'op' => 'gte', 'value' => min_level }]
    req << { 'claim' => 'source_repo', 'op' => 'eq', 'value' => source_repo } unless source_repo.nil?
    req << { 'claim' => 'builder_id', 'op' => 'in', 'value' => builder_ids } unless builder_ids.nil?
    req << { 'claim' => 'oidc_issuer', 'op' => 'eq', 'value' => oidc_issuer } unless oidc_issuer.nil?
    req << { 'claim' => 'runtime_bound', 'op' => 'eq', 'value' => true } unless require_runtime == false
    { 'type' => 'needs_discharge', 'id' => id || 'provenance', 'issuer' => issuer, 'issuer_class' => 'artifact', 'bind' => bind || 'action',
      'ttl_ms' => ttl_ms || 300_000, 'require' => req }
  end
end
