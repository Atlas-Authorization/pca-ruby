# frozen_string_literal: true

require 'openssl'
require 'set'
require_relative '../atlas_pca'
require_relative 'js_compat'
require_relative 'frost'

module AtlasPca
  # Post-quantum threshold step-up verification (the TypeScript reference, @atlasauth/pca-pq-threshold): a signed FROST group
  # descriptor that pins the threshold to the group key, an ML-DSA-65 pqT-of-m co-signer quorum, and the hybrid verdict that needs
  # BOTH. The FROST aggregate is checked as the plain Ed25519 signature it is; the quorum runs on the ML-DSA-65 verifier of the
  # core (OpenSSL with ML-DSA). Signing (hybrid_threshold_sign) runs the in-process FROST quorum of AtlasPca::Frost (libsodium via
  # ffi) and signs the ML-DSA co-signatures with any object that has `public` and `sign(msg)`. Folding the aggregate into a PCActn
  # and the core threshold hook are here too; verify_hybrid_step_up runs the full core verification through that hook (the core's
  # optional threshold_hook parameter), so the step-up passes only when the whole PCActn is valid AND both quorums hold.
  module PqThreshold
    GROUP_DESCRIPTOR_VERSION = 1
    GROUP_SUITE = 'frost-ed25519'
    MAX_GROUP_SIZE = 1024
    HYBRID_ARTIFACT_VERSION = 2
    HYBRID_CLASSICAL_ALG = 'frost-ed25519'
    PQ_QUORUM_VERSION = 2
    PQ_QUORUM_ALG = 'ml-dsa-65'
    HYBRID_PQ_ALG = PQ_QUORUM_ALG
    MAX_PQ_QUORUM_ENTRIES = 256
    ML_DSA_65_PUBLIC_KEY_BYTES = 1952

    DESCRIPTOR_DOMAIN = "atlas-pca-pq-threshold/group-descriptor/v1\x00".b.freeze
    SIGNER_SET_DOMAIN = "atlas-pca-pq-threshold/signer-set/v1\x00".b.freeze
    PQ_QUORUM_DOMAIN = "atlas-pca/pq-quorum/v2\x00".b.freeze
    ABSENT = Object.new.freeze # a JS `undefined`: an absent field, distinct from null

    module_function

    # Field read with JS semantics: arrays and scalars have no such field.
    def get(o, key) = o.is_a?(Hash) && o.key?(key) ? o[key] : ABSENT

    def num?(v) = v.is_a?(Integer) || v.is_a?(Float)
    def integer?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite? && v == v.floor)
    def safe_integer?(v) = integer?(v) && v.abs <= (2**53) - 1
    def num_eq?(v, n) = num?(v) && v == n
    def obj?(v) = v.is_a?(Hash) || v.is_a?(Array)

    # raw bytes (a binary String) become base64url; anything else is left as is
    def as_b64u(k) = k.is_a?(String) && k.encoding == Encoding::BINARY ? AtlasPca.b64e(k) : k

    def js_str(v) = v.equal?(ABSENT) ? 'undefined' : Js.string(v)

    def whole(v) = v.is_a?(Float) ? v.to_i : v

    def b64_len?(s, len) = !AtlasPca.b64d(s, len).nil?

    # ---- signed group descriptor
    # base64url(sha256(domain || canonical([{id, pk}] sorted by id))) over the FROST verification shares.
    def signer_set_commitment(participants)
      unless participants.is_a?(Array) && !participants.empty? && participants.length <= MAX_GROUP_SIZE
        raise ArgumentError, "signerSetCommitment: need 1..#{MAX_GROUP_SIZE} participants"
      end

      rows = participants.map do |p|
        raise TypeError, 'signerSetCommitment: participant must be an object' unless p.is_a?(Hash)

        pk = as_b64u(p['publicKey'])
        ident = p['identifier']
        raise ArgumentError, 'signerSetCommitment: participant identifiers must be positive safe integers' if !safe_integer?(ident) || ident <= 0
        raise ArgumentError, 'signerSetCommitment: verification share is not a canonical b64u(32) value' unless b64_len?(pk, 32)

        { 'id' => whole(ident), 'pk' => pk }
      end
      rows.sort_by! { |r| r['id'] }
      (1...rows.length).each do |i|
        raise ArgumentError, 'signerSetCommitment: duplicate participant identifier' if rows[i]['id'] == rows[i - 1]['id']
      end
      AtlasPca.b64e(OpenSSL::Digest::SHA256.digest(SIGNER_SET_DOMAIN + AtlasPca.canon_bytes(rows)))
    end

    def descriptor_bytes(d)
      DESCRIPTOR_DOMAIN + AtlasPca.canon_bytes({ 'v' => d['v'], 'suite' => d['suite'], 'group_pk' => d['groupPublicKey'], 't' => d['t'],
                                                  'n' => d['n'], 'signer_set' => d['signerSetCommitment'] })
    end

    def issue_group_descriptor(authority_secret_key, group_public_key, t, participants)
      n = participants.length
      raise ArgumentError, "issueGroupDescriptor: need 1 <= t <= n (t=#{js_str(t)}, n=#{n})" if !integer?(t) || t < 1 || t > n

      gpk = as_b64u(group_public_key)
      raise ArgumentError, 'issueGroupDescriptor: group public key is not canonical b64u(32)' unless b64_len?(gpk, 32)
      unless authority_secret_key.is_a?(String) && authority_secret_key.bytesize == 32
        raise ArgumentError, 'issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key'
      end

      key = OpenSSL::PKey.new_raw_private_key('ED25519', authority_secret_key.b)
      descriptor = { 'v' => GROUP_DESCRIPTOR_VERSION, 'suite' => GROUP_SUITE, 'groupPublicKey' => gpk, 't' => whole(t), 'n' => n,
                     'signerSetCommitment' => signer_set_commitment(participants) }
      { 'descriptor' => descriptor, 'authority' => AtlasPca.b64e(key.raw_public_key),
        'sig' => AtlasPca.b64e(key.sign(nil, descriptor_bytes(descriptor))) }
    end

    # {"ok" => true, "descriptor"} or {"ok" => false, "reason"}. Pins t to the group key: a FROST aggregate is a plain Ed25519
    # signature, so the threshold cannot be read off the key and must be attested by a trusted setup authority.
    def verify_group_descriptor(s, exp)
      fail = ->(reason) { { 'ok' => false, 'reason' => reason } }
      begin
        return fail.call('no signed group descriptor: the threshold is unattested') unless obj?(s)

        d = get(s, 'descriptor')
        authority = get(s, 'authority')
        sig = get(s, 'sig')
        return fail.call('malformed group descriptor') if !obj?(d) || !authority.is_a?(String) || !sig.is_a?(String)
        return fail.call('unsupported group descriptor version or suite') if !num_eq?(get(d, 'v'), GROUP_DESCRIPTOR_VERSION) || get(d, 'suite') != GROUP_SUITE

        dg = get(d, 'groupPublicKey')
        dssc = get(d, 'signerSetCommitment')
        return fail.call('malformed group descriptor') if !dg.is_a?(String) || !dssc.is_a?(String)

        dt = get(d, 't')
        dn = get(d, 'n')
        return fail.call('malformed group descriptor: need 1 <= t <= n') if !integer?(dt) || !integer?(dn) || dt < 1 || dn < dt || dn > MAX_GROUP_SIZE

        authorities = get(exp, 'trustedAuthorities')
        raise TypeError, 'trustedAuthorities must be an array' unless authorities.is_a?(Array)

        trusted = authorities.map { |a| as_b64u(a) }
        return fail.call('group descriptor authority is not trusted') unless trusted.include?(authority)

        authority_key = AtlasPca.b64d(authority, 32)
        raw_sig = AtlasPca.b64d(sig, 64)
        return fail.call('malformed authority key or signature') if authority_key.nil? || raw_sig.nil?
        return fail.call('group descriptor signature does not verify') unless AtlasPca::Ed25519Strict.verify(authority_key, descriptor_bytes(d), raw_sig)
        return fail.call('group descriptor is for a different group key') if dg != as_b64u(get(exp, 'groupKey'))

        et = get(exp, 't')
        return fail.call('required t must be a positive integer') if !integer?(et) || et < 1
        if dt != et
          return fail.call("group was set up as #{js_str(dt)}-of-#{js_str(dn)} but #{js_str(et)} is required: the threshold is not bound to this key")
        end

        pin = get(exp, 'signerSetCommitment')
        return fail.call('group descriptor is for a different signer set') if !pin.equal?(ABSENT) && dssc != pin

        { 'ok' => true, 'descriptor' => d }
      rescue StandardError
        fail.call('group descriptor could not be verified (malformed)')
      end
    end

    # ---- ML-DSA-65 co-signer quorum (a pqT-of-m multi-signature of single-party keys, not a threshold scheme)
    # The bytes every co-signature covers: domain || sha256(message).
    def pq_quorum_representative(message) = PQ_QUORUM_DOMAIN + OpenSSL::Digest::SHA256.digest(message.b)

    # The trusted pool as canonical base64url strings; entries that are not a well-formed ML-DSA-65 public key are ignored.
    def normalize_pq_quorum_pool(pks)
      raise TypeError, 'normalizePqQuorumPool: expected an array of public keys' unless pks.is_a?(Array) || pks.is_a?(Set)

      pks.each_with_object(Set.new) do |p, pool|
        s = as_b64u(p)
        pool << s if s.is_a?(String) && b64_len?(s, ML_DSA_65_PUBLIC_KEY_BYTES)
      end
    end

    # Count DISTINCT trusted keys whose co-signature verifies over `message`; ok iff the count reaches pq_t. Total (never raises
    # on a malformed block); a missing, v1 or unknown version is refused before any verification.
    def verify_pq_quorum(block, message, trusted_pool, pq_t)
      no = ->(reason) { { 'ok' => false, 'count' => 0, 'need' => pq_t, 'reason' => reason } }
      return no.call('pqT must be a positive integer') if !integer?(pq_t) || pq_t < 1
      return no.call('malformed pq block') unless obj?(block)

      v = get(block, 'v')
      alg = get(block, 'alg')
      signers = get(block, 'signers')
      return no.call('pq quorum version missing (pre-0.5 format is refused)') if v.equal?(ABSENT)
      return no.call('pq quorum version 1 is no longer accepted (pre-0.5 format)') if num_eq?(v, 1)
      return no.call('unsupported pq quorum version') unless num_eq?(v, PQ_QUORUM_VERSION)
      return no.call('malformed pq block') if alg != PQ_QUORUM_ALG || !signers.is_a?(Array)

      rep = pq_quorum_representative(message)
      counted = Set.new
      signers.first(MAX_PQ_QUORUM_ENTRIES).each do |entry|
        next unless entry.is_a?(Hash)

        pk = entry['pk']
        sig = entry['sig']
        next unless pk.is_a?(String) && sig.is_a?(String)
        next if !trusted_pool.include?(pk) || counted.include?(pk)
        next unless AtlasPca.pq_verify_b64u('ML-DSA-65', pk, rep, sig)

        counted << pk
      end
      count = counted.length
      return { 'ok' => true, 'count' => count, 'need' => pq_t } if count >= pq_t

      { 'ok' => false, 'count' => count, 'need' => pq_t,
        'reason' => "post-quantum quorum short: #{count} of #{js_str(pq_t)} required ML-DSA co-signatures" }
    end

    # ---- hybrid verification: the FROST aggregate AND the ML-DSA quorum, both over the same action message
    def normalize_group_key(k)
      s = as_b64u(k)
      b64_len?(s, 32) ? s : nil
    end

    # a FROST aggregate is an ordinary Ed25519 signature under the group key
    def verify_frost_aggregate?(sig, message, trusted_group_key) = sig.is_a?(String) && AtlasPca.verify_b64u(trusted_group_key, message, sig) ? true : false

    def check_descriptor(opts)
      exp = { 'trustedAuthorities' => get(opts, 'trustedAuthorities'), 'groupKey' => get(opts, 'groupKey'), 't' => get(opts, 't') }
      pin = get(opts, 'signerSetCommitment')
      exp['signerSetCommitment'] = pin unless pin.equal?(ABSENT)
      r = verify_group_descriptor(get(opts, 'groupDescriptor'), exp)
      r['ok'] ? nil : r['reason']
    end

    def strip(d)
      out = d.reject { |_, v| v.equal?(ABSENT) }
      out['pq'] = strip(out['pq']) if out['pq'].is_a?(Hash)
      out
    end

    # {"ok", "frost", "pq", "reason"?}: fail closed unless the FROST aggregate verifies under the trusted group key (whose
    # threshold the signed descriptor pins) AND at least pqT distinct trusted ML-DSA-65 keys co-signed.
    def verify_hybrid_threshold(action, artifact, opts)
      verify_hybrid_inner(action, artifact, opts)
    rescue StandardError
      reason = 'malformed action or verifier options'
      { 'ok' => false, 'frost' => false, 'pq' => { 'ok' => false, 'count' => 0, 'need' => 0, 'reason' => reason }, 'reason' => reason }
    end

    def verify_hybrid_inner(action, artifact, opts)
      version = get(artifact, 'v')
      pq_t = get(opts, 'pqT')
      unless num_eq?(version, HYBRID_ARTIFACT_VERSION)
        reason = if version.equal?(ABSENT) then 'artifact version missing (pre-0.5 format is refused)'
                 elsif num_eq?(version, 1) then 'artifact version 1 is no longer accepted (pre-0.5 format)'
                 else 'unsupported artifact version'
                 end
        return strip({ 'ok' => false, 'frost' => false, 'pq' => { 'ok' => false, 'count' => 0, 'need' => pq_t, 'reason' => reason }, 'reason' => reason })
      end
      message = AtlasPca.threshold_message(action)
      trusted_group_key = normalize_group_key(get(opts, 'groupKey'))
      pks = get(opts, 'pqPublicKeys')
      pool = normalize_pq_quorum_pool(pks.equal?(ABSENT) ? nil : pks)

      frost_ok = false
      frost_reason = nil
      descriptor_reason = check_descriptor(opts)
      t = get(opts, 't')
      frost = get(artifact, 'frost')
      ft = get(frost, 't')
      if !integer?(t) || t < 1 then frost_reason = 't must be a positive integer'
      elsif trusted_group_key.nil? then frost_reason = 'trusted FROST group key is not a canonical b64u(32) point'
      elsif !obj?(frost) || get(frost, 'alg') != HYBRID_CLASSICAL_ALG then frost_reason = 'malformed or missing FROST part'
      elsif !descriptor_reason.nil? then frost_reason = descriptor_reason
      elsif !integer?(ft) || ft < t then frost_reason = "FROST declared threshold #{js_str(ft)} is below the required t=#{js_str(t)} (downgrade)"
      elsif !verify_frost_aggregate?(get(frost, 'sig'), message, trusted_group_key)
        frost_reason = 'FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)'
      else frost_ok = true
      end

      pq_block = get(artifact, 'pq')
      pq = verify_pq_quorum(pq_block.equal?(ABSENT) ? nil : pq_block, message, pool, pq_t)
      ok = frost_ok && pq['ok']
      return strip({ 'ok' => ok, 'frost' => frost_ok, 'pq' => pq }) if ok

      strip({ 'ok' => ok, 'frost' => frost_ok, 'pq' => pq, 'reason' => frost_ok ? pq['reason'] : frost_reason })
    end

    # ---- signing, folding into a PCActn, and the core threshold hook
    # One ML-DSA-65 co-signature per key pair (an object with `public` bytes and `sign(msg)`) over the quorum representative.
    def sign_pq_quorum(message, key_pairs, pq_t = nil)
      rep = pq_quorum_representative(message)
      signers = key_pairs.map { |k| { 'pk' => k.public, 'sig' => AtlasPca.b64e(k.sign(rep)) } }
      { 'v' => PQ_QUORUM_VERSION, 'alg' => PQ_QUORUM_ALG, 'pqT' => pq_t.nil? ? signers.length : pq_t, 'signers' => signers }
    end

    # The hybrid artifact for `action`: a FROST t-of-n aggregate (frost: {groupPublicKey, quorum: [participant shares], t}) plus one
    # ML-DSA-65 co-signature per pq signer, both over the same message. Fails closed on a short quorum or an invalid share.
    def hybrid_threshold_sign(action, frost, pq_signers, pq_t = nil)
      t = frost['t']
      raise ArgumentError, "hybridThresholdSign: frost.t must be a positive integer (got #{js_str(t)})" if !integer?(t) || t < 1
      if frost['quorum'].length < t
        raise ArgumentError, "hybridThresholdSign: FROST quorum of #{frost['quorum'].length} is below the threshold t=#{t}"
      end
      raise ArgumentError, 'hybridThresholdSign: at least one ML-DSA co-signer is required' if pq_signers.empty?

      message = AtlasPca.threshold_message(action)
      gk = frost['groupPublicKey']
      if gk.is_a?(String) && gk.encoding != Encoding::BINARY
        gk = AtlasPca.b64d(gk, 32)
        raise ArgumentError, 'hybridThresholdSign: FROST group public key is not canonical b64u(32)' if gk.nil?
      elsif !gk.is_a?(String) || gk.bytesize != 32
        raise ArgumentError, 'hybridThresholdSign: FROST group public key must be 32 bytes'
      end
      gk = gk.b
      agg = Frost.cosign(gk, frost['quorum'].to_a, message, whole(t))
      { 'v' => HYBRID_ARTIFACT_VERSION, 'digest' => AtlasPca.b64e(OpenSSL::Digest::SHA256.digest(message)),
        'frost' => { 'alg' => HYBRID_CLASSICAL_ALG, 'group_pk' => AtlasPca.b64e(gk), 'sig' => AtlasPca.b64e(agg), 't' => whole(t),
                     'quorum' => frost['quorum'].length },
        'pq' => sign_pq_quorum(message, pq_signers, pq_t) }
    end

    # {"pcactn", "pq"}: the FROST aggregate becomes a `guardian` share of the PCActn's threshold container (the signed body is
    # unchanged: threshold_message excludes `threshold`); the PQ block travels beside it.
    def fold_hybrid_step_up(action, artifact)
      frost = artifact.is_a?(Hash) && artifact['frost'].is_a?(Hash) ? artifact['frost'] : nil
      raise TypeError, 'foldHybridStepUp: malformed action or artifact' if frost.nil? || !action.is_a?(Hash)

      share = { 'role' => 'guardian' }
      { 'publicKey' => 'group_pk', 'sig' => 'sig' }.each { |k, m| share[k] = frost[m] if frost.key?(m) }
      th = action['threshold']
      existing = th.is_a?(Hash) && th['shares'].is_a?(Array) ? th['shares'] : []
      out = { 'pcactn' => action.merge('threshold' => { 'shares' => [*existing, share] }) }
      out['pq'] = artifact['pq'] if artifact.key?('pq')
      out
    end

    # The core `threshold` hook enforcing the hybrid step-up: the FROST aggregate folded into `pcactn.threshold` (an Ed25519
    # signature under the TRUSTED group key) AND the pqT-of-m quorum over this action. The configuration is snapshotted at creation.
    def create_hybrid_threshold_verifier(opts)
      opts = Marshal.load(Marshal.dump(opts))
      trusted = normalize_group_key(get(opts, 'groupKey'))
      pool = normalize_pq_quorum_pool(get(opts, 'pqPublicKeys'))
      lambda do |ctx|
        no = ->(reason) { { 'enforced' => true, 'ok' => false, 'reason' => reason } }
        d = check_descriptor(opts)
        next no.call(d) unless d.nil?

        message = AtlasPca.threshold_message(ctx['pcactn'])
        next no.call('trusted FROST group key is not a canonical b64u(32) point') if trusted.nil?

        th = ctx['pcactn']['threshold']
        shares = th.is_a?(Hash) && th['shares'].is_a?(Array) ? th['shares'] : []
        share = shares.find { |x| x.is_a?(Hash) && x['sig'].is_a?(String) && x['publicKey'] == trusted }
        next no.call('no FROST aggregate for the trusted group key in the step-up') if share.nil?
        next no.call('FROST aggregate does not verify under the trusted group key (quorum short or forged)') unless verify_frost_aggregate?(share['sig'], message, trusted)

        blk = get(opts, 'pqBlock')
        pqv = verify_pq_quorum(blk.equal?(ABSENT) ? nil : blk, message, pool, get(opts, 'pqT'))
        next no.call(pqv['reason'] || 'post-quantum quorum short') unless pqv['ok']

        { 'enforced' => true, 'ok' => true }
      end
    end

    HOOK_OPT_KEYS = %w[groupKey pqPublicKeys t pqT groupDescriptor trustedAuthorities signerSetCommitment].freeze

    # {"allow", "core", "pq", "reason"?}: the folded step-up ({pcactn, pq}) verified end to end. opts: grant, groupKey, pqPublicKeys, t
    # (the step-up tier), pqT, groupDescriptor, trustedAuthorities, signerSetCommitment?, audience? (String = must equal; nil = any;
    # key absent = refused when the PCActn carries an aud), nowEpoch? (ms). The threshold check runs inside the core verification.
    def verify_hybrid_step_up(step_up, opts)
      pcactn = step_up['pcactn']
      block = step_up['pq']
      pks = get(opts, 'pqPublicKeys')
      pool = normalize_pq_quorum_pool(pks.equal?(ABSENT) ? nil : pks)
      pq = verify_pq_quorum(block, AtlasPca.threshold_message(pcactn), pool, get(opts, 'pqT'))
      hook_opts = HOOK_OPT_KEYS.select { |k| opts.key?(k) }.to_h { |k| [k, opts[k]] }
      hook_opts['pqBlock'] = block
      audience = if !opts.key?('audience') then nil
                 elsif opts['audience'].nil? then pcactn['aud']
                 else opts['audience']
                 end
      now = opts['nowEpoch'] || (Time.now.to_f * 1000).to_i
      core = AtlasPca.verify_pcactn(pcactn, opts['grant'], now: now, audience: audience, insecure_skip_plan_root_check: true,
                                    threshold_hook: create_hybrid_threshold_verifier(hook_opts))
      out = { 'allow' => core.allow, 'core' => core, 'pq' => pq }
      out['reason'] = core.reason unless core.allow
      out
    end
  end
end
