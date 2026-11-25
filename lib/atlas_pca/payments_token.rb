# frozen_string_literal: true

require 'openssl'
require_relative 'payments'

# Payments, part 3: agent network tokens (an opaque token reference bound to a grant holder, never a PAN), the partner adapters
# with an injected transport, and the optimistic bonded claim over a charge. See payments.rb.
module AtlasPca
  module Payments
    # A network token provider: id plus callables issue({ 'controls', 'agentId' }) -> { 'token_ref' } and suspend(token_ref, reason).
    NetworkTokenProvider = Struct.new(:id, :issue, :suspend)

    module_function

    def luhn?(d)
      total = 0
      dbl = false
      d.reverse.each_char do |ch|
        n = ch.ord - 48
        if dbl
          n *= 2
          n -= 9 if n > 9
        end
        total += n
        dbl = !dbl
      end
      (total % 10).zero?
    end

    # True when a maximal digit run (spaces and hyphens removed) is 13..19 long and Luhn-valid. Whole runs only.
    def looks_like_pan?(s)
      s.scrub.gsub(/[#{Js::WS}-]/o, '').scan(/[0-9]+/).any? { |r| r.length.between?(13, 19) && luhn?(r) }
    end

    def token_ref_error(ref)
      return 'token_ref_malformed' unless ref.is_a?(String) && ref.b.match?(/\A[A-Za-z0-9_.:-]{8,128}\z/n)
      return 'token_ref_looks_like_pan' if looks_like_pan?(ref)

      nil
    end

    def binding_body(b)
      body = { 'kind' => NETWORK_TOKEN_BINDING_KIND, 'v' => 1, 'provider' => prop(b, 'provider'), 'token_ref' => prop(b, 'token_ref'),
               'grant_digest' => prop(b, 'grant_digest'), 'issuer_nonce' => prop(b, 'issuer_nonce'), 'holder' => prop(b, 'holder') }
      raise TypeError, 'canonicalize: unsupported type undefined' if body.values.any? { |v| undef?(v) }

      body
    end

    # The exact bytes the holder signs: utf8 of the canonical-JSON digest of the binding body.
    def binding_message(b) = AtlasPca.hash_canonical(binding_body(b)).b

    # Tie a grant holder to an OPAQUE network-token reference (never a PAN). opts: provider, token_ref, grant, issuer_nonce,
    # holder_secret (32-byte seed), holder_public (32 bytes).
    def bind_network_token(opts)
      e = token_ref_error(opts['token_ref'])
      raise ArgumentError, "bindNetworkToken: #{e}" unless e.nil?

      n = length(opts['issuer_nonce'])
      raise ArgumentError, 'bindNetworkToken: issuer nonce must be at least 16 chars' if !undef?(n) && n < 16

      holder_public = opts['holder_public']
      raise TypeError, 'holderPublic must be bytes' unless holder_public.is_a?(String)

      core = { 'provider' => opts.key?('provider') ? opts['provider'] : UNDEF, 'token_ref' => opts['token_ref'],
               'grant_digest' => hash_of(opts.key?('grant') ? opts['grant'] : UNDEF), 'issuer_nonce' => opts['issuer_nonce'],
               'holder' => AtlasPca.b64e(holder_public) }
      proof = KeyPair.new(opts['holder_secret']).sign(binding_message(core))
      { 'kind' => NETWORK_TOKEN_BINDING_KIND }.merge(core, 'binding_proof' => AtlasPca.b64e(proof))
    end

    # Total. nil = valid. expect: grant (the one the caller verified), holder (b64u), issuer_nonce, optional provider.
    def verify_network_token_binding(b, expect)
      return 'binding_malformed' if !container?(b) || prop(b, 'kind') != NETWORK_TOKEN_BINDING_KIND

      e = token_ref_error(prop(b, 'token_ref'))
      return e unless e.nil?

      prov = prop(b, 'provider')
      exp_prov = prop(expect, 'provider')
      return 'provider_mismatch' if !prov.is_a?(String) || prov.empty? || (!undef?(exp_prov) && !seq?(prov, exp_prov))
      return 'grant_digest_mismatch' unless seq?(prop(b, 'grant_digest'), hash_of(prop(expect, 'grant')))
      return 'holder_mismatch' unless seq?(prop(b, 'holder'), prop(expect, 'holder'))
      return 'issuer_nonce_mismatch' unless seq?(prop(b, 'issuer_nonce'), prop(expect, 'issuer_nonce'))

      pk = AtlasPca.b64d(prop(b, 'holder'))
      sg = AtlasPca.b64d(prop(b, 'binding_proof'))
      return 'binding_malformed' if pk.nil? || sg.nil?

      pk.bytesize == 32 && sg.bytesize == 64 && AtlasPca::Ed25519Strict.verify(pk, binding_message(b), sg) ? nil : 'binding_proof_invalid'
    rescue StandardError
      'binding_malformed'
    end

    # The network-side controls: always an upper-bounded copy of the rail limits.
    def controls_from_limits(limits, grant)
      c = { 'currency' => limits.fetch('currency'), 'perAuthorizationMax' => limits.fetch('perAuthorizationMax'),
            'totalMax' => limits.fetch('totalMax'), 'categories' => limits.fetch('categories').dup, 'merchants' => limits.fetch('merchants').dup }
      c['expiresAt'] = limits['expiresAt'] unless limits['expiresAt'].nil?
      c['metadata'] = { 'grant_digest' => AtlasPca.hash_canonical(grant) }
      c
    end

    def settlement_metadata(b, pcactn_digest)
      { 'pca_grant' => b.fetch('grant_digest'), 'pca_pcactn' => pcactn_digest, 'pca_token_ref' => b.fetch('token_ref') }
    end

    # A network settlement record joins the ledger entry only if all three echoed values match exactly. expected: grant_digest,
    # pcactn_digest, token_ref.
    def reconcile_network_settlement(expected, record)
      md = record.nil? ? UNDEF : optprop(record, 'metadata')
      m = nullish?(md) ? {} : md
      reasons = []
      ped = prop(m, 'pca_pcactn')
      reasons << 'pcactn_digest_missing' if !ped.is_a?(String) || ped.empty? || length(prop(expected, 'pcactn_digest')) == 0
      reasons << 'grant_digest_mismatch' unless seq?(prop(m, 'pca_grant'), prop(expected, 'grant_digest'))
      reasons << 'pcactn_digest_mismatch' unless seq?(ped, prop(expected, 'pcactn_digest'))
      reasons << 'token_ref_mismatch' unless seq?(prop(m, 'pca_token_ref'), prop(expected, 'token_ref'))
      reasons.empty? ? { 'ok' => true } : { 'ok' => false, 'reasons' => reasons }
    end

    # Build the PCActn for the charge and return the metadata for the network request, derived from THAT PCActn's digest:
    # there is no way to carry a digest that is not of a PCActn this call built. opts as charge_to_pcactn.
    def charge_with_network_token(binding_, mandate, charge, opts)
      raise ArgumentError, 'chargeWithNetworkToken: bad binding' unless token_ref_error(prop(binding_, 'token_ref')).nil?
      raise ArgumentError, 'chargeWithNetworkToken: binding is for another grant' unless seq?(prop(binding_, 'grant_digest'), hash_of(prop(mandate, 'grant')))

      built = charge_to_pcactn(mandate, charge, opts)
      digest = AtlasPca.hash_canonical(built['pcactn'])
      { 'pcactn' => built['pcactn'], 'node' => built['node'], 'metadata' => settlement_metadata(binding_, digest), 'pcactnDigest' => digest }
    end

    # ---- partner adapters (no network calls of their own: the transport is injected) ---------------------------------------

    def partner_adapter(id, scope_key, post)
      issue = lambda do |req|
        c = req['controls']
        scope = { 'currency' => c['currency'], 'per_authorization_max' => c['perAuthorizationMax'], 'total_max' => c['totalMax'],
                  'merchant_categories' => c['categories'], 'merchants' => c['merchants'] }
        scope['expires_at'] = c['expiresAt'] unless c['expiresAt'].nil?
        r = post.call('/tokens', { 'agent_id' => req['agentId'], scope_key => scope, 'metadata' => c['metadata'] })
        ref = r['token_ref']
        e = token_ref_error(ref)
        raise ArgumentError, "#{id}: provider returned #{e}" unless e.nil?

        { 'token_ref' => ref }
      end
      suspend = lambda do |token_ref, reason|
        post.call("/tokens/#{Js.encode_uri_component(token_ref)}/suspend", { 'reason' => reason })
        nil
      end
      NetworkTokenProvider.new(id, issue, suspend)
    end

    # Generic mappings of PCA controls onto a neutral control shape; the partner wire formats are access-gated.
    def visa_intelligent_commerce_adapter(post) = partner_adapter('visa_ic', 'instructions', post)
    def mastercard_agent_pay_adapter(post) = partner_adapter('mastercard_agent_pay', 'session_scope', post)

    # Issuance gate: issue a token whose controls equal the rail limits, then bind it to the grant holder. opts: provider, limits,
    # grant, agent_id, holder_secret, holder_public, issuer_nonce.
    def issue_bound_network_token(opts)
      controls = controls_from_limits(opts['limits'], opts['grant'])
      ref = opts['provider'].issue.call({ 'controls' => controls, 'agentId' => opts['agent_id'] })['token_ref']
      binding_ = bind_network_token({ 'provider' => opts['provider'].id, 'token_ref' => ref, 'grant' => opts['grant'],
                                      'issuer_nonce' => opts['issuer_nonce'], 'holder_secret' => opts['holder_secret'],
                                      'holder_public' => opts['holder_public'] })
      { 'binding' => binding_, 'controls' => controls }
    end

    # Grant revoked => suspend. Provider errors propagate (a failed suspend is not a success).
    def suspend_on_revoke(provider, binding_)
      provider.suspend.call(binding_['token_ref'], 'grant_revoked')
      nil
    end

    # Open the optimistic bonded claim for a charge (the dispute / refund window): a signed, bonded claim of compliance a
    # watchtower can challenge; refuses an irreversible charge. opts: bond_ref, claimed_r, challenge_window_ms?, issued_at?,
    # server_now?, window_policy?. signer_secret is the agent-leaf 32-byte Ed25519 seed.
    def open_charge_bond(pcactn, opts, signer_secret)
      action = pcactn.is_a?(Hash) ? pcactn['action'] : nil
      rc = action.is_a?(Hash) ? action['reversibility_class'] : nil
      raise ArgumentError, "openOptimistic: irreversible actions cannot use the optimistic fast-path (§9A)" if rc == AtlasPca::IRREVERSIBLE_CLASS
      raise ArgumentError, 'openOptimistic: claimedR must be finite' unless AtlasPca.opt_num?(opts['claimed_r'])

      policy = opts['window_policy'].nil? ? AtlasPca::DEFAULT_WINDOW_POLICY : opts['window_policy']
      server_now = AtlasPca.opt_num?(opts['server_now']) ? opts['server_now'] : now_ms
      issued_at = AtlasPca.opt_num?(opts['issued_at']) ? opts['issued_at'] : server_now
      window_ms = opts.key?('challenge_window_ms') ? opts['challenge_window_ms'] : policy['defaultWindowMs']
      bad = AtlasPca.opt_validate_window(issued_at, window_ms, server_now, policy)
      raise ArgumentError, "openOptimistic: #{bad}" if bad

      body = { 'pcactn_digest' => AtlasPca.hash_canonical(pcactn), 'bond_ref' => opts['bond_ref'], 'claimed_r' => opts['claimed_r'],
               'reversibility_class' => rc.is_a?(String) ? rc : 'unknown', 'issued_at' => issued_at, 'challenge_window_ms' => window_ms }
      body.merge('sig' => AtlasPca.b64e(KeyPair.new(signer_secret).sign(AtlasPca::OPTIMISTIC_CLAIM_DOMAIN.b + AtlasPca.canon_bytes(body))))
    end
  end
end
