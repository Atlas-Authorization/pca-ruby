# frozen_string_literal: true

require 'securerandom'
require_relative 'jose'

# OAuth Transaction Tokens as a chain-of-custody PROFILE of a PCA capability chain: the chain projected into the RFC 8693
# nested `sub` / `act` idiom, carried with the action (`tctx`) in an EdDSA Transaction Token (draft-ietf-oauth-transaction-
# tokens-11 by default, or the legacy shape). The token is the interop envelope, never the credential: the PCActn's signed
# chain stays the authority. Mirrors @atlasauth/pca-txn-tokens. Options are String-keyed snake_case Hashes.
module AtlasPca
  module TxnTokens
    TXN_TOKEN_TYP = 'txn_token+jwt'
    TXN_TOKEN_TYP_DRAFT_11 = 'txntoken+jwt'
    DEFAULT_TTL_SEC = 120
    MAX_TOKEN_CHARS = 16_384
    EDDSA = 'EdDSA'
    PCA_ACTION_KEYS = %w[verb resource aud].freeze

    # A verifier configured without a required security component (code 'replay_store_required').
    class TxnTokenError < StandardError
      attr_reader :code

      def initialize(code, message)
        @code = code
        super(message)
      end
    end

    module_function

    def m(o, k) = o.is_a?(Hash) ? o[k] : nil

    # RFC 8693 section 4.1 nesting, descending the chain: sub = root issuer, then one `act` level per hop holder.
    def sub_act_chain(chain)
      raise TypeError, 'subActChain: chain must be a non-empty CapabilityChain' unless chain.is_a?(Array) && !chain.empty?

      act = nil
      (chain.length - 1).downto(0) do |i|
        holder = m(chain[i], 'holder')
        raise TypeError, "subActChain: hop #{i} has no holder" unless holder.is_a?(String) && !holder.empty?

        act = act ? { 'sub' => holder, 'act' => act } : { 'sub' => holder }
      end
      iss = m(chain[0], 'issuer')
      raise TypeError, 'subActChain: root hop has no issuer (principal)' unless iss.is_a?(String) && !iss.empty?

      { 'sub' => iss, 'act' => act }
    end

    # The number of nested `act` levels.
    def act_depth(claim)
      raise TypeError, 'actDepth: expected a sub/act claim object' unless claim.is_a?(Hash) || claim.is_a?(Array)

      depth = 0
      cur = m(claim, 'act')
      while Js.truthy?(cur)
        depth += 1
        cur = m(cur, 'act')
      end
      depth
    end

    # The RFC 8693 order of an `act` chain (most recent actor outermost); `sub` unchanged.
    def to_rfc8693_act(claim)
      raise TypeError, 'toRfc8693Act: claim is null' if claim.nil?

      actors = []
      c = m(claim, 'act')
      while Js.truthy?(c)
        actors << m(c, 'sub')
        c = m(c, 'act')
      end
      act = nil
      actors.each { |s| act = { 'sub' => s, 'act' => act }.compact }
      { 'sub' => m(claim, 'sub'), 'act' => act }.compact
    end

    # Mint a signed Transaction Token. Args: chain, action {verb, resource, aud}, issuer, issuer_key (32-byte Ed25519 seed
    # or an OpenSSL Ed25519 key), profile ('draft-11' default | 'legacy'), scope, req_wl, txn, trust_domain, ttl_sec.
    def to_transaction_token(a)
      issuer = a['issuer']
      action = a['action']
      raise TypeError, 'toTransactionToken: `issuer` is required' unless issuer.is_a?(String) && !issuer.empty?
      unless action.is_a?(Hash) && %w[verb resource aud].all? { |k| action[k].is_a?(String) }
        raise TypeError, 'toTransactionToken: `action` must have string verb, resource and aud'
      end

      custody = sub_act_chain(a['chain'])
      ttl = a['ttl_sec'].nil? ? DEFAULT_TTL_SEC : a['ttl_sec']
      raise ArgumentError, 'toTransactionToken: ttlSec must be > 0' unless Js.num?(ttl) && ttl.to_f.finite? && ttl.positive?

      now = Time.now.to_i
      key = a['issuer_key']
      if key.is_a?(String) && key.bytesize != 32
        raise TypeError, 'toTransactionToken: a raw Ed25519 secret key must be 32 bytes'
      end

      draft = (a['profile'] || 'draft-11') == 'draft-11'
      if !a['profile'].nil? && a['profile'] != 'legacy' && !draft
        raise TypeError, 'toTransactionToken: profile must be legacy or draft-11'
      end

      tctx = { 'verb' => action['verb'], 'resource' => action['resource'], 'aud' => action['aud'] }
      if draft
        raise TypeError, 'toTransactionToken: draft-11 requires `scope`' unless a['scope'].is_a?(String) && !a['scope'].empty?
        raise TypeError, 'toTransactionToken: draft-11 requires `reqWl`' unless a['req_wl'].is_a?(String) && !a['req_wl'].empty?

        td = a['trust_domain'].nil? ? action['aud'] : a['trust_domain']
        unless td.is_a?(String) && !td.empty?
          raise TypeError, 'toTransactionToken: draft-11 requires a non-empty trust domain (aud)'
        end

        claims = { 'tctx' => tctx }
        claims['act'] = custody['act'] if custody['act']
        claims.merge!('txn' => a['txn'].nil? ? SecureRandom.uuid : a['txn'], 'scope' => a['scope'], 'req_wl' => a['req_wl'],
                      'iat' => now, 'iss' => issuer, 'sub' => custody['sub'], 'aud' => td, 'exp' => now + ttl)
        return Jose.sign_jwt(claims, { 'alg' => EDDSA, 'typ' => TXN_TOKEN_TYP_DRAFT_11 }, key)
      end

      claims = { 'tctx' => tctx }
      claims['act'] = custody['act'] if custody['act']
      claims.merge!('iat' => now, 'iss' => issuer, 'sub' => custody['sub'], 'aud' => action['aud'], 'exp' => now + ttl,
                    'jti' => SecureRandom.uuid)
      Jose.sign_jwt(claims, { 'alg' => EDDSA, 'typ' => TXN_TOKEN_TYP }, key)
    end

    def normalize_act(node, present)
      return nil unless present
      raise ArgumentError, 'transaction token: malformed `act` claim' unless node.is_a?(Hash)
      raise ArgumentError, 'transaction token: `act.sub` must be a non-empty string' unless node['sub'].is_a?(String) && !node['sub'].empty?

      { 'sub' => node['sub'], 'act' => normalize_act(node['act'], node.key?('act')) }.compact
    end

    def read_tctx(raw, draft)
      raise ArgumentError, 'transaction token: missing or malformed `tctx`' unless raw.is_a?(Hash)

      if !draft || PCA_ACTION_KEYS.any? { |k| raw.key?(k) }
        unless PCA_ACTION_KEYS.all? { |k| raw[k].is_a?(String) }
          raise ArgumentError, 'transaction token: missing or malformed `tctx`'
        end

        return [raw, raw.slice(*PCA_ACTION_KEYS)]
      end
      [raw, nil]
    end

    # Verify a Transaction Token and return {'chain', 'action', 'tctx', 'claims'}. Options: profile, audience,
    # clock_tolerance_sec, now_ms, seen_txn (callable(id, exp) -> true when already seen), replay_check ('unchecked').
    # Raises on any refusal; the replay identifier is consumed last.
    def from_transaction_token(jwt, verify_key, o = {})
      draft = (o['profile'] || 'draft-11') == 'draft-11'
      raise TypeError, 'fromTransactionToken: profile must be legacy or draft-11' if !o['profile'].nil? && o['profile'] != 'legacy' && !draft
      if draft && !(o['audience'].is_a?(String) && !o['audience'].empty?)
        raise TypeError, 'fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)'
      end
      unless o['seen_txn'].respond_to?(:call) || o['replay_check'] == 'unchecked'
        raise TxnTokenError.new('replay_store_required',
                                "fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'")
      end
      raise ArgumentError, 'transaction token: token exceeds the size limit' if jwt.is_a?(String) && jwt.length > MAX_TOKEN_CHARS

      Jose.assert_canonical_compact_jws(jwt)
      if verify_key.is_a?(String) && verify_key.bytesize != 32
        raise TypeError, 'fromTransactionToken: a raw Ed25519 public key must be 32 bytes'
      end

      # a non-finite tolerance or an invalid clock makes every exp/nbf comparison pass
      ct = o['clock_tolerance_sec']
      raise RangeError, 'fromTransactionToken: clockToleranceSec must be a finite number >= 0' unless ct.nil? || (Js.num?(ct) && ct.to_f.finite? && ct >= 0)
      raise RangeError, 'fromTransactionToken: now must be a valid Date' unless o['now_ms'].nil? || (Js.num?(o['now_ms']) && o['now_ms'].to_f.finite?)

      opts = { algorithms: [EDDSA], typ: draft ? TXN_TOKEN_TYP_DRAFT_11 : TXN_TOKEN_TYP,
               required_claims: draft ? %w[iat exp aud sub txn scope req_wl] : %w[exp] }
      opts[:audience] = o['audience'] unless o['audience'].nil?
      opts[:clock_tolerance] = o['clock_tolerance_sec'] unless o['clock_tolerance_sec'].nil?
      opts[:now_ms] = o['now_ms'] unless o['now_ms'].nil?
      payload, = Jose.jwt_verify(jwt, verify_key, **opts)
      if draft
        %w[txn scope req_wl].each do |k|
          raise ArgumentError, "transaction token: `#{k}` must be a non-empty string" unless payload[k].is_a?(String) && !payload[k].empty?
        end
      end
      sub = payload['sub']
      raise ArgumentError, 'transaction token: missing `sub` (root principal)' unless sub.is_a?(String) && !sub.empty?

      tctx, action = read_tctx(payload['tctx'], draft)
      raise ArgumentError, 'transaction token: malformed `rctx`' if draft && payload.key?('rctx') && !payload['rctx'].is_a?(Hash)

      act = normalize_act(payload['act'], payload.key?('act'))
      if o['seen_txn']
        id = draft ? payload['txn'] : payload['jti']
        raise ArgumentError, 'transaction token: no transaction identifier to check for replay' unless id.is_a?(String) && !id.empty?
        if o['seen_txn'].call(id, payload['exp'])
          raise ArgumentError, 'transaction token: replayed (transaction identifier already seen)'
        end
      end
      { 'chain' => { 'sub' => sub, 'act' => act }.compact, 'action' => action, 'tctx' => tctx, 'claims' => payload }.compact
    end
  end
end
