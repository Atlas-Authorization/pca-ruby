# frozen_string_literal: true

require_relative 'intent_v2'

# Intent capture and commitment: the principal's own words plus the structured reading, signed, with a content address (the intent
# ref). Native port of the statement artifact of the TypeScript reference (@atlasauth/pca and @atlasauth/pca-intent): shape, Ed25519
# signing, and verification through the verifier-pinned suite dispatch.
module AtlasPca
  module IntentStatement
    UNDEF = V2JS::UNDEF
    INTENT_SIG_DOMAIN = "atlas-pca/intent/v1\0"
    INTENT_REF_DOMAIN = 'atlas-pca/intent-ref/v1'
    INTENT_SOURCE_KINDS = %w[conversation ticket document form other].freeze
    BODY_KEYS = %w[v principal text slots sources created_at nonce].freeze

    module_function

    def g(o, k) = o.key?(k) ? o[k] : UNDEF

    # The signed body: suite fields and signatures excluded (the ref names the content).
    def statement_body(s)
      b = BODY_KEYS.select { |k| s.key?(k) && !s[k].equal?(UNDEF) }.to_h { |k| [k, s[k]] }
      Marshal.load(Marshal.dump(b))
    end

    # Content address of an intent statement.
    def intent_ref(s) = AtlasPca.hash_canonical({ 'd' => INTENT_REF_DOMAIN, 's' => statement_body(s) })

    def statement_shape_error(s)
      return 'intent statement is not an object' unless s.is_a?(Hash)
      return 'unsupported intent statement version' if !V2JS.strict_eq(g(s, 'v'), 1)
      return 'principal is not canonical base64url (32 bytes)' if AtlasPca.b64d(g(s, 'principal'), 32).nil?

      text = g(s, 'text')
      return 'text must be a non-empty string' if !text.is_a?(String) || text.empty?
      return 'slots must be an object' unless g(s, 'slots').is_a?(Hash)

      sources = g(s, 'sources')
      return 'sources must be an array' unless sources.is_a?(Array)

      sources.each_with_index do |src, i|
        return "sources[#{i}] has an unknown kind" if !src.is_a?(Hash) || !g(src, 'kind').is_a?(String) || !INTENT_SOURCE_KINDS.include?(g(src, 'kind'))
        return "sources[#{i}].uri must be a string" if !g(src, 'uri').equal?(UNDEF) && !src['uri'].is_a?(String)
        return "sources[#{i}].digest is not canonical base64url (32 bytes)" if AtlasPca.b64d(g(src, 'digest'), 32).nil?
      end
      ca = g(s, 'created_at')
      return 'created_at must be a non-negative safe integer (epoch ms)' unless V2JS.int?(ca) && ca >= 0

      nonce = g(s, 'nonce')
      return 'nonce must be a non-empty string' if !nonce.is_a?(String) || nonce.empty?

      nil
    end

    def suite_fields_error(a)
      alg = g(a, 'alg')
      return 'unknown signature suite' if !alg.equal?(UNDEF) && (!alg.is_a?(String) || !AtlasPca::REGISTERED_SUITES.include?(alg))
      return 'an ed25519 artifact must not carry pq_pk / pq_sig' if (alg.equal?(UNDEF) || alg == 'ed25519') && (!g(a, 'pq_pk').equal?(UNDEF) || !g(a, 'pq_sig').equal?(UNDEF))

      nil
    end

    def message(body) = INTENT_SIG_DOMAIN.b + AtlasPca.strict_bytes(body)

    # Sign a statement as its principal (an Ed25519 seed); `principal` defaults to the key of the seed.
    def sign_intent(s, principal_secret, suite = nil)
      raise ArgumentError, 'signIntentStatement: only Ed25519 signing is supported natively' if !suite.nil? && ![nil, 'ed25519'].include?(suite['alg'])

      key = KeyPair.new(principal_secret)
      principal = key.public
      raise ArgumentError, 'signIntentStatement: principal key mismatch' if s.key?('principal') && s['principal'] != principal

      body = statement_body(s.merge('principal' => principal))
      bad = statement_shape_error(body)
      raise ArgumentError, "signIntentStatement: #{bad}" if bad

      body.merge('sig' => AtlasPca.b64e(key.sign(message(body))))
    end

    # Verify a signed statement (shape, signer, suite signature; a PQ key must be pinned via opts['pqPins']). Never raises.
    def verify_intent(s, opts = nil)
      opts ||= {}
      bad = statement_shape_error(s)
      return { 'ok' => false, 'reason' => bad } if bad
      return { 'ok' => false, 'reason' => 'principal mismatch' } if !opts['expectedSigner'].nil? && s['principal'] != opts['expectedSigner']

      se = suite_fields_error(s)
      return { 'ok' => false, 'reason' => se } if se

      msg = message(IntentV2.bind_suite_fields(statement_body(s), g(s, 'alg'), g(s, 'pq_pk')))
      pins = opts['pqPins'].is_a?(Hash) ? opts['pqPins'] : nil
      return { 'ok' => false, 'reason' => 'bad signature' } unless IntentV2.verify_pinned_suite(g(s, 'alg'), s['principal'], g(s, 'pq_pk'), msg, g(s, 'sig'), g(s, 'pq_sig'), pins)

      { 'ok' => true }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "malformed intent statement: #{e.message}" }
    end
  end
end
