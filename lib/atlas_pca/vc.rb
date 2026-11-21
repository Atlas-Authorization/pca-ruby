# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'digest'
require 'base64'
require_relative 'jose'
require_relative 'whatwg_url'
require_relative 'oidc'
require_relative 'sdjwt'

# Verifiable-credential bridges: did:key (Ed25519, base58btc multibase), an AgentPassport as a W3C VC 2.0 SD-JWT (the four
# measurement digests selectively disclosable) and RFC 9421 HTTP Message Signatures with the Web Bot Auth profile. Every
# verifier fails closed. Keys are OpenSSL Ed25519 keys (a 32-byte seed is accepted wherever a private key signs). Options
# are Hashes with snake_case names; `now` (epoch ms) pins the clock where the reference reads Date.now().
module AtlasPca
  module Vc
    # #code is the reference runtime's code where it has one (ERR_INVALID_URL, ERR_OSSL_ASN1_NOT_ENOUGH_DATA).
    class Error < StandardError
      attr_reader :code

      def initialize(message = nil, code = nil)
        super(message)
        @code = code
      end
    end

    Js = AtlasPca::Js
    UNSET = Jose::UNSET
    B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    MAX_BASE58_INPUT = 1024
    VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2'
    AGENT_PASSPORT_CONTEXT = 'https://atlasauth.net/credentials/agent-passport/v1'
    AGENT_PASSPORT_VC_TYPE = 'AgentPassportCredential'
    SD_DIGEST_FIELDS = %w[weights_digest system_prompt_digest tool_manifest_digest runtime_measurement].freeze
    SIG_LABEL = 'sig1'

    V = 'https://atlasauth.net/credentials/agent-passport/v1#'
    XSD = 'http://www.w3.org/2001/XMLSchema#'
    term = ->(id, type) { { '@id' => "#{V}#{id}", '@type' => "#{XSD}#{type}" } }
    AGENT_PASSPORT_CONTEXT_DOC = {
      '@context' => {
        '@protected' => true,
        'AgentPassportCredential' => {
          '@id' => "#{V}AgentPassportCredential",
          '@context' => {
            '@protected' => true, 'id' => '@id', 'type' => '@type',
            'passport_id' => term.call('passportId', 'string'), 'model_id' => term.call('modelId', 'string'),
            'operator' => term.call('operator', 'string'), 'hardware_rooted' => term.call('hardwareRooted', 'boolean'),
            'weights_measured' => term.call('weightsMeasured', 'boolean'), 'issued_at' => term.call('issuedAt', 'integer'),
            'weights_digest' => term.call('weightsDigest', 'string'), 'system_prompt_digest' => term.call('systemPromptDigest', 'string'),
            'tool_manifest_digest' => term.call('toolManifestDigest', 'string'), 'runtime_measurement' => term.call('runtimeMeasurement', 'string'),
            '_sd' => { '@id' => "#{V}selectiveDisclosureDigest", '@container' => '@set' }
          }
        }
      }
    }.freeze

    module_function

    # Sorted-key JSON (JSON.stringify for scalars) of the context document.
    def canonical(v)
      case v
      when Hash then "{#{v.keys.sort.map { |k| "#{Js.json(k)}:#{canonical(v[k])}" }.join(',')}}"
      when Array then "[#{v.map { |x| canonical(x) }.join(',')}]"
      else Js.json(v)
      end
    end

    AGENT_PASSPORT_CONTEXT_DIGEST = Digest::SHA256.hexdigest(canonical(AGENT_PASSPORT_CONTEXT_DOC))

    def resolve_agent_passport_context(iri) = iri == AGENT_PASSPORT_CONTEXT ? AGENT_PASSPORT_CONTEXT_DOC : nil

    def b64u(bin) = Jose.b64u(bin)
    def sha256_ascii_b64u(s) = SdJwt.sha256_ascii_b64u(s)
    def obj?(v) = v.is_a?(Hash)
    def member(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNSET

    def as_string(v, label)
      raise Error, "pca-vc: expected string for #{label}" unless v.is_a?(String)

      v
    end

    def as_number(v, label)
      raise Error, "pca-vc: expected number for #{label}" unless Js.num?(v)

      v
    end

    def as_boolean(v, label)
      raise Error, "pca-vc: expected boolean for #{label}" unless [true, false].include?(v)

      v
    end

    def now_ms(o) = o.is_a?(Hash) && !o['now'].nil? ? o['now'] : (Time.now.to_f * 1000).floor

    # ---- base58btc / did:key ----

    def base58btc_encode(bytes)
      b = bytes.b.bytes
      zeros = b.take_while(&:zero?).length
      n = b.drop(zeros).inject(0) { |acc, x| (acc << 8) | x }
      out = +''
      while n.positive?
        n, r = n.divmod(58)
        out << B58[r]
      end
      ('1' * zeros) + out.reverse
    end

    def base58btc_decode(str)
      raise TypeError, 'base58btc input must be a string' unless str.is_a?(String)
      raise Error, 'pca-vc: base58btc input too long' if str.length > MAX_BASE58_INPUT

      chars = str.chars
      zeros = chars.take_while { |c| c == '1' }.length
      n = 0
      chars.drop(zeros).each do |c|
        d = B58.index(c)
        raise Error, 'pca-vc: invalid base58btc character' if d.nil?

        n = (n * 58) + d
      end
      body = +''.b
      while n.positive?
        body << (n & 0xff).chr
        n >>= 8
      end
      (("\x00".b * zeros) + body.reverse).b
    end

    def did_key_from_ed25519(public_key)
      raise Error, 'pca-vc: Ed25519 public key must be 32 bytes' unless public_key.is_a?(String) && public_key.bytesize == 32

      "did:key:z#{base58btc_encode("\xed\x01".b + public_key.b)}"
    end

    def ed25519_from_did_key(did)
      prefix = 'did:key:z'
      raise TypeError, 'did must be a string' unless did.is_a?(String)
      raise Error, 'pca-vc: not a did:key:z… identifier' unless did.start_with?(prefix)
      # exactly 48 base58 chars
      raise Error, 'pca-vc: did:key is not an Ed25519 (0xed01) key' if did.length > prefix.length + 64

      mc = base58btc_decode(did[prefix.length..])
      raise Error, 'pca-vc: did:key is not an Ed25519 (0xed01) key' unless mc.bytesize == 34 && mc.byteslice(0, 2) == "\xed\x01".b

      mc.byteslice(2, 32)
    end

    # ---- AgentPassport <-> SD-JWT VC ----

    def signing_key(k)
      return k unless k.is_a?(String)

      OpenSSL::PKey.new_raw_private_key('ED25519', k.b)
    rescue OpenSSL::PKey::PKeyError # a seed that is not 32 bytes
      raise Error.new('error:0680008E:asn1 encoding routines::not enough data', 'ERR_OSSL_ASN1_NOT_ENOUGH_DATA')
    end

    # JS `now + ttlSec` handed to setExpirationTime: a number is the exp, a string a time-span text.
    def exp_of(now, ttl)
      case ttl
      when nil, false then now
      when true then now + 1
      when Integer, Float then now + ttl
      when String then now + Jose.secs("#{now}#{ttl}")
      else raise TypeError, 'Invalid ttlSec'
      end
    end

    # Issue an AgentPassport as an SD-JWT VC: <JWT>~<Disclosure>~...~ . args: issuer_key, issuer_did, subject_did, ttl_sec, now.
    def passport_to_vc(passport, args)
      raise TypeError, 'passport must be an object' if passport.nil?

      disclosures = []
      sd = []
      SD_DIGEST_FIELDS.each do |field|
        value = member(passport, field)
        next if value.equal?(UNSET)

        disclosure = b64u(Js.json([b64u(SecureRandom.random_bytes(16)), field, value]).b)
        disclosures << disclosure
        sd << sha256_ascii_b64u(disclosure)
      end
      cs = {}
      cs['id'] = args['subject_did'] if args.key?('subject_did')
      { 'passport_id' => 'id', 'model_id' => 'model_id', 'operator' => 'operator', 'hardware_rooted' => 'hardware_rooted',
        'issued_at' => 'issued_at', 'weights_measured' => 'weights_measured' }.each do |claim, field|
        v = member(passport, field)
        cs[claim] = v unless v.equal?(UNSET)
      end
      cs['_sd'] = sd unless sd.empty?
      vc = { '@context' => [VC_CONTEXT, AGENT_PASSPORT_CONTEXT], 'type' => ['VerifiableCredential', AGENT_PASSPORT_VC_TYPE],
             'credentialSubject' => cs }
      now = (now_ms(args).to_f / 1000).floor
      payload = { 'vc' => vc }
      payload['_sd_alg'] = 'sha-256' unless sd.empty?
      payload['iss'] = args['issuer_did'] if args.key?('issuer_did')
      payload['sub'] = args['subject_did'] if args.key?('subject_did')
      payload['iat'] = now
      payload['exp'] = exp_of(now, args['ttl_sec']) if args.key?('ttl_sec')
      jwt = Jose.sign_jwt(payload, { 'alg' => 'EdDSA', 'typ' => 'vc+sd-jwt' }, signing_key(args['issuer_key']))
      ([jwt] + disclosures).map { |p| "#{p}~" }.join
    end

    # Verify an AgentPassport SD-JWT VC: canonical spelling, EdDSA signature, exp / nbf, the VC envelope and every
    # disclosure. Returns {'passport', 'issuerDid', 'subjectDid'}; raises on any refusal. options: expected_issuer_did, now.
    def verify_passport_vc(vc, issuer_verify_key, options = {})
      raise TypeError, 'vc must be a string' unless vc.is_a?(String)

      parts = vc.split('~', -1)
      jwt = parts[0]
      raise Error, 'pca-vc: empty SD-JWT' if jwt.nil? || jwt.empty?

      disclosures = parts[1..].reject(&:empty?)
      Jose.assert_canonical_compact_jws(jwt)
      disclosures.each { |d| Jose.decode_canonical_base64url(d) }

      payload, header = Jose.jwt_verify(jwt, issuer_verify_key, algorithms: ['EdDSA'], now_ms: now_ms(options))
      raise Error, "pca-vc: header typ must be 'vc+sd-jwt'" unless header['typ'] == 'vc+sd-jwt'

      vcc = payload['vc']
      raise Error, 'pca-vc: missing vc claim' unless obj?(vcc)

      ctx = vcc['@context']
      raise Error, "pca-vc: @context must begin with #{VC_CONTEXT}" unless ctx.is_a?(Array) && ctx[0] == VC_CONTEXT
      unless ctx.length == 2 && ctx[1] == AGENT_PASSPORT_CONTEXT
        raise Error, "pca-vc: @context must be exactly [#{VC_CONTEXT}, #{AGENT_PASSPORT_CONTEXT}]"
      end

      types = vcc['type']
      unless types.is_a?(Array) && types.include?('VerifiableCredential') && types.include?(AGENT_PASSPORT_VC_TYPE)
        raise Error, "pca-vc: type must include VerifiableCredential and #{AGENT_PASSPORT_VC_TYPE}"
      end

      cs = vcc['credentialSubject']
      raise Error, 'pca-vc: missing credentialSubject' unless obj?(cs)
      raise Error, 'pca-vc: _sd_alg must be a top-level claim' if cs.key?('_sd_alg')
      raise Error, 'pca-vc: unsupported _sd_alg (require sha-256)' if payload.key?('_sd_alg') && payload['_sd_alg'] != 'sha-256'

      sd_list = cs['_sd'].is_a?(Array) ? cs['_sd'].grep(String) : []
      recovered = {}
      seen = {}
      disclosures.each do |disclosure|
        digest = sha256_ascii_b64u(disclosure)
        raise Error, 'pca-vc: disclosure does not match any _sd digest' unless sd_list.include?(digest)
        raise Error, 'pca-vc: duplicate disclosure' if seen.key?(digest)

        seen[digest] = true
        decoded = begin
          AtlasPca.parse_json_text(Jose.lenient_b64d(disclosure).force_encoding('UTF-8').scrub("�"))
        rescue StandardError
          raise Error, 'pca-vc: malformed disclosure'
        end
        raise Error, 'pca-vc: malformed disclosure' unless decoded.is_a?(Array) && decoded.length == 3

        name = as_string(decoded[1], 'disclosure name')
        raise Error, "pca-vc: unexpected disclosure claim '#{name}'" unless SD_DIGEST_FIELDS.include?(name)
        raise Error, "pca-vc: disclosure claim '#{name}' appears more than once" if recovered.key?(name)

        recovered[name] = as_string(decoded[2], 'disclosure value')
      end

      passport = { 'id' => as_string(cs['passport_id'], 'passport_id'), 'model_id' => as_string(cs['model_id'], 'model_id'),
                   'operator' => as_string(cs['operator'], 'operator'),
                   'hardware_rooted' => as_boolean(cs['hardware_rooted'], 'hardware_rooted'),
                   'issued_at' => as_number(cs['issued_at'], 'issued_at') }
      passport['weights_measured'] = as_boolean(cs['weights_measured'], 'weights_measured') if cs.key?('weights_measured')
      SD_DIGEST_FIELDS.each { |f| passport[f] = recovered[f] if recovered.key?(f) }

      issuer_did = as_string(payload['iss'], 'iss')
      subject_did = as_string(cs['id'], 'credentialSubject.id')
      raise Error, 'pca-vc: sub does not match credentialSubject.id' unless payload['sub'] == subject_did
      if options.is_a?(Hash) && options.key?('expected_issuer_did') && issuer_did != options['expected_issuer_did']
        raise Error, 'pca-vc: iss does not match expectedIssuerDid'
      end

      { 'passport' => passport, 'issuerDid' => issuer_did, 'subjectDid' => subject_did }
    end

    # ---- RFC 9421 HTTP Message Signatures (Web Bot Auth profile) ----

    def normalize_headers(headers)
      raise TypeError, 'Cannot convert undefined or null to object' if headers.nil?

      Js.js_keys(headers).each_with_object({}) { |k, out| out[k.downcase] = headers[k] }
    end

    def url_host(url)
      u = WhatwgUrl.parse(url)
      raise Error.new('Invalid URL', 'ERR_INVALID_URL') if u.nil?

      u['host']
    end

    def component_value(name, method, url, headers)
      return method.upcase if name == '@method'
      return url if name == '@target-uri'
      return url_host(url) if name == '@authority'
      raise Error, "pca-vc: covered header '#{name}' absent from request" unless headers.key?(name)

      v = headers[name]
      raise TypeError, 'covered header value must be a string' unless v.is_a?(String)

      # a lone surrogate (WTF-8) makes the text invalid UTF-8: trim the ASCII whitespace bytewise
      v.valid_encoding? ? Js.trim(v) : v.b.sub(/\A[\t\n\v\f\r ]+/n, '').sub(/[\t\n\v\f\r ]+\z/n, '').force_encoding('UTF-8')
    end

    def signature_base(components, sig_params, method, url, headers)
      (components.map { |c| %("#{c}": #{component_value(c, method, url, headers)}) } + [%("@signature-params": #{sig_params})]).join("\n")
    end

    # Sign a request: every given header (lower-cased) is covered, plus @method / @target-uri (and host, derived from the URL
    # when absent). args: method, url, headers, key (Ed25519 private key or 32-byte seed), keyid, created, signature_agent, now.
    # Returns {'signatureInput', 'signature', 'signatureAgent'?}.
    def sign_request_message(args)
      method = args['method']
      url = args['url']
      created = args['created'].nil? ? (now_ms(args).to_f / 1000).floor : args['created']
      headers = normalize_headers(args['headers'])
      headers['host'] = url_host(url) unless headers.key?('host')
      agent = args.key?('signature_agent') ? %("#{Js.string(args['signature_agent'])}") : nil
      headers['signature-agent'] = agent if agent

      components = ['@method', '@target-uri', *headers.keys.sort]
      params = ";created=#{Js.string(created)};keyid=\"#{Js.string(args['keyid'])}\";alg=\"ed25519\""
      params += ';tag="web-bot-auth"' if agent
      sig_params = "(#{components.map { |c| %("#{c}") }.join(' ')})#{params}"
      base = signature_base(components, sig_params, method, url, headers)
      sig = signing_key(args['key']).sign(nil, Js.utf8(base))
      out = { 'signatureInput' => "#{SIG_LABEL}=#{sig_params}", 'signature' => "#{SIG_LABEL}=:#{Base64.strict_encode64(sig)}:" }
      out['signatureAgent'] = agent if agent
      out
    end

    def parse_components(sig_params)
      open = sig_params.index('(')
      close = sig_params.index(')')
      raise Error, 'pca-vc: malformed @signature-params' unless open&.zero? && close

      inner = Js.trim(sig_params[(open + 1)...close])
      return [] if inner.empty?

      inner.split(/[#{Js::WS}]+/o).map do |tok|
        m = /\A"(.*)"\z/.match(tok)
        raise Error, 'pca-vc: malformed component identifier' if m.nil?

        m[1]
      end
    end

    # Node's lenient base64: both alphabets, characters outside them skipped, decoding stops at the first '='.
    def node_b64d(s)
      t = s.tr('-_', '+/').split('=', 2)[0].to_s.delete('^A-Za-z0-9+/')
      t = t[0, t.length - 1] if t.length % 4 == 1
      (t + ('=' * (-t.length % 4))).unpack1('m0')
    end

    def to_num(v) = v.nil? ? 0 : Oidc.to_num(v)

    # Verify a request signature (true / false, never raises). args: method, url, headers, signature_input, signature,
    # signature_agent, required_components, max_age_sec, now_sec.
    def verify_request_signature(args, verify_key)
      sig_input = args['signature_input']
      return false unless sig_input.is_a?(String)

      eq = sig_input.index('=')
      return false if eq.nil?

      sig_params = sig_input[(eq + 1)..]
      components = parse_components(sig_params)
      req = args['required_components']
      (req.nil? ? [] : SdJwt.js_set(req)).each { |need| return false unless components.include?(need) }
      alg = /;alg="([^"]*)"/.match(sig_params)
      return false if alg && alg[1] != 'ed25519'

      if args.key?('max_age_sec')
        created = /;created=(\d+)/.match(sig_params)
        return false if created.nil?

        now = args['now_sec'].nil? ? Time.now.to_i : args['now_sec']
        c = AtlasPca.js_string_to_number(created[1])
        max_age = to_num(args['max_age_sec'])
        now_n = to_num(now)
        return false unless now_n.to_f.finite? && c.to_f.finite? && now_n - c <= max_age && c - now_n <= 5
      end

      headers = normalize_headers(args['headers'])
      headers['host'] = url_host(args['url']) unless headers.key?('host')
      if components.include?('signature-agent') && !headers.key?('signature-agent')
        return false unless args.key?('signature_agent')

        headers['signature-agent'] = args['signature_agent']
      end
      base = signature_base(components, sig_params, args['method'], args['url'], headers)

      sig = args['signature']
      return false unless sig.is_a?(String)

      se = sig.index('=')
      return false if se.nil?

      m = /\A:(.*):\z/.match(Js.trim(sig[(se + 1)..]))
      return false if m.nil?

      verify_key.verify(nil, node_b64d(m[1]), Js.utf8(base)) == true
    rescue StandardError
      false
    end
  end
end
