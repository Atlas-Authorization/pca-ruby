# frozen_string_literal: true

require 'base64'
require 'digest'
require 'openssl'
require 'securerandom'
require_relative 'attest_eat_common'
require_relative 'jose'

# Per-session attestation freshness and channel binding for PCA, matching the TypeScript reference (@atlasauth/pca-attest-eat).
#
# Emits attestation evidence as an Entity Attestation Token (RFC 9711, a compact JWS with the eat+jwt typ), binds it to a live
# channel and a fresh nonce (IETF SEAT / RA-TLS), and appraises it with the RATS (RFC 9334) split of evidence, reference values
# and endorsements into a trust tier. The AMD SEV-SNP hardware root is delegated to AtlasPca::Attest::Amd; this layer adds
# freshness, channel binding, EAT emission and appraisal, and the AMD root stays a classical ECDSA/RSA chain (labelled, never
# upgraded).
#
# Options and results are String-keyed Hashes with the reference's member names (maxAgeMs, expectedNonce, reasons ...), so a claim
# set or verdict is JSON-identical to the reference. Keys: EdDSA signs with a 32-byte Ed25519 seed and verifies with the 32 raw
# public-key bytes (binary Strings); ES256 uses an OpenSSL::PKey::EC (P-256) key. The post-quantum co-signature lives in
# attest_eat_pqcosign and admission / artifact provenance in attest_eat_admission.
module AtlasPca
  module AttestEat
    EAT_TYP = 'eat+jwt'
    DEFAULT_EAT_ALG = 'EdDSA'
    SUPPORTED_ALGS = %w[EdDSA ES256].freeze
    DEFAULT_MAX_AGE_MS = 5 * 60_000
    CHANNEL_BINDING_DOMAIN = 'atlas-pca/eat-channel/v1'
    AMD_SEV_SNP_SIGNED_REGION_END = 0x2A0
    AMD_SEV_SNP_HARDWARE_ROOT_LABEL = "amd-sev-snp/ecdsa-p384 (VCEK\u2192ASK\u2192ARK; classical hardware root, not post-quantum)"
    KNOWN_AMD_ARK_SPKI_SHA384 = Attest::Amd::ARK_SPKI_SHA384
    AMD_MILAN_ARK_SPKI_SHA384 = KNOWN_AMD_ARK_SPKI_SHA384['milan']
    KNOWN_REPORT_VERSIONS = [2, 3, 5].freeze
    MAX_EAT_BYTES = 1 << 20
    DBGSTAT_VALUES = %w[enabled disabled disabled-since-boot disabled-permanently disabled-fully-and-permanently].freeze
    TRUSTWORTHY_TIERS = %w[affirming-hw-rooted affirming warning].freeze

    module_function

    # RFC 7515 4.1.9: a typ without a slash is the application/ form.
    def normalize_typ(typ)
      t = typ.downcase
      t.include?('/') ? t : "application/#{t}"
    end

    def supported_alg?(v) = v.is_a?(String) && SUPPORTED_ALGS.include?(v)

    # ------------------------------------------------------------------------------------------------ keys + JWS

    # A fresh signing key pair: EdDSA -> {'publicKey' => 32 bytes, 'privateKey' => 32-byte seed}; ES256 -> OpenSSL P-256 keys.
    def generate_eat_key_pair(alg = DEFAULT_EAT_ALG)
      case alg
      when 'EdDSA'
        seed = SecureRandom.random_bytes(32)
        { 'publicKey' => OpenSSL::PKey.new_raw_private_key('ED25519', seed).raw_public_key, 'privateKey' => seed }
      when 'ES256'
        priv = OpenSSL::PKey::EC.generate('prime256v1')
        { 'publicKey' => OpenSSL::PKey.read(priv.public_to_der), 'privateKey' => priv }
      else raise ArgumentError, "generateEatKeyPair: unsupported alg '#{js_string(alg)}'"
      end
    end

    # A verify key from a JWK: OKP / Ed25519 -> the 32 raw public-key bytes, EC / P-256 -> an OpenSSL public key.
    def verify_key_from_jwk(jwk)
      kty = g(jwk, 'kty')
      crv = g(jwk, 'crv')
      if kty == 'OKP' && crv == 'Ed25519'
        x = b64d_strict(g(jwk, 'x'), 32)
        raise ArgumentError, 'verifyKeyFromJwk: bad Ed25519 public key' if x.nil?

        return x
      end
      if kty == 'EC' && crv == 'P-256'
        x = b64d_strict(g(jwk, 'x'), 32)
        y = b64d_strict(g(jwk, 'y'), 32)
        raise ArgumentError, 'verifyKeyFromJwk: bad P-256 public key' if x.nil? || y.nil?

        return Attest::Common.ec_key_from_point('P-256', "\x04".b + x + y)
      end
      raise ArgumentError, 'verifyKeyFromJwk: unsupported key (OKP Ed25519 and EC P-256 only)'
    end

    def b64d_strict(s, len = nil) = s.is_a?(String) ? AtlasPca.b64d(s, len) : nil

    def sign_jws(alg, key, signing_input)
      data = u8(signing_input)
      if alg == 'EdDSA'
        raise TypeError, 'EdDSA signing needs a 32-byte Ed25519 seed' unless bytes?(key) && key.bytesize == 32

        return AtlasPca.b64e(OpenSSL::PKey.new_raw_private_key('ED25519', key).sign(nil, data))
      end
      # ES256: ECDSA P-256 over SHA-256, JWS wants raw r || s
      unless key.is_a?(OpenSSL::PKey::EC) && key.private? && key.group.curve_name == 'prime256v1'
        raise TypeError, 'an ES256 token is signed with a P-256 key'
      end

      r, s = OpenSSL::ASN1.decode(key.sign(OpenSSL::Digest.new('SHA256'), data)).value.map { |i| i.value.to_i }
      AtlasPca.b64e([r.to_s(16).rjust(64, '0'), s.to_s(16).rjust(64, '0')].pack('H*H*'))
    end

    def verify_jws(alg, key, signing_input, sig_b64u)
      data = u8(signing_input)
      sig = b64d_strict(sig_b64u) || ''.b
      if alg == 'EdDSA'
        raise TypeError, 'EdDSA verification needs the 32 raw Ed25519 public-key bytes' unless bytes?(key)

        return AtlasPca::Ed25519Strict.verify(key, data, sig)
      end
      raise TypeError, 'an ES256 token verifies under an EC key' unless key.is_a?(OpenSSL::PKey::EC)

      Attest::Common.ecdsa_verify_raw(key, sig, data, 'sha256')
    end

    # ------------------------------------------------------------------------------------------------ nonce

    # A fresh single-use challenge: b64u(random) + "." + base36(now). `bytes` is the random length (min 16, default 32).
    # shortcut: a non-integral `now` is refused (the reference prints base-36 fractions), the clock is always integral.
    def issue_nonce(opts = nil)
      opts ||= {}
      now = opts['now']
      now = finite?(now) ? now : now_ms
      if now.is_a?(Float)
        raise ArgumentError, 'issueNonce: now must be an integral millisecond count' unless now == now.floor

        now = now.to_i
      end
      n = opts['bytes']
      n = 32 if n.nil?
      raise ArgumentError, 'issueNonce: bytes must be a finite number' unless finite?(n)

      n = [16, n.floor].max
      { 'value' => "#{AtlasPca.b64e(SecureRandom.random_bytes(n))}.#{now.to_s(36)}", 'issuedAt' => now }
    end

    # ------------------------------------------------------------------------------------------------ evidence projection

    # Project a parsed SEV-SNP report (Attest::Amd.parse_sev_snp_report) into the JSON-safe evidence an EAT carries.
    def evidence_from_report(report)
      { 'version' => report['version'], 'measurement' => Attest::Common.to_hex(report['measurement']),
        'reported_tcb' => report['reported_tcb'].to_s, 'guest_svn' => report['guest_svn'],
        'chip_id' => Attest::Common.to_hex(report['chip_id']), 'debug' => report['policy'].anybits?(Attest::Amd::POLICY_DEBUG_BIT) }
    end

    # The measured identity of a report: runtime_measurement = hex(MEASUREMENT), operator = hex(CHIP_ID); no weights field.
    def measured_from_report(report)
      { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false,
        'runtime_measurement' => Attest::Common.to_hex(report['measurement']), 'operator' => Attest::Common.to_hex(report['chip_id']) }
    end

    # ------------------------------------------------------------------------------------------------ tolerant parse

    OFF_VERSION = 0x000
    OFF_GUEST_SVN = 0x004
    OFF_POLICY = 0x008
    OFF_MEASUREMENT = 0x090
    OFF_REPORTED_TCB = 0x180
    OFF_CHIP_ID = 0x1A0
    FULL_REPORT_MIN_LEN = 0x2E8 + 72

    def slice(b, off, n) = off + n > b.bytesize ? nil : b.byteslice(off, n)
    def u32(b, off) = (s = slice(b, off, 4)) && s.unpack1('V')
    def u64(b, off) = (s = slice(b, off, 8)) && s.unpack1('Q<')

    # Parse an SEV-SNP report across format versions, degrading to the version-stable header instead of raising. A known version
    # with a complete buffer gets the full parse (report + evidence, degraded false).
    def parse_report_tolerant(raw)
      return { 'ok' => false, 'version' => 0, 'known' => false, 'degraded' => true, 'notes' => ['input is not a Uint8Array'] } unless bytes?(raw)

      b = raw
      notes = []
      version = u32(b, OFF_VERSION)
      if version.nil?
        return { 'ok' => false, 'version' => 0, 'known' => false, 'degraded' => true, 'notes' => ['buffer too short to read the report version'] }
      end

      known = KNOWN_REPORT_VERSIONS.include?(version)
      if known && b.bytesize >= FULL_REPORT_MIN_LEN
        begin
          report = Attest::Amd.parse_sev_snp_report(b)
          return { 'ok' => true, 'version' => report['version'], 'known' => true, 'degraded' => false, 'notes' => notes, 'report' => report,
                   'evidence' => evidence_from_report(report) }
        rescue StandardError => e # degrade, as the reference
          notes << "full parse failed, falling back to the stable header: #{msg_of(e)}"
        end
      elsif !known
        notes << "unknown report version #{version} \u2014 parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, " \
                 'may relocate version-specific fields)'
      else
        notes << "buffer length #{b.bytesize} < full report #{FULL_REPORT_MIN_LEN} \u2014 degraded header-only parse"
      end

      measurement = slice(b, OFF_MEASUREMENT, 48)
      if measurement.nil?
        return { 'ok' => false, 'version' => version, 'known' => known, 'degraded' => true,
                 'notes' => notes + ['buffer too short to read the launch measurement'] }
      end

      evidence = { 'version' => version, 'measurement' => Attest::Common.to_hex(measurement), 'degraded' => true }
      guest_svn = u32(b, OFF_GUEST_SVN)
      evidence['guest_svn'] = guest_svn unless guest_svn.nil?
      policy = u64(b, OFF_POLICY)
      evidence['debug'] = policy.anybits?(Attest::Amd::POLICY_DEBUG_BIT) unless policy.nil?
      tcb = u64(b, OFF_REPORTED_TCB)
      evidence['reported_tcb'] = tcb.to_s unless tcb.nil?
      chip = slice(b, OFF_CHIP_ID, 64)
      evidence['chip_id'] = Attest::Common.to_hex(chip) unless chip.nil?
      { 'ok' => true, 'version' => version, 'known' => known, 'degraded' => true, 'notes' => notes, 'evidence' => evidence }
    end

    # ------------------------------------------------------------------------------------------------ channel binding

    # cnf.tls_exporter = b64u(sha256(DOMAIN || channelId)) (RA-TLS), plus jkt when a thumbprint is given.
    def derive_channel_cnf(channel_id, holder_key_thumbprint = nil)
      raise ArgumentError, 'deriveChannelCnf: channelId is required' unless channel_id.is_a?(String) && !channel_id.empty?

      cnf = { 'tls_exporter' => AtlasPca.b64e(Digest::SHA256.digest(u8(CHANNEL_BINDING_DOMAIN) + u8(channel_id))) }
      cnf['jkt'] = holder_key_thumbprint if holder_key_thumbprint.is_a?(String) && !holder_key_thumbprint.empty?
      cnf
    end

    # Bind evidence to a TLS channel id and a per-session freshness nonce (the inputs of build_eat).
    def bind_channel(evidence, channel_id, nonce)
      raise ArgumentError, 'bindChannel: a per-session nonce is required for freshness' unless nonce.is_a?(String) && !nonce.empty?

      { 'evidence' => evidence, 'nonce' => nonce, 'cnf' => derive_channel_cnf(channel_id) }
    end

    # ------------------------------------------------------------------------------------------------ build / verify

    def resolve_cnf(args)
      out = {}
      out['tls_exporter'] = derive_channel_cnf(args['channelId'])['tls_exporter'] if has?(args, 'channelId')
      if has?(args, 'channelBinding')
        cb = args['channelBinding']
        te = g(cb, 'tls_exporter')
        jkt = g(cb, 'jkt')
        out['tls_exporter'] = te if te.is_a?(String)
        out['jkt'] = jkt if jkt.is_a?(String)
      end
      out
    end

    # A signed EAT (compact JWS, typ eat+jwt) over the evidence: iss, iat, eat_nonce, cnf and the optional measured identity /
    # sevsnp evidence / measurements / ueid / sueid / dbgstat / oemid claims. It needs a nonce AND a channel binding: an unbound
    # EAT would re-open the replay gap. `key` is an Ed25519 seed (EdDSA) or a P-256 key (ES256).
    def build_eat(args)
      issuer = g(args, 'issuer')
      nonce = g(args, 'nonce')
      raise ArgumentError, 'buildEAT: issuer is required' unless issuer.is_a?(String) && !issuer.empty?
      raise ArgumentError, 'buildEAT: nonce (eat_nonce) is required for freshness' unless nonce.is_a?(String) && !nonce.empty?

      alg = args['alg']
      alg = DEFAULT_EAT_ALG if alg.nil?
      raise ArgumentError, "buildEAT: unsupported alg '#{js_string(alg)}'" unless supported_alg?(alg)

      cnf = resolve_cnf(args)
      unless cnf.key?('tls_exporter') || cnf.key?('jkt')
        raise ArgumentError, 'buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) ' \
                             "is required (RA-TLS) \u2014 refusing to emit unbound evidence"
      end

      now = args['now']
      iat_ms = finite?(now) ? now : now_ms
      claims = { 'iss' => issuer, 'iat' => iat_ms.is_a?(Float) ? (iat_ms / 1000).floor : iat_ms.div(1000), 'eat_nonce' => nonce, 'cnf' => cnf }
      %w[ueid sueid oemid dbgstat measurements measured sevsnp].each { |k| claims[k] = args[k] if args.key?(k) }
      signing_input = "#{AtlasPca.b64e(u8(Js.json({ 'alg' => alg, 'typ' => EAT_TYP })))}.#{AtlasPca.b64e(u8(Js.json(claims)))}"
      "#{signing_input}.#{sign_jws(alg, args['key'], signing_input)}"
    end

    def parse_cnf(v)
      return nil unless record?(v)

      out = {}
      out['tls_exporter'] = v['tls_exporter'] if v['tls_exporter'].is_a?(String)
      out['jkt'] = v['jkt'] if v['jkt'].is_a?(String)
      out.empty? ? nil : out
    end

    def parse_measurements(v)
      return nil unless v.is_a?(Array)

      out = v.select { |e| record?(e) && e['type'].is_a?(String) && e['value'].is_a?(String) }.map { |e| { 'type' => e['type'], 'value' => e['value'] } }
      out.empty? ? nil : out
    end

    def parse_tcb_version(v)
      return v if finite?(v) || v.is_a?(String)
      return %w[bootloader tee snp microcode].select { |k| number?(v[k]) }.to_h { |k| [k, v[k]] } if record?(v)

      U
    end

    def parse_measured(v)
      return nil unless record?(v)
      return nil unless %w[model_id weights_digest runtime_measurement operator].all? { |k| v[k].is_a?(String) }

      out = { 'model_id' => v['model_id'], 'weights_digest' => v['weights_digest'], 'runtime_measurement' => v['runtime_measurement'],
              'operator' => v['operator'] }
      out['weights_measured'] = v['weights_measured'] if [true, false].include?(v['weights_measured'])
      out['system_prompt_digest'] = v['system_prompt_digest'] if v['system_prompt_digest'].is_a?(String)
      out['tool_manifest_digest'] = v['tool_manifest_digest'] if v['tool_manifest_digest'].is_a?(String)
      out
    end

    def parse_sevsnp(v)
      return nil unless record?(v) && number?(v['version']) && v['measurement'].is_a?(String)

      out = { 'version' => v['version'], 'measurement' => v['measurement'] }
      tcb = parse_tcb_version(v['reported_tcb'])
      out['reported_tcb'] = tcb unless tcb.equal?(U)
      out['guest_svn'] = v['guest_svn'] if number?(v['guest_svn'])
      out['chip_id'] = v['chip_id'] if v['chip_id'].is_a?(String)
      out['debug'] = v['debug'] if [true, false].include?(v['debug'])
      out['degraded'] = v['degraded'] if [true, false].include?(v['degraded'])
      out
    end

    # Verify an EAT's signature and typ / iss and parse it into claims. Raises on an invalid signature, wrong key, failed iss / typ
    # check, unsupported alg, or a missing iss / iat. A claim of the wrong type is dropped, so a later check fails closed. This
    # proves AUTHENTICITY only: freshness, channel binding and appraisal are separate steps.
    def verify_eat(eat, verify_key, opts = nil)
      opts = {} if opts.nil?
      raise ArgumentError, 'EAT invalid: token is not a string' unless eat.is_a?(String)

      begin
        parsed = Jose.assert_canonical_compact_jws(eat, max_bytes: MAX_EAT_BYTES) # one accepted spelling per EAT
      rescue StandardError => e
        raise ArgumentError, "EAT invalid: #{msg_of(e)}"
      end
      h, p, s = parsed['segments']
      header = parsed['header']
      payload = parsed['payload']
      raise ArgumentError, 'EAT invalid: missing or unsupported `alg` header' unless supported_alg?(header['alg'])

      allowed = opts['algorithms']
      allowed = SUPPORTED_ALGS if allowed.nil?
      alg_ok = case allowed
               when String then allowed.include?(header['alg'])
               when Array then includes?(allowed, header['alg'])
               else raise TypeError, 'allowed.includes is not a function'
               end
      raise ArgumentError, "EAT invalid: alg #{header['alg']} not in the allowed set" unless alg_ok

      unless opts['requireTyp'] == false
        want = opts['typ']
        want = EAT_TYP if want.nil?
        typ = header.fetch('typ', U)
        raise ArgumentError, "EAT invalid: typ #{js_string(typ)} is not #{js_string(want)}" if !typ.is_a?(String) || normalize_typ(typ) != normalize_typ(want)
      end
      raise ArgumentError, 'EAT invalid: signature does not verify' unless verify_jws(header['alg'], verify_key, "#{h}.#{p}", s)

      iss = payload['iss']
      iat = payload['iat']
      raise ArgumentError, 'EAT invalid: missing or non-string `iss`' unless iss.is_a?(String)
      raise ArgumentError, 'EAT invalid: missing or non-numeric `iat`' unless finite?(iat)

      if opts.key?('issuer')
        want_iss = opts['issuer']
        raise ArgumentError, "EAT invalid: iss #{iss} is not an accepted issuer" unless includes?(want_iss.is_a?(Array) ? want_iss : [want_iss], iss)
      end
      claims = { 'iss' => iss, 'iat' => iat }
      claims['eat_nonce'] = payload['eat_nonce'] if payload['eat_nonce'].is_a?(String)
      cnf = parse_cnf(payload['cnf'])
      claims['cnf'] = cnf unless cnf.nil?
      claims['ueid'] = payload['ueid'] if payload['ueid'].is_a?(String)
      claims['sueid'] = payload['sueid'] if payload['sueid'].is_a?(String)
      measurements = parse_measurements(payload['measurements'])
      claims['measurements'] = measurements unless measurements.nil?
      claims['dbgstat'] = payload['dbgstat'] if payload['dbgstat'].is_a?(String) && DBGSTAT_VALUES.include?(payload['dbgstat'])
      claims['oemid'] = payload['oemid'] if payload['oemid'].is_a?(String)
      measured = parse_measured(payload['measured'])
      claims['measured'] = measured unless measured.nil?
      sevsnp = parse_sevsnp(payload['sevsnp'])
      claims['sevsnp'] = sevsnp unless sevsnp.nil?
      claims
    end

    # ------------------------------------------------------------------------------------------------ freshness + channel

    # ANTI-REPLAY FRESHNESS: the eat_nonce must equal the server-issued challenge and iat must lie in [now - maxAgeMs, now] (plus
    # clockSkewMs). Absent / mismatched nonce, future iat or a stale token fail closed. A present clockSkewMs that is not a finite
    # number (NaN, Infinity, a string, null) is refused: it would disable the age window.
    def verify_freshness(eat, opts)
      now = g(opts, 'now')
      now = finite?(now) ? now : now_ms
      skew = g(opts, 'clockSkewMs')
      return { 'ok' => false, 'reason' => 'invalid clockSkewMs (must be a finite number)' } if !skew.equal?(U) && !finite?(skew)

      skew = skew.equal?(U) ? 0 : [0, skew].max
      expected = g(opts, 'expectedNonce')
      return { 'ok' => false, 'reason' => 'no expected (server-issued) nonce supplied (fail closed)' } unless expected.is_a?(String) && !expected.empty?

      nonce = g(eat, 'eat_nonce')
      unless nonce.is_a?(String) && !nonce.empty?
        return { 'ok' => false, 'reason' => "EAT carries no eat_nonce \u2014 cannot establish freshness (replayable)" }
      end
      unless ct_eq(nonce, expected)
        return { 'ok' => false, 'reason' => 'eat_nonce does not match the server-issued challenge (replayed or relayed evidence)' }
      end

      iat = g(eat, 'iat')
      return { 'ok' => false, 'reason' => 'EAT has no valid iat (cannot establish age)' } unless finite?(iat)

      max_age = g(opts, 'maxAgeMs')
      return { 'ok' => false, 'reason' => 'invalid maxAgeMs' } if !finite?(max_age) || max_age <= 0

      iat_ms = iat * 1000
      return { 'ok' => false, 'reason' => 'EAT iat is in the future' } if iat_ms - skew > now
      unless now - iat_ms <= max_age + skew
        return { 'ok' => false, 'reason' => "EAT is stale (iat older than maxAgeMs) \u2014 expired/replayed attestation" }
      end

      { 'ok' => true }
    end

    # CHANNEL BINDING (RA-TLS): every field of the expected cnf (derived from channelId and / or an explicit expectedCnf) must be
    # present and equal in the token's cnf. No cnf, or one bound to another channel / key, fails closed.
    def verify_channel_binding(eat, opts)
      exp = {}
      channel_id = g(opts, 'channelId')
      exp['tls_exporter'] = derive_channel_cnf(channel_id)['tls_exporter'] if channel_id.is_a?(String) && !channel_id.empty?
      if has?(opts, 'expectedCnf')
        e = opts['expectedCnf']
        te = g(e, 'tls_exporter')
        jkt = g(e, 'jkt')
        exp['tls_exporter'] = te if te.is_a?(String)
        exp['jkt'] = jkt if jkt.is_a?(String)
      end
      return { 'ok' => false, 'reason' => 'no expected channel binding supplied (fail closed)' } if exp.empty?

      cnf = g(eat, 'cnf')
      c_te = truthy?(cnf) ? g(cnf, 'tls_exporter') : U
      c_jkt = truthy?(cnf) ? g(cnf, 'jkt') : U
      if c_te.equal?(U) && c_jkt.equal?(U)
        return { 'ok' => false, 'reason' => "EAT carries no channel/key binding (cnf) \u2014 evidence is not bound to a live channel (RA-TLS)" }
      end
      if exp.key?('tls_exporter') && (c_te.equal?(U) || !ct_eq(c_te, exp['tls_exporter']))
        return { 'ok' => false, 'reason' => 'TLS-exporter channel binding mismatch (evidence lifted to another channel?)' }
      end
      return { 'ok' => false, 'reason' => 'holder-key thumbprint (cnf.jkt) mismatch' } if exp.key?('jkt') && (c_jkt.equal?(U) || !ct_eq(c_jkt, exp['jkt']))

      { 'ok' => true }
    end

    # ------------------------------------------------------------------------------------------------ RATS appraisal

    def nonempty_list?(v) = v.is_a?(Array) && !v.empty?

    # A TCB version as a comparable integer, or nil for an unknown shape (fail closed). Only a number, a decimal string or a
    # component record is comparable: null, a boolean or an array is not.
    def pack_tcb(v)
      return (finite?(v) && v >= 0 ? v.floor : nil) if number?(v)
      return (t = Js.trim(v)).match?(/\A[0-9]+\z/) ? t.to_i : nil if v.is_a?(String)
      return nil unless record?(v)

      comp = lambda do |x|
        next 0 if x.equal?(U)
        next nil unless number?(x)

        if x.is_a?(Float)
          next nil if !x.finite? || x != x.floor || (x.zero? && (1.0 / x).negative?)

          x = x.to_i
        end
        x >= 0 && x <= 255 ? x : nil
      end
      parts = %w[bootloader tee snp microcode].map { |k| comp.call(g(v, k)) }
      return nil if parts.any?(&:nil?)

      bl, tee, snp, uc = parts
      bl | (tee << 8) | (snp << 48) | (uc << 56)
    end

    def lc(s)
      raise TypeError, 's.toLowerCase is not a function' unless s.is_a?(String)

      s.downcase
    end

    # `lst?.find(pred)`: undefined for an absent list, a TypeError for a value without find.
    def find(lst)
      return U if lst.equal?(U) || lst.nil?
      raise TypeError, 'eat.measurements?.find is not a function' unless lst.is_a?(Array)

      lst.each { |e| return e if yield(e) }
      U
    end

    def launch_measurement(eat)
      measured = g(eat, 'measured')
      sevsnp = g(eat, 'sevsnp')
      if truthy?(measured)
        rm = g(measured, 'runtime_measurement')
        return rm if rm.is_a?(String) && !rm.empty?
      end
      if truthy?(sevsnp)
        m = g(sevsnp, 'measurement')
        return m if m.is_a?(String)
      end
      hit = find(g(eat, 'measurements')) { |e| %w[launch measurement].include?(g(e, 'type')) }
      hit.equal?(U) ? U : g(hit, 'value')
    end

    def weights_measurement(eat)
      measured = g(eat, 'measured')
      if truthy?(measured)
        wd = g(measured, 'weights_digest')
        return wd if wd.is_a?(String) && !wd.empty?
      end
      hit = find(g(eat, 'measurements')) { |e| g(e, 'type') == 'weights' }
      hit.equal?(U) ? U : g(hit, 'value')
    end

    # true / false when the debug status is known, else nil (the caller fails closed). A dbgstat that is not one of the RFC 9711
    # values is unknown (the reference reads any value other than 'enabled' as disabled); a malformed claim never lifts a debug
    # requirement.
    def debug_disabled?(eat)
      dbg = g(eat, 'dbgstat')
      return DBGSTAT_VALUES.include?(dbg) && dbg.is_a?(String) ? dbg != 'enabled' : nil unless dbg.equal?(U)

      sevsnp = g(eat, 'sevsnp')
      return g(sevsnp, 'debug') == false if truthy?(sevsnp) && [true, false].include?(g(sevsnp, 'debug'))

      nil
    end

    # APPRAISE an EAT's evidence against RATS reference values and endorsements (RFC 9334), kept as separate inputs. Tiers:
    # affirming-hw-rooted > affirming > warning (acceptable); contraindicated (the measured state is actively bad) and rejected
    # (empty policy, or a required input absent / in an unknown format) fail closed. Endorsements gate WHO (mismatch -> rejected);
    # reference values gate WHAT (bad -> contraindicated, absent -> rejected). An omitted argument defaults to {}; an explicit nil
    # is dereferenced and raises, as in the reference.
    def appraise(evidence, reference_values = U, endorsements = U, extras = U)
      rv = reference_values.equal?(U) ? {} : reference_values
      en = endorsements.equal?(U) ? {} : endorsements
      reasons = []
      result = lambda do |tier, reason|
        { 'tier' => tier, 'trustworthy' => TRUSTWORTHY_TIERS.include?(tier), 'reasons' => reasons + [reason] }
      end

      en_issuers = g(en, 'issuers')
      en_oemids = g(en, 'oemids')
      en_operators = g(en, 'operators')
      has_endorsements = nonempty_list?(en_issuers) || nonempty_list?(en_oemids) || nonempty_list?(en_operators)
      rv_meas = g(rv, 'measurements')
      rv_models = g(rv, 'models')
      rv_weights = g(rv, 'weightsMeasurements')
      rv_min_tcb = g(rv, 'minTcb')
      rv_min_svn = g(rv, 'minGuestSvn')
      has_reference_values = nonempty_list?(rv_meas) || nonempty_list?(rv_models) || nonempty_list?(rv_weights) ||
                             g(rv, 'requireMeasuredWeights') == true || !rv_min_tcb.equal?(U) || number?(rv_min_svn) ||
                             g(rv, 'requireDebugDisabled') == true
      if !has_endorsements && !has_reference_values
        return { 'tier' => 'rejected', 'trustworthy' => false,
                 'reasons' => ['empty appraisal policy: no endorsements or reference values to appraise against (fail closed)'] }
      end

      iss = g(evidence, 'iss')
      # Endorsements (WHO) -> rejected on mismatch.
      if nonempty_list?(en_issuers)
        return result.call('rejected', "issuer #{js_string(iss)} is not an endorsed attester") unless includes?(en_issuers, iss)

        reasons << 'issuer endorsed'
      end
      if nonempty_list?(en_oemids)
        oemid = g(evidence, 'oemid')
        return result.call('rejected', 'oemid absent or not endorsed (fail closed)') if !oemid.is_a?(String) || !includes?(en_oemids, oemid)

        reasons << 'oemid endorsed'
      end
      if nonempty_list?(en_operators)
        measured = g(evidence, 'measured')
        op = measured.nil? || measured.equal?(U) ? U : g(measured, 'operator')
        if !op.is_a?(String) || op.empty? || !includes?(en_operators, op)
          return result.call('rejected', 'hardware operator absent or not endorsed (fail closed)')
        end

        reasons << 'operator endorsed'
      end

      # Reference values (WHAT): bad value -> contraindicated; absent / unknown required -> rejected.
      if nonempty_list?(rv_meas)
        m = launch_measurement(evidence)
        return result.call('rejected', 'no launch measurement in evidence to compare against reference values (fail closed)') if m.equal?(U)

        lowered = rv_meas.map { |x| lc(x) }
        return result.call('contraindicated', 'launch measurement not in reference values') unless lowered.include?(lc(m))

        reasons << 'launch measurement matches a reference value'
      end
      if nonempty_list?(rv_models)
        measured = g(evidence, 'measured')
        model = measured.nil? || measured.equal?(U) ? U : g(measured, 'model_id')
        return result.call('rejected', 'no model id in evidence (fail closed)') if !model.is_a?(String) || model.empty?
        return result.call('contraindicated', 'model id not in reference values (model swap?)') unless includes?(rv_models, model)

        reasons << 'model id matches a reference value'
      end
      if g(rv, 'requireMeasuredWeights') == true
        measured = g(evidence, 'measured')
        wm = measured.nil? || measured.equal?(U) ? U : g(measured, 'weights_measured')
        unless wm == true
          return result.call('contraindicated', 'weights digest is not hardware-measured (require_measured_weights: ' \
                                                'self-asserted or host-asserted weights rejected)')
        end

        reasons << 'weights digest is hardware-measured'
      end
      if nonempty_list?(rv_weights)
        w = weights_measurement(evidence)
        return result.call('rejected', 'no measured-weights digest in evidence (fail closed)') if w.equal?(U) || (w.is_a?(String) && w.empty?)

        lowered = rv_weights.map { |x| lc(x) }
        unless lowered.include?(lc(w))
          return result.call('contraindicated', 'weights measurement not in reference values (model swap / fine-tune?)')
        end

        reasons << 'weights measurement matches a reference value'
      end
      unless rv_min_tcb.equal?(U)
        minimum = pack_tcb(rv_min_tcb)
        return result.call('rejected', 'reference minTcb is not a comparable TCB version') if minimum.nil?

        sevsnp = g(evidence, 'sevsnp')
        raw_tcb = sevsnp.nil? || sevsnp.equal?(U) ? U : g(sevsnp, 'reported_tcb')
        got = raw_tcb.equal?(U) ? nil : pack_tcb(raw_tcb)
        if got.nil?
          return result.call('rejected', "evidence TCB version is absent or an unknown format \u2014 failing closed " \
                                         '(see 2025-10-27 GCP firmware drift)')
        end
        return result.call('contraindicated', 'reported TCB is below the reference minimum (downgrade / rollback)') if got < minimum

        reasons << 'TCB at or above reference minimum'
      end
      if number?(rv_min_svn)
        sevsnp = g(evidence, 'sevsnp')
        svn = sevsnp.nil? || sevsnp.equal?(U) ? U : g(sevsnp, 'guest_svn')
        return result.call('rejected', 'guest_svn absent (fail closed)') unless finite?(svn)
        if svn < rv_min_svn
          return result.call('contraindicated', "guest_svn #{Attest::Common.js_num_str(svn)} below reference minimum #{Attest::Common.js_num_str(rv_min_svn)}")
        end

        reasons << 'guest_svn at or above reference minimum'
      end
      if g(rv, 'requireDebugDisabled') == true
        disabled = debug_disabled?(evidence)
        return result.call('rejected', "debug status unknown \u2014 failing closed") if disabled.nil?
        return result.call('contraindicated', 'debug is enabled (host can inspect the guest \u2014 no confidentiality)') unless disabled

        reasons << 'debug disabled'
      end

      # All checks passed: degraded evidence -> warning; a verified AMD signature -> the hardware-rooted tier.
      sevsnp = g(evidence, 'sevsnp')
      if !sevsnp.nil? && !sevsnp.equal?(U) && g(sevsnp, 'degraded') == true
        return { 'tier' => 'warning', 'trustworthy' => true,
                 'reasons' => reasons + ["evidence came from a degraded (version-tolerant) parse \u2014 review"] }
      end

      ex = extras.equal?(U) ? {} : extras
      if g(ex, 'hardwareVerified') == true
        label = g(ex, 'hardwareRootLabel')
        label = AMD_SEV_SNP_HARDWARE_ROOT_LABEL if label.equal?(U) || label.nil?
        return { 'tier' => 'affirming-hw-rooted', 'trustworthy' => true,
                 'reasons' => reasons + ["AMD SEV-SNP report signature + VCEK\u2192ASK\u2192ARK chain verified \u2014 #{js_string(label)}"] }
      end
      { 'tier' => 'affirming', 'trustworthy' => true, 'reasons' => reasons }
    end

    # ------------------------------------------------------------------------------------------------ AMD delegation

    def cert_to_der(inp)
      return inp.b if bytes?(inp)
      raise TypeError, 'a certificate is DER bytes or a PEM string' unless inp.is_a?(String)

      blocks = Attest::Common.pem_blocks(inp)
      raise ArgumentError, "expected exactly one PEM certificate, found #{blocks.length}" unless blocks.length == 1

      Attest::Common.pem_to_der(blocks[0])
    end

    def der_to_pem(der)
      b64 = Base64.strict_encode64(der).gsub(/(.{64})/, "\\1\n")
      "-----BEGIN CERTIFICATE-----\n#{b64}\n-----END CERTIFICATE-----\n"
    end

    # Compose the AMD SEV-SNP hardware root of trust into one verdict by delegating to Attest::Amd.verify_genuine_sev_snp_report
    # (per-family ARK pin, exact ASK-then-ARK bundle, validity against the verifier clock nowMs, report signature, VCEK binding),
    # then project the verified report into EAT evidence and a measured identity. Fails closed on any failure and never raises.
    # Supply exactly one of family (milan | genoa | turin) or trustAnchorArkSpkiSha384; the root is never inferred from the evidence.
    def verify_amd_attestation(raw_report, opts)
      root = AMD_SEV_SNP_HARDWARE_ROOT_LABEL
      has_family = has?(opts, 'family')
      has_pin = has?(opts, 'trustAnchorArkSpkiSha384')
      if has_family == has_pin
        return { 'ok' => false, 'reason' => 'exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)',
                 'hardwareRoot' => root }
      end

      if has_family
        fam = opts['family']
        unless fam.is_a?(String) && KNOWN_AMD_ARK_SPKI_SHA384.key?(fam)
          return { 'ok' => false, 'reason' => "unknown AMD family #{js_string(fam)} (expected milan | genoa | turin)", 'hardwareRoot' => root }
        end

        pin = KNOWN_AMD_ARK_SPKI_SHA384[fam]
      else
        pin = opts['trustAnchorArkSpkiSha384']
      end
      begin
        vcek_der = cert_to_der(g(opts, 'vcek'))
        ask_ark_pem = der_to_pem(cert_to_der(g(opts, 'ask'))) + der_to_pem(cert_to_der(g(opts, 'ark')))
      rescue StandardError => e
        return { 'ok' => false, 'reason' => "certificate parse failed: #{msg_of(e)}", 'hardwareRoot' => root }
      end
      report = begin
        Attest::Amd.parse_sev_snp_report(raw_report)
      rescue StandardError # the verifier reports the parse failure with its own reason
        nil
      end
      expected = g(opts, 'expectedMeasurement')
      measurements = expected.is_a?(String) && !expected.empty? ? [expected] : []
      skew = g(opts, 'clockSkewMs')
      now_ms_opt = g(opts, 'nowMs')
      verdict = Attest::Amd.verify_genuine_sev_snp_report(raw_report, vcek_der, ask_ark_pem, pin, now_ms_opt.equal?(U) ? nil : now_ms_opt,
                                                          skew.equal?(U) ? nil : skew, nil,
                                                          { 'measurements' => measurements, 'allowDebug' => g(opts, 'allowDebug') == true })
      if verdict['ok'] != true || verdict['report'].nil?
        out = { 'ok' => false, 'reason' => truthy?(verdict['reason']) ? verdict['reason'] : 'AMD SEV-SNP verification failed', 'hardwareRoot' => root }
        out['report'] = report unless report.nil?
        return out
      end
      { 'ok' => true, 'hardwareRoot' => root, 'report' => verdict['report'], 'evidence' => evidence_from_report(verdict['report']),
        'measured' => measured_from_report(verdict['report']) }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "AMD attestation verification error (fail closed): #{msg_of(e)}", 'hardwareRoot' => AMD_SEV_SNP_HARDWARE_ROOT_LABEL }
    end

    # ------------------------------------------------------------------------------------------------ composition

    # The end-to-end check a resource server runs: verify the EAT's signature, then FRESHNESS (nonce + iat), CHANNEL BINDING (cnf
    # vs the live channel) and APPRAISAL against the RATS policy. The first failing gate stops the pipeline and names the reason.
    # With opts['amd'] the AMD report signature and chain are verified here (success lifts the tier to affirming-hw-rooted, failure
    # is contraindicated). Options: verifyKey, nonce, channelId | channelBinding, policy, now, maxAgeMs, clockSkewMs, issuer,
    # algorithms, typ, requireTyp, amd.
    def verify_fresh_attested_eat(eat, opts)
      reasons = []
      begin
        claims = verify_eat(eat, g(opts, 'verifyKey'), %w[issuer algorithms typ requireTyp].select { |k| opts.key?(k) }.to_h { |k| [k, opts[k]] })
      rescue StandardError => e
        return { 'ok' => false, 'reasons' => ["EAT signature/claims invalid: #{msg_of(e)}"] }
      end
      reasons << 'signature + typ/iss verified'

      now = g(opts, 'now')
      now = finite?(now) ? now : now_ms
      max_age = g(opts, 'maxAgeMs')
      fopts = { 'expectedNonce' => g(opts, 'nonce'), 'maxAgeMs' => max_age.equal?(U) || max_age.nil? ? DEFAULT_MAX_AGE_MS : max_age, 'now' => now }
      fopts['clockSkewMs'] = opts['clockSkewMs'] if has?(opts, 'clockSkewMs')
      fresh = verify_freshness(claims, fopts)
      return { 'ok' => false, 'reasons' => reasons + [truthy?(fresh['reason']) ? fresh['reason'] : 'not fresh'], 'claims' => claims } unless fresh['ok']

      reasons << 'fresh (nonce + iat within window)'

      copts = {}
      copts['channelId'] = opts['channelId'] if has?(opts, 'channelId')
      copts['expectedCnf'] = opts['channelBinding'] if has?(opts, 'channelBinding')
      chan = verify_channel_binding(claims, copts)
      return { 'ok' => false, 'reasons' => reasons + [truthy?(chan['reason']) ? chan['reason'] : 'channel binding failed'], 'claims' => claims } unless chan['ok']

      reasons << 'channel-bound (cnf matches live channel)'

      extras = {}
      if has?(opts, 'amd')
        amd = opts['amd']
        expected = g(amd, 'expectedMeasurement')
        expected = launch_measurement(claims) if expected.equal?(U) || expected.nil?
        aopts = { 'vcek' => g(amd, 'vcek'), 'ask' => g(amd, 'ask'), 'ark' => g(amd, 'ark'), 'nowMs' => now }
        %w[family trustAnchorArkSpkiSha384 clockSkewMs allowDebug].each { |k| aopts[k] = amd[k] if has?(amd, k) }
        aopts['expectedMeasurement'] = expected unless expected.equal?(U)
        hw = verify_amd_attestation(g(amd, 'rawReport'), aopts)
        unless hw['ok']
          return { 'ok' => false, 'tier' => 'contraindicated',
                   'reasons' => reasons + ["AMD hardware root verification failed: #{truthy?(hw['reason']) ? hw['reason'] : 'unknown'}"], 'claims' => claims }
        end

        reasons << "AMD SEV-SNP hardware root verified (#{hw['hardwareRoot']})"
        extras = { 'hardwareVerified' => true, 'hardwareRootLabel' => hw['hardwareRoot'] }
      end

      policy = g(opts, 'policy')
      rvs = g(policy, 'referenceValues')
      ens = g(policy, 'endorsements')
      app = appraise(claims, rvs.equal?(U) || rvs.nil? ? {} : rvs, ens.equal?(U) || ens.nil? ? {} : ens, extras)
      { 'ok' => app['trustworthy'], 'tier' => app['tier'], 'reasons' => reasons + app['reasons'], 'claims' => claims }
    end
  end
end

require_relative 'attest_eat_pqcosign'
require_relative 'attest_eat_admission'
