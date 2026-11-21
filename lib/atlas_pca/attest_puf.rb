# frozen_string_literal: true

require 'open3'
require 'securerandom'

module AtlasPca
  # The PUF (Physical Unclonable Function) attestation root (the reference's `attest-puf`): an independent root for the multi-root policy whose
  # identity is derived from a device's manufacturing variation (an SRAM power-up state, a TPM Endorsement Key), so it cannot be copied to
  # another device. This is the software layer around the unclonable source: a fuzzy extractor (a code-offset secure sketch over a repetition
  # code, then an HKDF-SHA256 extractor) that turns a noisy reading into a stable key, a provider abstraction (a simulated PUF for tests, a TPM
  # EK provider over an INJECTED tpm2-tools runner), enrollment (the key seeds an Ed25519 or ML-DSA key pair; only the public key and the helper
  # data are kept), the device attestor, the enrollment registry and the verifier.
  #
  # Honest scope: unclonability is a classical property (it is not quantum resistance); an ml-dsa-* suite at enrollment makes the identity also
  # post-quantum signed. A PUF response is a binary String with ONE 0 / 1 byte per bit. Records are String-keyed Hashes with the reference's wire
  # members (providerId, challenge, alg, publicKey, helper, helperCommitment, notAfter?).
  module AttestPuf
    PUF_EXTRACT_INFO = 'atlas-pca/puf-extract/v1'
    PUF_ATTEST_DOMAIN = "atlas-pca/attest-puf/v1\0"
    PUF_KEY_BYTES = 32
    TPM_EK_PUF_DOMAIN = 'atlas-pca/puf-tpm-ek/v1'
    PUF_SUITES = %w[ed25519 ml-dsa-65 ml-dsa-87].freeze

    module_function

    def bytes?(x) = x.is_a?(String) && x.encoding == Encoding::BINARY

    # The correctable bit errors per repetition block.
    def repetition_correction_bound(rep) = ((rep - 1) / 2.0).floor

    def assert_bits(b, where)
      raise RangeError, "#{where}: response must be a 0/1 bit array" if b.each_byte.any? { |x| x > 1 }
    end

    def xor_bits(a, b) = a.bytes.zip(b.bytes).map { |x, y| (x ^ y) & 1 }

    def rep_encode(message, rep) = message.flat_map { |bit| [bit & 1] * rep }

    # strict majority; a tie (an even rep) resolves to 0, so use an odd rep
    def rep_decode(code, rep) = code.each_slice(rep).map { |blk| blk.sum { |x| x & 1 } * 2 > rep ? 1 : 0 }

    def pack_bits(bits)
      out = Array.new((bits.length + 7) / 8, 0)
      bits.each_with_index { |b, i| out[i >> 3] |= 1 << (i & 7) if b.anybits?(1) }
      out.pack('C*')
    end

    def unpack_bits(packed, n) = Array.new(n) { |i| (packed.getbyte(i >> 3) >> (i & 7)) & 1 }

    def extract_key(bits, salt)
      OpenSSL::KDF.hkdf(pack_bits(bits), salt: salt.b, info: PUF_EXTRACT_INFO, length: PUF_KEY_BYTES, hash: 'SHA256')
    end

    def positive_int?(x) = Attestation.integer_number?(x) && x >= 1

    # Enroll a PUF response. `params` is {'rep', 'messageBits'} (rep an odd positive integer; the response is exactly rep * messageBits bits);
    # `random_bytes` is a callable (n) -> n random bytes, called first for the messageBits message bits, then for 32 salt bytes. Returns
    # {'key' => the 32-byte extracted key (the device's signing seed), 'helper' => {sketch, salt, rep, messageBits, n}}.
    def fuzzy_enroll(response_bits, params, random_bytes)
      rep = params['rep']
      mb = params['messageBits']
      raise RangeError, 'fuzzyEnroll: rep must be an odd positive integer' if !positive_int?(rep) || rep.to_i.even?
      raise RangeError, 'fuzzyEnroll: messageBits must be a positive integer' unless positive_int?(mb)

      rep = rep.to_i
      mb = mb.to_i
      n = rep * mb
      raise RangeError, "fuzzyEnroll: response length #{response_bits.bytesize} != rep*messageBits #{n}" if response_bits.bytesize != n

      assert_bits(response_bits, 'fuzzyEnroll')
      mr = random_bytes.call(mb).bytes
      m = Array.new(mb) { |i| mr[i] & 1 }
      sketch = xor_bits(rep_encode(m, rep).pack('C*'), response_bits) # C xor W
      salt = random_bytes.call(32)
      { 'key' => extract_key(response_bits.bytes, salt),
        'helper' => { 'sketch' => AtlasPca.b64e(pack_bits(sketch)), 'salt' => AtlasPca.b64e(salt), 'rep' => rep, 'messageBits' => mb, 'n' => n } }
    end

    # The key of an enrolled helper from a (noisy) response: the same key while the noise is within the repetition bound per block.
    # Beyond it a DIFFERENT key comes out (a statement signed with it then fails verification). Raises RangeError on a malformed helper
    # or response.
    def fuzzy_reproduce(response_bits, helper)
      h = helper.is_a?(Hash) ? helper : {}
      rep = h['rep']
      mb = h['messageBits']
      if !helper.is_a?(Hash) || !Attestation.integer_number?(rep) || !Attestation.integer_number?(mb) || rep < 1 || rep.to_i.even?
        raise RangeError, 'fuzzyReproduce: malformed helper params'
      end

      rep = rep.to_i
      mb = mb.to_i
      n = rep * mb
      raise RangeError, 'fuzzyReproduce: helper.n inconsistent with rep*messageBits' unless h['n'].is_a?(Numeric) && h['n'] == n
      raise RangeError, "fuzzyReproduce: response length #{response_bits.bytesize} != #{n}" if response_bits.bytesize != n

      assert_bits(response_bits, 'fuzzyReproduce')
      unless h['sketch'].is_a?(String) && h['salt'].is_a?(String)
        raise RangeError, 'fuzzyReproduce: helper data missing sketch or salt'
      end

      packed = AtlasPca.b64d(h['sketch'])
      salt = AtlasPca.b64d(h['salt'])
      raise RangeError, 'fuzzyReproduce: helper sketch or salt is not canonical base64url' if packed.nil? || salt.nil?
      raise RangeError, 'fuzzyReproduce: helper sketch has the wrong length' if packed.bytesize != (n + 7) / 8
      raise RangeError, 'fuzzyReproduce: helper salt has the wrong length' if salt.bytesize != 32

      sketch = unpack_bits(packed, n)
      corrupted = response_bits.bytes.zip(sketch).map { |x, y| (x ^ y) & 1 } # W' xor s = C xor e
      m_hat = rep_decode(corrupted, rep)
      w_rec = rep_encode(m_hat, rep).zip(sketch).map { |x, y| (x ^ y) & 1 } # C_hat xor s = the enrolled W within the bound
      extract_key(w_rec, salt)
    end

    # A simulated PUF for tests and demos: a counter-mode SHA-256 stream over (seed || challenge || ctr), one bit per output bit; `flip`
    # positions (those inside the response) are inverted to model noise.
    class SimulatedPuf
      attr_reader :id

      def initialize(id:, seed:, length:, flip: nil)
        @id = id
        @seed = seed.b
        @length = length
        @flips = (flip || []).to_a.uniq
      end

      def response(challenge)
        blocks = (((@length + 7) / 8) + 31) / 32
        stream = (0...blocks).map { |blk| Digest::SHA256.digest(@seed + challenge.b + [blk].pack('N')) }.join.b
        bits = Array.new(@length) { |i| (stream.getbyte(i >> 3) >> (i & 7)) & 1 }
        @flips.each { |pos| bits[pos] ^= 1 if pos.is_a?(Integer) && pos >= 0 && pos < bits.length }
        bits.pack('C*')
      end
    end

    def create_simulated_puf(id:, seed:, length:, flip: nil) = SimulatedPuf.new(id: id, seed: seed, length: length, flip: flip)

    # The default runner of the TPM provider: spawns the tool and answers {'status', 'stdout', 'stderr'?, 'error'?} (a spawn failure has no
    # status and an `error`). Only for a real TPM host; tests inject a runner.
    def default_tpm_command_runner(command, args)
      out, err, st = Open3.capture3(command, *args, binmode: true)
      { 'status' => st.exitstatus, 'stdout' => out.b, 'stderr' => err.dup.force_encoding('UTF-8').scrub }
    rescue SystemCallError => e
      { 'status' => nil, 'stdout' => ''.b, 'error' => "#{command}: #{e.class.name.split('::').last}" }
    end

    # A PUF provider over a TPM 2.0 Endorsement Key: the EK public area is read once per response with tpm2-tools (through the injected
    # `run`, a callable (command, args) -> {'status', 'stdout', 'stderr'?, 'error'?}); the response is HKDF over it, bound to the challenge.
    # Fails closed everywhere (tool absent, TPM unavailable, a non-zero exit, a too-short EK). `opts`: {'id', 'length', 'run'?, 'tool'?,
    # 'ekHandle'?, 'args'?, 'minEkBytes'?}.
    class TpmEkPufProvider
      attr_reader :id

      def initialize(opts)
        o = opts.is_a?(Hash) ? opts : nil
        raise TypeError, 'TpmEkPufProvider: id must be a non-empty string' unless o && o['id'].is_a?(String) && !o['id'].empty?
        unless Attestation.integer_number?(o['length']) && o['length'] >= 1
          raise RangeError, 'TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)'
        end
        if !o['minEkBytes'].nil? && !(Attestation.integer_number?(o['minEkBytes']) && o['minEkBytes'] >= 1)
          raise RangeError, 'TpmEkPufProvider: minEkBytes must be a positive integer'
        end

        @id = o['id']
        @length = o['length'].to_i
        @run = o['run'] || AttestPuf.method(:default_tpm_command_runner)
        @tool = o['tool'].is_a?(String) && !o['tool'].empty? ? o['tool'] : 'tpm2_readpublic'
        handle = o['ekHandle'].is_a?(String) && !o['ekHandle'].empty? ? o['ekHandle'] : '0x81010001'
        @args = o['args'] || ['-c', handle, '-f', 'der', '-o', '/dev/stdout', '-Q']
        @min = o['minEkBytes'].nil? ? 64 : o['minEkBytes'].to_i
      end

      def read_ek_public
        begin
          res = @run.call(@tool, @args)
        rescue StandardError => e
          raise "TpmEkPufProvider: tpm2-tools invocation threw (fail closed): #{e.message}"
        end
        raise 'TpmEkPufProvider: command runner returned no result (fail closed)' unless res.is_a?(Hash)

        err = res['error']
        raise "TpmEkPufProvider: tpm2-tools unavailable (fail closed): #{err}" if err.is_a?(String) && !err.empty?

        if res['status'] != 0
          st = res['status'].nil? ? 'null' : Attestation.jstr(res['status'])
          why = Attestation.truthy?(res['stderr']) ? ": #{Attest::Common.js_trim(res['stderr'])}" : ''
          raise "TpmEkPufProvider: '#{@tool}' exited with status #{st} (fail closed)#{why}"
        end
        ek = res['stdout']
        if !AttestPuf.bytes?(ek) || ek.bytesize < @min
          raise "TpmEkPufProvider: EK public too short (#{AttestPuf.bytes?(ek) ? ek.bytesize : 0} < #{@min} bytes) — TPM unavailable or wrong handle (fail closed)"
        end

        ek
      end

      def response(challenge)
        secret = OpenSSL::KDF.hkdf(read_ek_public, salt: TPM_EK_PUF_DOMAIN, info: challenge.b, length: 32, hash: 'SHA256')
        blocks = [1, (((@length + 7) / 8) + 31) / 32].max
        stream = (0...blocks).map { |blk| Digest::SHA256.digest(secret + [blk].pack('N')) }.join.b
        Array.new(@length) { |i| (stream.getbyte(i >> 3) >> (i & 7)) & 1 }.pack('C*')
      end
    end

    # ---- the PUF-derived signing key (Ed25519, or post-quantum ML-DSA-65 / ML-DSA-87) ------------------------------------------------

    def assert_puf_suite(alg)
      return alg if PUF_SUITES.include?(alg)

      raise RangeError, "PUF root: unsupported derived suite '#{Attestation.jstr(alg)}' (use ed25519, ml-dsa-65 or ml-dsa-87)"
    end

    # {'public_key', 'sign' => lambda (msg) -> [sig, pq_sig]} of the key the 32-byte extracted `seed` derives.
    def puf_signer_from_seed(alg, seed)
      case alg
      when 'ed25519'
        kp = AtlasPca::KeyPair.new(seed)
        { 'public_key' => kp.public, 'sign' => ->(msg) { AtlasPca.sign_with_suite('ed25519', kp, nil, msg) } }
      else
        kp = AtlasPca::PqKeyPair.from_seed(alg == 'ml-dsa-65' ? 'ML-DSA-65' : 'ML-DSA-87', seed)
        { 'public_key' => kp.public, 'sign' => ->(msg) { AtlasPca.sign_with_suite(alg, nil, kp, msg) } }
      end
    end

    def statement_message(body) = PUF_ATTEST_DOMAIN.b + AtlasPca.canon_bytes(body)

    # Enroll `provider` (an object with #id and #response(challenge)) under `challenge`: extract the key, derive the device key pair of
    # `alg` (default ml-dsa-65) and keep only the public key and the helper data (with a commitment to it). `opts`: {'rep', 'messageBits',
    # 'alg'?, 'randomBytes'?}. Returns the enrollment Hash.
    def enroll_puf(provider, challenge, opts)
      alg = assert_puf_suite(opts['alg'].nil? ? 'ml-dsa-65' : opts['alg'])
      random = opts['randomBytes'] || ->(n) { SecureRandom.random_bytes(n) }
      fe = fuzzy_enroll(provider.response(challenge), { 'rep' => opts['rep'], 'messageBits' => opts['messageBits'] }, random)
      signer = puf_signer_from_seed(alg, fe['key'])
      { 'providerId' => provider.id, 'challenge' => AtlasPca.b64e(challenge), 'alg' => alg, 'publicKey' => signer['public_key'],
        'helper' => fe['helper'], 'helperCommitment' => AtlasPca.hash_canonical(fe['helper']) }
    end

    # The device attestor: re-reads the PUF, reproduces the key from the enrolled helper data and signs a statement
    # {provider_id, measurement, weights_digest?, binding, alg} under PUF_ATTEST_DOMAIN. Construction raises on an unsupported suite or a
    # challenge that is not canonical base64url.
    class Attestor
      def initialize(provider, enrollment)
        e = enrollment.is_a?(Hash) ? enrollment : {}
        @provider = provider
        @enrollment = e
        @alg = AttestPuf.assert_puf_suite(e['alg'])
        @challenge = AtlasPca.b64d(e['challenge'].is_a?(String) ? e['challenge'] : '') || raise(RangeError, 'not canonical base64url')
      end

      # `claims`: {measurement, weights_digest?, holder_pub, grant_ref, epoch, nonce}.
      def attest(claims)
        c = claims.is_a?(Hash) ? claims : {}
        key = AttestPuf.fuzzy_reproduce(@provider.response(@challenge), @enrollment['helper'])
        signer = AttestPuf.puf_signer_from_seed(@alg, key)
        binding = Attestation.attestation_binding_b64u({ 'holderPub' => c['holder_pub'], 'grantRef' => c['grant_ref'], 'epoch' => c['epoch'],
                                                          'nonce' => c['nonce'] })
        body = { 'provider_id' => @provider.id, 'measurement' => c.key?('measurement') ? c['measurement'] : Attestation::UNDEF, 'binding' => binding,
                 'alg' => @alg }
        body['weights_digest'] = c['weights_digest'] if c.key?('weights_digest')
        sig, pq_sig = signer['sign'].call(AttestPuf.statement_message(body))
        out = body.merge('sig' => sig)
        out['pq_sig'] = pq_sig unless pq_sig.nil?
        out
      end
    end

    def create_puf_attestor(provider, enrollment) = Attestor.new(provider, enrollment)

    # An in-memory enrollment registry. A revoked provider stays revoked (a later register does not un-revoke it) and is not found by lookup.
    class EnrollmentRegistry
      def initialize(enrollments = nil)
        @by_id = {}
        @revoked = {}
        (enrollments.is_a?(Array) ? enrollments : []).each { |e| register(e) }
      end

      def register(enrollment)
        @by_id[enrollment['providerId']] = enrollment if enrollment.is_a?(Hash) && enrollment['providerId'].is_a?(String)
        nil
      end

      def lookup(provider_id) = @revoked.key?(provider_id) ? nil : @by_id[provider_id]

      def revoke(provider_id)
        @revoked[provider_id] = true
        nil
      end

      def revoked?(provider_id) = @revoked.key?(provider_id)
    end

    def create_puf_enrollment_registry(enrollments = nil) = EnrollmentRegistry.new(enrollments)

    # The default identity of a verified statement: weights_measured is always false (a PUF root vouches for a device, not for weights).
    def default_identity(st, _enrollment)
      { 'model_id' => '', 'weights_digest' => st['weights_digest'].is_a?(String) ? st['weights_digest'] : '', 'weights_measured' => false,
        'runtime_measurement' => st['measurement'], 'operator' => '' }
    end

    # A hardware-verifier (verify(document, expected, now_ms)) over the PUF root. Given the signed statement from `resolve_evidence` (a
    # callable taking the document; none configured fails closed), in order: a revoked provider (`revoked`, a callable) is named as revoked;
    # `resolve_enrollment` (a callable taking the provider id) must know it and the enrollment must not have expired (notAfter); the helper
    # data must match its commitment; the statement's suite must be the enrolled one (`require_pq` also demands an ML-DSA suite); the
    # signature must verify under the ENROLLED public key (another device derives another key); `binding` must equal
    # attestation_binding(expected); then the policy (a non-empty `measurements` allowlist is required at construction, `weightsMeasurements`
    # optional, `derive_identity` maps a statement and its enrollment to the measured identity). Fails closed with a specific reason.
    class Verifier
      def initialize(policy: nil, resolve_enrollment: nil, require_pq: nil, revoked: nil, resolve_evidence: nil)
        pol = policy.is_a?(Hash) ? policy : {}
        meas = pol['measurements']
        raise TypeError, 'createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)' unless meas.is_a?(Array) && !meas.empty?
        raise TypeError, 'createPufVerifier: resolveEnrollment is required' unless resolve_enrollment.respond_to?(:call)

        @measurements = meas.dup.freeze # an allowlist emptied after construction must not become accept-all
        @weights = pol['weightsMeasurements'].is_a?(Array) ? pol['weightsMeasurements'].dup.freeze : nil
        @resolve_enrollment = resolve_enrollment
        @require_pq = require_pq == true
        @revoked = revoked
        @resolve = resolve_evidence
        @derive = pol['deriveIdentity'] || AttestPuf.method(:default_identity)
        AtlasPca.set_assurance_label(self, 'software', vendor: 'puf')
      end

      def verify(document, expected, now_ms)
        refuse = ->(reason) { { 'ok' => false, 'reason' => reason } }
        return refuse.call('no PUF evidence resolver configured (fail closed)') if @resolve.nil?

        st = @resolve.call(document)
        unless st.is_a?(Hash) && st['provider_id'].is_a?(String) && st['alg'].is_a?(String)
          return refuse.call('no PUF attestation statement for this action')
        end

        pid = st['provider_id']
        return refuse.call("PUF enrollment for provider '#{pid}' is revoked") if @revoked && Attestation.truthy?(@revoked.call(pid))

        enr = @resolve_enrollment.call(pid)
        return refuse.call("no PUF enrollment registered for provider '#{pid}'") unless Attestation.truthy?(enr)

        e = enr.is_a?(Hash) ? enr : {}
        if e.key?('notAfter') && !(now_ms.is_a?(Numeric) && e['notAfter'].is_a?(Numeric) && now_ms < e['notAfter'])
          return refuse.call('PUF enrollment has expired')
        end
        unless e['helperCommitment'].is_a?(String) && e['helperCommitment'] == AtlasPca.hash_canonical(e.key?('helper') ? e['helper'] : Attestation::UNDEF)
          return refuse.call('PUF enrollment helper commitment mismatch (helper tampered)')
        end
        if st['alg'] != e['alg']
          return refuse.call("PUF statement suite '#{st['alg']}' does not match the enrolled suite '#{Attestation.jstr(e['alg'])}'")
        end

        alg = st['alg']
        return refuse.call("PUF statement declares an unknown signature alg '#{alg}'") unless REGISTERED_SUITES.include?(alg) && SIG_SUITES.key?(alg)

        if @require_pq && !AttestPqSoftware.has_pq?(AttestPqSoftware.suite_of(alg))
          return refuse.call("PQ required: PUF-derived suite '#{alg}' is classical")
        end

        message = AttestPuf.statement_message(st.reject { |k, _| %w[sig pq_sig].include?(k) })
        parts = { 'alg' => alg, 'sig' => st['sig'] }
        parts['pq_sig'] = st['pq_sig'] if st.key?('pq_sig')
        # the enrolled key (the verifier's own registry) is the PQ key of a pure-PQ PUF suite
        pq = AtlasPca.resolve_pq_key('', nil, trusted_pk: e['publicKey'])
        unless st['sig'].is_a?(String) && AtlasPca.verify_suite(parts, e['publicKey'], message, pq)
          return refuse.call('PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)')
        end
        return refuse.call('no expected attestation binding supplied') unless Attestation.truthy?(expected)

        begin
          want = Attestation.attestation_binding_b64u(expected)
        rescue StandardError => e2
          return refuse.call("binding not constructible: #{e2.message}")
        end
        return refuse.call('PUF statement binding mismatch (holder/grant/epoch/nonce)') unless st['binding'].is_a?(String) && st['binding'] == want
        return refuse.call('measurement not in policy allowlist') unless @measurements.any? { |m| Attestation.same_value_zero?(m, st['measurement']) }
        if @weights && !@weights.empty? && !(st['weights_digest'].is_a?(String) && @weights.include?(st['weights_digest']))
          return refuse.call('measured weights digest not in policy allowlist')
        end

        { 'ok' => true, 'bound' => true, 'measured' => @derive.call(st, enr), 'hostAsserted' => { 'provider_id' => pid, 'suite' => alg } }
      rescue StandardError => e
        refuse.call("puf verification error (fail closed): #{e.message}")
      end
    end

    def create_puf_verifier(**opts) = Verifier.new(**opts)
  end
end
