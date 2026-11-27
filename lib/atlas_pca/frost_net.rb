# frozen_string_literal: true

require 'securerandom'

module AtlasPca
  # Networked FROST(Ed25519) signing, where every signer is a separate service (the reference's `frost-net`): a policy authority signs an ALLOW TOKEN
  # (typ `pca.frost.allow.v1`, bound to sha256(message) and the group key); a signer answers round 1 only inside a session and round 2 only for a valid
  # token; a signer's PROOF OF POSSESSION (a Schnorr proof under its verification share) gates enrollment (a rogue key is refused); the EQUIVOCATION
  # GUARD refuses a second different message for the same (session, round, signer). GuardianSignerService holds one share; NetworkCoordinator drives
  # t-of-n over signer transports (objects answering `identifier`, `round1(req)` and `round2(req)`) with timeouts, refusals and equivocation detection.
  # The HTTP adapters are not part of this module: a transport is any object with those three members. Wire records are String-keyed Hashes; bytes are
  # binary Strings. `random` seams are callables (length -> bytes) so a test can script the randomness.
  module FrostNet
    UNDEF = IntentV2::UNDEF
    ALLOW_TOKEN_TYP = 'pca.frost.allow.v1'
    SIGNER_POP_DST = 'pca.frost.signer-pop.v1'
    MAX_FROST_SIGNING_SET = 256
    ROUND1_TYP = 'pca.frost.round1.v1'
    ROUND2_TYP = 'pca.frost.round2.v1'

    class PoPError < StandardError
      attr_reader :identifier

      def initialize(message, identifier = nil)
        super(message)
        @identifier = identifier
      end
    end

    class EquivocationError < StandardError
      attr_reader :session_id, :round, :identifier, :previous_digest, :offending_digest

      def initialize(session_id, round, identifier, previous_digest, offending_digest)
        super("equivocation: signer #{identifier} sent two different messages for session '#{session_id}' round #{round}")
        @session_id = session_id
        @round = round
        @identifier = identifier
        @previous_digest = previous_digest
        @offending_digest = offending_digest
      end
    end

    class CoordinatorError < StandardError
      attr_reader :refusals

      def initialize(message, refusals = [])
        super(message)
        @refusals = refusals
      end
    end

    class CoordinatorTimeoutError < CoordinatorError
      attr_reader :timeout_ms

      def initialize(message, timeout_ms, refusals = [])
        super(message, refusals)
        @timeout_ms = timeout_ms
      end
    end

    module_function

    def pm(h, k) = h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF
    def nullish?(x) = x.nil? || UNDEF.equal?(x)
    def bytes?(x, len = nil) = x.is_a?(String) && (len.nil? || x.bytesize == len)
    def id?(x) = Attestation.safe_int?(x) && x.positive?
    def b64u(b) = AtlasPca.b64e(b)
    def sha256(b) = Digest::SHA256.digest(b.b)
    def rand32(random) = (random ? random.call(32) : SecureRandom.random_bytes(32)).b

    # base64url(sha256(message)): what an allow token authorizes
    def frost_action_digest(message)
      raise TypeError, 'frostActionDigest: message must be bytes' unless message.is_a?(String)

      b64u(sha256(message))
    end

    # The policy authority's allow token {body, authority, sig}. `opts`: 'message' or 'frostActionDigest', 'groupPublicKey', 'nonce'? (a random one
    # otherwise), 'notBefore'?, 'expiresAt'?.
    def issue_allow_token(policy_secret, opts, random: nil)
      fad = pm(opts, 'frostActionDigest')
      msg = pm(opts, 'message')
      digest = nullish?(fad) ? (msg.is_a?(String) ? frost_action_digest(msg) : nil) : fad
      raise 'issueAllowToken: provide message or frostActionDigest' unless Attestation.truthy?(digest)

      nonce = pm(opts, 'nonce')
      body = { 'typ' => ALLOW_TOKEN_TYP, 'action_digest' => digest, 'group_pk' => b64u(pm(opts, 'groupPublicKey')), 'nonce' => nullish?(nonce) ? b64u(rand32(random)) : nonce }
      body['not_before'] = opts['notBefore'] unless UNDEF.equal?(pm(opts, 'notBefore'))
      body['expires_at'] = opts['expiresAt'] unless UNDEF.equal?(pm(opts, 'expiresAt'))
      key = policy_secret.is_a?(AtlasPca::KeyPair) ? policy_secret : AtlasPca::KeyPair.new(policy_secret)
      { 'body' => body, 'authority' => key.public, 'sig' => b64u(key.sign(AtlasPca.canon_bytes(body))) }
    end

    def js_lt(a, b) = BeaconsApi.js_num(a) < BeaconsApi.js_num(b)

    # {ok, reason?}: the token is the trusted authority's, for this group key and this action, and valid at `now`. `expect`: 'policyAuthorityPublicKey'
    # (bytes), 'groupPublicKey', 'message', 'now'. Fail closed: an error is a refusal.
    def verify_allow_token(token, expect)
      return { 'ok' => false, 'reason' => 'allow token missing or malformed' } unless token.is_a?(Hash) || token.is_a?(Array)

      body = pm(token, 'body')
      return { 'ok' => false, 'reason' => 'allow token has no body' } unless body.is_a?(Hash) || body.is_a?(Array)
      return { 'ok' => false, 'reason' => "allow token wrong typ (#{Attestation.jstr(pm(body, 'typ'))})" } unless pm(body, 'typ') == ALLOW_TOKEN_TYP

      sig = pm(token, 'sig')
      return { 'ok' => false, 'reason' => 'allow token missing signature' } unless sig.is_a?(String)

      sig_bytes = AtlasPca.b64d(sig, 64)
      return { 'ok' => false, 'reason' => 'allow token signature not canonical base64url' } if sig_bytes.nil?

      authority = pm(expect, 'policyAuthorityPublicKey')
      # a key that is not 32 bytes verifies nothing (the reference's verifier answers false): the token is not the authority's
      unless bytes?(authority, 32) && AtlasPca::Ed25519Strict.verify(authority.b, AtlasPca.canon_bytes(body), sig_bytes)
        return { 'ok' => false, 'reason' => 'allow token not signed by the trusted policy authority' }
      end
      return { 'ok' => false, 'reason' => 'allow token authorizes a different group key' } unless Attestation.js_eq(pm(body, 'group_pk'), b64u(pm(expect, 'groupPublicKey')))
      unless Attestation.js_eq(pm(body, 'action_digest'), frost_action_digest(pm(expect, 'message')))
        return { 'ok' => false, 'reason' => 'allow token authorizes a different action digest' }
      end

      now = pm(expect, 'now')
      return { 'ok' => false, 'reason' => 'invalid verification time' } unless Attestation.finite?(now)
      return { 'ok' => false, 'reason' => 'allow token not yet valid' } if !UNDEF.equal?(pm(body, 'not_before')) && js_lt(now, body['not_before'])
      return { 'ok' => false, 'reason' => 'allow token expired' } if !UNDEF.equal?(pm(body, 'expires_at')) && BeaconsApi.js_num(now) >= BeaconsApi.js_num(body['expires_at'])

      { 'ok' => true }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "allow token verification error (fail closed): #{e.message}" }
    end

    def pop_challenge(group_public_key, identifier, pk, r)
      h = OpenSSL::Digest::SHA512.digest(SIGNER_POP_DST.b + group_public_key.b + Frost.int_scalar(identifier) + pk.b + r.b)
      e = Frost.reduce_bytes(h)
      e == Frost::ZERO ? Frost.int_scalar(1) : e
    end

    # The signer's Schnorr proof of possession of its share under its verification share, bound to the group key and the identifier:
    # {identifier, publicKey, R, s}. `opts`: 'groupPublicKey', 'nonce'? (32 bytes; random otherwise: a nonce that reduces to zero is redrawn).
    def create_signer_pop(identifier, share, opts, random: nil)
      raise 'createSignerPoP: identifier must be a positive integer' unless id?(identifier)
      raise 'createSignerPoP: share must be 32 bytes' unless bytes?(share, 32)

      gpk = pm(opts, 'groupPublicKey')
      raise 'createSignerPoP: groupPublicKey must be 32 bytes' unless bytes?(gpk, 32)

      x = Frost.reduce_bytes(share)
      pk = Frost.enc(Frost.mul_base(x))
      nonce = pm(opts, 'nonce')
      k = Attestation.truthy?(nonce) || nonce.is_a?(String) ? Frost.reduce_bytes(nonce) : Frost::ZERO
      k = Frost.reduce_bytes(rand32(random)) while k == Frost::ZERO
      r = Frost.enc(Frost.mul_base(k))
      e = pop_challenge(gpk, identifier, pk, r)
      s = Frost.sc_add(k, Frost.sc_mul(e, x))
      { 'identifier' => identifier, 'publicKey' => b64u(pk), 'R' => b64u(r), 's' => b64u(s) }
    end

    # true iff `pop` proves possession of the share behind its publicKey for this group key. Never raises.
    def verify_signer_pop(pop, expect)
      return false unless pop.is_a?(Hash)

      identifier = pop['identifier']
      return false unless id?(identifier)

      gpk = pm(expect, 'groupPublicKey')
      return false unless bytes?(gpk, 32)

      pk = AtlasPca.b64d(pop['publicKey'], 32)
      rb = AtlasPca.b64d(pop['R'], 32)
      sb = AtlasPca.b64d(pop['s'], 32)
      return false if pk.nil? || rb.nil? || sb.nil?

      pk_pt = Frost.decode_safe_point(pk)
      r_pt = Frost.decode_safe_point(rb)
      return false unless Frost.canonical_scalar?(sb)

      e = pop_challenge(gpk, identifier, pk, rb)
      Frost.enc(Frost.mul_base(sb)) == Frost.enc(Frost.padd(r_pt, Frost.mul_pt(pk_pt, e)))
    rescue StandardError
      false
    end

    # The verification shares of the enrolled signers [{identifier, publicKey}], each backed by a valid proof of possession (a rogue key is refused).
    # Raises PoPError.
    def enroll_verification_shares(enrollments, expect)
      raise PoPError, 'enrollVerificationShares: no signer enrollments' if !enrollments.is_a?(Array) || enrollments.empty?

      gpk = pm(expect, 'groupPublicKey')
      raise PoPError, 'enrollVerificationShares: groupPublicKey must be 32 bytes' unless bytes?(gpk, 32)

      out = []
      seen = {}
      enrollments.each do |e|
        raise PoPError, 'enrollVerificationShares: enrollment with invalid identifier' unless e.is_a?(Hash) && id?(e['identifier'])

        id = e['identifier']
        raise PoPError.new("enrollVerificationShares: duplicate enrollment for signer #{id}", id) if seen.key?(id)

        seen[id] = true
        raise PoPError.new("enrollVerificationShares: signer #{id} verification share must be 32 bytes", id) unless bytes?(e['publicKey'], 32)

        pop = e['pop']
        if !pop.is_a?(Hash) || !Attestation.js_eq(pop['identifier'], id) || !Attestation.js_eq(pop['publicKey'], b64u(e['publicKey']))
          raise PoPError.new("enrollVerificationShares: signer #{id} missing or mismatched proof-of-possession (rogue key rejected)", id)
        end
        unless verify_signer_pop(pop, { 'groupPublicKey' => gpk })
          raise PoPError.new("enrollVerificationShares: signer #{id} invalid proof-of-possession (rogue key rejected)", id)
        end
        out << { 'identifier' => id, 'publicKey' => e['publicKey'] }
      end
      out
    end

    # Refuses a second DIFFERENT message from one signer for one (session, round): the digest of the first is remembered.
    class EquivocationGuard
      def initialize = @seen = {}

      def observe(session_id, round, identifier, message)
        raise ArgumentError, 'EquivocationGuard: session_id must be a non-empty string' if !session_id.is_a?(String) || session_id.empty?
        raise ArgumentError, 'EquivocationGuard: round must be a positive integer' unless Attestation.safe_int?(round) && round >= 1
        raise ArgumentError, 'EquivocationGuard: identifier must be a positive integer' unless FrostNet.id?(identifier)

        key = "#{session_id}\0#{round}\0#{identifier}"
        digest = FrostNet.b64u(FrostNet.sha256(AtlasPca.canon_bytes(message)))
        prev = @seen[key]
        if prev.nil?
          @seen[key] = digest
          return nil
        end
        raise EquivocationError.new(session_id, round, identifier, prev, digest) if prev != digest

        nil
      end

      def forget(session_id)
        prefix = "#{session_id}\0"
        @seen.delete_if { |k, _| k.start_with?(prefix) }
        nil
      end
    end

    def encode_commitment(c) = { 'identifier' => c['identifier'], 'hiding' => b64u(c['hiding']), 'binding' => b64u(c['binding']) }

    def decode_commitment(w)
      raise 'bad commitment' unless w.is_a?(Hash)

      hiding = AtlasPca.b64d(pm(w, 'hiding'), 32)
      binding = AtlasPca.b64d(pm(w, 'binding'), 32)
      raise 'bad commitment identifier' unless id?(pm(w, 'identifier'))
      raise 'bad commitment point encoding' if hiding.nil? || binding.nil?

      { 'identifier' => w['identifier'], 'hiding' => hiding, 'binding' => binding }
    end

    def decode_commitments(list)
      raise 'commitments must be a list' unless list.is_a?(Array)
      raise 'commitments list exceeds the maximum signing set' if list.length > MAX_FROST_SIGNING_SET

      list.map { |w| decode_commitment(w) }
    end

    def decode_verification_shares(list)
      raise 'verification_shares must be a list' unless list.is_a?(Array)
      raise 'verification_shares list exceeds the maximum signing set' if list.length > MAX_FROST_SIGNING_SET

      list.map do |v|
        raise 'bad verification share' unless v.is_a?(Hash)

        pk = AtlasPca.b64d(pm(v, 'publicKey'), 32)
        raise 'bad verification-share identifier' unless id?(pm(v, 'identifier'))
        raise 'bad verification-share key encoding' if pk.nil?

        { 'identifier' => v['identifier'], 'publicKey' => pk }
      end
    end

    # A signer service as a transport of the coordinator, in the same address space (state isolation without a process boundary: fast, deterministic
    # tests). For process isolation use `FrostNetHttp.http_signer_transport` against a service in its own process.
    InProcessTransport = Struct.new(:identifier, :service) do
      def round1(req) = service.round1(req)
      def round2(req) = service.round2(req)
    end

    def in_process_transport(service) = InProcessTransport.new(service.identifier, service)

    # One signer service: holds ONE share, answers round 1 (a fresh nonce pair, committed once per session) and round 2 (only for a valid allow token,
    # once per session). With a nonce store the nonces survive a restart and burn before they sign.
    class GuardianSignerService
      attr_reader :identifier, :verification_share, :proof_of_possession

      def initialize(identifier:, share:, group_public_key:, threshold:, policy_authority_public_key:, session_ttl_ms: nil, now: nil, nonce_store: nil, random: nil)
        raise 'GuardianSignerService: identifier must be a positive integer' unless FrostNet.id?(identifier)
        raise 'GuardianSignerService: share must be 32 bytes' unless FrostNet.bytes?(share, 32)
        raise 'GuardianSignerService: groupPublicKey must be 32 bytes' unless FrostNet.bytes?(group_public_key, 32)
        raise 'GuardianSignerService: threshold must be a positive integer' unless Attestation.safe_int?(threshold) && threshold >= 1
        raise 'GuardianSignerService: policyAuthorityPublicKey must be 32 bytes' unless FrostNet.bytes?(policy_authority_public_key, 32)
        if !session_ttl_ms.nil? && (!Attestation.finite?(session_ttl_ms) || session_ttl_ms <= 0)
          raise 'GuardianSignerService: sessionTtlMs must be a positive finite number'
        end

        @identifier = identifier
        @share = share.b.dup
        @group_public_key = group_public_key.b.dup
        @threshold = threshold
        @policy_authority = policy_authority_public_key.b.dup
        @ttl = session_ttl_ms
        @now = now || -> { (Time.now.to_f * 1000).to_i }
        @random = random
        @sessions = {}
        @spent = {}
        unless nonce_store.nil?
          { create: 'create', load: 'load', spend: 'spend', drop: 'drop', spent?: 'isSpent' }.each do |m, name|
            raise "GuardianSignerService: nonceStore.#{name} must be a function" unless nonce_store.respond_to?(m)
          end
        end
        @store = nonce_store
        @verification_share = Frost.verifying_share(@share)
        @proof_of_possession = FrostNet.create_signer_pop(identifier, @share, { 'groupPublicKey' => @group_public_key }, random: random)
      end

      def enrollment = { 'identifier' => @identifier, 'publicKey' => @verification_share.dup, 'pop' => @proof_of_possession }

      def round1(req)
        sid = FrostNet.pm(req, 'session_id')
        unless req.is_a?(Hash) && req['typ'] == ROUND1_TYP && sid.is_a?(String) && !sid.empty?
          return { 'ok' => false, 'identifier' => @identifier, 'reason' => 'malformed round-1 request' }
        end
        return { 'ok' => false, 'identifier' => @identifier, 'reason' => 'session already signed' } if @spent.key?(sid) || (@store && @store.spent?(sid))
        return { 'ok' => false, 'identifier' => @identifier, 'reason' => 'duplicate round-1 for session' } if @sessions.key?(sid) || (@store && @store.load(sid))

        c = Frost.commit({ 'identifier' => @identifier, 'share' => @share, 'publicKey' => @verification_share }, FrostNet.rand32(@random), FrostNet.rand32(@random))
        created_at = @now.call
        @store&.create(sid, { 'hiding' => c['hidingNonce'], 'binding' => c['bindingNonce'], 'hidingCommitment' => c['commitment']['hiding'],
                              'bindingCommitment' => c['commitment']['binding'], 'createdAt' => created_at })
        @sessions[sid] = { nonces: { 'hiding' => c['hidingNonce'], 'binding' => c['bindingNonce'] }, commitment: c['commitment'], created_at: created_at }
        { 'ok' => true, 'identifier' => @identifier, 'commitment' => FrostNet.encode_commitment(c['commitment']), 'pop' => @proof_of_possession }
      rescue StandardError => e
        { 'ok' => false, 'identifier' => @identifier, 'reason' => e.message }
      end

      def refuse(reason) = { 'ok' => false, 'identifier' => @identifier, 'refused' => true, 'reason' => reason }

      def round2(req)
        sid = FrostNet.pm(req, 'session_id')
        return refuse('malformed round-2 request') unless req.is_a?(Hash) && req['typ'] == ROUND2_TYP && sid.is_a?(String)
        return refuse('session already signed (one-shot)') if @spent.key?(sid) || (@store && @store.spent?(sid))

        state = @sessions[sid]
        if state.nil? && @store
          rec = @store.load(sid)
          if rec
            state = { nonces: { 'hiding' => rec['hiding'], 'binding' => rec['binding'] },
                      commitment: { 'identifier' => @identifier, 'hiding' => rec['hidingCommitment'], 'binding' => rec['bindingCommitment'] }, created_at: rec['createdAt'] }
            @sessions[sid] = state
          end
        end
        return refuse('no round-1 state for this session') if state.nil?

        if !@ttl.nil? && !(Attestation.finite?(age = @now.call - state[:created_at]) && age <= @ttl)
          @sessions.delete(sid)
          @store&.drop(sid)
          return refuse("session expired (stale-session guard: round-1 older than #{Predicates.js_number_string(@ttl.to_f)}ms)")
        end
        message = AtlasPca.b64d(FrostNet.pm(req, 'message'))
        return refuse('message not canonical base64url') if message.nil?
        return refuse('request names a different group key') unless Attestation.js_eq(FrostNet.pm(req, 'group_pk'), FrostNet.b64u(@group_public_key))

        allow = FrostNet.verify_allow_token(FrostNet.pm(req, 'allow'), { 'policyAuthorityPublicKey' => @policy_authority, 'groupPublicKey' => @group_public_key,
                                                                          'message' => message, 'now' => @now.call })
        return refuse("policy authorization failed: #{allow['reason']}") unless allow['ok']

        commitments = FrostNet.decode_commitments(FrostNet.nullish?(FrostNet.pm(req, 'commitments')) ? [] : req['commitments'])
        return refuse("signing set below threshold t=#{@threshold}") if commitments.length < @threshold

        own = commitments.find { |c| c['identifier'] == @identifier }
        return refuse('our commitment is not in the signing set') if own.nil?
        if FrostNet.b64u(own['hiding']) != FrostNet.b64u(state[:commitment]['hiding']) || FrostNet.b64u(own['binding']) != FrostNet.b64u(state[:commitment]['binding'])
          return refuse('equivocation detected: our commitment in the signing set differs from our round-1 commitment')
        end

        verification_shares = FrostNet.decode_verification_shares(FrostNet.pm(req, 'verification_shares'))
        @store&.spend(sid)
        sig = Frost.sign(@identifier, @share, @group_public_key, state[:nonces], message, commitments, @threshold, @verification_share, verification_shares)
        @sessions.delete(sid)
        @spent[sid] = true
        { 'ok' => true, 'identifier' => @identifier, 'sig_share' => FrostNet.b64u(sig['sigShare']) }
      rescue StandardError => e
        refuse(e.message)
      end
    end

    # Drives t-of-n signing over signer transports: round 1 to the chosen signers in parallel, every commitment checked (a known verification share, a
    # valid proof of possession, no equivocation), round 2 to the first t committed, every signature share verified at aggregation. A window (`timeout_ms`)
    # bounds the whole session.
    class NetworkCoordinator
      def initialize(group_public_key:, threshold:, signers:, verification_shares: nil, enroll: nil, new_session_id: nil, timeout_ms: nil, new_timer: nil)
        raise 'NetworkCoordinator: groupPublicKey must be 32 bytes' unless FrostNet.bytes?(group_public_key, 32)
        raise 'NetworkCoordinator: threshold must be a positive integer' unless Attestation.safe_int?(threshold) && threshold >= 1
        raise 'NetworkCoordinator: timeoutMs must be a positive finite number' if !timeout_ms.nil? && (!Attestation.finite?(timeout_ms) || timeout_ms <= 0)

        @group_public_key = group_public_key
        @threshold = threshold
        @signers = signers.dup
        if !enroll.nil?
          @verification_shares = FrostNet.enroll_verification_shares(enroll, { 'groupPublicKey' => group_public_key })
        elsif !verification_shares.nil?
          @verification_shares = verification_shares.dup
        else
          raise 'NetworkCoordinator: provide verificationShares or enroll'
        end
        @pk_by_id = @verification_shares.to_h { |v| [v['identifier'], FrostNet.b64u(v['publicKey'])] }
        @equivocation = EquivocationGuard.new
        @new_session_id = new_session_id || -> { FrostNet.b64u(SecureRandom.random_bytes(32)) }
        @timeout_ms = timeout_ms
        # new_timer.call(ms, queue) starts the session deadline and must push :expired onto the queue when ms have passed; nil is the real clock.
        @new_timer = new_timer
      end

      # {signature, sessionId, signers}; raises CoordinatorError / CoordinatorTimeoutError.
      def sign(message, allow, signer_ids: nil, timeout_ms: nil)
        window = timeout_ms.nil? ? @timeout_ms : timeout_ms
        return drive(message, allow, signer_ids) if window.nil? || !Attestation.finite?(window) || window <= 0

        outcome = Thread::Queue.new
        @new_timer&.call(window, outcome) # started before the session, so a fake clock sees the deadline first
        worker = Thread.new do
          outcome << [:done, drive(message, allow, signer_ids)]
        rescue Exception => e # rubocop:disable Lint/RescueException
          outcome << [:error, e]
        end
        worker.report_on_exception = false
        if @new_timer
          kind, value = outcome.pop
        elsif worker.join(window / 1000.0)
          kind, value = outcome.pop
        end
        if kind.nil? || kind == :expired
          raise CoordinatorTimeoutError.new("coordinator: signing session did not reach threshold within #{Predicates.js_number_string(window.to_f)}ms", window)
        end
        error = kind == :error ? value : nil
        result = value
        raise error if error

        result
      end

      private

      def respond(thread_results, idx, &blk)
        Thread.new do
          thread_results[idx] = blk.call
        rescue StandardError => e
          thread_results[idx] = { error: e }
        end
      end

      def parallel(items, &blk)
        results = Array.new(items.length)
        threads = items.each_with_index.map { |item, i| respond(results, i) { blk.call(item) } }
        threads.each(&:join)
        results
      end

      def refusal(resp, key)
        r = { 'identifier' => FrostNet.pm(resp, 'identifier') }
        r['reason'] = FrostNet.pm(resp, 'reason') if key
        r.reject { |_k, v| UNDEF.equal?(v) }
      end

      def drive(message, allow, signer_ids)
        raise 'coordinator.sign: message must be bytes' unless message.is_a?(String)

        chosen = signer_ids.nil? ? @signers.first(@threshold) : @signers.select { |s| signer_ids.include?(s.identifier) }
        raise CoordinatorError.new("coordinator: only #{chosen.length} signer(s) selected, need t=#{@threshold}") if chosen.length < @threshold

        session_id = @new_session_id.call
        r1 = parallel(chosen) do |s|
          { s: s, resp: s.round1({ 'typ' => ROUND1_TYP, 'session_id' => session_id }) }
        end.each_with_index.map do |res, i|
          res.is_a?(Hash) && res.key?(:error) ? { s: chosen[i], resp: { 'ok' => false, 'identifier' => chosen[i].identifier, 'reason' => res[:error].message } } : res
        end
        refusals = []
        committed = []
        r1.each do |entry|
          s = entry[:s]
          resp = entry[:resp]
          unless Attestation.truthy?(FrostNet.pm(resp, 'ok'))
            refusals << refusal(resp, true)
            next
          end
          expected_pk = @pk_by_id[FrostNet.pm(resp, 'identifier')]
          if expected_pk.nil?
            refusals << { 'identifier' => resp['identifier'], 'reason' => 'no verification share on record for this signer' }
            next
          end
          pop = FrostNet.pm(resp, 'pop')
          if !pop.is_a?(Hash) || !Attestation.js_eq(pop['identifier'], resp['identifier']) || !Attestation.js_eq(pop['publicKey'], expected_pk) ||
             !FrostNet.verify_signer_pop(pop, { 'groupPublicKey' => @group_public_key })
            refusals << { 'identifier' => resp['identifier'], 'reason' => 'invalid or missing proof-of-possession (rogue-key defense)' }
            next
          end
          begin
            @equivocation.observe(session_id, 1, resp['identifier'], FrostNet.pm(resp, 'commitment'))
          rescue StandardError => e
            refusals << { 'identifier' => resp['identifier'], 'reason' => e.is_a?(EquivocationError) ? e.message : 'equivocation check failed' }
            next
          end
          committed << { transport: s, commitment: resp['commitment'] }
        end
        if committed.length < @threshold
          raise CoordinatorError.new("coordinator: round 1 produced #{committed.length} commitment(s), need t=#{@threshold}", refusals)
        end

        set = committed.first(@threshold)
        commitments = set.map { |c| c[:commitment] }
        set_ids = set.map { |c| c[:commitment]['identifier'] }
        verification_shares = @verification_shares.select { |v| set_ids.include?(v['identifier']) }.map { |v| { 'identifier' => v['identifier'], 'publicKey' => FrostNet.b64u(v['publicKey']) } }
        raise CoordinatorError, 'coordinator: missing a verification share for a signer in the set' if verification_shares.length != set.length

        r2 = parallel(set) do |c|
          c[:transport].round2({ 'typ' => ROUND2_TYP, 'session_id' => session_id, 'message' => FrostNet.b64u(message), 'group_pk' => FrostNet.b64u(@group_public_key),
                                 'commitments' => Marshal.load(Marshal.dump(commitments)), 'verification_shares' => Marshal.load(Marshal.dump(verification_shares)), 'allow' => allow })
        end.each_with_index.map do |res, i|
          res.is_a?(Hash) && res.key?(:error) ? { 'ok' => false, 'identifier' => set[i][:transport].identifier, 'refused' => true, 'reason' => res[:error].message } : res
        end
        sig_shares = []
        r2.each do |resp|
          unless Attestation.truthy?(FrostNet.pm(resp, 'ok'))
            refusals << refusal(resp, true)
            next
          end
          begin
            @equivocation.observe(session_id, 2, resp['identifier'], { 'sig_share' => FrostNet.pm(resp, 'sig_share') })
          rescue StandardError => e
            refusals << { 'identifier' => resp['identifier'], 'reason' => e.is_a?(EquivocationError) ? e.message : 'equivocation check failed' }
            next
          end
          sb = AtlasPca.b64d(FrostNet.pm(resp, 'sig_share'), 32)
          if sb.nil? then refusals << { 'identifier' => resp['identifier'], 'reason' => 'malformed signature share' }
          else sig_shares << { 'identifier' => resp['identifier'], 'sigShare' => sb }
          end
        end
        raise CoordinatorError.new("coordinator: round 2 produced #{sig_shares.length} share(s), need t=#{@threshold}", refusals) if sig_shares.length < @threshold

        agg_commitments = commitments.map { |w| FrostNet.decode_commitment(w) }
        signature = Frost.aggregate(message, agg_commitments, sig_shares, @group_public_key, @verification_shares.select { |v| set_ids.include?(v['identifier']) }, @threshold)
        { 'signature' => signature, 'sessionId' => session_id, 'signers' => set_ids }
      end
    end
  end
end
