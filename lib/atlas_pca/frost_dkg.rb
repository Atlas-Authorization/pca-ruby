# frozen_string_literal: true

require 'securerandom'

module AtlasPca
  # FROST distributed key generation (the reference's `frost-dkg`): Pedersen DKG with Feldman commitments. Round 1 broadcasts the commitments to a
  # random polynomial and a proof of knowledge of its constant term; round 2 sends every other participant its polynomial value, SIGNED under the
  # constant-term commitment (so a bad share is non-repudiable); a share that fails VSS is a complaint, the accused may rebut, blame is resolved from
  # the signed evidence alone, the qualified set is every participant with a valid proof and no upheld complaint, an echo round makes every party agree
  # on one transcript, and finalize sums the received shares into the signing share. Records are String-keyed Hashes; scalars, shares and points are
  # binary Strings (32 bytes); `random` seams are callables (length -> bytes) so a test can script the randomness.
  module FrostDkg
    UNDEF = IntentV2::UNDEF
    DKG_POP_DST = 'dkg-pop'
    DKG_SHARE_DST = 'dkg-share'
    DKG_SHARE_NONCE_DST = 'dkg-share-nonce'

    module_function

    def pm(h, k) = h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF
    def b64u(b) = AtlasPca.b64e(b)
    def unb64u(s) = AtlasPca.b64d(s) || raise(ArgumentError, 'invalid base64url')
    def pos_int?(x) = Attestation.integer_number?(x) && x.positive?
    def ctx = Frost::CONTEXT_STRING
    def sc(i) = Frost.int_scalar(i.is_a?(Float) ? i.to_i : i)
    def rand32(random) = (random ? random.call(32) : SecureRandom.random_bytes(32)).b
    def hash_to_scalar(msg) = Frost.h2s(msg)

    def canonical_scalar(b)
      raise 'dkg: scalar must be 32 bytes and < the group order' unless Frost.canonical_scalar?(b)

      Frost.reduce_bytes(b)
    end

    # the commitment vector of a package: its decoded constant-term commitment and the bytes a signature binds (uint32 count || every point)
    def commit_vec_of(commitments)
      raise 'dkg: empty commitment vector' if !commitments.is_a?(Array) || commitments.empty?

      pts = commitments.map { |c| Frost.decode_safe_point(unb64u(c)) }
      { c0: pts[0], bytes: [pts.length].pack('N') + pts.join.b }
    end

    # f(x) by Horner over secret scalars
    def eval_poly(coeffs, x)
      xb = sc(x)
      acc = Frost::ZERO
      coeffs.reverse_each { |a| acc = Frost.sc_add(Frost.sc_mul(acc, xb), a) }
      acc
    end

    # Feldman check: g^share == prod C_k^(at_id^k)
    def vss_check(share, commitments, at_id)
      return false if commitments.empty?

      lhs = Frost.mul_base(share)
      rhs = nil
      x = sc(at_id)
      xk = sc(1)
      commitments.each do |c|
        rhs = Frost.padd(rhs, Frost.mul_pt(Frost.decode_safe_point(unb64u(c)), xk))
        xk = Frost.sc_mul(xk, x)
      end
      Frost.enc(lhs) == Frost.enc(rhs)
    end

    def pop_challenge(sid, identifier, cv, r)
      hash_to_scalar(ctx + DKG_POP_DST.b + sid.b + sc(identifier) + cv[:bytes] + Frost.enc(r))
    end

    def share_challenge(sid, from, to, share, cv, rs)
      hash_to_scalar(ctx + DKG_SHARE_DST.b + sid.b + sc(from) + sc(to) + share.b + cv[:bytes] + Frost.enc(rs))
    end

    def share_nonce(a0, sid, from, to, share, cv)
      hash_to_scalar(ctx + DKG_SHARE_NONCE_DST.b + a0 + sid.b + sc(from) + sc(to) + share.b + cv[:bytes])
    end

    # base64url(R_s || s): a Schnorr signature of the sender under its constant-term commitment over (session, from, to, share, commitments)
    def sign_share_scalar(a0, cv, sid, from, to, share)
      k = share_nonce(a0, sid, from, to, share, cv)
      rs = Frost.mul_base(k)
      e = share_challenge(sid, from, to, share, cv, rs)
      s = Frost.sc_add(k, Frost.sc_mul(a0, e))
      b64u(Frost.enc(rs) + s)
    end

    def verify_share_sig(sig, sid, from, to, share, cv)
      raw = unb64u(sig)
      return false unless raw.bytesize == 64

      rs = Frost.decode_safe_point(raw.byteslice(0, 32))
      s = canonical_scalar(raw.byteslice(32, 32))
      e = share_challenge(sid, from, to, share, cv, rs)
      Frost.enc(Frost.mul_base(s)) == Frost.enc(Frost.padd(rs, Frost.mul_pt(cv[:c0], e)))
    rescue StandardError
      false
    end

    def verify_share_sig_against_package(sig, sid, from, to, share, pkg)
      return false if !sig.is_a?(String) || pm(pkg, 'coefficientCommitments').empty?

      verify_share_sig(sig, sid, from, to, share, commit_vec_of(pkg['coefficientCommitments']))
    rescue StandardError
      false
    end

    def dkg_sign_share(state, to, share)
      raise TypeError, "The number #{Attestation.jstr(to)} cannot be converted to a BigInt because it is not an integer" unless Attestation.integer_number?(to)

      a0 = Frost.reduce_bytes(state['coefficients'][0])
      sign_share_scalar(a0, commit_vec_of(state['package']['coefficientCommitments']), state['sessionId'], state['identifier'], to, share)
    end

    # Round 1: {package, state}. `opts`: 'coefficients'? (t scalars; random otherwise), 'popNonce'? (random otherwise). Randomness is drawn in order: the
    # t coefficients (unless given), then the proof-of-knowledge nonce (unless given).
    def dkg_round1(identifier, t, n, session_id, opts = {}, random: nil)
      raise 'dkgRound1: identifier must be a positive integer' unless pos_int?(identifier)
      raise "dkgRound1: need 1 <= t <= n (got t=#{Attestation.jstr(t)}, n=#{Attestation.jstr(n)})" unless Attestation.integer_number?(t) && Attestation.integer_number?(n) && t >= 1 && n >= t
      raise 'dkgRound1: sessionId must be a non-empty byte string' if !session_id.is_a?(String) || session_id.empty?

      given = pm(opts, 'coefficients')
      if Attestation.truthy?(given) || given.is_a?(Array)
        raise "dkgRound1: coefficients.length must equal t (#{t})" if given.length != t

        coeffs = given.map { |c| Frost.reduce_bytes(c) }
      else
        coeffs = Array.new(t) { Frost.reduce_bytes(rand32(random)) }
      end
      commitments = coeffs.map { |a| b64u(Frost.enc(Frost.mul_base(a))) }
      cv = commit_vec_of(commitments)
      nonce = pm(opts, 'popNonce')
      k = nonce.is_a?(String) ? Frost.reduce_bytes(nonce) : Frost.reduce_bytes(rand32(random))
      r = Frost.mul_base(k)
      c = pop_challenge(session_id, identifier, cv, r)
      mu = Frost.sc_add(k, Frost.sc_mul(coeffs[0], c))
      pkg = { 'identifier' => identifier, 'sessionId' => b64u(session_id), 'coefficientCommitments' => commitments,
              'proofOfKnowledge' => { 'R' => b64u(Frost.enc(r)), 'mu' => b64u(mu) } }
      { 'package' => pkg, 'state' => { 'identifier' => identifier, 't' => t, 'n' => n, 'sessionId' => session_id.b.dup, 'coefficients' => coeffs, 'package' => pkg } }
    end

    # true iff the package proves knowledge of the constant term behind its first commitment, bound to the session and the sender. Never raises.
    def dkg_verify_round1(from_identifier, pkg, session_id)
      return false unless pkg['sessionId'] == b64u(session_id)
      return false if pkg['coefficientCommitments'].empty?

      cv = commit_vec_of(pkg['coefficientCommitments'])
      r = Frost.decode_safe_point(unb64u(pkg['proofOfKnowledge']['R']))
      mu = canonical_scalar(unb64u(pkg['proofOfKnowledge']['mu']))
      c = pop_challenge(session_id, from_identifier, cv, r)
      Frost.enc(Frost.mul_base(mu)) == Frost.enc(Frost.padd(r, Frost.mul_pt(cv[:c0], c)))
    rescue StandardError
      false
    end

    # Round 2: the signed share for every other participant (package order). Raises on duplicate ids, a missing own package or another session.
    def dkg_round2(state, packages)
      ids = packages.map { |p| p['identifier'] }
      raise 'dkgRound2: duplicate identifiers in round-1 packages' if ids.uniq.length != ids.length
      raise 'dkgRound2: my own round-1 package is missing' unless ids.include?(state['identifier'])

      sid = b64u(state['sessionId'])
      packages.each { |p| raise "dkgRound2: participant #{p['identifier']} round-1 package is from a different session" if p['sessionId'] != sid }
      coeffs = state['coefficients'].map { |c| Frost.reduce_bytes(c) }
      cv = commit_vec_of(state['package']['coefficientCommitments'])
      ids.reject { |j| j == state['identifier'] }.map do |j|
        share = eval_poly(coeffs, j)
        { 'from' => state['identifier'], 'to' => j, 'sessionId' => sid, 'share' => share,
          'sig' => sign_share_scalar(coeffs[0], cv, state['sessionId'], state['identifier'], j, share) }
      end
    end

    # true iff the share is validly signed by the sender, the sender's package is valid, and the share passes VSS. Never raises.
    def dkg_verify_share(received, sender_package, my_identifier, session_id)
      return false unless received.is_a?(Hash) && received['share'].is_a?(String)
      return false unless dkg_verify_round1(sender_package['identifier'], sender_package, session_id)
      return false unless verify_share_sig_against_package(pm(received, 'sig'), session_id, received['from'], my_identifier, received['share'], sender_package)

      vss_check(canonical_scalar(received['share']), sender_package['coefficientCommitments'], my_identifier)
    rescue StandardError
      false
    end

    # A complaint against an accused that sent a share failing VSS: carries the accused-signed share as evidence.
    def dkg_file_complaint(params)
      accused = pm(params, 'accused')
      accuser = pm(params, 'accuser')
      sig = pm(params, 'shareSig')
      sid = pm(params, 'sessionId')
      raise 'dkgFileComplaint: accused must be a positive integer' unless pos_int?(accused)
      raise 'dkgFileComplaint: accuser must be a positive integer' unless pos_int?(accuser)
      raise 'dkgFileComplaint: cannot file a complaint against yourself' if accused == accuser
      raise 'dkgFileComplaint: shareSig (the accused-signed share) is required' if !sig.is_a?(String) || sig.empty?
      raise 'dkgFileComplaint: sessionId must be a non-empty byte string' if !sid.is_a?(String) || sid.empty?

      { 'accused' => accused, 'accuser' => accuser, 'sessionId' => b64u(sid), 'revealedShare' => b64u(Frost.reduce_bytes(pm(params, 'receivedShare'))), 'shareSig' => sig }
    end

    def find_package(packages, id) = packages.find { |p| p['identifier'] == id }

    # {justified, disqualify? | atFault?, reason}: adjudicates a complaint from the accused's own signed evidence.
    def dkg_verify_complaint(complaint, packages)
      accused_pkg = find_package(packages, complaint['accused'])
      return { 'justified' => false, 'reason' => "accused #{complaint['accused']} has no round-1 package to adjudicate against" } if accused_pkg.nil?
      return { 'justified' => false, 'reason' => 'complaint sessionId does not match the accused round-1 package session' } if accused_pkg['sessionId'] != complaint['sessionId']

      sid = unb64u(complaint['sessionId'])
      share = unb64u(complaint['revealedShare'])
      unless verify_share_sig_against_package(complaint['shareSig'], sid, complaint['accused'], complaint['accuser'], share, accused_pkg)
        return { 'justified' => false, 'atFault' => complaint['accuser'], 'reason' => 'revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)' }
      end
      if vss_check(canonical_scalar(share), accused_pkg['coefficientCommitments'], complaint['accuser'])
        return { 'justified' => false, 'atFault' => complaint['accuser'], 'reason' => 'accused-signed share is VALID against the accused commitments — false accusation' }
      end

      { 'justified' => true, 'disqualify' => complaint['accused'], 'reason' => 'accused non-repudiably signed a share that FAILS VSS against its broadcast commitments' }
    rescue StandardError
      { 'justified' => false, 'reason' => 'malformed complaint' }
    end

    # The accused's rebuttal: the correctly signed share for the accuser. Raises when the state is not the accused's or the session differs.
    def dkg_rebut(accused, complaint, state)
      raise 'dkgRebut: myRound2State is not the accused' if state['identifier'] != accused
      raise 'dkgRebut: complaint does not name this accused' if complaint['accused'] != accused
      raise 'dkgRebut: complaint is scoped to a different session than my state' if b64u(state['sessionId']) != complaint['sessionId']

      coeffs = state['coefficients'].map { |c| Frost.reduce_bytes(c) }
      share = eval_poly(coeffs, complaint['accuser'])
      { 'accused' => accused, 'accuser' => complaint['accuser'], 'sessionId' => complaint['sessionId'], 'presentedShare' => b64u(share),
        'shareSig' => dkg_sign_share(state, complaint['accuser'], share) }
    end

    # {guilty, reason}: who is at fault, from the signed evidence alone (an unsigned accusation can never frame the accused).
    def dkg_resolve_blame(complaint, rebuttal, packages)
      accused_pkg = find_package(packages, complaint['accused'])
      return { 'guilty' => complaint['accused'], 'reason' => "accused #{complaint['accused']} has no round-1 package to defend with" } if accused_pkg.nil?
      return { 'guilty' => complaint['accuser'], 'reason' => 'complaint names a session the accused did not run — inadmissible' } if accused_pkg['sessionId'] != complaint['sessionId']

      sid = unb64u(complaint['sessionId'])
      share = unb64u(complaint['revealedShare'])
      if verify_share_sig_against_package(complaint['shareSig'], sid, complaint['accused'], complaint['accuser'], share, accused_pkg)
        unless vss_check(canonical_scalar(share), accused_pkg['coefficientCommitments'], complaint['accuser'])
          return { 'guilty' => complaint['accused'], 'reason' => 'accused non-repudiably signed a share that fails VSS' }
        end

        return { 'guilty' => complaint['accuser'], 'reason' => 'accused-signed share is valid against its commitments — false accusation' }
      end
      if Attestation.truthy?(rebuttal) && rebuttal['accused'] == complaint['accused'] && rebuttal['accuser'] == complaint['accuser'] && rebuttal['sessionId'] == complaint['sessionId']
        r_share = unb64u(rebuttal['presentedShare'])
        valid = verify_share_sig_against_package(rebuttal['shareSig'], sid, complaint['accused'], complaint['accuser'], r_share, accused_pkg) &&
                vss_check(canonical_scalar(r_share), accused_pkg['coefficientCommitments'], complaint['accuser'])
        if valid
          return { 'guilty' => complaint['accuser'],
                   'reason' => 'accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted' }
        end

        return { 'guilty' => complaint['accused'], 'reason' => 'accused could not present a validly-signed, VSS-correct share on rebuttal' }
      end
      { 'guilty' => complaint['accuser'], 'reason' => 'complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused' }
    rescue StandardError
      { 'guilty' => complaint['accuser'], 'reason' => 'malformed complaint — inadmissible' }
    end

    # The qualified participants (ascending): a valid proof of knowledge, the run's session, and no upheld complaint against them.
    def dkg_qualified_set(participants, complaints, packages, rebuttals = [])
      pkg_by_id = {}
      packages.each { |p| pkg_by_id[p['identifier']] = p }
      counts = {}
      packages.each { |p| counts[p['sessionId']] = (counts[p['sessionId']] || 0) + 1 }
      run_session = ''
      best = -1
      counts.each do |s, c|
        if c > best
          best = c
          run_session = s
        end
      end
      qualified = []
      participants.each do |p|
        pkg = pkg_by_id[p]
        next if pkg.nil? || pkg['sessionId'] != run_session

        sid = AtlasPca.b64d(pkg['sessionId'])
        next if sid.nil?

        qualified << p if dkg_verify_round1(p, pkg, sid) && !qualified.include?(p)
      end
      complaints.each do |c|
        reb = rebuttals.find { |r| r['accused'] == c['accused'] && r['accuser'] == c['accuser'] && r['sessionId'] == c['sessionId'] }
        res = dkg_resolve_blame(c, reb, packages)
        qualified.delete(res['guilty']) if res['guilty'] == c['accused']
      end
      qualified.sort
    end

    def round1_package_digest(p)
      AtlasPca.hash_canonical({ 'identifier' => p['identifier'], 'sessionId' => p['sessionId'], 'coefficientCommitments' => p['coefficientCommitments'],
                                'proofOfKnowledge' => { 'R' => p['proofOfKnowledge']['R'], 'mu' => p['proofOfKnowledge']['mu'] } })
    end

    def complaint_digest(c)
      AtlasPca.hash_canonical({ 'accused' => c['accused'], 'accuser' => c['accuser'], 'sessionId' => c['sessionId'], 'revealedShare' => c['revealedShare'],
                                'shareSig' => c['shareSig'] })
    end

    # base64url(sha256) over the canonical transcript: the sorted package and complaint digests and the sorted qualified set.
    # `args`: 'round1Packages', 'complaints', 'qualified', 'sessionId'.
    def dkg_transcript_digest(args)
      AtlasPca.hash_canonical({ 'sessionId' => b64u(args['sessionId']), 'round1' => args['round1Packages'].map { |p| round1_package_digest(p) }.sort,
                                'complaints' => args['complaints'].map { |c| complaint_digest(c) }.sort, 'qualified' => args['qualified'].sort })
    end

    def dkg_echo(args)
      { 'identifier' => args['identifier'], 'sessionId' => b64u(args['sessionId']),
        'transcriptDigest' => dkg_transcript_digest({ 'round1Packages' => args['round1Packages'], 'complaints' => args['complaints'], 'qualified' => args['qualified'],
                                                      'sessionId' => args['sessionId'] }) }
    end

    # {agreed, digest | reason}: every qualified participant echoed the same transcript digest for this session.
    def dkg_check_echoes(qualified, echoes, session_id)
      sid = b64u(session_id)
      q_set = qualified.uniq
      by_id = {}
      echoes.each do |e|
        next unless q_set.include?(e['identifier'])
        return { 'agreed' => false, 'reason' => "echo from #{e['identifier']} is bound to a different session" } if e['sessionId'] != sid
        return { 'agreed' => false, 'reason' => "duplicate echo from qualified participant #{e['identifier']}" } if by_id.key?(e['identifier'])

        by_id[e['identifier']] = e
      end
      agreed = nil
      q_set.each do |j|
        e = by_id[j]
        return { 'agreed' => false, 'reason' => "missing echo from qualified participant #{j}" } if e.nil?

        if agreed.nil? then agreed = e['transcriptDigest']
        elsif e['transcriptDigest'] != agreed
          return { 'agreed' => false, 'reason' => "qualified participant #{j} echoed a DIFFERENT transcript (equivocation detected)" }
        end
      end
      return { 'agreed' => false, 'reason' => 'no qualified echoes to agree on' } if agreed.nil?

      { 'agreed' => true, 'digest' => agreed }
    rescue StandardError
      { 'agreed' => false, 'reason' => 'malformed echoes' }
    end

    # The key package: the signing share (own polynomial value + every qualified share), the group key and every verifying share. Raises on any
    # inconsistency. `agreement`: {'echoes', 'complaints'?} (echo-broadcast agreement is checked when echoes are given).
    def dkg_finalize(my_identifier, state, received_shares, all_commitments, qualified = nil, agreement = nil)
      raise 'dkgFinalize: myState.identifier != myIdentifier' if state['identifier'] != my_identifier

      ids = all_commitments.map { |p| p['identifier'] }
      raise 'dkgFinalize: duplicate identifiers in commitments' if ids.uniq.length != ids.length
      raise 'dkgFinalize: my own package is missing from allCommitments' unless ids.include?(my_identifier)

      sid = b64u(state['sessionId'])
      all_commitments.each { |p| raise "dkgFinalize: participant #{p['identifier']} round-1 package is from a different session" if p['sessionId'] != sid }
      qset = (qualified.nil? ? ids : qualified).select { |id| ids.include?(id) }
      q_set = qset.uniq
      raise 'dkgFinalize: myIdentifier is not in the qualified set' unless q_set.include?(my_identifier)

      t = state['t']
      raise "dkgFinalize: qualified set (#{q_set.length}) is smaller than the threshold t=#{t}" if q_set.length < t

      all_commitments.each do |p|
        next unless q_set.include?(p['identifier'])
        if p['coefficientCommitments'].length != t
          raise "dkgFinalize: participant #{p['identifier']} committed to #{p['coefficientCommitments'].length} coefficients, expected t=#{t}"
        end
      end
      if agreement.is_a?(Hash) && agreement.key?('echoes')
        q_sorted = q_set.sort
        check = dkg_check_echoes(q_sorted, agreement['echoes'], state['sessionId'])
        raise "dkgFinalize: echo-broadcast agreement failed — #{check['reason']}" unless check['agreed']

        my_digest = dkg_transcript_digest({ 'round1Packages' => all_commitments, 'complaints' => agreement['complaints'] || [], 'qualified' => q_sorted, 'sessionId' => state['sessionId'] })
        if check['digest'] != my_digest
          raise 'dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)'
        end
      end
      recv = {}
      received_shares.each do |r|
        next if r['from'] == my_identifier || !q_set.include?(r['from'])
        raise "dkgFinalize: received share from #{r['from']} is from a different session" if r['sessionId'] != sid
        raise "dkgFinalize: duplicate received share from #{r['from']}" if recv.key?(r['from'])

        recv[r['from']] = r['share']
      end
      qset.each do |j|
        next if j == my_identifier
        raise "dkgFinalize: missing received share from qualified participant #{j}" unless recv.key?(j)
      end
      my_coeffs = state['coefficients'].map { |c| Frost.reduce_bytes(c) }
      signing_share = eval_poly(my_coeffs, my_identifier)
      recv.each_value { |share| signing_share = Frost.sc_add(signing_share, Frost.reduce_bytes(share)) }
      group_points = (0...t).map do |k|
        acc = nil
        all_commitments.each { |p| acc = Frost.padd(acc, Frost.decode_safe_point(unb64u(p['coefficientCommitments'][k]))) if q_set.include?(p['identifier']) }
        acc
      end
      group_public_key = Frost.enc(group_points[0])
      verifying = qset.map do |j|
        acc = nil
        xk = sc(1)
        group_points.each do |phi|
          acc = Frost.padd(acc, Frost.mul_pt(phi, xk))
          xk = Frost.sc_mul(xk, sc(j))
        end
        { 'identifier' => j, 'publicKey' => Frost.enc(acc) }
      end
      verifying_share = Frost.enc(Frost.mul_base(signing_share))
      mine = verifying.find { |v| v['identifier'] == my_identifier }
      if mine.nil? || verifying_share != Frost.enc(Frost.decode_safe_point(mine['publicKey']))
        raise 'dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)'
      end

      { 'identifier' => my_identifier, 'signingShare' => signing_share, 'groupPublicKey' => group_public_key, 'verifyingShare' => verifying_share,
        'publicKeyPackage' => { 'groupPublicKey' => group_public_key, 'groupCommitment' => group_points.map { |p| Frost.enc(p) }, 'verifyingShares' => verifying } }
    end

    # The whole ceremony in process (a test and key-ceremony helper). `opts`: 'identifiers'?, 'coefficientsByParticipant'?, 'sessionId'?, 'cheaters'? (ids
    # that send a corrupted share), 'equivocateEchoFor'?. Randomness: the session id (unless given), then each participant in order.
    def frost_dkg_simulate(t, n, opts = {}, random: nil)
      unless Attestation.integer_number?(t) && Attestation.integer_number?(n) && t >= 1 && n >= t
        raise "frostDkgSimulate: need 1 <= t <= n (got t=#{Attestation.jstr(t)}, n=#{Attestation.jstr(n)})"
      end

      given_ids = pm(opts, 'identifiers')
      ids = given_ids.is_a?(Array) ? given_ids : (1..n).to_a
      raise 'frostDkgSimulate: identifiers.length must equal n' if ids.length != n
      raise 'frostDkgSimulate: identifiers must be distinct' if ids.uniq.length != n
      raise 'frostDkgSimulate: identifiers must be positive integers' if ids.any? { |x| !pos_int?(x) }

      sid = pm(opts, 'sessionId')
      sid = rand32(random) unless sid.is_a?(String)
      cheaters = pm(opts, 'cheaters')
      cheaters = [] unless cheaters.is_a?(Array)
      by_participant = pm(opts, 'coefficientsByParticipant')
      states = ids.each_with_index.map do |id, idx|
        cb = by_participant.is_a?(Array) ? by_participant[idx] : nil
        dkg_round1(id, t, n, sid, cb.nil? ? {} : { 'coefficients' => cb }, random: random)['state']
      end
      packages = states.map { |s| s['package'] }
      packages.each { |pkg| raise "frostDkgSimulate: PoP verification failed for participant #{pkg['identifier']}" unless dkg_verify_round1(pkg['identifier'], pkg, sid) }
      inbox = ids.to_h { |id| [id, []] }
      complaints = []
      by_id = states.to_h { |s| [s['identifier'], s] }
      states.each do |st|
        dkg_round2(st, packages).each do |out|
          share = out['share']
          sig = out['sig']
          if cheaters.include?(out['from'])
            bad = share.dup
            bad.setbyte(0, bad.getbyte(0) ^ 1)
            share = bad
            sig = dkg_sign_share(st, out['to'], bad)
          end
          sender = find_package(packages, out['from'])
          if dkg_verify_share({ 'from' => out['from'], 'share' => share, 'sig' => sig }, sender, out['to'], sid)
            inbox[out['to']] << { 'from' => out['from'], 'sessionId' => out['sessionId'], 'share' => share, 'sig' => sig }
          else
            complaints << dkg_file_complaint({ 'accused' => out['from'], 'accuser' => out['to'], 'receivedShare' => share, 'shareSig' => sig,
                                               'senderCommitments' => sender['coefficientCommitments'], 'sessionId' => sid })
          end
        end
      end
      rebuttals = complaints.map { |c| dkg_rebut(c['accused'], c, by_id[c['accused']]) }
      qualified = dkg_qualified_set(ids, complaints, packages, rebuttals)
      raise "frostDkgSimulate: only #{qualified.length} qualified participants (< t=#{t}) after the blame round" if qualified.length < t

      equiv = pm(opts, 'equivocateEchoFor')
      echoes = qualified.map do |id|
        view = id == equiv ? qualified.reject { |q| q == qualified.last } : qualified
        dkg_echo({ 'identifier' => id, 'round1Packages' => packages, 'complaints' => complaints, 'qualified' => view, 'sessionId' => sid })
      end
      key_packages = states.select { |st| qualified.include?(st['identifier']) }.map do |st|
        dkg_finalize(st['identifier'], st, inbox[st['identifier']], packages, qualified, { 'echoes' => echoes, 'complaints' => complaints })
      end
      gpk = key_packages[0]['groupPublicKey']
      key_packages.each { |kp| raise 'frostDkgSimulate: participants disagree on the group public key' if kp['groupPublicKey'] != gpk }
      { 'groupPublicKey' => gpk,
        'participantShares' => key_packages.map { |kp| { 'identifier' => kp['identifier'], 'share' => kp['signingShare'], 'publicKey' => kp['verifyingShare'] } },
        'groupCommitment' => key_packages[0]['publicKeyPackage']['groupCommitment'], 'keyPackages' => key_packages, 'round1Packages' => packages, 'qualified' => qualified,
        'complaints' => complaints, 'rebuttals' => rebuttals, 'echoes' => echoes, 'sessionId' => sid }
    end
  end
end
