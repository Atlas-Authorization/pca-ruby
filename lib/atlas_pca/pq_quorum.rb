# frozen_string_literal: true

require 'digest'

module AtlasPca
  # Post-quantum t-of-n authorization by composition (the reference's in-core `pq-threshold` module): a quorum set is n registered
  # PQ signers, a threshold t and a diversity floor (the least number of hash-based signers); a proof is t INDEPENDENT per-signer
  # signatures over one domain-separated message. Rotation: the old quorum signs the next set's id at the next epoch, and the chain
  # verifier enforces linkage and monotone epochs. No new cryptography: counting, binding and de-duplication over the suite seam.
  # Records are String-keyed Hashes with the reference's wire members; verifiers never raise and return typed verdicts; signers
  # raise. Signing keys are {'ed' => KeyPair, 'ml_dsa' => PqKeyPair, 'ml_dsa87' => PqKeyPair, ...} (Pq::SUITE_KEY_SLOTS).
  module PqQuorum
    SET_DOMAIN = 'atlas-pca/pq-quorum-set/v1'
    MSG_DOMAIN = "atlas-pca/pq-quorum-msg/v1\0"
    ROTATION_KIND = 'pq-quorum-rotation'
    MAX_SIGNERS = 256
    MAX_CHAIN = 1024
    ED_PK_BYTES = 32
    # the suites a quorum set admits, by PQ primitive, with the public-key member a signer input carries (LESS is not admitted)
    KEY_MEMBERS = { 'ML-DSA-65' => 'mlDsaPub', 'ML-DSA-87' => 'mlDsa87Pub', 'SLH-DSA-SHA2-128f' => 'slhDsaPub',
                    'SLH-DSA-SHA2-256s' => 'slhDsa256sPub', 'FN-DSA-512' => 'fnDsa512Pub', 'FN-DSA-1024' => 'fnDsa1024Pub' }.freeze
    BAD_SET = { 'ok' => false, 'reason' => 'bad-set' }.freeze

    module_function

    def rec?(x) = x.is_a?(Hash)
    def epoch?(n) = V2JS.nonneg?(n)
    def no(reason, extra = {}) = { 'ok' => false, 'reason' => reason }.merge(extra)

    # [sig bytes, needs pq_pk, needs pq_sig, primitive, nested] of a suite a quorum set admits, else nil
    def suite_of(alg)
      spec = alg.is_a?(String) ? SIG_SUITES[alg] : nil
      spec && KEY_MEMBERS.key?(spec[3]) ? spec : nil
    end

    def hybrid?(alg) = alg.start_with?('hybrid-')
    def hash_based?(alg) = SIG_SUITES[alg][3].start_with?('SLH-DSA')

    # {alg, ed?, pq} of one signer, or nil: a registered PQ suite, a canonical key of the suite's length, an Ed25519 key exactly
    # when the suite is a hybrid (`has_ed`: the member is present, null included).
    def normalize_entry(alg, has_ed, ed, pq)
      spec = suite_of(alg)
      return nil if spec.nil? || AtlasPca.b64d(pq, PQ_PRIMS[spec[3]][0]).nil?

      if hybrid?(alg)
        return nil if AtlasPca.b64d(ed, ED_PK_BYTES).nil?

        return { 'alg' => alg, 'ed' => ed, 'pq' => pq }
      end
      has_ed ? nil : { 'alg' => alg, 'pq' => pq }
    end

    def entry_key(e) = "#{e['alg']}|#{e['ed'] || ''}|#{e['pq']}"

    def compute_id(t, k, signers)
      body = { 'd' => SET_DOMAIN, 't' => t, 'k' => k, 's' => signers.map { |e| { 'a' => e['alg'], 'e' => e['ed'], 'p' => e['pq'] } } }
      AtlasPca.b64e(Digest::SHA384.digest(AtlasPca.canon_bytes(body)))
    end

    def finalize(entries, t, k)
      n = entries.length
      return BAD_SET if n < 1 || n > MAX_SIGNERS
      return BAD_SET if !V2JS.int?(t) || t < 1 || t > n
      return BAD_SET if !V2JS.int?(k) || k.negative? || k > t

      t = V2JS.ival(t)
      k = V2JS.ival(k)
      sorted = entries.sort_by { |e| entry_key(e).b } # all ASCII: byte order is the reference's string order
      seen = {}
      sorted.each do |e|
        (e.key?('ed') ? [e['ed'], e['pq']] : [e['pq']]).each do |c|
          return BAD_SET if seen.key?(c) # one key component never serves two signers

          seen[c] = true
        end
      end
      return BAD_SET if sorted.count { |e| hash_based?(e['alg']) } < k

      { 'ok' => true, 'set' => { 't' => t, 'minHashBased' => k, 'signers' => sorted, 'id' => compute_id(t, k, sorted) } }
    end

    # Build a quorum set from [{'alg', 'keys' => {'edPub'?, 'mlDsaPub'?, ...}}] (base64url public keys), a threshold and a
    # diversity floor: {'ok' => true, 'set' => {'t', 'minHashBased', 'signers', 'id'}} or {'ok' => false, 'reason' => 'bad-set'}.
    def build_quorum_set(signers, t, min_hash_based = 0)
      return BAD_SET unless signers.is_a?(Array)

      entries = signers.map do |s|
        return BAD_SET if !rec?(s) || !rec?(s['keys'])

        spec = suite_of(s['alg'])
        return BAD_SET if spec.nil?

        normalize_entry(s['alg'], s['keys'].key?('edPub'), s['keys']['edPub'], s['keys'][KEY_MEMBERS[spec[3]]]) or return BAD_SET
      end
      finalize(entries, t, min_hash_based)
    rescue StandardError, SystemStackError
      BAD_SET
    end

    # Load a quorum set from its wire form: the id is re-derived and must match, the order must already be canonical.
    def load_quorum_set(x)
      return BAD_SET if !rec?(x) || !x['signers'].is_a?(Array) || !x['id'].is_a?(String)

      entries = x['signers'].map do |s|
        return BAD_SET unless rec?(s)

        normalize_entry(s['alg'], s.key?('ed'), s['ed'], s['pq']) or return BAD_SET
      end
      r = finalize(entries, x['t'], x['minHashBased'])
      return r unless r['ok']
      return BAD_SET if r['set']['signers'].each_with_index.any? { |e, i| entry_key(e) != entry_key(entries[i]) }

      r['set']['id'] == x['id'] ? r : BAD_SET
    rescue StandardError, SystemStackError
      BAD_SET
    end

    # The bytes every signer signs: the domain tag and SHA-384 of the strict canonical {set_id, epoch, action}. The three values
    # are placed as given (any JSON value); only a value the canonical form refuses raises.
    def quorum_message(set_id, epoch, action_digest)
      MSG_DOMAIN.b + Digest::SHA384.digest(AtlasPca.canon_bytes({ 'set_id' => set_id, 'epoch' => epoch, 'action' => action_digest }))
    end

    # The action digest of a message (bytes) a quorum approves.
    def quorum_action_digest(message)
      raise TypeError, 'quorumActionDigest: the message is bytes' unless message.is_a?(String)

      AtlasPca.b64e(Digest::SHA384.digest(message.b))
    end

    # One signer's share over (set, epoch, action digest): {'i', 'sig', 'pq_sig'?}. Raises on an unknown index or missing keys.
    def sign_quorum_share(set, index, epoch, action_digest, keys)
      found, e = AtlasPca.mesh_at(set['signers'], index)
      raise RangeError, 'signQuorumShare: no such signer index' unless found
      raise TypeError, 'signQuorumShare: malformed signer entry or keys' if !rec?(e) || !rec?(keys)

      spec = SIG_SUITES[e['alg']] or raise ArgumentError, "signQuorumShare: unknown suite #{e['alg'].inspect}"
      pair = spec[1] ? keys[Pq::SUITE_KEY_SLOTS[spec[3]]] : nil
      sig, pq_sig = AtlasPca.sign_with_suite(e['alg'], keys['ed'], pair, quorum_message(set['id'], epoch, action_digest))
      pq_sig.nil? ? { 'i' => index, 'sig' => sig } : { 'i' => index, 'sig' => sig, 'pq_sig' => pq_sig }
    end

    # The elements of a share list as the reference spreads it (a string by character).
    def spread(shares)
      return shares.dup if shares.is_a?(Array)
      return shares.chars if shares.is_a?(String)

      raise TypeError, 'shares is not iterable'
    end

    def assemble_quorum_proof(set, shares) = { 'set_id' => set['id'], 'sigs' => spread(shares) }

    # Math.max(a, b) over a JSON value b (nil when the result is not a number)
    def js_max(a, b)
      n = V2JS.num?(b) ? b : AnalyzerJs.to_number(b)
      n.is_a?(Float) && n.nan? ? nil : [a, n].max
    end

    # Verify a quorum proof. `input`: {'set', 'proof', 'epoch', 'actionDigest', 'expectedSetId'?, 'requireHashBased'?}. Returns
    # {'ok' => true, 'signers', 'count', 'hashBased'} or {'ok' => false, 'reason', 'detail'?}; the first failing share wins.
    def verify_quorum(input)
      return no('malformed') unless rec?(input)

      loaded = load_quorum_set(input['set'])
      return no('bad-set') unless loaded['ok']

      set = loaded['set']
      n = set['signers'].length
      return no('set-mismatch') if input.key?('expectedSetId') && input['expectedSetId'] != set['id']
      return no('malformed') if !epoch?(input['epoch']) || !input['actionDigest'].is_a?(String)

      p = input['proof']
      return no('malformed') if !rec?(p) || !p['set_id'].is_a?(String) || !p['sigs'].is_a?(Array)
      return no('set-mismatch') if p['set_id'] != set['id']
      return no('too-many-signatures') if p['sigs'].length > n # before any signature work

      msg = quorum_message(set['id'], input['epoch'], input['actionDigest'])
      seen = {}
      hash_based = 0
      p['sigs'].each do |raw|
        return no('malformed') if !rec?(raw) || !raw['sig'].is_a?(String)
        return no('unknown-signer') if !V2JS.nonneg?(raw['i']) || raw['i'] >= n

        i = V2JS.ival(raw['i'])
        return no('duplicate-signer', 'detail' => i) if seen.key?(i)

        seen[i] = true
        e = set['signers'][i]
        return no('bad-signature', 'detail' => i) if SIG_SUITES[e['alg']][2] != raw.key?('pq_sig')

        share = { 'alg' => e['alg'], 'sig' => raw['sig'] }
        share['pq_sig'] = raw['pq_sig'] if raw.key?('pq_sig')
        return no('bad-signature', 'detail' => i) unless AtlasPca.suite_dispatch(share, e['ed'], msg, e['pq'])

        hash_based += 1 if hash_based?(e['alg'])
      end
      return no('below-threshold') if seen.size < set['t']

      k = js_max(set['minHashBased'], input['requireHashBased'].nil? ? 0 : input['requireHashBased'])
      return no('malformed') if k.nil? || !(k.is_a?(Integer) || (k.finite? && k == k.floor)) || k.abs > V2JS::MAX_SAFE_INT || k.negative?
      return no('diversity-unmet') if hash_based < k

      { 'ok' => true, 'signers' => seen.keys.sort, 'count' => seen.size, 'hashBased' => hash_based }
    rescue StandardError, SystemStackError
      no('malformed')
    end

    # True when the quorum approves `message` (bytes) at `epoch`. `opts`: {'expectedSetId'?, 'requireHashBased'?}.
    def verify_quorum_approval(set, proof, message, epoch, opts = {})
      return false unless message.is_a?(String)

      pins = rec?(opts) ? opts.slice('expectedSetId', 'requireHashBased') : {}
      verify_quorum({ 'set' => set, 'proof' => proof, 'epoch' => epoch, 'actionDigest' => quorum_action_digest(message) }.merge(pins))['ok']
    rescue StandardError, SystemStackError
      false
    end

    # The action the old quorum signs to hand over to the set `to_set_id` at `to_epoch`.
    def rotation_action_digest(to_set_id, to_epoch)
      AtlasPca.b64e(Digest::SHA384.digest(AtlasPca.canon_bytes({ 'kind' => ROTATION_KIND, 'to_set_id' => to_set_id, 'to_epoch' => to_epoch })))
    end

    # the reference's `from_epoch + 1` (a string epoch concatenates; such a certificate never verifies)
    def next_epoch(from_epoch) = from_epoch.is_a?(String) ? "#{from_epoch}1" : from_epoch + 1

    def build_rotation_cert(from, from_epoch, to, shares)
      { 'from_set_id' => from['id'], 'from_epoch' => from_epoch, 'to_set' => to, 'to_epoch' => next_epoch(from_epoch),
        'proof' => assemble_quorum_proof(from, shares) }
    end

    def sign_rotation_share(from, index, from_epoch, to, keys)
      sign_quorum_share(from, index, from_epoch, rotation_action_digest(to['id'], next_epoch(from_epoch)), keys)
    end

    # Verify a rotation chain from a genesis set and epoch: {'ok' => true, 'set', 'epoch', 'length'} or {'ok' => false, 'reason',
    # 'at'} (the failing link; -1 before any link).
    def verify_rotation_chain(genesis_set, genesis_epoch, chain)
      g = load_quorum_set(genesis_set)
      return no('bad-set', 'at' => -1) if !g['ok'] || !epoch?(genesis_epoch)
      return no('malformed', 'at' => -1) unless chain.is_a?(Array)
      return no('chain-too-long', 'at' => -1) if chain.length > MAX_CHAIN

      cur = g['set']
      epoch = V2JS.ival(genesis_epoch)
      chain.each_with_index do |c, n|
        return no('malformed', 'at' => n) if !rec?(c) || !c['from_set_id'].is_a?(String) || !epoch?(c['from_epoch']) || !epoch?(c['to_epoch'])
        return no('chain-broken', 'at' => n) if c['from_set_id'] != cur['id']
        return no('non-monotone-epoch', 'at' => n) if c['from_epoch'] != epoch || c['to_epoch'] != epoch + 1

        nxt = load_quorum_set(c['to_set'])
        return no('bad-rotation', 'at' => n) if !nxt['ok'] || nxt['set']['id'] == cur['id']

        v = verify_quorum({ 'set' => cur, 'proof' => c['proof'], 'epoch' => epoch,
                            'actionDigest' => rotation_action_digest(nxt['set']['id'], c['to_epoch']), 'expectedSetId' => cur['id'] })
        return no(v['reason'], 'at' => n) unless v['ok']

        cur = nxt['set']
        epoch = V2JS.ival(c['to_epoch'])
      end
      { 'ok' => true, 'set' => cur, 'epoch' => epoch, 'length' => chain.length }
    rescue StandardError, SystemStackError
      no('malformed', 'at' => -1)
    end

    # the reference's strict equality of two members (absent on both sides is equal; an object or array equals nothing)
    def same_member?(a, b, key)
      return !a.key?(key) && !b.key?(key) if !a.key?(key) || !b.key?(key)

      x = a[key]
      y = b[key]
      return false if x.is_a?(Hash) || x.is_a?(Array) || y.is_a?(Hash) || y.is_a?(Array)
      return x == y if V2JS.num?(x) && V2JS.num?(y)

      x.class == y.class && x == y
    end

    # Two certificates leave the same set and epoch for different sets (a fork). Pure structural comparison.
    def rotation_fork?(a, b)
      return false if !rec?(a) || !rec?(b) || !rec?(a['to_set']) || !rec?(b['to_set'])

      same_member?(a, b, 'from_set_id') && same_member?(a, b, 'from_epoch') && a['to_set']['id'].is_a?(String) &&
        b['to_set']['id'].is_a?(String) && a['to_set']['id'] != b['to_set']['id']
    end

    def share_bytes(e)
      spec = SIG_SUITES.fetch(e['alg'])
      spec[0] + (spec[2] ? PQ_PRIMS[spec[3]][1] : 0)
    end

    # Proof sizes in signature bytes: the t smallest and t largest shares, and the shares of `indices` when given (an unknown
    # index counts 0). There is no compact form: {'minBytes', 'maxBytes', 'chosenBytes'?, 't', 'compact' => false}.
    def quorum_proof_size(set, indices = MESH_UNSET)
      sizes = set['signers'].map { |e| share_bytes(e) }.sort
      t = set['t']
      r = { 'minBytes' => sizes.first(t).sum, 'maxBytes' => sizes.last(t).sum, 't' => t, 'compact' => false }
      unless MESH_UNSET.equal?(indices)
        raise TypeError, 'quorumProofSize: indices is a list' unless indices.is_a?(Array)

        r['chosenBytes'] = indices.sum do |i|
          found, e = AtlasPca.mesh_at(set['signers'], i)
          found ? share_bytes(e) : 0
        end
      end
      r
    end
  end

  PQ_QUORUM_MAX_SIGNERS = PqQuorum::MAX_SIGNERS
  PQ_QUORUM_MAX_CHAIN = PqQuorum::MAX_CHAIN
end
