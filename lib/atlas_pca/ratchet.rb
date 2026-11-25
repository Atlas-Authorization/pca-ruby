# frozen_string_literal: true

require 'openssl'
require_relative 'js_compat'
require_relative 'ratchet_group'
require_relative 'ratchet_accumulator'

# The PCA Capability Ratchet, matching the TypeScript reference (@atlasauth/pca-ratchet): puncturable forward-secure one-time
# capability keys (a GGM tree of Ed25519 leaf keys under a Merkle-root commitment), the verifier-side spent-leaf and
# attested-risk bindings, and the adapters to the PCActn counter and the risk budget. The homomorphic accumulator lives in
# ratchet_accumulator.rb and is re-exported here. Wire shapes are the reference's JSON shapes (camelCase members): a ratchet
# state is a Hash {'depth', 'leafCount', 'rootCommitment', 'leafPubKeys', 'covering'} whose covering maps "level:node" to
# {'level', 'nodeIndex', 'seed'}. Seeds and messages are binary Strings. Leaf signing is OpenSSL Ed25519 (constant time);
# the accumulator runs on libsodium (see ratchet_group.rb).
module AtlasPca
  module Ratchet
    Acc = RatchetAccumulator
    AccumulatorError = Acc::AccumulatorError
    N_BITS = Acc::N_BITS
    MAX_PROVABLE_CEILING = Acc::MAX_PROVABLE_CEILING
    MAX_RATCHET_DEPTH = 20
    RISK_SCALE = 1000

    # code: invalid_depth | invalid_seed | leaf_out_of_range | leaf_punctured
    class RatchetError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    %i[add_commitments commit_risk open_commitment prove_budget prove_risk_range verify_budget verify_bounded_budget
       verify_risk_range].each { |m| define_singleton_method(m) { |*args| Acc.public_send(m, *args) } }

    PRG_DOMAIN = 'atlas-pca-ratchet/ggm-prg/v1'
    LEAFKEY_DOMAIN = 'atlas-pca-ratchet/ggm-leafkey/v1'
    ROOT_DOMAIN = 'atlas-pca-ratchet/ggm-root/v1'
    NULLIFIER_DOMAIN = "atlas-pca-ratchet/nullifier/v1\0"
    SIG_DOMAIN = "atlas-pca-ratchet/leaf-sig/v1\0"
    ATTEST_DOMAIN = "atlas-pca-ratchet/risk-attestation/v1\0"
    NANO = 1_000_000

    module_function

    # ---- helpers mirroring JS number semantics ----

    def integer?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor)

    # JS ToNumber for the JSON types (null 0, true 1, numeric strings, arrays by their string form), NaN otherwise.
    def to_number(x)
      case x
      when nil, false then 0.0
      when true then 1.0
      when Integer then x.to_f
      when Float then x
      when String then AtlasPca.js_string_to_number(x)
      when Array then AtlasPca.js_string_to_number(Js.string(x))
      else Float::NAN
      end
    end

    def u64(x) = [x & 0xFFFFFFFFFFFFFFFF].pack('Q>')
    def be32(s) = [s.bytesize].pack('N')
    def text(x) = x.is_a?(String) ? Js.utf8(x) : raise(TypeError, 'expected a string')
    def bytes(x) = x.is_a?(String) ? x.b : raise(TypeError, 'expected bytes')

    # ---- GGM puncturable PRF tree ----

    def hmac(key, msg) = OpenSSL::HMAC.digest('SHA256', key.b, msg.b)
    def prg_left(seed) = hmac(seed, "#{PRG_DOMAIN}\x00")
    def prg_right(seed) = hmac(seed, "#{PRG_DOMAIN}\x01")
    def root_seed(seed) = hmac(seed, ROOT_DOMAIN)
    def leaf_signing_seed(leaf_seed) = hmac(leaf_seed, LEAFKEY_DOMAIN)
    def ed_key(seed) = OpenSSL::PKey.new_raw_private_key('ED25519', seed.b)
    def ed_sign(seed, msg) = ed_key(seed).sign(nil, msg.b)
    def leaf_public_key(leaf_seed) = AtlasPca.b64e(ed_key(leaf_signing_seed(leaf_seed)).raw_public_key)

    # floor(leaf / 2^k) with the leaf coerced as JS does (a fraction or a numeric string still lands in a subtree)
    def covers(level, node_index, leaf_index, depth)
      q = to_number(leaf_index) / (2**(depth - level)).to_f
      q.finite? && q.floor == node_index
    end

    def descend_bit(level, leaf_index, depth) = (leaf_index / (2**(depth - level - 1))) % 2 # a validated integer leaf only

    def derive_leaf_seed(node, leaf_index, depth)
      seed = node['seed']
      (node['level']...depth).each { |level| seed = descend_bit(level, leaf_index, depth).zero? ? prg_left(seed) : prg_right(seed) }
      seed
    end

    # The off-path siblings covering every leaf under `node` except `leaf_index`; on-path seeds are dropped.
    def puncture_siblings(node, leaf_index, depth)
      out = []
      seed = node['seed']
      node_index = node['nodeIndex']
      (node['level']...depth).each do |level|
        bit = descend_bit(level, leaf_index, depth)
        left = prg_left(seed)
        right = prg_right(seed)
        child_base = node_index * 2
        out << { 'level' => level + 1, 'nodeIndex' => child_base + (1 - bit), 'seed' => bit.zero? ? right : left }
        seed = bit.zero? ? left : right
        node_index = child_base + bit
      end
      out
    end

    def all_leaf_public_keys(root, depth)
      out = Array.new(2**depth)
      recurse = lambda do |seed, level, base|
        if level == depth
          out[base] = leaf_public_key(seed)
        else
          recurse.call(prg_left(seed), level + 1, base)
          recurse.call(prg_right(seed), level + 1, base + (2**(depth - level - 1)))
        end
      end
      recurse.call(root, 0, 0)
      out
    end

    def cover_key(level, node_index) = "#{level}:#{node_index}"

    # ---- ratchet ----

    # b64u(sha256(domain || len32(root) || root || index64)): what a verifier records to detect leaf reuse.
    def leaf_nullifier(root_commitment, leaf_index)
      root = text(root_commitment)
      AtlasPca.b64e(AtlasPca.sha(NULLIFIER_DOMAIN.b + be32(root) + root + u64(Js.bigint(leaf_index))))
    end

    def leaf_sig_message(leaf_index, message) = SIG_DOMAIN.b + u64(Js.bigint(leaf_index)) + bytes(message)

    # Build a ratchet from >= 32 bytes of entropy and a tree depth in [1, MAX_RATCHET_DEPTH]: {'rootCommitment', 'state'}.
    def derive_ratchet_root(seed, depth)
      raise RatchetError.new('invalid_depth', "depth must be an integer in [1, #{MAX_RATCHET_DEPTH}]") unless integer?(depth) && depth >= 1 && depth <= MAX_RATCHET_DEPTH
      raise RatchetError.new('invalid_seed', 'seed must be bytes of at least 32 bytes') unless seed.is_a?(String) && seed.encoding == Encoding::BINARY && seed.bytesize >= 32

      depth = depth.to_i
      root = root_seed(seed)
      leaf_pub_keys = all_leaf_public_keys(root, depth)
      root_commitment = AtlasPca.merkle_root(leaf_pub_keys)
      covering = { cover_key(0, 0) => { 'level' => 0, 'nodeIndex' => 0, 'seed' => root } }
      { 'rootCommitment' => root_commitment,
        'state' => { 'depth' => depth, 'leafCount' => 2**depth, 'rootCommitment' => root_commitment,
                     'leafPubKeys' => leaf_pub_keys, 'covering' => covering } }
    end

    def find_covering(state, leaf_index) = state['covering'].each_value.find { |n| covers(n['level'], n['nodeIndex'], leaf_index, state['depth']) }

    def merkle_proof(leaves, index)
      path = []
      prove = lambda do |hs, idx|
        next if hs.length == 1

        k = AtlasPca.split_point(hs.length)
        if idx < k
          prove.call(hs[0, k], idx)
          path << { 'side' => 'R', 'hash' => AtlasPca.b64e(AtlasPca.build(hs[k..])) }
        else
          prove.call(hs[k..], idx - k)
          path << { 'side' => 'L', 'hash' => AtlasPca.b64e(AtlasPca.build(hs[0, k])) }
        end
      end
      prove.call(leaves.map { |x| AtlasPca.leaf_hash(x) }, index)
      { 'index' => index, 'size' => leaves.length, 'path' => path }
    end

    # Sign at a leaf, then puncture it: {'signature', 'newState'}. Raises RatchetError for an out-of-range or spent leaf.
    def sign_at_leaf(state, leaf_index, message)
      unless integer?(leaf_index) && leaf_index >= 0 && leaf_index < state['leafCount']
        raise RatchetError.new('leaf_out_of_range', "leaf #{leaf_index} is out of range [0, #{state['leafCount']})")
      end

      leaf_index = leaf_index.to_i
      node = find_covering(state, leaf_index)
      raise RatchetError.new('leaf_punctured', "leaf #{leaf_index} is already punctured (spent) and cannot sign") if node.nil?

      leaf_seed = derive_leaf_seed(node, leaf_index, state['depth'])
      ed_sig = AtlasPca.b64e(ed_sign(leaf_signing_seed(leaf_seed), leaf_sig_message(leaf_index, message)))
      leaf_pub = leaf_public_key(leaf_seed)
      merkle_path = merkle_proof(state['leafPubKeys'].dup, leaf_index)
      covering = state['covering'].dup
      covering.delete(cover_key(node['level'], node['nodeIndex']))
      puncture_siblings(node, leaf_index, state['depth']).each { |sib| covering[cover_key(sib['level'], sib['nodeIndex'])] = sib }
      { 'signature' => { 'edSig' => ed_sig, 'leafPubKey' => leaf_pub, 'merklePath' => merkle_path,
                         'nullifier' => leaf_nullifier(state['rootCommitment'], leaf_index) },
        'newState' => state.merge('covering' => covering) }
    end

    # Offline check against the root commitment; never raises, malformed input is false.
    def verify_leaf_signature(root_commitment, leaf_index, message, signature)
      return false unless signature.is_a?(Hash)

      ed_sig = signature['edSig']
      leaf_pub = signature['leafPubKey']
      merkle_path = signature['merklePath']
      nullifier = signature['nullifier']
      return false unless nullifier.is_a?(String) && nullifier == leaf_nullifier(root_commitment, leaf_index)
      return false unless ed_sig.is_a?(String) && leaf_pub.is_a?(String) && merkle_path.is_a?(Hash)

      mp_index = merkle_path['index']
      return false unless Js.num?(mp_index) && Js.num?(leaf_index) && mp_index == leaf_index
      # the root commits under sha256: a proof naming any other hash suite cannot belong to it (the core verifier ignores the member)
      return false if merkle_path.key?('hash_suite') && merkle_path['hash_suite'] != 'sha256'
      return false unless AtlasPca.verify_b64u(leaf_pub, leaf_sig_message(leaf_index, message), ed_sig)

      AtlasPca.verify_inclusion(root_commitment, merkle_path, leaf_pub)
    rescue StandardError
      false
    end

    def available_leaves(state)
      out = []
      state['covering'].each_value do |node|
        span = 2**(state['depth'] - node['level'])
        base = node['nodeIndex'] * span
        out.concat((base...(base + span)).to_a)
      end
      out.sort
    end

    def leaf_available?(state, leaf_index) = !find_covering(state, leaf_index).nil?

    # ---- adapters: ratchet leaf <-> PCActn counter, accumulator units <-> RiskPolicy budget ----

    def counter_to_leaf_index(counter, depth)
      raise RatchetError.new('invalid_depth', "depth must be an integer in [1, #{MAX_RATCHET_DEPTH}]") unless integer?(depth) && depth >= 1 && depth <= MAX_RATCHET_DEPTH
      raise RatchetError.new('leaf_out_of_range', 'counter must be a non-negative safe integer') unless safe_index?(counter)
      raise RatchetError.new('leaf_out_of_range', "counter #{counter} exceeds the ratchet capacity 2^#{depth}") if counter >= 2**depth

      counter.to_i
    end

    def safe_index?(x) = Js.safe_integer?(x) && !Js.neg_zero?(x) && x >= 0

    def leaf_index_to_counter(leaf_index)
      raise RatchetError.new('leaf_out_of_range', 'leafIndex must be a non-negative safe integer') unless safe_index?(leaf_index)

      leaf_index.to_i
    end

    def leaf_index_for_action(actn, depth)
      raise TypeError, 'actn must be an object' unless actn.is_a?(Hash)

      counter_to_leaf_index(actn['counter'], depth)
    end

    def js_round(v)
      f = v.floor
      v - f >= 0.5 ? f + 1 : f
    end

    def check_risk!(r)
      return if Js.num?(r) && (r.is_a?(Integer) || r.finite?) && r >= 0

      raise AccumulatorError.new('invalid_value', 'risk must be a finite number >= 0')
    end

    # Quantize a risk score to integer accumulator units, rounding UP so the sum never under-counts (float noise tolerated).
    def risk_to_units(r)
      check_risk!(r)
      v = r * RISK_SCALE
      nearest = js_round(v)
      (v - nearest).abs <= 1e-9 * [1, v].max ? nearest : v.ceil
    end

    # Carry-forward quantizer: the running total of emitted units is always ceil(sum(true risk) * SCALE).
    class RiskQuantizer
      attr_reader :total_units

      def initialize
        @nano = 0
        @total_units = 0
      end

      def next(r)
        Ratchet.check_risk!(r)
        @nano += (r * RISK_SCALE * 1e6 - 1e-3).ceil
        total = (@nano + NANO - 1) / NANO
        out = total - @total_units
        @total_units = total
        out
      end
    end

    # The accumulator ceiling in units: floor(safety_bound(policy) * RISK_SCALE).
    def budget_ceiling_units(policy)
      raise TypeError, 'policy must be an object' unless policy.is_a?(Hash)

      # JS arithmetic on the members: a missing or non-numeric bMax is NaN (refused below), a missing kappa is not > 0 (bound 0)
      b_max = policy.key?('bMax') ? to_number(policy['bMax']) : Float::NAN
      kappa = policy.key?('kappa') ? to_number(policy['kappa']) : Float::NAN
      bound = if kappa > 0
                (b_max.nan? ? Float::NAN : (b_max > 0 ? b_max : 0.0)) / kappa
              else
                0.0
              end
      raise AccumulatorError.new('invalid_value', 'safety bound (bMax/kappa) must be finite and >= 0') unless bound.finite? && bound >= 0

      (bound * RISK_SCALE).floor
    end

    # ---- verifier-side bindings ----

    # In-process spent-leaf store (first claim wins); use a shared store for a verifier fleet.
    class MemorySpentLeafStore
      def initialize
        @seen = {}
        @lock = Mutex.new
      end

      def claim(nullifier, record)
        @lock.synchronize do
          prev = @seen[nullifier]
          if prev.nil?
            @seen[nullifier] = record
            { 'first' => true }
          else
            { 'first' => false, 'record' => prev }
          end
        end
      end
    end

    def memory_spent_leaf_store = MemorySpentLeafStore.new

    def message_digest(leaf_index, message)
      idx = integer?(leaf_index) ? leaf_index.to_i : leaf_index
      "#{AtlasPca.b64e(AtlasPca.sha(bytes(message)))}@#{idx}"
    end

    # Verify a leaf signature and enforce one-time use: a second signature at a leaf is `replay` (same message) or
    # `equivocation` (different message). Fail closed: a store that raises denies with `store-error`.
    def verify_leaf_signature_once(root_commitment, leaf_index, message, signature, store)
      return { 'ok' => false, 'reason' => 'invalid' } unless verify_leaf_signature(root_commitment, leaf_index, message, signature)

      nullifier = leaf_nullifier(root_commitment, leaf_index)
      mine = message_digest(leaf_index, message)
      begin
        r = store.claim(nullifier, mine)
        raise TypeError, 'claim must return an object' unless r.is_a?(Hash)
        return { 'ok' => true } if r['first']
        return { 'ok' => false, 'reason' => 'replay', 'nullifier' => nullifier } if r['record'] == mine

        { 'ok' => false, 'reason' => 'equivocation', 'nullifier' => nullifier,
          'firstMessageDigest' => r['record'], 'secondMessageDigest' => mine }
      rescue StandardError
        { 'ok' => false, 'reason' => 'store-error' }
      end
    end

    def attest_message(action_digest, commitment)
      a = text(action_digest)
      c = text(commitment)
      ATTEST_DOMAIN.b + be32(a) + a + be32(c) + c
    end

    # Risk authority side: commit to the risk, prove its range, and sign (action_digest, commitment).
    def issue_risk_commitment(risk, action_digest, authority_secret_key)
      c = Acc.commit_risk(risk)
      range_proof = Acc.prove_risk_range(risk, c['blinding'])
      sig = AtlasPca.b64e(ed_sign(bytes(authority_secret_key), attest_message(action_digest, c['commitment'])))
      { 'commitment' => c['commitment'], 'blinding' => c['blinding'], 'rangeProof' => range_proof,
        'attestation' => { 'actionDigest' => action_digest, 'sig' => sig } }
    end

    def verify_risk_attestation(commitment, attestation, authority_public_key)
      return false unless attestation.is_a?(Hash)

      digest = attestation['actionDigest']
      sig = attestation['sig']
      return false unless digest.is_a?(String) && sig.is_a?(String)

      AtlasPca.verify_b64u(authority_public_key, attest_message(digest, commitment), sig)
    rescue StandardError
      false
    end

    # Every item must carry a valid authority attestation for exactly the expected digest and commitment, then the
    # bounded-budget proof must hold. Never raises.
    def verify_attested_budget(items, expected_action_digests, authority_public_key, b_max, budget_proof)
      return false unless items.is_a?(Array) && expected_action_digests.is_a?(Array) && items.length == expected_action_digests.length
      return false unless items.all?(Hash)

      items.each_with_index do |item, i|
        att = item['attestation']
        return false unless att.is_a?(Hash) && att['actionDigest'] == expected_action_digests[i]
        return false unless verify_risk_attestation(item['commitment'], att, authority_public_key)
      end
      Acc.verify_bounded_budget(items.map { |i| i['commitment'] }, items.map { |i| i['rangeProof'] }, b_max, budget_proof)
    rescue StandardError
      false
    end
  end
end
