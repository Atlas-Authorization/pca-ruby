# frozen_string_literal: true

require_relative 'js_compat'

# Key rotation and subtree revocation for capability chains, matching the TypeScript reference. A chain binds authority to
# keys, so rotating or losing a key means re-issuing what it carried under a fresh key and naming the old one in a revocation
# record a registry can act on. Re-issue uses the real builders (AtlasPca.mint_root / AtlasPca.delegate_cap) and carries
# exactly the caveats each replaced hop carried, so a re-issue can never widen authority. Keys are AtlasPca::KeyPair; chains
# and revocation records are JSON-shaped String-keyed Hashes with the reference's member names (capId, capIds, subtreeRoot,
# revokedAt ...). `now` is epoch milliseconds (default the clock).
module AtlasPca
  module Rotate
    module_function

    def now_ms = (Time.now.to_f * 1000).floor

    def pub(secret)
      raise TypeError, 'expected a KeyPair secret key' unless secret.is_a?(KeyPair)

      secret.public
    end

    def hop(chain, i, ctx)
      raise IndexError, "#{ctx}: no capability at index #{i} (chain length #{chain.length})" unless i >= 0 && i < chain.length

      c = chain[i]
      raise TypeError, "#{ctx}: a chain hop is not an object" unless c.is_a?(Hash)

      c
    end

    # The caveats a child appended beyond its parent (caveats are append-only, so re-delegating with this slice reproduces it).
    def appended_caveats(parent, child)
      pc = parent['caveats']
      cc = child['caveats']
      raise TypeError, 'malformed capability: caveats must be arrays' unless cc.is_a?(Array) && pc.is_a?(Array)
      raise ArgumentError, 'malformed chain: a child carries fewer caveats than its parent (not an attenuation)' if cc.length < pc.length

      cc[pc.length..]
    end

    def check_now!(now, ctx)
      return if now.nil?
      raise TypeError, "#{ctx}: now must be a finite number" unless Js.num?(now) && (now.is_a?(Integer) || now.finite?)
    end

    def require_non_empty!(chain, ctx)
      raise ArgumentError, "#{ctx}: empty chain" unless chain.is_a?(Array) && !chain.empty?
    end

    def new_holder_of(kp, what)
      raise TypeError, "expected a KeyPair for the #{what}" unless kp.is_a?(KeyPair)

      kp.public
    end

    # Rotate the AGENT (leaf holder) key: the leaf's parent re-signs the leaf, re-binding it to `new_key_pair` with the leaf's
    # exact caveats. `old_holder_secret` must be the leaf's issuer (the parent's holder); a root-only chain has no leaf to
    # re-issue. Returns {'chain', 'revocation'}.
    def rotate_agent_key(chain, old_holder_secret, new_key_pair, reason = nil, now = nil)
      require_non_empty!(chain, 'rotateAgentKey')
      raise ArgumentError, 'rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey' if chain.length < 2

      parent = hop(chain, chain.length - 2, 'rotateAgentKey')
      leaf = hop(chain, chain.length - 1, 'rotateAgentKey')
      signer_pub = pub(old_holder_secret)
      if signer_pub != leaf['issuer']
        raise ArgumentError, "rotateAgentKey: oldHolderSecret (pub #{signer_pub}) is not the leaf's issuer #{leaf['issuer']}; " \
                             'the leaf is re-signed by its parent holder (the leaf issuer)'
      end

      new_holder = new_holder_of(new_key_pair, 'new key')
      raise ArgumentError, 'rotateAgentKey: newKeyPair is the key being rotated out' if new_holder == leaf['holder']

      check_now!(now, 'rotateAgentKey')
      new_leaf = AtlasPca.delegate_cap(parent, old_holder_secret, to_holder: new_holder, added: appended_caveats(parent, leaf))
      {
        'chain' => chain[0...-1] + [new_leaf],
        'revocation' => { 'capId' => leaf['id'], 'holder' => leaf['holder'], 'issuer' => leaf['issuer'], 'capIds' => [leaf['id']],
                          'reason' => reason.nil? ? 'agent key rotated' : reason, 'revokedAt' => now.nil? ? now_ms : now }
      }
    end

    # Rotate the PRINCIPAL (root) key by re-rooting: mint a fresh root under `new_principal_key_pair` bound to the same holder
    # and caveats, then re-issue every downstream hop (`holder_secrets`: each non-root hop's issuer secret, in chain order).
    # Pass the full `chain` or, for a root-only chain, just `old_root`. Returns {'chain', 'revocation'} (the whole old chain is
    # revoked).
    def rotate_principal_key(old_principal_secret, new_principal_key_pair, chain = nil, old_root = nil, holder_secrets = nil, reason = nil, now = nil)
      chain = Js.truthy?(old_root) ? [old_root] : [] if chain.nil?
      require_non_empty!(chain, 'rotatePrincipalKey')
      old_root = hop(chain, 0, 'rotatePrincipalKey')
      raise ArgumentError, 'rotatePrincipalKey: chain[0] is not a root (it has a parent)' if old_root.key?('parent')

      old_pub = pub(old_principal_secret)
      if old_pub != old_root['issuer']
        raise ArgumentError, "rotatePrincipalKey: oldPrincipalSecret (pub #{old_pub}) is not the root's issuer #{old_root['issuer']}"
      end

      secrets = holder_secrets || []
      if secrets.length != chain.length - 1
        raise ArgumentError, "rotatePrincipalKey: expected #{chain.length - 1} holderSecrets (one per non-root hop), got #{secrets.length}"
      end
      if new_holder_of(new_principal_key_pair, 'new principal key') == old_root['issuer']
        raise ArgumentError, 'rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out'
      end

      check_now!(now, 'rotatePrincipalKey')
      new_chain = [AtlasPca.mint_root(new_principal_key_pair, old_root['holder'], old_root['caveats'])]
      (1...chain.length).each do |i|
        old_parent = hop(chain, i - 1, 'rotatePrincipalKey')
        old_child = hop(chain, i, 'rotatePrincipalKey')
        signer = secrets[i - 1]
        signer_pub = pub(signer)
        if signer_pub != old_child['issuer']
          raise ArgumentError, "rotatePrincipalKey: holderSecret for hop #{i} (pub #{signer_pub}) is not that hop's issuer #{old_child['issuer']}"
        end

        new_chain << AtlasPca.delegate_cap(new_chain[i - 1], signer, to_holder: old_child['holder'], added: appended_caveats(old_parent, old_child))
      end
      {
        'chain' => new_chain,
        'revocation' => { 'capId' => old_root['id'], 'issuer' => old_root['issuer'], 'holder' => old_root['holder'],
                          'subtreeRoot' => old_root['id'], 'capIds' => chain.map { |c| c.is_a?(Hash) ? c['id'] : nil },
                          'reason' => reason.nil? ? 'principal key rotated (re-root)' : reason, 'revokedAt' => now.nil? ? now_ms : now }
      }
    end

    def index_of_holder(chain, holder) = (0...chain.length).find { |i| hop(chain, i, 'revokeAndReissueSubtree')['holder'] == holder } || -1

    # Treat `compromised_holder` as COMPROMISED: revoke the hop it first holds and every descendant, and re-issue one delegation
    # from the nearest safe ancestor to `new_key_pair` carrying the deepest leaf's caveats (never wider). `ancestor_secret` is
    # the safe ancestor's holder secret. Raises when the holder is not in the chain or is the root holder. Returns
    # {'chain', 'revocation'}.
    def revoke_and_reissue_subtree(chain, compromised_holder, new_key_pair, ancestor_secret, reason = nil, now = nil)
      require_non_empty!(chain, 'revokeAndReissueSubtree')
      idx = index_of_holder(chain, compromised_holder)
      raise ArgumentError, "revokeAndReissueSubtree: holder #{compromised_holder} is not in the chain" if idx.negative?
      if idx.zero?
        raise ArgumentError, 'revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); ' \
                             'rotate the root with rotatePrincipalKey'
      end

      ancestor = hop(chain, idx - 1, 'revokeAndReissueSubtree')
      subtree_root = hop(chain, idx, 'revokeAndReissueSubtree')
      leaf = hop(chain, chain.length - 1, 'revokeAndReissueSubtree')
      ancestor_pub = pub(ancestor_secret)
      if ancestor_pub != ancestor['holder']
        raise ArgumentError, "revokeAndReissueSubtree: ancestorSecret (pub #{ancestor_pub}) is not the safe ancestor's holder #{ancestor['holder']}"
      end

      new_holder = new_holder_of(new_key_pair, 'new key')
      if chain[idx..].any? { |c| c.is_a?(Hash) && c['holder'] == new_holder }
        raise ArgumentError, 'revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree'
      end

      check_now!(now, 'revokeAndReissueSubtree')
      new_hop = AtlasPca.delegate_cap(ancestor, ancestor_secret, to_holder: new_holder, added: appended_caveats(ancestor, leaf))
      {
        'chain' => chain[0...idx] + [new_hop],
        'revocation' => { 'capId' => subtree_root['id'], 'holder' => compromised_holder, 'issuer' => subtree_root['issuer'],
                          'subtreeRoot' => subtree_root['id'], 'capIds' => chain[idx..].map { |c| c['id'] },
                          'reason' => reason.nil? ? 'delegation subtree compromised' : reason, 'revokedAt' => now.nil? ? now_ms : now }
      }
    end

    # revoke_and_reissue_subtree end to end: one revocation record PER capability in the compromised subtree (root to leaf)
    # plus the re-issued chain. Returns {'revocations', 'reissued'}.
    def compromised_key_flow(chain, compromised_holder, new_key_pair, ancestor_secret, reason = nil, now = nil)
      require_non_empty!(chain, 'compromisedKeyFlow')
      idx = index_of_holder(chain, compromised_holder)
      raise ArgumentError, "compromisedKeyFlow: holder #{compromised_holder} is not in the chain" if idx.negative?

      reissued = revoke_and_reissue_subtree(chain, compromised_holder, new_key_pair, ancestor_secret, reason, now)['chain']
      subtree_root = hop(chain, idx, 'compromisedKeyFlow')
      at = now.nil? ? now_ms : now
      why = reason.nil? ? 'delegation subtree compromised' : reason
      {
        'revocations' => chain[idx..].map do |c|
          { 'capId' => c['id'], 'holder' => c['holder'], 'issuer' => c['issuer'], 'subtreeRoot' => subtree_root['id'],
            'capIds' => [c['id']], 'reason' => why, 'revokedAt' => at }
        end,
        'reissued' => reissued
      }
    end

    # Revoke what a rotation replaced, all or nothing. `sink` has revoke(input), unrevoke(key) and lookup(kind, value) (an
    # AtlasPca::Revoke::RevocationRegistry fits). Every capability id the record(s) cover is revoked; if any revoke fails, the
    # ones this call added are removed again and the error is re-raised. Only capability ids are revoked (revoking the old
    # holder key would deny the re-issued chain). Refuses, before touching the sink, a record naming no capability id and a
    # re-issued chain that shares an id with what is being revoked. Returns the revoked ids.
    def apply_rotation(sink, records, reissued = nil)
      todo = {}
      (records.is_a?(Array) ? records : [records]).each do |r|
        raise TypeError, 'applyRotation: a record is null' if r.nil?

        rd = r.is_a?(Hash) ? r : {}
        ids = if !rd['capIds'].nil?
                # the reference iterates a string character by character; a string here is refused instead
                raise TypeError, 'applyRotation: capIds must be a list' unless rd['capIds'].is_a?(Array)

                rd['capIds']
              else
                rd.key?('capId') ? [rd['capId']] : []
              end
        ids.each do |i|
          raise TypeError, 'applyRotation: a record names an invalid capability id' unless i.is_a?(String) && !i.empty?

          todo[i] = rd unless todo.key?(i)
        end
      end
      raise ArgumentError, 'applyRotation: the record names no capability to revoke' if todo.empty?
      raise TypeError, 'applyRotation: reissued must be a chain' unless reissued.nil? || reissued.is_a?(Array)

      kept = (reissued || []).map do |c|
        raise TypeError, 'applyRotation: a re-issued hop is null' if c.nil?

        c.is_a?(Hash) ? c['id'] : nil
      end
      raise ArgumentError, 'applyRotation: the re-issued chain contains a capability that is being revoked' if todo.keys.any? { |i| kept.include?(i) }

      added = []
      begin
        todo.each do |i, r|
          added << i if sink.lookup('cap', i).nil?
          sink.revoke({ 'kind' => 'cap', 'value' => i, 'reason' => r['reason'], 'revokedAt' => r['revokedAt'] })
        end
      rescue StandardError
        added.each do |i|
          sink.unrevoke({ 'kind' => 'cap', 'value' => i })
        rescue StandardError # best effort: the original failure is the one to report
          nil
        end
        raise
      end
      todo.keys
    end
  end
end
