# frozen_string_literal: true

require 'json'
require_relative 'private_file'

module AtlasPca
  # The issuing side of the agent mesh (the reference's `mesh` and `durable-mesh-witness`): an independent log witness (MeshWitness) with its
  # durable stores, the issuer-side domain (MeshDomain: delegation log, revocation set, head publication, per-hop evidence), the sorted
  # revocation set (RevocationSet) and RFC 9162 consistency proofs. Verification of a whole proof is verify_mesh_proof; signing the leaf
  # action and assembling the proof are in signers_more. Records are String-keyed Hashes; keys are AtlasPca::KeyPair.
  MESH_DEFAULT_MAX_CLOCK_SKEW_MS = 60_000
  MESH_MAX_REV_IDS = 1_000_000

  # Id used in a domain's revocation set to revoke an agent KEY (kills every capability it issues).
  def self.key_revocation_id(agent_public) = "key:#{agent_public.is_a?(String) ? agent_public : Predicates.js_string(agent_public)}"

  # RFC 6962 SUBPROOF(m, D[n], true): the consistency proof between the first `old_size` and the first `new_size` commits.
  def self.mesh_consistency_proof(commits, old_size, new_size = nil)
    new_size = commits.length if new_size.nil?
    ok = ->(x) { x.is_a?(Integer) }
    raise RangeError, 'consistencyProof: invalid sizes' if !ok.call(old_size) || !ok.call(new_size) || old_size.negative? || old_size > new_size || new_size > commits.length

    out = []
    sub = nil
    sub = lambda do |m, hs, b|
      n = hs.length
      if m == n
        out << build(hs) unless b
        next
      end
      k = 1
      k *= 2 while k * 2 < n
      if m <= k
        sub.call(m, hs[0, k], b)
        out << build(hs[k..])
      else
        sub.call(m - k, hs[k..], false)
        out << build(hs[0, k])
      end
    end
    sub.call(old_size, commits[0, new_size].map { |c| leaf_hash(c) }, true) if old_size.positive? && old_size < new_size
    { 'oldSize' => old_size, 'newSize' => new_size, 'path' => out.map { |h| b64e(h) } }
  end

  # A sorted set of revoked ids (UTF-8 byte order). `root` is bound to the size, so a prefix of the set never has the full root.
  class RevocationSet
    def initialize(initial = [])
      @ids = []
      initial.each { |i| revoke(i) }
    end

    def size = @ids.length

    # Idempotent. True when newly revoked.
    def revoke(rid)
      raise TypeError, 'revoke: id must be a string' unless rid.is_a?(String)

      lo = lower_bound(rid)
      return false if lo < @ids.length && @ids[lo] == rid

      @ids.insert(lo, rid)
      true
    end

    def has?(rid)
      lo = lower_bound(rid)
      lo < @ids.length && @ids[lo] == rid
    end

    # Sorted revoked ids (a copy).
    def list = @ids.dup

    def root = IntentV2.bind_root(@ids.length, @ids.empty? ? IntentV2.empty_tree : AtlasPca.merkle_root(@ids))

    def membership_proof(rid)
      lo = lower_bound(rid)
      raise ArgumentError, 'membershipProof: id is not revoked' unless lo < @ids.length && @ids[lo] == rid

      Grants.merkle_proof(@ids, lo)
    end

    # Raises when the id IS revoked (no such proof can exist).
    def non_membership_proof(rid)
      raise TypeError, 'not a string' unless rid.is_a?(String)
      raise ArgumentError, 'nonMembershipProof: id is revoked' if has?(rid)

      lo = lower_bound(rid)
      p = { 'size' => @ids.length }
      p['lo'] = { 'id' => @ids[lo - 1], 'proof' => Grants.merkle_proof(@ids, lo - 1) } if lo.positive?
      p['hi'] = { 'id' => @ids[lo], 'proof' => Grants.merkle_proof(@ids, lo) } if lo < @ids.length
      p
    end

    private

    def lower_bound(rid)
      lo = 0
      hi = @ids.length
      while lo < hi
        mid = (lo + hi) >> 1
        if (@ids[mid].b <=> rid.b).negative? then lo = mid + 1
        else hi = mid
        end
      end
      lo
    end
  end

  # In-process witness store (a test double, and the default when no store is given). It does not survive a restart.
  class MemoryMeshWitnessStore
    def initialize
      @state = nil
    end

    def load = @state.nil? ? nil : JSON.parse(@state)
    def save(state) = (@state = JSON.generate(state))
  end

  # A file-backed witness store. Every save writes a temporary file, fsyncs it, renames it over the real file and fsyncs the directory, so a
  # crash leaves the old state or the new one, never a torn file. The file carries a digest of its state: a file that does not parse, has the
  # wrong shape or fails the digest makes `load` raise (a witness never starts empty over a damaged file). A missing file is a first run.
  # Single process: two witnesses must not share one file.
  class FileMeshWitnessStore
    def initialize(path)
      @path = path
    end

    def load
      return nil unless File.exist?(@path)

      doc = begin
        JSON.parse(File.read(@path, encoding: 'UTF-8'))
      rescue StandardError
        raise ArgumentError, 'FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty'
      end
      unless doc.is_a?(Hash) && doc['v'] == 1 && doc['digest'].is_a?(String) && doc['state'].is_a?(Hash)
        raise ArgumentError, 'FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty'
      end
      raise ArgumentError, 'FileMeshWitnessStore: the state file fails its digest; refusing to start empty' if AtlasPca.hash_canonical(doc['state']) != doc['digest']

      doc['state']
    end

    def save(state)
      body = JSON.generate({ 'v' => 1, 'state' => state, 'digest' => AtlasPca.hash_canonical(state) })
      tmp = "#{@path}.tmp"
      AtlasPca::PrivateFile.open(tmp, File::WRONLY | File::CREAT | File::TRUNC) do |f|
        f.write(body)
        f.fsync
      end
      File.rename(tmp, @path)
      begin
        File.open(File.dirname(File.expand_path(@path)), File::RDONLY, &:fsync)
      rescue SystemCallError, IOError
        nil # some platforms cannot fsync a directory; the rename above is already atomic
      end
    end
  end

  # An independent log witness. It cosigns a domain head only if (1) the domain signed it, (2) it is an RFC 9162-verified append-only extension
  # of the last head THIS witness cosigned for that domain, (3) its revocation list reproduces `rev_root` and is a superset of the previously
  # cosigned list, and (4) the timestamp does not regress (nor run ahead of the witness's own clock, when configured). State is committed only
  # after every check passes (and after the store saved it). First sight of a domain is trust-on-first-use.
  class MeshWitness
    attr_reader :id

    # `secret` is the witness's KeyPair; `store` (#load / #save(state)) is durable memory (a corrupt state raises: the witness never starts empty
    # over damaged memory); `clock` (-> ms) and `max_clock_skew_ms` refuse heads from the witness's future.
    def initialize(secret, store: nil, clock: nil, max_clock_skew_ms: nil)
      @secret = secret
      @store = store
      @clock = clock
      @skew = max_clock_skew_ms.nil? ? MESH_DEFAULT_MAX_CLOCK_SKEW_MS : max_clock_skew_ms
      @id = secret.public
      @seen = {}
      loaded = store&.load
      import_state(loaded) unless loaded.nil?
    end

    # The newest head this witness cosigned for `domain` (what a domain must prove consistency from).
    def last_seen(domain)
      s = @seen[domain]
      s ? s['head'].dup : nil
    end

    # Cosign a head: `req` is {'head' => CosignedHead, 'consistency'?, 'rev_ids'}. Raises (and changes nothing) if any rule is violated.
    def cosign(req)
      ch = req.is_a?(Hash) ? req['head'] : nil
      raise ArgumentError, 'witness: malformed head' if !ch.is_a?(Hash) || AtlasPca.mesh_valid_head(ch['head']).nil? || !ch['sig'].is_a?(String)

      h = ch['head']
      raise ArgumentError, 'witness: head not signed by its domain' unless AtlasPca.verify_b64u(h['domain'], AtlasPca.mesh_msg(AtlasPca::MESH_HEAD_DOMAIN, h), ch['sig'])
      raise ArgumentError, 'witness: head timestamp is in the future' if @clock && !(AtlasPca.mesh_fin?(clk = @clock.call) && AtlasPca.mesh_fin?(@skew) && h['timestamp'] <= clk + @skew)

      ids = req['rev_ids']
      raise ArgumentError, 'witness: malformed revocation list' if !ids.is_a?(Array) || ids.length > MESH_MAX_REV_IDS || !ids.all? { |i| i.is_a?(String) }

      rs = RevocationSet.new(ids)
      raise ArgumentError, 'witness: revocation list does not match head' if rs.size != h['rev_size'] || rs.root != h['rev_root']

      prev = @seen[h['domain']]
      unless prev.nil?
        why = AtlasPca.mesh_check_head_advance(prev['head'], h, req['consistency'])
        raise ArgumentError, "witness: #{why}" if why
        raise ArgumentError, 'witness: timestamp regresses' unless h['timestamp'] >= prev['head']['timestamp']

        now = rs.list
        raise ArgumentError, 'witness: revocation set drops a previously cosigned revocation' unless prev['rev'].all? { |i| now.include?(i) }
      end
      unless @store.nil?
        nxt = @seen.merge(h['domain'] => { 'head' => h.dup, 'rev' => rs.list })
        begin
          @store.save(state_of(nxt)) # persist first, commit to memory second
        rescue StandardError
          raise ArgumentError, 'witness: could not persist state; refusing to cosign'
        end
      end
      @seen[h['domain']] = { 'head' => h.dup, 'rev' => rs.list }
      { 'witness' => @id, 'sig' => AtlasPca.b64e(@secret.sign(AtlasPca.mesh_msg(AtlasPca::MESH_COSIG_DOMAIN, h))) }
    end

    # Memory for persistence, in a deterministic order.
    def export_state = state_of(@seen)

    # Restore memory; each record must be internally consistent (its revocation list reproduces its root).
    def import_state(state)
      nxt = {}
      seen = state.is_a?(Hash) ? state['seen'] : nil
      (seen.nil? ? [] : seen).each do |s|
        unless s.is_a?(Hash) && !AtlasPca.mesh_valid_head(s['head']).nil? && s['rev_ids'].is_a?(Array) && s['rev_ids'].all? { |i| i.is_a?(String) }
          raise ArgumentError, 'witness: malformed state'
        end

        rs = RevocationSet.new(s['rev_ids'])
        raise ArgumentError, 'witness: malformed state' if rs.size != s['head']['rev_size'] || rs.root != s['head']['rev_root']

        nxt[s['head']['domain']] = { 'head' => s['head'].dup, 'rev' => rs.list }
      end
      @seen.clear
      @seen.merge!(nxt)
    end

    private

    def state_of(seen)
      items = seen.values.map { |s| { 'head' => s['head'].dup, 'rev_ids' => s['rev'].dup } }
      { 'seen' => items.sort_by { |x| x['head']['domain'].encode('UTF-16BE').b } }
    end
  end

  # Issuer-side state of one organisation: an append-only delegation log, a revocation set and head publication (in memory, so the protocol
  # can be exercised end to end).
  class MeshDomain
    attr_reader :name, :id

    def initialize(name, secret)
      @name = name
      @secret = secret
      @id = secret.public
      @log = []
      @rev = RevocationSet.new
      @snaps = {}
    end

    # Vouch that an agent key belongs to this domain.
    def enroll(agent, role)
      { 'agent' => agent, 'domain' => @id, 'role' => role,
        'sig' => AtlasPca.b64e(@secret.sign(AtlasPca.mesh_msg(AtlasPca::MESH_BINDING_DOMAIN, { 'agent' => agent, 'domain' => @id, 'role' => role }))) }
    end

    # Log a delegation hop issued in this domain. Idempotent.
    def record(cap)
      h = AtlasPca.cap_hash(cap)
      i = @log.index(h)
      return i unless i.nil?

      @log << h
      @log.length - 1
    end

    # Revoke a capability id (`cap['id']`) or an agent key (AtlasPca.key_revocation_id).
    def revoke(rid) = @rev.revoke(rid)

    def revocation_set_copy = RevocationSet.new(@rev.list)

    # RFC 9162 consistency proof between two sizes of this domain's current log.
    def consistency_proof(old_size, new_size = nil) = AtlasPca.mesh_consistency_proof(@log, old_size, new_size)

    # The proof a verifier holding `pin` needs to accept `head` (a head this domain published, larger than the pin).
    def pin_proof(pin, head)
      snap = @snaps[head['sig']]
      raise ArgumentError, 'pinProof: unknown head' if snap.nil?

      { 'domain' => @id, 'proof' => AtlasPca.mesh_consistency_proof(snap['log'], pin['size'], head['head']['size']) }
    end

    # Publish a head: domain-signed, then cosigned by `witnesses`, each shown a real consistency proof from ITS last-seen head plus the
    # revocation list. Raises if a witness refuses (unless `threshold` tolerates it); nothing is recorded as published on failure.
    def publish_head(witnesses, timestamp, threshold = nil)
      head = { 'domain' => @id, 'size' => @log.length, 'root' => @log.empty? ? '' : AtlasPca.merkle_root(@log), 'rev_root' => @rev.root,
               'rev_size' => @rev.size, 'timestamp' => timestamp }
      ch = { 'head' => head, 'sig' => AtlasPca.b64e(@secret.sign(AtlasPca.mesh_msg(AtlasPca::MESH_HEAD_DOMAIN, head))), 'cosigs' => [] }
      rev_ids = @rev.list
      errors = []
      witnesses.each do |w|
        prev = w.last_seen(@id)
        consistency = nil
        if prev && prev['size'] < head['size']
          consistency = AtlasPca.mesh_consistency_proof(@log, prev['size'], head['size'])
        elsif prev && prev['size'] > head['size']
          consistency = { 'oldSize' => prev['size'], 'newSize' => head['size'], 'path' => [] } # will be refused as a rollback
        end
        begin
          req = { 'head' => ch, 'rev_ids' => rev_ids }
          req['consistency'] = consistency unless consistency.nil?
          ch['cosigs'] << w.cosign(req)
        rescue StandardError => e
          errors << e
        end
      end
      need = threshold.nil? ? witnesses.length : threshold
      raise(errors[0] || ArgumentError.new('publishHead: not enough witnesses')) if ch['cosigs'].length < need

      @snaps[ch['sig']] = { 'log' => @log.dup, 'rev' => RevocationSet.new(@rev.list) }
      ch
    end

    # Per-hop evidence against a previously published head. Raises if the cap is not in that head's log or if the cap or issuer key is
    # revoked as of that head (no non-membership proof can exist).
    def evidence(cap, head, binding = nil)
      snap = @snaps[head['sig']]
      raise ArgumentError, 'evidence: unknown head' if snap.nil?

      i = snap['log'].index(AtlasPca.cap_hash(cap))
      raise ArgumentError, 'evidence: capability not in this head' if i.nil?

      ev = { 'domain' => @id, 'head' => head, 'inclusion' => Grants.merkle_proof(snap['log'], i),
             'revocation' => { 'cap' => snap['rev'].non_membership_proof(cap['id']),
                               'issuer_key' => snap['rev'].non_membership_proof(AtlasPca.key_revocation_id(cap['issuer'])) } }
      ev['binding'] = binding if binding
      ev
    end
  end
end
