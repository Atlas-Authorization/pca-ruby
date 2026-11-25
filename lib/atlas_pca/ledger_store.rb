# frozen_string_literal: true

require 'monitor'
require_relative 'store_errors'

module AtlasPca
  # An in-memory RFC 9162 transparency log over opaque commits (the verifier-side checks are in ledger.rb). Build it from entries with
  # `TransparencyLedger.from_entries` and extend it with #append_commitment; #head is {'size', 'root'}.
  class TransparencyLedger
    attr_reader :principal

    def initialize(principal = '')
      @principal = principal
      @commits = []
    end

    def self.from_entries(entries, principal = '')
      t = new(principal)
      entries.each { |e| t.instance_variable_get(:@commits) << e['commit'] }
      t
    end

    def size = @commits.length

    # Append a precomputed opaque commitment leaf; refuses a non-string or empty commit.
    def append_commitment(commit)
      raise ArgumentError, 'appendCommitment: commit must be a non-empty string' unless commit.is_a?(String) && !commit.empty?

      @commits << commit
      { 'index' => @commits.length - 1, 'commit' => commit }
    end

    def head = { 'size' => size, 'root' => AtlasPca.ledger_root_of(@commits) }

    # The root the log had when it contained only the first `size` entries.
    def root_at(sz)
      ok = sz.is_a?(Numeric) && !(sz.is_a?(Float) && !sz.finite?) && sz == sz.to_i && sz >= 0 && sz <= size
      raise ::RangeError, 'rootAt: size out of range' unless ok

      AtlasPca.ledger_root_of(@commits[0, sz.to_i])
    end

    def commits = @commits.dup
    def inclusion_proof(index) = Grants.merkle_proof(@commits, index)

    def consistency_proof(old_size, new_size = nil) = AtlasPca.mesh_consistency_proof(@commits, old_size, new_size.nil? ? size : new_size)
  end

  # Root of a commit sequence (the empty log is SHA-256 of the empty string).
  def self.ledger_root_of(commits)
    commits.empty? ? b64e(sha(''.b)) : b64e(build(commits.map { |c| leaf_hash(c) }))
  end

  # The pure store transitions and the reference store / ledger of the durable transparency ledger (the reference's `ledger-store`).
  #
  # CLAIMED: TAMPER EVIDENCE, given at least one honest independent witness. The ledger is an append-only Merkle log with guardian-signed
  # checkpoints. A store's `append` and `append_checkpoint` are compare-and-swap on the current length (all entries of a batch or none);
  # committing the same batch again at the same position is a replay. StoredLedger.open rebuilds the tree from the stored commits and checks
  # it against EVERY stored checkpoint: a store that lost entries after a checkpoint (rollback), edited an entry (tamper) or holds a forged
  # checkpoint FAILS CLOSED with a typed error.
  module LedgerStoreDocs
    DOC_KEY = 'pca-ledger-store/v1'

    module_function

    def commit?(c) = c.is_a?(String) && !c.empty?
    def safe_int?(x) = AtlasPca.ledger_safe_int?(x)
    def empty_doc = { 'v' => 1, 'commits' => [], 'checkpoints' => [] }

    # Append `commits` to `doc` iff it has exactly `expected_size` entries (all or none); a batch already stored there is a replay.
    def append_to_doc(doc, expected_size, commits)
      raise ::RangeError, 'append: expectedSize must be a non-negative safe integer' unless safe_int?(expected_size) && expected_size >= 0
      raise ::RangeError, 'append: commits must be a non-empty array of non-empty strings' unless commits.is_a?(Array) && !commits.empty? && commits.all? { |c| commit?(c) }

      size = doc['commits'].length
      if expected_size < size
        same = commits.each_with_index.all? { |c, i| i + expected_size < size && doc['commits'][expected_size + i] == c }
        return { 'outcome' => same ? 'replayed' : 'conflict', 'size' => size }
      end
      return { 'outcome' => 'conflict', 'size' => size } if expected_size > size

      doc['commits'].concat(commits)
      { 'outcome' => 'appended', 'size' => doc['commits'].length }
    end

    def checkpoint_to_doc(doc, expected_count, cp)
      raise ::RangeError, 'appendCheckpoint: expectedCount must be a non-negative safe integer' unless safe_int?(expected_count) && expected_count >= 0

      count = doc['checkpoints'].length
      if expected_count < count
        return { 'outcome' => 'replayed', 'count' => count } if AtlasPca.hash_canonical(doc['checkpoints'][expected_count]) == AtlasPca.hash_canonical(cp)

        return { 'outcome' => 'conflict', 'count' => count, 'reason' => 'another checkpoint holds that position' }
      end
      return { 'outcome' => 'conflict', 'count' => count, 'reason' => 'the checkpoint position is ahead of the log' } if expected_count > count

      sth = cp.is_a?(Hash) ? cp['sth'] : nil
      unless sth.is_a?(Hash) && safe_int?(sth['size']) && sth['size'] >= 0 && !V2JS.neg_zero?(sth['size']) && sth['root'].is_a?(String)
        return { 'outcome' => 'conflict', 'count' => count, 'reason' => 'malformed checkpoint' }
      end
      return { 'outcome' => 'conflict', 'count' => count, 'reason' => 'the checkpoint is beyond the end of the log' } if sth['size'] > doc['commits'].length

      last = count.positive? ? doc['checkpoints'][count - 1]['sth'] : nil
      if last && (sth['size'] < last['size'] || (sth['size'] == last['size'] && sth['root'] != last['root']))
        return { 'outcome' => 'conflict', 'count' => count, 'reason' => 'the checkpoint does not extend the previous one' }
      end

      doc['checkpoints'] << Marshal.load(Marshal.dump(cp))
      { 'outcome' => 'appended', 'count' => doc['checkpoints'].length }
    end

    def decode_doc(raw)
      return empty_doc if raw.nil?

      unless raw.is_a?(Hash) && raw['v'] == 1 && raw['commits'].is_a?(Array) && raw['checkpoints'].is_a?(Array) && raw['commits'].all? { |c| commit?(c) }
        raise LedgerStoreError.new('store_corrupt', 'ledger document has the wrong shape')
      end
      raise LedgerStoreError.new('store_corrupt', 'malformed checkpoint entry') unless raw['checkpoints'].all? { |c| c.is_a?(Hash) && c['sth'].is_a?(Hash) }

      raw
    end
  end

  # The reference ledger store: the whole log is one document in an atomic key-value store (#get / #update), so every write is one atomic
  # read-modify-write. LIMIT: rewritten on every write; a production log lives in a database with a unique index on the position.
  class KvLedgerStore
    D = LedgerStoreDocs

    def initialize(kv, key = D::DOC_KEY)
      raise LedgerStoreError.new('store_missing', 'KvLedgerStore needs an atomic kv') unless kv.respond_to?(:get) && kv.respond_to?(:update)

      @kv = kv
      @key = key
    end

    def size = doc['commits'].length

    def read(from, to)
      d = doc
      raise ::RangeError, 'read: range is not inside the log' unless D.safe_int?(from) && D.safe_int?(to) && from >= 0 && from <= to && to <= d['commits'].length

      d['commits'][from.to_i, (to - from).to_i]
    end

    def append(expected_size, commits)
      out = nil
      @kv.update(@key) do |prev|
        d = D.decode_doc(prev)
        out = D.append_to_doc(d, expected_size, commits)
        out['outcome'] == 'appended' ? d : nil
      end
      out
    end

    def checkpoint_count = doc['checkpoints'].length

    def checkpoints(from = 0)
      d = doc
      raise ::RangeError, 'checkpoints: from is not inside the list' unless D.safe_int?(from) && from >= 0 && from <= d['checkpoints'].length

      Marshal.load(Marshal.dump(d['checkpoints'][from.to_i..]))
    end

    def append_checkpoint(expected_count, cp)
      out = nil
      @kv.update(@key) do |prev|
        d = D.decode_doc(prev)
        out = D.checkpoint_to_doc(d, expected_count, cp)
        out['outcome'] == 'appended' ? d : nil
      end
      out
    end

    private

    def doc = D.decode_doc(@kv.get(@key))
  end

  # A transparency log over a ledger store. Open it with StoredLedger.open; there is no public constructor, so no instance exists whose state
  # was not verified against the stored checkpoints.
  class StoredLedger
    D = LedgerStoreDocs
    private_class_method :new

    # Load the log and verify it against every stored checkpoint. `guardian` is the guardian KeyPair; `alg` / `pq` choose a post-quantum or hybrid
    # checkpoint suite (which needs `pin`, the PQ pins {ed25519 b64u => pq_pk}). Raises LedgerStoreError: store_missing, guardian_key_missing,
    # pin_missing, rollback, tamper, forged_checkpoint, inconsistent, store_corrupt or store_unavailable.
    def self.open(store, guardian, instance_id, principal, clock = nil, alg: nil, pq: nil, pin: nil)
      unless !store.nil? && %i[append read append_checkpoint size checkpoints].all? { |m| store.respond_to?(m) }
        raise LedgerStoreError.new('store_missing', 'a LedgerStore is required (there is no in-memory default)')
      end
      raise LedgerStoreError.new('guardian_key_missing', 'a guardian secret key is required') unless !guardian.nil? && guardian.respond_to?(:public) && guardian.public.is_a?(String)

      if !alg.nil? && ((alg != 'ed25519' && !AtlasPca::SIG_SUITES.key?(alg)) || (alg != 'ed25519' && (pin.nil? || pin.empty?)))
        raise LedgerStoreError.new('pin_missing', 'a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)')
      end

      opts = { store: store, guardian: guardian, instance_id: instance_id, principal: principal, clock: clock, alg: alg, pq: pq, pin: pin }
      begin
        size = store.size
        commits = store.read(0, size)
        cps = store.checkpoints(0)
        log = TransparencyLedger.from_entries(commits.map { |c| { 'commit' => c } }, principal)
        led = new(opts, guardian.public, log, cps)
        led.send(:verify_against_checkpoints)
        led
      rescue StandardError => e
        raise unavailable(e)
      end
    end

    def self.unavailable(e) = e.is_a?(LedgerStoreError) ? e : LedgerStoreError.new('store_unavailable', e.message.to_s.empty? ? 'store failed' : e.message)

    # The guardian public key (b64u) every checkpoint verifies under.
    attr_reader :guardian

    def initialize(opts, guardian_public, log, cps)
      @opts = opts
      @guardian = guardian_public
      @log = log
      @cps = cps
      @lock = Monitor.new
    end

    def size = @log.size
    def latest_checkpoint = @cps.empty? ? nil : @cps[-1]['sth']
    def checkpoint_chain = Marshal.load(Marshal.dump(@cps))
    def head = @log.head
    def inclusion_proof(index) = @log.inclusion_proof(index)

    # RFC 9162 proof from a size the caller already pinned to the current log.
    def consistency_proof_from(old_size) = @log.consistency_proof(old_size, @log.size)

    def commits = @log.commits

    # Append an opaque commitment leaf. Idempotent under retry at the position the caller read; if another writer took that position the ledger
    # reloads and appends at the new tail. Returns {'index', 'commit'}.
    def append(commit)
      raise LedgerStoreError.new('invalid_commit', 'a commit must be a non-empty string') unless D.commit?(commit)

      @lock.synchronize do
        16.times do
          index = @log.size
          out = begin
            @opts[:store].append(index, [commit])
          rescue StandardError => e
            raise self.class.unavailable(e)
          end
          if %w[appended replayed].include?(out['outcome'])
            @log.append_commitment(commit)
            return { 'index' => index, 'commit' => commit }
          end
          catch_up_locked # another writer advanced the log: pick up its entries, then try the new tail
        end
        raise LedgerStoreError.new('conflict', 'the log kept moving; could not append')
      end
    end

    # Reload entries other writers appended since this handle last looked (and re-verify them against the checkpoints).
    def catch_up
      @lock.synchronize { catch_up_locked }
      nil
    end

    # Sign and persist a checkpoint of the current head. It is verified BEFORE it is stored: the new head must be consistent with the previous
    # checkpoint, so a log that was rewritten under this handle is refused (`inconsistent`). An unchanged head returns the existing checkpoint.
    def checkpoint
      @lock.synchronize do
        catch_up_locked
        assert_store_matches_memory
        prev = @cps.empty? ? nil : @cps[-1]
        h = @log.head
        return prev['sth'] if prev && prev['sth']['size'] == h['size']

        t = @opts[:clock] ? @opts[:clock].call : Time.now.to_f * 1000
        raise LedgerStoreError.new('clock_invalid', 'the clock returned a non-finite time') unless t.is_a?(Numeric) && !(t.is_a?(Float) && !t.finite?)

        t = t.floor
        body = { 'instance_id' => @opts[:instance_id], 'principal' => @opts[:principal], 'size' => h['size'], 'root' => h['root'],
                 'prev_root' => prev ? prev['sth']['root'] : '', 'timestamp' => t }
        signed = AtlasPca.sign_artifact(AtlasPca::STH_DOMAIN, body, @opts[:guardian], alg: @opts[:alg], pq: @opts[:pq])
        sth = body.dup
        sth['guardian'] = @guardian
        signed.each { |k, v| sth[k] = v unless body.key?(k) }
        cp = prev ? { 'sth' => sth, 'proof' => @log.consistency_proof(prev['sth']['size'], h['size']) } : { 'sth' => sth }
        v = verify_chain(@cps + [cp])
        unless v['ok']
          if v['reason'] == 'head'
            raise LedgerStoreError.new('forged_checkpoint', 'the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)')
          end

          raise LedgerStoreError.new('inconsistent', "the new head is not consistent with checkpoint #{v['at'] - 1}")
        end
        out = begin
          @opts[:store].append_checkpoint(@cps.length, cp)
        rescue StandardError => e
          raise self.class.unavailable(e)
        end
        raise LedgerStoreError.new('conflict', out['reason']) if out['outcome'] == 'conflict'

        @cps << cp
        sth
      end
    end

    private

    def verify_chain(cps)
      pin = @opts[:pin]
      cps.each_with_index do |cp, i|
        return { 'ok' => false, 'at' => i, 'reason' => 'head' } unless cp.is_a?(Hash) && AtlasPca.verify_tree_head(cp['sth'], @guardian, nil, pin)
        next if i.zero?
        return { 'ok' => false, 'at' => i, 'reason' => 'proof_missing' } if cp['proof'].nil? || cp['proof'] == false || cp['proof'] == {}
        return { 'ok' => false, 'at' => i, 'reason' => 'inconsistent' } unless AtlasPca.verify_head_consistency(cps[i - 1]['sth'], cp['sth'], cp['proof'], @guardian, nil, pin)
      end
      { 'ok' => true }
    end

    def verify_against_checkpoints
      attested = ([0] + @cps.map { |c| D.safe_int?(c['sth']['size']) ? c['sth']['size'] : 0 }).max
      raise LedgerStoreError.new('rollback', "the log has #{@log.size} entries but a checkpoint attests #{attested}") if @log.size < attested

      @cps.each_with_index do |cp, i|
        raise LedgerStoreError.new('forged_checkpoint', "checkpoint #{i} belongs to another log") if cp['sth']['instance_id'] != @opts[:instance_id] || cp['sth']['principal'] != @opts[:principal]
        if @log.root_at(cp['sth']['size']) != cp['sth']['root']
          raise LedgerStoreError.new('tamper', "the stored entries do not reproduce the root of checkpoint #{i} (size #{AtlasPca::Predicates.js_number_string(cp['sth']['size'].to_f)})")
        end
      end
      return if @cps.empty?

      v = verify_chain(@cps)
      raise LedgerStoreError.new(v['reason'] == 'inconsistent' ? 'inconsistent' : 'forged_checkpoint', "checkpoint #{v['at']}: #{v['reason']}") unless v['ok']
    end

    def catch_up_locked
      st = @opts[:store]
      size = st.size
      raise LedgerStoreError.new('rollback', "the store shrank from #{@log.size} to #{size} entries") if size < @log.size

      st.read(@log.size, size).each { |c| @log.append_commitment(c) }
      @cps.concat(st.checkpoints(@cps.length))
      verify_against_checkpoints
    rescue StandardError => e
      raise self.class.unavailable(e)
    end

    def assert_store_matches_memory
      stored = begin
        @opts[:store].read(0, @log.size)
      rescue StandardError => e
        raise self.class.unavailable(e)
      end
      raise LedgerStoreError.new('tamper', 'the stored entries no longer match this handle; refusing to sign a checkpoint over them') if stored != @log.commits
    end
  end
end
