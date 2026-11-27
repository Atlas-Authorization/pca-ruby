# frozen_string_literal: true

require 'openssl'
require_relative 'scitt'
require_relative 'private_file'

# Transparency Service logs for SCITT: the durable service over a pluggable store (an append is O(log n) store reads and
# writes, state lives entirely in the store), a file-backed and an in-memory store, the in-memory reference service for tests,
# and a conformance check for stores. Synchronous mirror of the TypeScript reference (@atlasauth/pca-scitt).
#
# A store implements size, get_entry(index), get_node(level, index) and append(expected_size, entry, nodes) where nodes are
# Hashes {'level', 'index', 'hash'}; append is an atomic compare-and-set on the size. A signing key that is nil or empty is
# refused when the service is built, never carried until a later signature fails.
module AtlasPca
  module ScittLog
    MAX_APPEND_ATTEMPTS = 16
    S = AtlasPca::Scitt

    # code: store_required | store_corrupt | append_contention | out_of_range | bad_statement.
    class ScittLogError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    module_function

    # `Number.isInteger`
    def integer?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite? && v == v.floor)

    def pow2?(n) = n.positive? && (n & (n - 1)).zero?

    def largest_pow2_below(n)
      k = 1
      k *= 2 while k * 2 < n
      k
    end

    def require_key!(key)
      raise ArgumentError, 'a signing key is required' if key.nil? || (key.respond_to?(:empty?) && key.empty?)
    end

    def b64u(b) = AtlasPca.b64e(b)

    # Read-side algorithms over a store (hashes of arbitrary ranges, root, proofs).
    class LogReader
      def initialize(store)
        @store = store
      end

      def node(level, index)
        h = @store.get_node(level, index)
        raise ScittLogError.new('store_corrupt', "missing or malformed subtree hash (#{level}, #{index})") if h.nil? || h.bytesize != 32

        h
      end

      def range(lo, n)
        return node(0, lo) if n == 1
        return node(n.bit_length - 1, lo / n) if ScittLog.pow2?(n) && (lo % n).zero?

        k = ScittLog.largest_pow2_below(n)
        S.node_hash(range(lo, k), range(lo + k, n - k))
      end

      def root(size) = size.zero? ? S.empty_root : range(0, size)

      def inclusion(index, size)
        walk = lambda do |lo, n, idx|
          next [] if n == 1

          k = ScittLog.largest_pow2_below(n)
          idx < k ? walk.call(lo, k, idx) + [range(lo + k, n - k)] : walk.call(lo + k, n - k, idx - k) + [range(lo, k)]
        end
        walk.call(0, size, index)
      end

      def consistency(m, size)
        sub = lambda do |lo, n, mm, complete|
          next(complete ? [] : [range(lo, n)]) if mm == n

          k = ScittLog.largest_pow2_below(n)
          mm <= k ? sub.call(lo, k, mm, complete) + [range(lo + k, n - k)] : sub.call(lo + k, n - k, mm - k, false) + [range(lo, k)]
        end
        sub.call(0, size, m, true)
      end
    end

    # A durable SCITT Transparency Service over a store you supply (there is no in-memory default).
    class DurableTransparencyService
      # opts: 'issuer' (present adds the iss claim to every receipt)
      def initialize(store, alg, key, opts = {})
        unless %i[size get_entry get_node append].all? { |m| store.respond_to?(m) }
          raise ScittLogError.new('store_required', 'a ScittLogStore (size, get_entry, get_node, append) is required; there is no in-memory default')
        end

        ScittLog.require_key!(key)
        @store = store
        @reader = LogReader.new(store)
        @signer = [alg, key, opts]
      end

      def size
        n = @store.size
        raise ScittLogError.new('store_corrupt', 'the store reported an invalid size') if S.safe_int(n).nil? || n.negative? || S.neg_zero?(n)

        n.to_i
      end

      def root = ScittLog.b64u(@reader.root(size))

      def receipt_for(index, size)
        root = @reader.root(size)
        sides = S.sibling_sides(index, size)
        path = @reader.inclusion(index, size).each_with_index.map { |h, i| { 'side' => sides[i], 'hash' => ScittLog.b64u(h) } }
        alg, key, opts = @signer
        { 'index' => index, 'receipt' => S.build_receipt(ScittLog.b64u(root), { 'index' => index, 'size' => size, 'path' => path }, alg, key, opts), 'root' => ScittLog.b64u(root) }
      end

      # Append a Signed Statement (validated structurally first) and return its receipt against the new root.
      def register(statement)
        begin
          raise TypeError, 'detached payload' if S.decode_cose_sign1(statement)['payload'].nil?
        rescue StandardError => e
          raise ScittLogError.new('bad_statement', "cannot register: #{e.message}")
        end
        MAX_APPEND_ATTEMPTS.times do
          n = size
          nodes = [{ 'level' => 0, 'index' => n, 'hash' => S.leaf_hash(statement) }]
          h = nodes[0]['hash']
          level = 1
          while ((n + 1) % (2**level)).zero? # the new leaf completes a subtree: its left sibling is already stored
            idx = ((n + 1) / (2**level)) - 1
            left = @store.get_node(level - 1, 2 * idx)
            raise ScittLogError.new('store_corrupt', "missing subtree hash (#{level - 1}, #{2 * idx})") if left.nil? || left.bytesize != 32

            h = S.node_hash(left, h)
            nodes << { 'level' => level, 'index' => idx, 'hash' => h }
            level += 1
          end
          return receipt_for(n, n + 1) if @store.append(n, statement, nodes)
        end
        raise ScittLogError.new('append_contention', 'could not append: the log kept changing')
      end

      # opts: 'subject', 'content_type' (see Scitt.sign_statement)
      def append_and_receipt(payload, alg, key, issuer, opts = {})
        statement = S.sign_statement(payload, alg, key, issuer, opts)
        { 'statement' => statement }.merge(register(statement))
      end

      # A receipt for an entry, against the CURRENT root.
      def get_receipt(index)
        n = size
        raise ScittLogError.new('out_of_range', 'getReceipt: index out of range') if !ScittLog.integer?(index) || index.negative? || index >= n

        receipt_for(index.to_i, n)
      end

      def get_entry(index)
        n = size
        raise ScittLogError.new('out_of_range', 'getEntry: index out of range') if !ScittLog.integer?(index) || index.negative? || index >= n

        e = @store.get_entry(index.to_i)
        raise ScittLogError.new('store_corrupt', "entry #{index} is missing") if e.nil?

        e
      end

      # An RFC 9162 consistency proof that the first `old_size` entries are a prefix of the current log.
      def consistency_proof(old_size)
        n = size
        raise ScittLogError.new('out_of_range', 'consistencyProof: size out of range') if !ScittLog.integer?(old_size) || old_size < 1 || old_size > n

        old_size = old_size.to_i
        path = @reader.consistency(old_size, n)
        { 'oldSize' => old_size, 'newSize' => n, 'oldRoot' => ScittLog.b64u(@reader.root(old_size)), 'newRoot' => ScittLog.b64u(@reader.root(n)),
          'proof' => S.encode([old_size, n, path]) }
      end
    end

    # Check a store against the contract the service relies on (compare-and-set, atomic entry-plus-nodes, immutability).
    # Returns the failures (empty = conforms).
    def check_scitt_log_store(make_store)
      failures = []
      begin
        s = make_store.call
        failures << 'a new store is not empty' if s.size != 0
        h = ->(b) { ([b] * 32).pack('C*') }
        failures << 'append at the right size was refused' unless s.append(0, "\x01".b, [{ 'level' => 0, 'index' => 0, 'hash' => h.call(1) }])
        failures << 'append at a stale size was accepted (no compare-and-set)' if s.append(0, "\x02".b, [{ 'level' => 0, 'index' => 1, 'hash' => h.call(2) }])
        failures << 'a refused append changed the size' if s.size != 1
        failures << 'a refused append left a node behind (not atomic)' unless s.get_node(0, 1).nil?
        failures << 'a refused append left an entry behind' unless s.get_entry(1).nil?
        e0 = s.get_entry(0)
        failures << 'the stored entry does not read back' if e0.nil? || e0.bytesize != 1 || e0.getbyte(0) != 1
        e0.setbyte(0, 9) if e0 && !e0.frozen? # a returned entry must not alias the stored one
        again = s.get_entry(0)
        failures << 'a returned entry aliases the stored one (mutable)' if again.nil? || again.getbyte(0) != 1
        wins = [1, 2, 3, 4].map { |i| s.append(1, [10 + i].pack('C'), [{ 'level' => 0, 'index' => 1, 'hash' => h.call(10 + i) }]) }
        failures << 'concurrent appends at the same size did not produce exactly one winner' if wins.count { |w| w } != 1
        failures << 'the size after a race is not 2' if s.size != 2
      rescue StandardError => e
        failures << "the store threw: #{e.message}"
      end
      failures
    end

    # In-memory store: single process, forgets everything on restart. For tests only.
    class MemoryScittLogStore
      def initialize
        @entries = []
        @nodes = {}
      end

      def size = @entries.length

      def get_entry(index) = ScittLog.integer?(index) && index >= 0 && index < @entries.length ? @entries[index.to_i] : nil
      def get_node(level, index) = @nodes[[level, index]]

      def append(expected_size, entry, nodes)
        return false if @entries.length != expected_size

        @entries << entry.b.freeze
        nodes.each { |n| @nodes[[n['level'], n['index']]] = n['hash'].b.freeze }
        true
      end
    end

    # File-backed store: one append-only file of checksummed transactions (entry plus its new subtree hashes), fsynced before
    # `append` returns, so a crash leaves the whole transaction or none of it. A torn final record is discarded on open;
    # corruption elsewhere raises `store_corrupt`. SINGLE PROCESS: it does not lock the file.
    class FileScittLogStore
      def self.open(path)
        s = new(AtlasPca::PrivateFile.open(path, File::RDWR | File::CREAT, binmode: true))
        s.send(:load_log)
        s
      end

      def initialize(io)
        @io = io
        @nodes = {}
        @offsets = []
        @end = 0
      end

      def close = @io.close

      def size = @offsets.length

      def get_entry(index)
        return nil unless ScittLog.integer?(index) && index >= 0 && index < @offsets.length

        at, n = @offsets[index.to_i]
        read(at, n)
      end

      def get_node(level, index) = @nodes[[level, index]]

      def append(expected_size, entry, nodes)
        return false if @offsets.length != expected_size

        nodes.each do |n|
          next if ScittLog.integer?(n['level']) && n['level'] >= 0 && n['level'] <= 255 && ScittLog.integer?(n['index']) && n['index'] >= 0 &&
                  n['index'] <= 0xFFFFFFFF && n['hash'].bytesize == 32

          raise ScittLogError.new('store_corrupt', 'a subtree node is malformed')
        end
        entry = entry.b
        payload = [entry.bytesize].pack('N') + entry + [nodes.length].pack('n')
        nodes.each { |n| payload += [n['level'].to_i].pack('C') + [n['index'].to_i].pack('N') + ("\x00".b * 3) + n['hash'].b }
        record = [payload.bytesize].pack('N') + payload + OpenSSL::Digest::SHA256.digest(payload)
        w = 0
        w += @io.pwrite(record.byteslice(w..), @end + w) while w < record.bytesize
        @io.fsync
        @offsets << [@end + 8, entry.bytesize]
        nodes.each { |n| @nodes[[n['level'].to_i, n['index'].to_i]] = n['hash'].b }
        @end += record.bytesize
        true
      end

      private

      def read(at, n)
        got = String.new(encoding: Encoding::BINARY)
        while got.bytesize < n
          chunk = begin
            @io.pread(n - got.bytesize, at + got.bytesize)
          rescue EOFError
            nil
          end
          break if chunk.nil? || chunk.empty?

          got << chunk
        end
        got
      end

      def load_log
        total = @io.stat.size
        pos = 0
        while pos < total
          head = read(pos, 4)
          n = head.bytesize == 4 ? head.unpack1('N') : -1
          rec_end = pos + 4 + n + 32
          if n < 6 || rec_end > total
            discard_tail(pos, rec_end > total)
            return
          end
          payload = read(pos + 4, n)
          unless OpenSSL::Digest::SHA256.digest(payload) == read(pos + 4 + n, 32)
            discard_tail(pos, rec_end == total)
            return
          end
          entry_len = payload.unpack1('N')
          p = 4 + entry_len
          raise ScittLogError.new('store_corrupt', 'a log record has an inconsistent length') if p + 2 > n

          count = payload.byteslice(p, 2).unpack1('n')
          p += 2
          raise ScittLogError.new('store_corrupt', 'a log record has an inconsistent length') if p + (count * 40) != n

          @offsets << [pos + 8, entry_len]
          count.times do
            @nodes[[payload.getbyte(p), payload.byteslice(p + 1, 4).unpack1('N')]] = payload.byteslice(p + 8, 32)
            p += 40
          end
          pos = rec_end
        end
        @end = pos
      end

      def discard_tail(pos, is_tail)
        raise ScittLogError.new('store_corrupt', "the log file is corrupt at offset #{pos}") unless is_tail

        @io.truncate(pos)
        @io.fsync
        @end = pos
      end
    end

    # In-memory reference log: recomputes the Merkle tree on every registration and loses everything on restart. For tests
    # and demos only; the production log is DurableTransparencyService.
    class TransparencyService
      # opts: 'issuer' (present adds the iss claim to every receipt)
      def initialize(alg, key, opts = {})
        ScittLog.require_key!(key)
        @statements = []
        @leaf_hashes = []
        @signer = [alg, key, opts]
      end

      def size = @statements.length
      def root = ScittLog.b64u(S.tree_hash(@leaf_hashes))
      def snapshot = @statements.map { |st| ScittLog.b64u(st) }

      def receipt_for(index)
        root = S.tree_hash(@leaf_hashes)
        size = @leaf_hashes.length
        sides = S.sibling_sides(index, size)
        path = S.inclusion_path(@leaf_hashes, index).each_with_index.map { |h, i| { 'side' => sides[i], 'hash' => ScittLog.b64u(h) } }
        alg, key, opts = @signer
        { 'index' => index, 'receipt' => S.build_receipt(ScittLog.b64u(root), { 'index' => index, 'size' => size, 'path' => path }, alg, key, opts), 'root' => ScittLog.b64u(root) }
      end

      def register(statement)
        raise S::Error, 'scitt: cannot register a statement with a detached payload' if S.decode_cose_sign1(statement)['payload'].nil?

        index = @statements.length
        @statements << statement.b
        @leaf_hashes << S.leaf_hash(statement)
        receipt_for(index)
      end

      def append_and_receipt(payload, alg, key, issuer, opts = {})
        statement = S.sign_statement(payload, alg, key, issuer, opts)
        { 'statement' => statement }.merge(register(statement))
      end

      def get_receipt(index)
        raise ArgumentError, 'getReceipt: index out of range' if !ScittLog.integer?(index) || index.negative? || index >= @statements.length

        receipt_for(index.to_i)
      end

      # The log at `old_size` entries is a prefix of the current log: both roots and the RFC 9942 proof encoding.
      def consistency_proof(old_size)
        raise ArgumentError, 'consistencyProof: size out of range' if !ScittLog.integer?(old_size) || old_size < 1 || old_size > @statements.length

        old_size = old_size.to_i
        path = S.consistency_path(@leaf_hashes, old_size)
        { 'oldSize' => old_size, 'newSize' => @statements.length, 'oldRoot' => ScittLog.b64u(S.tree_hash(@leaf_hashes[0, old_size])),
          'newRoot' => root, 'proof' => S.encode([old_size, @statements.length, path]) }
      end
    end

    # Register a Signed Statement into a Transparency Service (RFC 9943 register-signed-statement).
    def register_statement(statement, service) = service.register(statement)
  end
end
