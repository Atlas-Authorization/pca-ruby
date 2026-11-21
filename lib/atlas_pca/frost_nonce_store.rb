# frozen_string_literal: true

module AtlasPca
  # The durable nonce-store contract of networked FROST signing (the reference's `frost-nonce-store`): a signer persists its round-1 nonces BEFORE it
  # releases the commitment and burns them BEFORE it signs, so a restart can neither lose a promised commitment nor sign twice with one nonce pair.
  # A store answers `create(session_id, record)`, `load(session_id)` (a copy, or nil), `spend(session_id)` (zeroes the secret, keeps a spent marker),
  # `drop(session_id)` (no marker) and `spent?(session_id)`. A record is {'hiding', 'binding', 'hidingCommitment', 'bindingCommitment', 'createdAt'}
  # (the nonces and commitments as 32-byte strings).
  module FrostNonceStore
    NONCE_STORE_METHODS = %i[create load spend drop spent?].freeze

    module_function

    def copy(r) = { 'hiding' => r['hiding'].dup, 'binding' => r['binding'].dup, 'hidingCommitment' => r['hidingCommitment'].dup,
                    'bindingCommitment' => r['bindingCommitment'].dup, 'createdAt' => r['createdAt'] }

    def wipe(s) = s.replace("\0".b * s.bytesize)

    # The in-memory reference store.
    class MemoryNonceStore
      def initialize
        @live = {}
        @spent = {}
      end

      def create(session_id, record)
        raise 'nonce-store: session id must be a non-empty string' if !session_id.is_a?(String) || session_id.empty?
        raise 'nonce-store: session already exists' if @live.key?(session_id) || @spent.key?(session_id)

        @live[session_id] = FrostNonceStore.copy(record)
        nil
      end

      def load(session_id)
        r = @live[session_id]
        r && FrostNonceStore.copy(r)
      end

      def spend(session_id)
        r = @live[session_id]
        raise 'nonce-store: cannot spend a session that is not live' if r.nil?

        FrostNonceStore.wipe(r['hiding'])
        FrostNonceStore.wipe(r['binding'])
        @live.delete(session_id)
        @spent[session_id] = true
        nil
      end

      def drop(session_id)
        r = @live[session_id]
        return nil if r.nil?

        FrostNonceStore.wipe(r['hiding'])
        FrostNonceStore.wipe(r['binding'])
        @live.delete(session_id)
        nil
      end

      def spent?(session_id) = @spent.key?(session_id)
    end

    # Self-test a custom store must pass: `make` builds a fresh store, `reopen` simulates a restart over the same backing state. Raises
    # `nonce-store contract: <what>` on the first violation.
    def assert_nonce_store_contract(make, reopen = ->(s) { s })
      rec = lambda do |n|
        { 'hiding' => ([n].pack('C') * 32).b, 'binding' => ([n + 1].pack('C') * 32).b, 'hidingCommitment' => ([n + 2].pack('C') * 32).b,
          'bindingCommitment' => ([n + 3].pack('C') * 32).b, 'createdAt' => n }
      end
      must = ->(ok, what) { raise "nonce-store contract: #{what}" unless ok }
      throws = lambda do |&f|
        f.call
        false
      rescue StandardError
        true
      end
      s = make.call
      must.call(s.load('a').nil? && !s.spent?('a'), 'an unknown id is neither live nor spent')
      s.create('a', rec.call(1))
      must.call(throws.call { s.create('a', rec.call(9)) }, 'create must refuse an existing live id')
      s.create('b', rec.call(5))
      s = reopen.call(s)
      got = s.load('a')
      must.call(!got.nil? && got['hiding'].getbyte(0) == 1 && got['createdAt'] == 1, 'a live record survives a restart')
      got['hiding'].replace(([0xee].pack('C') * 32).b)
      must.call(s.load('a')['hiding'].getbyte(0) == 1, 'load returns a copy')
      s.spend('a')
      must.call(s.load('a').nil? && s.spent?('a'), 'spend removes the secret and records the marker')
      must.call(throws.call { s.spend('a') }, 'a second spend must throw')
      must.call(throws.call { s.create('a', rec.call(2)) }, 'create must refuse a spent id')
      must.call(throws.call { s.spend('zzz') }, 'spend of an unknown id must throw')
      s = reopen.call(s)
      must.call(s.spent?('a') && s.load('a').nil?, 'a spent marker survives a restart')
      must.call(!s.load('b').nil?, 'the other live record survives')
      s.drop('b')
      must.call(s.load('b').nil? && !s.spent?('b'), 'drop removes a live record without marking it spent')
      s.drop('never-existed')
      nil
    end
  end
end
