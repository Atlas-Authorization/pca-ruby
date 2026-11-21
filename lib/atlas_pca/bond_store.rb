# frozen_string_literal: true

require_relative 'store_errors'

module AtlasPca
  # Durable bond settlement, the store half (the reference's `bond-store`): the BondStore contract (#read(claim_id, depositor), #commit(plan,
  # observed_at), #deposit(account, amount)), the exact micro-unit arithmetic every store shares, the pure transition function and KvBondStore,
  # one document in any atomic key-value store (#get and #update). INTERNAL ACCOUNTING ONLY: nothing here moves money.
  #
  # A plan is {'claimId', 'expect', 'next', 'open'? => {'amount', 'depositor', 'maxOpenClaims', 'maxOpenAmount', 'window'?}, 'moves' =>
  # [{'account', 'op', 'amount'}], 'record'}. `commit` applies it ALL OR NOTHING: the compare-and-swap on the bond's phase, every balance
  # movement, the new phase and the signed record become visible together; committing the same transition twice is a replay (the stored
  # record, nothing moved). Records are String-keyed Hashes.
  module BondStoreDocs
    MICROS = 1_000_000
    MAX_SAFE_MICROS = 1e15
    DOC_KEY = 'pca-bond-store/v1'
    PHASES = %w[open released slashed].freeze

    module_function

    def fin?(x) = (x.is_a?(Integer) || (x.is_a?(Float) && x.finite?))

    # Integer micro-units of `x` when it is a micro-grid amount below 1e15 micros, else nil.
    def to_micros(x)
      return nil if !fin?(x) || x.negative?

      scaled = x * MICROS
      return nil if scaled > MAX_SAFE_MICROS

      r = (scaled + 0.5).floor # JavaScript Math.round
      return nil if r.to_f / MICROS != x && (scaled - r).abs > 1e-3 # genuinely sub-micro: not a micro-grid amount

      r
    end

    # a whole amount is an Integer (JS has one number type; the canonical serializer refuses an integral Float)
    def from_micros(m) = (m % MICROS).zero? ? m / MICROS : m.to_f / MICROS

    # a + sign*b in exact micro-unit integers when both are micro-grid amounts; plain float otherwise.
    def exact_add(a, b, sign)
      ma = to_micros(a)
      mb = to_micros(b)
      return a + (sign * b) if ma.nil? || mb.nil?

      from_micros(sign == 1 ? ma + mb : ma - mb)
    end

    # Apply moves in order over a balance reader; RAISES ArgumentError (applying nothing) on an invalid amount or an overdraft.
    def apply_bond_moves(balance_of, moves)
      out = {}
      bal = ->(a) { out.key?(a) ? out[a] : balance_of.call(a) }
      moves.each do |m|
        raise ArgumentError, "#{m['op']}: invalid amount" if !fin?(m['amount']) || m['amount'].negative?
        raise ArgumentError, "debit: insufficient balance for #{m['account']}" if m['op'] == 'debit' && bal.call(m['account']) < m['amount']

        out[m['account']] = exact_add(bal.call(m['account']), m['amount'], m['op'] == 'debit' ? -1 : 1)
      end
      out
    end

    # Same settlement: action, bond, amount, parties, evidence and split (time and signature bytes ignored).
    def same_settlement?(a, b)
      a['claimId'] == b['claimId'] && a['action'] == b['action'] && a['amount'] == b['amount'] && a['from'] == b['from'] && a['to'] == b['to'] &&
        a['evidenceDigest'] == b['evidenceDigest'] && AtlasPca.hash_canonical(a['split']) == AtlasPca.hash_canonical(b['split'])
    end

    def same_window?(a, b)
      return a.nil? && b.nil? if a.nil? || b.nil?

      a['windowMs'] == b['windowMs'] && a['claimDigest'] == b['claimDigest'] # registeredAt is the first call's
    end

    def empty_doc = { 'balances' => {}, 'bonds' => {}, 'highWater' => 0 }

    # Apply `plan` to `doc` ('balances': account => number, 'bonds': claim id => row, 'highWater') following the BondStore.commit rules. Mutates
    # `doc` ONLY on 'committed' (the moves are checked on an overlay first).
    def commit_plan(doc, plan, observed_at)
      claim_id = plan['claimId']
      bond = doc['bonds'][claim_id]
      cur = bond ? bond['status'] : 'none'
      o = plan['open']
      if plan['expect'] == 'none'
        return { 'outcome' => 'conflict', 'reason' => 'malformed open plan', 'current' => cur } if !truthy?(o) || plan['next'] != 'open'

        if bond
          same = bond['depositor'] == o['depositor'] && bond['amount'] == o['amount'] && same_window?(bond['window'], o['window']) &&
                 bond['records'].length.positive? && same_settlement?(bond['records'][0], plan['record'])
          return same ? { 'outcome' => 'replayed', 'record' => bond['records'][0] } : { 'outcome' => 'conflict', 'reason' => "bond #{claim_id} already exists", 'current' => bond['status'] }
        end
        count = 0
        total = 0
        doc['bonds'].each_value do |b|
          next unless b['status'] == 'open' && b['depositor'] == o['depositor']

          count += 1
          total += b['amount']
        end
        return { 'outcome' => 'conflict', 'reason' => 'depositor open-claim cap reached', 'current' => 'none' } if count + 1 > o['maxOpenClaims']
        return { 'outcome' => 'conflict', 'reason' => 'depositor aggregate open-bond cap exceeded', 'current' => 'none' } if total + o['amount'] > o['maxOpenAmount']
      elsif bond.nil?
        return { 'outcome' => 'conflict', 'reason' => "no bond for #{claim_id}", 'current' => 'none' }
      elsif bond['status'] != plan['expect']
        last = bond['records'].empty? ? nil : bond['records'][-1]
        return { 'outcome' => 'replayed', 'record' => last } if bond['status'] == plan['next'] && !last.nil? && same_settlement?(last, plan['record'])

        return { 'outcome' => 'conflict', 'reason' => "bond #{claim_id} is already #{bond['status']}", 'current' => bond['status'] }
      end
      begin
        nxt = apply_bond_moves(->(a) { doc['balances'].fetch(a, 0) }, plan['moves'])
      rescue ArgumentError => e
        return { 'outcome' => 'conflict', 'reason' => e.message, 'current' => cur }
      end
      doc['balances'].update(nxt)
      if truthy?(o)
        row = { 'claimId' => claim_id, 'amount' => o['amount'], 'depositor' => o['depositor'], 'status' => 'open' }
        row['window'] = o['window'] if truthy?(o['window'])
        row['records'] = [plan['record']]
        doc['bonds'][claim_id] = row
      else
        bond['status'] = plan['next']
        bond['records'] << plan['record']
      end
      doc['highWater'] = [doc['highWater'], fin?(observed_at) ? observed_at : 0].max
      { 'outcome' => 'committed', 'record' => plan['record'] }
    end

    # Python-style truthiness of an optional member (nil, false and an empty Hash are absent).
    def truthy?(v) = !(v.nil? || v == false || v == {})

    # What a planner may read: the bond, the depositor's balance and open totals, and the store's time high-water mark.
    def snapshot_of(doc, claim_id, depositor = nil)
      bond = doc['bonds'][claim_id]
      count = 0
      total = 0
      balances = []
      unless depositor.nil?
        doc['bonds'].each_value do |b|
          next unless b['status'] == 'open' && b['depositor'] == depositor

          count += 1
          total += b['amount']
        end
        balances << [depositor, doc['balances'].fetch(depositor, 0)]
      end
      out = {}
      out['bond'] = Marshal.load(Marshal.dump(bond)) if bond
      out.merge('balances' => balances, 'openTotals' => { 'count' => count, 'sum' => total }, 'highWater' => doc['highWater'])
    end

    def bad(why) = BondStoreError.new('store_corrupt', why)

    def decode_doc(raw)
      return empty_doc if raw.nil?

      unless raw.is_a?(Hash) && raw['v'] == 1 && raw['balances'].is_a?(Array) && raw['bonds'].is_a?(Array) && (raw['highWater'].is_a?(Integer) || raw['highWater'].is_a?(Float))
        raise bad('bond document has the wrong shape')
      end

      doc = empty_doc
      raise bad('highWater is not a non-negative number') if !fin?(raw['highWater']) || raw['highWater'].negative?

      doc['highWater'] = raw['highWater']
      raw['balances'].each do |e|
        raise bad('malformed balance entry') unless e.is_a?(Array) && e.length == 2 && e[0].is_a?(String) && fin?(e[1]) && !e[1].negative?

        doc['balances'][e[0]] = e[1]
      end
      raw['bonds'].each do |b|
        unless b.is_a?(Hash) && b['claimId'].is_a?(String) && b['depositor'].is_a?(String) && fin?(b['amount']) && PHASES.include?(b['status']) &&
               b['records'].is_a?(Array) && !b['records'].empty?
          raise bad('malformed bond row')
        end
        raise bad('duplicate bond row') if doc['bonds'].key?(b['claimId'])

        doc['bonds'][b['claimId']] = Marshal.load(Marshal.dump(b))
      end
      doc
    end

    def encode_doc(d) = { 'v' => 1, 'balances' => d['balances'].map { |a, v| [a, v] }, 'bonds' => d['bonds'].values, 'highWater' => d['highWater'] }
  end

  def self.bond_store?(s) = !s.nil? && %i[read commit deposit].all? { |m| s.respond_to?(m) }

  # The reference bond store: the whole book is one document in an atomic key-value store, so every transition is a single atomic
  # read-modify-write (SqliteAtomicKv is crash-safe; MemoryAtomicKv is for tests). LIMIT: one document, rewritten on every commit; a
  # production deployment implements the store over a database transaction.
  class KvBondStore
    D = BondStoreDocs

    def initialize(kv, key = D::DOC_KEY)
      raise BondStoreError.new('store_missing', 'KvBondStore needs an atomic kv') unless kv.respond_to?(:get) && kv.respond_to?(:update)

      @kv = kv
      @key = key
    end

    def read(claim_id, depositor = nil) = D.snapshot_of(D.decode_doc(@kv.get(@key)), claim_id, depositor)

    def commit(plan, observed_at)
      out = nil
      @kv.update(@key) do |prev|
        doc = D.decode_doc(prev)
        out = D.commit_plan(doc, plan, observed_at)
        out['outcome'] == 'committed' ? D.encode_doc(doc) : nil # nil: leave the key untouched
      end
      out
    end

    # Atomically credit `account` with `amount` (a positive finite number). Returns the new balance.
    def deposit(account, amount)
      raise ::RangeError, 'deposit: account is required' unless account.is_a?(String) && !account.empty?
      raise ::RangeError, 'deposit: amount must be a positive finite number' if !D.fin?(amount) || amount <= 0

      res = nil
      @kv.update(@key) do |prev|
        doc = D.decode_doc(prev)
        bal = D.apply_bond_moves(->(a) { doc['balances'].fetch(a, 0) }, [{ 'account' => account, 'op' => 'credit', 'amount' => amount }])[account]
        doc['balances'][account] = bal
        res = bal
        D.encode_doc(doc)
      end
      res
    end
  end
end
