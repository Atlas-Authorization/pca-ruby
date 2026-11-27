# frozen_string_literal: true

# Differential oracle: the durable stores against the TypeScript reference (ref-core-stores-java): the ledger store, the stored ledger with its
# checkpoint verification, the bond store, the budget ledger with signed releases and aggregate admission, and the mesh witness. Every failure is
# compared by its stable code ('RangeError' for an argument error).
require_relative 'support/ref_oracle'
require_relative 'test_ref_core_mesh'
require 'minitest/autorun'

class TestRefCoreStores < Minitest::Test
  A = AtlasPca
  B = AtlasPca::BudgetLedger
  CASES = Ref.load('core-stores-java')

  def self.key(label) = A::KeyPair.new(Digest::SHA256.digest("atlas-pca-conformance/#{label}"))

  def self.script(ops)
    ops.map do |op|
      yield(op)
    rescue StandardError => e
      { '$err' => A.store_error_code(e) }
    end
  end

  def self.ledger_store(ops)
    kv = A::MemoryAtomicKv.new
    s = A::KvLedgerStore.new(kv)
    script(ops) do |op|
      case op[0]
      when 'size' then s.size
      when 'read' then s.read(op[1], op[2])
      when 'append' then s.append(op[1], op[2])
      when 'cpCount' then s.checkpoint_count
      when 'cps' then s.checkpoints(op[1])
      when 'appendCp' then s.append_checkpoint(op[1], op[2])
      when 'kvSet' then kv.set('pca-ledger-store/v1', op[1])
      else raise ArgumentError, 'op'
      end
    end
  end

  def self.stored_ledger(ops)
    kv = A::MemoryAtomicKv.new
    store = A::KvLedgerStore.new(kv)
    handles = {}
    calls = 0
    gkey = key('stored-ledger-guardian')
    clock = lambda do
      t = 1_800_000_000_000 + (1000 * calls)
      calls += 1
      t
    end
    script(ops) do |op|
      head = op[0]
      case head
      when 'open'
        g = op.length > 2 && op[2] == 'other-key' ? key('other') : gkey
        h = A::StoredLedger.open(store, g, op.length > 3 && !op[3].nil? ? op[3] : 'inst', 'pr', clock)
        handles[op[1]] = h
        { 'size' => h.size, 'guardian' => h.guardian }
      when 'kvSet' then kv.set('pca-ledger-store/v1', op[1])
      when 'kvGet' then kv.get('pca-ledger-store/v1')
      else
        h = handles[head]
        case op[1]
        when 'append' then h.append(op[2])
        when 'checkpoint' then h.checkpoint
        when 'catchUp' then h.catch_up
        when 'head' then h.head
        when 'size' then h.size
        when 'incl' then h.inclusion_proof(op[2])
        when 'consFrom' then h.consistency_proof_from(op[2])
        when 'commits' then h.commits
        when 'latest' then h.latest_checkpoint
        when 'chain' then h.checkpoint_chain
        when 'guardian' then h.guardian
        else raise ArgumentError, 'op'
        end
      end
    end
  end

  def self.bond_store(ops)
    kv = A::MemoryAtomicKv.new
    s = A::KvBondStore.new(kv)
    script(ops) do |op|
      case op[0]
      when 'read' then s.read(op[1], op[2])
      when 'commit' then s.commit(op[1], op[2])
      when 'deposit' then s.deposit(op[1], op[2])
      when 'kvSet' then kv.set('pca-bond-store/v1', op[1])
      when 'kvGet' then kv.get('pca-bond-store/v1')
      else raise ArgumentError, 'op'
      end
    end
  end

  def self.budget_ledger(ops)
    rkey = key('release-signer')
    kv = A::MemoryAtomicKv.new
    ledger = nil
    log = A::KvLedgerStore.new(A::MemoryAtomicKv.new)
    script(ops) do |op|
      case op[0]
      when 'new'
        ledger = A::KvBudgetLedger.new(kv, op[1])
        ledger.durable
      when 'snapshot' then ledger.snapshot(op[1])
      when 'reserve' then ledger.reserve(op[1], op[2])
      when 'start' then ledger.start(op[1], op[2])
      when 'commit' then ledger.commit(op[1], op[2])
      when 'release' then ledger.release(op[1], op[2], op[3])
      when 'expire' then ledger.expire(op[1], op[2])
      when 'signRelease' then B.sign_release(op[1], op[2], op[3], op[4], rkey)
      when 'verifyRelease' then B.verify_release(op[1], op[2] == 'signer' ? rkey.public : op[2])
      when 'releaseCommit' then [B.release_digest(op[1]), B.release_commit(op[1])]
      when 'anchor' then [B.anchor_release(log, op[1]), log.size]
      when 'scopeKey' then B.scope_key(op[1], op[2])
      when 'kvSet' then kv.set(op[1], op[2])
      when 'admit'
        ad = op[1]
        allow = ad['allow']
        B.admit_aggregate_action(ledger, ad['ids'], ad['accumulators'], nil, ad['event'], ->(state) { { 'allow' => allow, 'state' => state } },
                                 ad['expiresAt'], ad['maxAttempts'])
      when 'startAgg' then B.start_aggregate(ledger, op[1])
      when 'settleAgg' then B.settle_aggregate(ledger, op[1], op[2], nil)
      else raise ArgumentError, 'op'
      end
    end
  end

  MAP = {
    'ledgerStore' => ->(ops) { ledger_store(ops) }, 'storedLedger' => ->(ops) { stored_ledger(ops) }, 'bondStore' => ->(ops) { bond_store(ops) },
    'budgetLedger' => ->(ops) { budget_ledger(ops) }, 'meshWitness' => ->(ops) { TestRefCoreMesh.witness_script(ops) }
  }.freeze

  def test_every_section_is_covered = assert_equal MAP.keys.sort, CASES.keys.sort

  MAP.each do |fn, call|
    define_method("test_#{fn}_matches_the_reference") { Ref.run(self, CASES[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 227, CASES.values.sum(&:length), 'core-stores-java'
  end

end
