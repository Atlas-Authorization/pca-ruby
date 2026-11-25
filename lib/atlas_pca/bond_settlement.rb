# frozen_string_literal: true

require_relative 'store_errors'
require_relative 'bond_store'
require_relative 'optimistic_adjudication'

module AtlasPca
  # Durable bond settlement (the reference's `bond-settlement` planner and `StoreBondLedger`): exact micro-unit money arithmetic, the slash
  # split, bond sizing, the evidence digests a signed settlement record commits to, BondSettlementPlanner (the pure half: validates a transition
  # against a read view, re-derives every slash verdict ITSELF, computes the balance movements and signs the record) and StoreBondLedger (commits
  # the plans to a bond store atomically, fails closed, and stamps every time from a clock the claimant cannot touch). INTERNAL ACCOUNTING ONLY:
  # nothing here moves money.
  #
  # THE CHALLENGE-WINDOW CLOCK: the window opens at the ledger's own `registeredAt` (its clock at open_claim), lasts the claim's
  # `challenge_window_ms` and is never derived from the claim's `issued_at`. The ledger's "now" is max(clock, highest time the store has ever
  # recorded), so a clock that steps backwards cannot reopen a closed window or release early. Records are String-keyed Hashes.
  module BondSettlement
    ESCROW_ACCOUNT = 'escrow'
    COMPENSATION_POOL_ACCOUNT = 'pca:pool:compensation'
    SETTLEMENT_DOMAIN = "atlas-pca/bond-settlement/v1\x00"
    SETTLEMENT_LEAF_DOMAIN = 'atlas-pca/settlement-leaf/v1'
    DEFAULT_MIN_CHALLENGE_WINDOW_MS = 30_000
    MAX_SAFE_MICROS = 1e15
    MIN_SHARE_QUANTUM = 2.0**-30
    B = BondStoreDocs

    module_function

    def fin?(x) = B.fin?(x)
    def lenient(v) = AtlasPca.b64e(AtlasPca.sha(AtlasPca.canonical_bytes_lenient(v)))
    def js_num(x) = AtlasPca::Predicates.js_number_string(x.to_f)

    # The conservative reference split: challenger 50%, victim pool 40%, treasury the remainder.
    def default_slash_split_policy = { 'challengerBps' => 5000, 'victimBps' => 4000 }
    def default_bond_policy = { 'floor' => 1, 'k' => 1, 'maxOpenClaims' => 100, 'maxOpenAmount' => Float::INFINITY }

    # Snap a computed amount UP onto the micro grid (a bond is never rounded down); float noise below 1e-3 micro-units is absorbed.
    def quantize_up(x)
      return x if !fin?(x) || x <= 0

      scaled = x * 1_000_000
      return x if scaled > MAX_SAFE_MICROS

      r = (scaled + 0.5).floor
      m = r.to_f / 1_000_000 == x || (scaled - r).abs <= 1e-3 ? r : scaled.ceil
      B.from_micros(m)
    end

    def assert_split_policy(p)
      total = 0
      %w[challengerBps victimBps].each do |k|
        v = p.is_a?(Hash) ? p[k] : nil
        raise ArgumentError, "slash split: #{k} must be an integer in [0,10000]" if !fin?(v) || v != v.floor || v.negative? || v > 10_000

        total += v
      end
      raise ArgumentError, 'slash split: challengerBps + victimBps must not exceed 10000' if total > 10_000
    end

    def ulp_of(x)
      f = x.to_f.abs
      f.next_float - f
    end

    def share_quantum(amount)
      u = ulp_of(amount)
      amount == amount.floor ? [1, u].max : [MIN_SHARE_QUANTUM, u].max
    end

    # The challenger / victim / treasury division of a slashed `amount`: exact (treasury = amount - challenger - victim). `dest` has
    # 'challengerAccount' (a string, or an explicit nil for an anonymous challenge, which pays the whole bond to the treasury),
    # 'victimAccount' and 'treasuryAccount'.
    def compute_slash_split(amount, policy, dest)
      raise ArgumentError, 'computeSlashSplit: amount must be a positive finite number' if !fin?(amount) || amount <= 0

      assert_split_policy(policy)
      victim = dest['victimAccount']
      treasury = dest['treasuryAccount']
      raise ArgumentError, 'computeSlashSplit: victimAccount is required' unless victim.is_a?(String) && !victim.empty?
      raise ArgumentError, 'computeSlashSplit: treasuryAccount is required' unless treasury.is_a?(String) && !treasury.empty?

      has = dest.key?('challengerAccount')
      ch = dest['challengerAccount']
      out = lambda do |c, v, t, amt|
        r = { 'amount' => amt, 'challengerReward' => c, 'victimCompensation' => v, 'treasuryRemainder' => t }
        r['challengerAccount'] = ch if has
        r.merge('victimAccount' => victim, 'treasuryAccount' => treasury)
      end
      return out.call(0, 0, amount, amount) if has && ch.nil?

      micros = amount == amount.floor ? nil : B.to_micros(amount) # integer bonds keep whole-unit shares
      cbps = policy['challengerBps']
      vbps = policy['victimBps']
      unless micros.nil?
        c = micros * cbps.to_i / 10_000
        v = micros * vbps.to_i / 10_000
        t = micros - c - v
        return out.call(B.from_micros(c), B.from_micros(v), B.from_micros(t), B.from_micros(micros))
      end
      q = share_quantum(amount)
      share = ->(bps) { (((amount * bps) / 10_000.0) / q).floor * q }
      challenger = [share.call(cbps), amount].min
      victim_comp = [share.call(vbps), amount - challenger].min
      out.call(challenger, victim_comp, amount - challenger - victim_comp, amount)
    end

    # e^gamma for gamma a multiple of 1/8 in [1, 64], from exactly rounded operations only (no pow, which differs in the last bit between
    # libm implementations): e multiplied floor(n / 8) times, then the 1/2, 1/4 and 1/8 roots by repeated sqrt, in that order
    def pow_eighths(e, gamma)
      n = gamma * 8
      raise ArgumentError, 'bondAmount: power curve gamma must be a multiple of 1/8 and at most 64' unless n.to_f == n.to_f.floor && gamma <= 64

      n = n.to_i
      e = e.to_f
      r = 1.0
      (n / 8).times { r *= e }
      sq = ->(x) { x.negative? ? Float::NAN : Math.sqrt(x) } # JavaScript Math.sqrt of a negative is NaN
      s1 = sq.call(e)
      s2 = sq.call(s1)
      s3 = sq.call(s2)
      f = n % 8
      r *= s1 if f.anybits?(4)
      r *= s2 if f.anybits?(2)
      r *= s3 if f.anybits?(1)
      r
    end

    def curve_component(curve, k, e)
      kind = curve.is_a?(Hash) ? curve['kind'] : nil
      return k * e if curve.nil? || kind == 'linear'

      if kind == 'power'
        g = curve['gamma']
        raise ArgumentError, 'bondAmount: power curve requires finite gamma >= 1' unless fin?(g) && g >= 1

        return k * pow_eighths(e, g)
      end
      tiers = curve['tiers']
      raise ArgumentError, 'bondAmount: piecewise curve requires at least one tier' if !tiers.is_a?(Array) || tiers.empty?

      acc = 0
      prev_up = 0
      prev_marginal = 0
      tiers.each do |tier|
        raise ArgumentError, 'bondAmount: malformed tier' unless tier.is_a?(Hash)

        up_to = tier['upTo']
        mk = tier['marginalK']
        raise ArgumentError, 'bondAmount: piecewise tier `upTo` must be strictly increasing' unless (fin?(up_to) && up_to > prev_up) || up_to == Float::INFINITY
        raise ArgumentError, 'bondAmount: piecewise `marginalK` must be a finite number >= 0' unless fin?(mk) && mk >= 0
        raise ArgumentError, 'bondAmount: piecewise marginal rates must be non-decreasing (convex)' if mk < prev_marginal

        width = [e, up_to].min - prev_up
        acc += width * mk if width.positive?
        prev_up = up_to
        prev_marginal = mk
        break if e <= up_to
      end
      acc += (e - prev_up) * prev_marginal if e > prev_up
      k * acc
    end

    # max(floor, curve(k, exposure)) snapped up onto the micro grid; no curve = linear. A non-finite or non-positive exposure gives the floor.
    def bond_amount(policy, exposure)
      e = fin?(exposure) && exposure.positive? ? exposure : 0
      v = [policy['floor'], curve_component(policy['curve'], policy['k'], e)].max
      # JS numbers are doubles: an integer beyond 2^53 is its nearest double, never an exact bignum
      v = v.to_f if v.is_a?(Integer) && v.abs > 9_007_199_254_740_992
      quantize_up(v)
    end

    def claim_identity(claim) = { 'claimDigest' => claim['pcactn_digest'], 'bond_ref' => claim['bond_ref'] }

    # Binds a slash to the server-derived fraud verdict.
    def settlement_evidence_digest(claim, v)
      lenient(claim_identity(claim).merge('fraudulent' => v['fraudulent'], 'slashBondRef' => v['slashBondRef'], 'reason' => v['reason']))
    end

    def revocation_evidence_digest(claim, revoked_cap_id) = lenient(claim_identity(claim).merge('kind' => 'revocation', 'revokedCapId' => revoked_cap_id))

    # Evidence digest of a dispute-game slash: the adjudicator's own verdict, never a challenger assertion.
    def dispute_evidence_digest(claim, v)
      lenient(claim_identity(claim).merge('kind' => 'dispute', 'outcome' => v['outcome'], 'input' => v['input'], 'agentValue' => v['agentValue'],
                                          'oracleValue' => v['oracleValue'], 'slashBondRef' => v['slashBondRef'], 'reason' => v['reason']))
    end

    def message(body) = SETTLEMENT_DOMAIN.b + AtlasPca.canonical_bytes_lenient(body)

    # Verify a settlement record's signature under the guardian public key; suite-agile (see settlement_wire_check).
    def verify_settlement(record, guardian_public, pins = nil) = AtlasPca.settlement_wire_check(record, guardian_public, pins) == 'ok'

    def settlement_record_digest(record) = lenient({ 't' => SETTLEMENT_LEAF_DOMAIN, 'record' => record })

    # The salted commitment of a settlement record (the opaque transparency-log leaf).
    def settlement_commit(salt, record)
      raise ArgumentError, 'settlementCommit: salt must be a non-empty string' unless salt.is_a?(String) && !salt.empty?

      lenient({ 'salt' => salt, 'settlement_digest' => settlement_record_digest(record) })
    end
  end

  # The pure half of bond settlement. A plan is {'claimId', 'expect', 'next', 'open'?, 'moves', 'record'} (see bond_store.rb). `view` is
  # {'bond' => ->(id) { row | nil }, 'balance_of' => ->(account) { number }, 'open_totals' => ->(depositor) { [count, sum] }}.
  class BondSettlementPlanner
    S = BondSettlement
    attr_reader :guardian_public_key, :escrow, :bond_policy, :slash_split_policy

    def initialize(guardian, guardian_epoch: nil, alg: nil, pq: nil, escrow_account: nil, bond_policy: nil, slash_split_policy: nil)
      raise ArgumentError, 'BondLedger: guardian must be a KeyPair' unless guardian.is_a?(AtlasPca::KeyPair)
      if !guardian_epoch.nil? && (!guardian_epoch.is_a?(Integer) || guardian_epoch.negative? || guardian_epoch > 9_007_199_254_740_991)
        raise ArgumentError, 'BondLedger: guardianEpoch must be a non-negative safe integer'
      end

      @g = guardian
      @epoch = guardian_epoch
      @alg = alg
      @pq = pq
      @guardian_public_key = guardian.public
      @escrow = escrow_account || S::ESCROW_ACCOUNT
      @bond_policy = bond_policy || S.default_bond_policy
      @slash_split_policy = slash_split_policy || S.default_slash_split_policy
    end

    def plan_open(view, claim_id, amount, depositor, exposure, now, window = nil)
      raise ArgumentError, 'openBond: claimId is required' unless claim_id.is_a?(String) && !claim_id.empty?
      raise ArgumentError, 'openBond: amount must be a positive finite number' if !S.fin?(amount) || amount <= 0
      raise ArgumentError, 'openBond: depositor is required' unless depositor.is_a?(String) && !depositor.empty?
      raise ArgumentError, "openBond: bond #{claim_id} already exists (double-open refused)" unless view['bond'].call(claim_id).nil?

      required = S.bond_amount(@bond_policy, exposure.nil? ? 0 : exposure)
      raise ArgumentError, "openBond: amount #{S.js_num(amount)} is below the required bond #{S.js_num(required)}" if amount < required

      count, total = view['open_totals'].call(depositor)
      raise ArgumentError, 'openBond: depositor open-claim cap reached' unless S.fin?(count) && count + 1 <= @bond_policy['maxOpenClaims']
      raise ArgumentError, 'openBond: depositor aggregate open-bond cap exceeded' unless S.fin?(total + amount) && total + amount <= @bond_policy['maxOpenAmount']
      raise ArgumentError, 'openBond: insufficient balance for the bond' if view['balance_of'].call(depositor) < amount

      record = sign(base(claim_id, 'open', amount, depositor, @escrow, now, ''))
      open_ = { 'amount' => amount, 'depositor' => depositor, 'maxOpenClaims' => @bond_policy['maxOpenClaims'], 'maxOpenAmount' => @bond_policy['maxOpenAmount'] }
      open_['window'] = window unless window.nil?
      plan(claim_id, 'none', 'open', [move(depositor, 'debit', amount), move(@escrow, 'credit', amount)], record).merge('open' => open_)
    end

    def plan_release(view, claim_id, now)
      bond = view['bond'].call(claim_id)
      raise ArgumentError, "releaseBond: no bond for #{claim_id}" if bond.nil?
      raise ArgumentError, "releaseBond: bond #{claim_id} is already #{bond['status']} (double-settle refused)" if bond['status'] != 'open'

      amount = bond['amount']
      depositor = bond['depositor']
      plan(claim_id, 'open', 'released', [move(@escrow, 'debit', amount), move(depositor, 'credit', amount)],
           sign(base(claim_id, 'release', amount, @escrow, depositor, now, '')))
    end

    # Slash against a VERIFIED fraud verdict; re-runs the policy VM itself. `p`: claimId, claim, fraudProof, grant, openSnapshot, treasury, and
    # optionally challengerAccount, compensationAccount, splitPolicy.
    def plan_slash(view, p, now)
      claim_id = p['claimId']
      claim = p['claim']
      bond = open_bond(view, 'slashBond', claim_id)
      need_treasury(p, 'slashBond')
      raise ArgumentError, 'slashBond: claim.bond_ref does not match claimId' if claim['bond_ref'] != claim_id

      verdict = OptimisticAdjudication.verify_fraud_proof(claim, p['fraudProof'], p['grant'], p['openSnapshot'])
      if verdict['fraudulent'] != true || verdict['slashBondRef'] != claim_id
        raise ArgumentError, "slashBond: refused — no verified fraud verdict slashing #{claim_id} (#{verdict['reason']})"
      end

      slash_plan(bond, claim_id, now, S.settlement_evidence_digest(claim, verdict), p)
    end

    # Slash because a capability in the claim's chain was revoked after the bond opened (server-derived evidence). `p` adds revokedCapId.
    def plan_slash_on_revocation(view, p, now)
      claim_id = p['claimId']
      claim = p['claim']
      bond = open_bond(view, 'slashBondOnRevocation', claim_id)
      need_treasury(p, 'slashBondOnRevocation')
      raise ArgumentError, 'slashBondOnRevocation: claim.bond_ref does not match claimId' if claim['bond_ref'] != claim_id

      revoked = p['revokedCapId']
      raise ArgumentError, 'slashBondOnRevocation: revokedCapId is required' unless revoked.is_a?(String) && !revoked.empty?

      slash_plan(bond, claim_id, now, S.revocation_evidence_digest(claim, revoked), p)
    end

    # Slash the AGENT's bond because a dispute proved it understated a risk input; re-runs the adjudication itself. `p` adds dispute, oracle, rMargin?.
    def plan_slash_on_dispute(view, p, now)
      claim_id = p['claimId']
      claim = p['claim']
      bond = open_bond(view, 'slashBondOnDispute', claim_id)
      need_treasury(p, 'slashBondOnDispute')
      raise ArgumentError, 'slashBondOnDispute: claim.bond_ref does not match claimId' if claim['bond_ref'] != claim_id

      v = OptimisticAdjudication.adjudicate_dispute(claim, p['dispute'], p['grant'], p['openSnapshot'], p['oracle'], p['rMargin'])
      if v['outcome'] != 'agent-fraud' || v['fraudulent'] != true || v['slashBondRef'] != claim_id
        raise ArgumentError, "slashBondOnDispute: refused — no verified agent-fraud verdict slashing #{claim_id} (#{v['outcome']}: #{v['reason']})"
      end

      slash_plan(bond, claim_id, now, S.dispute_evidence_digest(claim, v), p)
    end

    # Slash the CHALLENGER's counter-bond because the dispute was frivolous (anti-griefing); an anonymous slash, 100% to the treasury.
    def plan_slash_counter_bond(view, p, now)
      cid = p['counterBondId']
      claim = p['claim']
      bond = view['bond'].call(cid)
      raise ArgumentError, "slashCounterBond: no counter-bond for #{cid}" if bond.nil?
      raise ArgumentError, "slashCounterBond: counter-bond #{cid} is already #{bond['status']} (double-settle refused)" if bond['status'] != 'open'

      need_treasury(p, 'slashCounterBond')
      v = OptimisticAdjudication.adjudicate_dispute(claim, p['dispute'], p['grant'], p['openSnapshot'], p['oracle'], p['rMargin'])
      if v['outcome'] != 'claim-upheld' || v['slashCounterBond'] != true
        raise ArgumentError, "slashCounterBond: refused — the dispute is not frivolous (#{v['outcome']}: #{v['reason']})"
      end

      slash_plan(bond, cid, now, S.dispute_evidence_digest(claim, v),
                 { 'treasury' => p['treasury'], 'challengerAccount' => nil, 'compensationAccount' => p['compensationAccount'], 'splitPolicy' => p['splitPolicy'] })
    end

    private

    def sign(base_h)
      with_epoch = base_h.dup
      with_epoch['guardian_epoch'] = @epoch unless @epoch.nil?
      body = AtlasPca.bind_suite(with_epoch, @alg, @pq)
      sig, pq_sig = AtlasPca.sign_with_suite(@alg, @g, @pq, S.message(body))
      out = body.merge('sig' => sig)
      out['pq_sig'] = pq_sig unless pq_sig.nil?
      out
    end

    def move(account, op, amount) = { 'account' => account, 'op' => op, 'amount' => amount }

    def base(claim_id, action, amount, frm, to, at, evidence)
      { 'claimId' => claim_id, 'action' => action, 'amount' => amount, 'from' => frm, 'to' => to, 'at' => at, 'evidenceDigest' => evidence }
    end

    def plan(claim_id, expect, nxt, moves, record) = { 'claimId' => claim_id, 'expect' => expect, 'next' => nxt, 'moves' => moves, 'record' => record }

    def open_bond(view, who, claim_id)
      bond = view['bond'].call(claim_id)
      raise ArgumentError, "#{who}: no bond for #{claim_id}" if bond.nil?
      raise ArgumentError, "#{who}: bond #{claim_id} is already #{bond['status']} (double-settle refused)" if bond['status'] != 'open'

      bond
    end

    def need_treasury(p, who)
      raise ArgumentError, "#{who}: treasury is required" unless p['treasury'].is_a?(String) && !p['treasury'].empty?
    end

    def slash_plan(bond, claim_id, now, evidence, p)
      treasury = p['treasury']
      amount = bond['amount']
      policy = p['splitPolicy'].is_a?(Hash) ? p['splitPolicy'] : @slash_split_policy
      comp = p['compensationAccount']
      dest = { 'challengerAccount' => p['challengerAccount'], 'victimAccount' => comp.nil? || comp == '' ? S::COMPENSATION_POOL_ACCOUNT : comp,
               'treasuryAccount' => treasury }
      split = S.compute_slash_split(amount, policy, dest)
      moves = [move(@escrow, 'debit', amount)] # the full bond leaves escrow
      ca = split['challengerAccount']
      moves << move(ca, 'credit', split['challengerReward']) if ca && ca != '' && split['challengerReward'] > 0
      moves << move(split['victimAccount'], 'credit', split['victimCompensation']) if split['victimCompensation'] > 0
      moves << move(split['treasuryAccount'], 'credit', split['treasuryRemainder']) if split['treasuryRemainder'] > 0
      b = base(claim_id, 'slash', amount, @escrow, treasury, now, evidence)
      b['split'] = split
      plan(claim_id, 'open', 'slashed', moves, sign(b))
    end
  end

  # Durable, restart-safe bond settlement over a bond store (KvBondStore or your own). Every method is idempotent under retry: repeating a
  # transition that already committed returns the stored record and moves nothing, while a conflicting transition (a release after a slash, a
  # second slash with different evidence) raises. Every failure is a BondStoreError: store_missing, guardian_key_missing, clock_invalid,
  # store_unavailable, store_corrupt, invalid_claim, window_open, window_closed, unregistered, claim_mismatch or conflict. Planner failures keep
  # their own message (a plain ArgumentError).
  class StoreBondLedger
    S = BondSettlement
    B = BondStoreDocs

    def initialize(store, guardian, clock: nil, window_policy: nil, guardian_epoch: nil, alg: nil, pq: nil, escrow_account: nil, bond_policy: nil,
                   slash_split_policy: nil)
      raise BondStoreError.new('store_missing', 'a BondStore is required (there is no in-memory default)') unless AtlasPca.bond_store?(store)
      raise BondStoreError.new('guardian_key_missing', 'a guardian secret key is required') unless guardian.is_a?(AtlasPca::KeyPair)

      @store = store
      @planner = BondSettlementPlanner.new(guardian, guardian_epoch: guardian_epoch, alg: alg, pq: pq, escrow_account: escrow_account,
                                                     bond_policy: bond_policy, slash_split_policy: slash_split_policy)
      @clock = clock || -> { Time.now.to_f * 1000 }
      @wp = window_policy || AtlasPca::DEFAULT_WINDOW_POLICY
    end

    def guardian_public_key = @planner.guardian_public_key

    # Top up an account of the internal books (a positive finite amount).
    def deposit(account, amount) = guard { @store.deposit(account, amount) }

    def balance_of(account)
      snap = guard { @store.read('', account) }
      snap['balances'].empty? ? 0 : snap['balances'][0][1]
    end

    def bond_status(claim_id)
      snap = guard { @store.read(claim_id, nil) }
      snap['bond'] ? snap['bond']['status'] : 'none'
    end

    def get_bond(claim_id) = guard { @store.read(claim_id, nil) }['bond']

    # Where the claim's challenge window stands on the ledger's clock; raises `unregistered` for a bond with no claim.
    def challenge_status(claim_id)
      snap, _, now = load_state(claim_id)
      w = (snap['bond'] || {})['window']
      raise BondStoreError.new('unregistered', "bond #{claim_id} has no registered claim") if w.nil? || w == {}

      ends = w['registeredAt'] + w['windowMs']
      { 'phase' => now <= ends ? 'open' : 'finalized', 'endsAt' => ends, 'now' => now }
    end

    # Register an optimistic claim and lock its bond in one atomic commit. The claim must pass the claim check against the ledger's clock and its
    # window must be at least the realistic floor; the window then runs from the ledger's own `registeredAt`.
    def open_claim(claim, pcactn, signer_public, amount, depositor, exposure = nil)
      bond_ref = claim.is_a?(Hash) ? claim['bond_ref'] : nil # a non-object claim is refused by the claim check below
      snap, view, now = load_state(bond_ref.nil? ? 'None' : bond_ref.to_s, depositor)
      check = AtlasPca.claim_check(claim, AtlasPca.hash_canonical(pcactn), signer_public, now, @wp)
      if check != 'ok'
        reason = { 'malformed' => 'malformed claim', 'irreversible' => 'irreversible action is ineligible for the optimistic path',
                   'digest' => 'claim does not cover this PCActn', 'claimed_r' => 'claimed_r is not finite',
                   'signature' => 'claim signature does not verify' }[check]
        reason = AtlasPca.opt_validate_window(claim['issued_at'], claim['challenge_window_ms'], now, @wp) if check == 'window'
        raise BondStoreError.new('invalid_claim', reason || check)
      end
      floor = [@wp['minWindowMs'], S::DEFAULT_MIN_CHALLENGE_WINDOW_MS].max
      if claim['challenge_window_ms'] < floor
        raise BondStoreError.new('invalid_claim', "challenge window #{S.js_num(claim['challenge_window_ms'])} ms is below the #{S.js_num(floor)} ms floor")
      end
      raise BondStoreError.new('invalid_claim', 'claim has no bond_ref') unless claim['bond_ref'].is_a?(String) && !claim['bond_ref'].empty?

      window = { 'registeredAt' => now, 'windowMs' => claim['challenge_window_ms'], 'claimDigest' => S.lenient(claim) }
      return replay_open(snap['bond'], depositor, amount, window) if snap['bond']

      submit(@planner.plan_open(view, claim['bond_ref'], amount, depositor, exposure, now, window), now)
    end

    # Open a bond that backs no claim (a challenger's counter-bond). It has no window; settle it with slash_counter_bond or release_unregistered.
    def open_bond(claim_id, amount, depositor, exposure = nil)
      snap, view, now = load_state(claim_id, depositor)
      return replay_open(snap['bond'], depositor, amount) if snap['bond']

      submit(@planner.plan_open(view, claim_id, amount, depositor, exposure, now, nil), now)
    end

    # Release a registered claim's bond once its challenge window has closed on the ledger's clock.
    def release(claim_id)
      gate = lambda do |bond, now|
        w = bond['window']
        raise BondStoreError.new('unregistered', "bond #{claim_id} has no registered claim; use release_unregistered for a counter-bond") if w.nil? || w == {}
        unless now > w['registeredAt'] + w['windowMs']
          raise BondStoreError.new('window_open', "the challenge window of #{claim_id} closes at #{S.js_num(w['registeredAt'] + w['windowMs'])}")
        end
      end
      settle(claim_id, ->(view, now) { @planner.plan_release(view, claim_id, now) }, gate)
    end

    # Release a bond that backs no claim (a counter-bond).
    def release_unregistered(claim_id)
      gate = lambda do |bond, _now|
        raise BondStoreError.new('conflict', "bond #{claim_id} backs a registered claim; use release") if B.truthy?(bond['window'])
      end
      settle(claim_id, ->(view, now) { @planner.plan_release(view, claim_id, now) }, gate)
    end

    # Slash on a fraud proof the ledger re-verifies itself, inside the challenge window.
    def slash_bond(params)
      settle(params['claimId'], ->(view, now) { @planner.plan_slash(view, params, now) }, challenge_gate(params['claim']))
    end

    # Slash on a dispute the ledger re-adjudicates itself, inside the challenge window.
    def slash_bond_on_dispute(params)
      settle(params['claimId'], ->(view, now) { @planner.plan_slash_on_dispute(view, params, now) }, challenge_gate(params['claim']))
    end

    # Slash because a capability in the claim's chain was revoked (server-derived evidence; not window-gated).
    def slash_bond_on_revocation(params)
      gate = lambda do |bond, _now|
        if B.truthy?(bond['window']) && bond['window']['claimDigest'] != S.lenient(params['claim'])
          raise BondStoreError.new('claim_mismatch', "the claim is not the one registered for #{bond['claimId']}")
        end
      end
      settle(params['claimId'], ->(view, now) { @planner.plan_slash_on_revocation(view, params, now) }, gate)
    end

    # Slash a challenger's counter-bond after a frivolous dispute.
    def slash_counter_bond(params)
      settle(params['counterBondId'], ->(view, now) { @planner.plan_slash_counter_bond(view, params, now) })
    end

    private

    def guard
      yield
    rescue BondStoreError
      raise
    rescue StandardError => e
      raise BondStoreError.new('store_unavailable', e.message.to_s.empty? ? 'store failed' : e.message)
    end

    def load_state(claim_id, depositor = nil)
      snap = guard { @store.read(claim_id, depositor) }
      t = @clock.call
      raise BondStoreError.new('clock_invalid', 'the clock returned a non-finite time') unless S.fin?(t)

      bond = snap['bond']
      bal = snap['balances'].to_h { |a, v| [a, v] }
      view = { 'bond' => ->(cid) { bond && bond['claimId'] == cid ? bond : nil }, 'balance_of' => ->(a) { bal.fetch(a, 0) },
               'open_totals' => ->(_d) { [snap['openTotals']['count'], snap['openTotals']['sum']] } }
      [snap, view, [t, snap['highWater']].max]
    end

    def submit(plan, now)
      out = guard { @store.commit(plan, now) }
      raise BondStoreError.new('conflict', out['reason']) if out['outcome'] == 'conflict'

      out['record']
    end

    def settle(claim_id, plan, gate = nil)
      snap, view, now = load_state(claim_id)
      bond = snap['bond']
      if bond && bond['status'] != 'open'
        last = bond['records'].empty? ? nil : bond['records'][-1]
        as_open = view.merge('bond' => ->(_c) { bond.merge('status' => 'open') })
        again = plan.call(as_open, now) # raises if the evidence no longer holds
        return last if last && B.same_settlement?(last, again['record'])

        return plan.call(view, now)['record'] # raises the standard double-settle refusal
      end
      gate.call(bond, now) if bond && gate
      submit(plan.call(view, now), now)
    end

    def replay_open(prior, depositor, amount, window = nil)
      same = prior['depositor'] == depositor && prior['amount'] == amount && (prior['window'] || {})['claimDigest'] == (window || {})['claimDigest']
      return prior['records'][0] if same && !prior['records'].empty?

      raise BondStoreError.new('conflict', "openBond: bond #{prior['claimId']} already exists (double-open refused)")
    end

    def challenge_gate(claim)
      lambda do |bond, now|
        w = bond['window']
        raise BondStoreError.new('unregistered', "bond #{bond['claimId']} has no registered claim") if w.nil? || w == {}
        raise BondStoreError.new('claim_mismatch', "the claim is not the one registered for #{bond['claimId']}") if w['claimDigest'] != S.lenient(claim)
        unless now <= w['registeredAt'] + w['windowMs']
          raise BondStoreError.new('window_closed', "the challenge window of #{bond['claimId']} closed at #{S.js_num(w['registeredAt'] + w['windowMs'])}")
        end
      end
    end
  end
end
