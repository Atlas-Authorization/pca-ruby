# frozen_string_literal: true

require_relative 'store_errors'

module AtlasPca
  # Durable aggregate budgets (the reference's `budget-ledger`): the BudgetLedger contract, the reference KvBudgetLedger, signed and anchored
  # releases, and scoped admission.
  #
  # CLAIMED: NO OVERSPEND AT PRINCIPAL, ORG AND FLEET SCOPE, given a ledger that is linearizable per key and durable. An accumulator with
  # `scope: principal | org | fleet` counts the events of EVERY session and delegated agent of that scope in ONE state keyed by the scope id,
  # so N sessions share one cap and a split across sessions or agents buys nothing. A reservation counts as soon as it is made; the ledger
  # refuses one whose post-value would pass the accumulator's `domain_max`, inside the same atomic step that records it.
  #
  # TWO PHASES, THREE STEPS: `reserve` (counted at once), `start` (recorded BEFORE the effect runs), then `commit` (the effect happened) or
  # `release` (it did not; a signed event, BudgetLedger.sign_release, that can be anchored in a transparency log, BudgetLedger.anchor_release).
  # `expire` frees only a reservation that was never started: expiry needs no trusted clock. A release that never arrives only OVER-restricts.
  # admit_aggregate_action refuses (`not_durable`) a ledger whose `durable` is not true, and denies `scope_unbound` when the caller names no id
  # for a scope the root uses. Events are Hashes {'id', 'verb', 'resource', 'params', 't', 'status'}.
  module BudgetLedger
    PREFIX = 'pca-budget-ledger/v1/'
    RELEASE_DOMAIN = "atlas-pca/budget-release/v1\x00"
    RELEASE_REASONS = %w[effect_failed effect_not_run denied_downstream rollback].freeze

    module_function

    def int?(x) = AtlasPca.ledger_safe_int?(x)
    def id_ok?(s) = AtlasPca.undo_id_ok?(s)

    # The ledger key of a scope ('principal' | 'org' | 'fleet') and its id. Injective: the id is percent-encoded.
    def scope_key(scope, id)
      raise BudgetLedgerError.new('invalid', 'a scope id is a non-empty string of at most 256 characters without control characters') unless id_ok?(id)

      "#{scope}/#{id.b.gsub(/[^A-Za-z0-9\-_.!~*'()]/n) { |c| format('%%%02X', c.ord) }}"
    end

    def empty_doc = { 'v' => 1, 'ver' => 0, 'events' => [] }

    def decode_doc(raw)
      return empty_doc if raw.nil?

      unless raw.is_a?(Hash) && raw['v'] == 1 && int?(raw['ver']) && raw['events'].is_a?(Array) && raw['events'].all? { |e| e.is_a?(Hash) && e['id'].is_a?(String) }
        raise BudgetLedgerError.new('store_corrupt', 'budget document has the wrong shape')
      end

      raw
    end

    def same_event?(a, b)
      k = ->(e) { AtlasPca.hash_canonical({ 'id' => e['id'], 'verb' => e['verb'], 'resource' => e['resource'], 'params' => e['params'], 't' => e['t'] }) }
      k.call(a) == k.call(b)
    end

    # Reserve req['event'] in `doc` ({'ver', 'events'}) unless it would pass an accumulator's cap. The pure transition every store is this plus a
    # per-key lock.
    def reserve_in_doc(doc, req)
      e = req.is_a?(Hash) ? req['event'] : nil
      unless e.is_a?(Hash) && id_ok?(e['id']) && e['verb'].is_a?(String) && e['resource'].is_a?(String) && int?(e['t']) && (e['params'].is_a?(Hash) || e['params'].is_a?(Array))
        raise ::RangeError, 'reserve: a malformed event'
      end
      raise ::RangeError, 'reserve: accumulators must be an array' unless req['accumulators'].is_a?(Array)

      ev = req['expectedVersion']
      raise ::RangeError, 'reserve: expectedVersion must be a non-negative safe integer' if !ev.nil? && (!int?(ev) || ev.negative?)
      raise ::RangeError, 'reserve: expiresAt must be a safe integer' if !req['expiresAt'].nil? && !int?(req['expiresAt'])

      prior = doc['events'].find { |x| x['id'] == e['id'] }
      unless prior.nil?
        return same_event?(prior, e) ? { 'outcome' => 'replayed', 'version' => doc['ver'], 'status' => prior['status'] } : { 'outcome' => 'id_conflict', 'version' => doc['ver'] }
      end
      return { 'outcome' => 'conflict', 'version' => doc['ver'] } if !ev.nil? && ev != doc['ver']

      schema = req['schema'].nil? ? V2JS::UNDEF : req['schema']
      post = {}
      req['accumulators'].each do |a|
        raise ::RangeError, "reserve: accumulator #{a['id']} has no domain_max (the cap)" if a['domain_max'].nil?
        next unless AtlasPca.acc_selects(a, e['verb'], schema)

        p = begin
          AtlasPca.acc_post(a, doc['events'], { 'verb' => e['verb'], 'params' => e['params'], 't' => e['t'] }, schema)
        rescue StandardError => err
          raise BudgetLedgerError.new('store_corrupt', err.message.to_s.empty? ? 'unreadable history' : err.message)
        end
        return { 'outcome' => 'over_cap', 'version' => doc['ver'], 'acc' => a['id'], 'post' => p, 'cap' => a['domain_max'] } if p > a['domain_max']

        post[a['id']] = p
      end
      entry = { 'id' => e['id'], 'verb' => e['verb'], 'resource' => e['resource'], 'params' => Marshal.load(Marshal.dump(e['params'])), 't' => e['t'], 'status' => 'reserved' }
      entry['exp'] = req['expiresAt'] unless req['expiresAt'].nil?
      doc['events'] << entry
      doc['ver'] += 1
      { 'outcome' => 'reserved', 'version' => doc['ver'], 'post' => post }
    end

    def find(doc, id) = doc['events'].find { |x| x['id'] == id }

    def start_in_doc(doc, id)
      e = find(doc, id)
      return { 'outcome' => 'unknown', 'version' => doc['ver'] } if e.nil?
      return { 'outcome' => 'refused', 'version' => doc['ver'], 'status' => e['status'] } if e['status'] == 'released'
      return { 'outcome' => 'replayed', 'version' => doc['ver'] } if e['started'] || e['status'] == 'committed'

      e['started'] = true
      doc['ver'] += 1
      { 'outcome' => 'settled', 'version' => doc['ver'] }
    end

    def commit_in_doc(doc, id)
      e = find(doc, id)
      return { 'outcome' => 'unknown', 'version' => doc['ver'] } if e.nil?
      return { 'outcome' => 'replayed', 'version' => doc['ver'] } if e['status'] == 'committed'
      return { 'outcome' => 'refused', 'version' => doc['ver'], 'status' => e['status'] } if e['status'] != 'reserved'

      e['status'] = 'committed'
      doc['ver'] += 1
      { 'outcome' => 'settled', 'version' => doc['ver'] }
    end

    def release_in_doc(doc, key, id, evidence)
      e = find(doc, id)
      return { 'outcome' => 'unknown', 'version' => doc['ver'] } if e.nil?
      return { 'outcome' => 'replayed', 'version' => doc['ver'] } if e['status'] == 'released'
      return { 'outcome' => 'refused', 'version' => doc['ver'], 'status' => e['status'] } if e['status'] != 'reserved'
      raise ::RangeError, 'release: the evidence is for another reservation' if !evidence.nil? && (evidence['key'] != key || evidence['id'] != id)

      e['status'] = 'released'
      e['rel'] = Marshal.load(Marshal.dump(evidence)) if !evidence.nil? && evidence != {}
      doc['ver'] += 1
      { 'outcome' => 'settled', 'version' => doc['ver'] }
    end

    def expire_in_doc(doc, now)
      raise ::RangeError, 'expire: now must be a safe integer' unless int?(now)

      released = []
      doc['events'].each do |e|
        next unless e['status'] == 'reserved' && !e['started'] && !e['exp'].nil? && e['exp'] <= now

        e['status'] = 'released'
        e['rel'] = { 'reason' => 'expired', 'at' => now }
        released << e['id']
      end
      doc['ver'] += 1 unless released.empty?
      { 'released' => released, 'version' => doc['ver'] }
    end

    # ---- signed, anchored releases ----------------------------------------------------------------------------------------

    def release_message(r)
      body = %w[v key id reason at signer].to_h { |k| [k, r[k]] }
      RELEASE_DOMAIN.b + AtlasPca.strict_bytes(body)
    end

    # A signed statement by the releaser that a reservation's effect did NOT happen (`reason`: effect_failed, effect_not_run, denied_downstream
    # or rollback). `secret` is the releaser's KeyPair.
    def sign_release(key, id, reason, at, secret)
      raise ::RangeError, 'signRelease: a malformed release' if !RELEASE_REASONS.include?(reason) || !int?(at) || !id_ok?(key) || !id_ok?(id)

      base = { 'v' => 1, 'key' => key, 'id' => id, 'reason' => reason, 'at' => at, 'signer' => secret.public }
      base.merge('sig' => AtlasPca.b64e(secret.sign(release_message(base))))
    end

    # True iff `r` is well formed and signed by `expected_signer` over exactly its content. Never raises.
    def verify_release(r, expected_signer)
      return false unless r.is_a?(Hash) && r['v'] == 1 && r['signer'] == expected_signer && RELEASE_REASONS.include?(r['reason']) && int?(r['at']) &&
                          id_ok?(r['key']) && id_ok?(r['id']) && r['sig'].is_a?(String) && !AtlasPca.b64d(r['sig'], 64).nil?

      AtlasPca.verify_b64u(expected_signer, release_message(r), r['sig'])
    rescue StandardError
      false
    end

    def release_digest(r) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/budget-release-ref/v1', 'r' => r })

    # The log leaf of a release.
    def release_commit(r) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/budget-release-leaf/v1', 'digest' => release_digest(r) })

    # Anchor a signed release in a transparency log store (retries on a position conflict). Returns the leaf index.
    def anchor_release(log, r)
      commit = release_commit(r)
      64.times do
        size = log.size
        o = log.append(size, [commit])
        return size if %w[appended replayed].include?(o['outcome'])
      end
      raise BudgetLedgerError.new('conflict_exhausted', 'could not anchor the release: the log kept moving')
    end

    # ---- scoped admission ---------------------------------------------------------------------------------------------------

    # The ledger key of an accumulator for this admission, or nil when it is session-scoped. Raises `scope_unbound`.
    def aggregate_key_of(a, ids)
      scope = a['scope']
      return nil if scope.nil? || scope == 'session'

      i = ids[scope]
      raise BudgetLedgerError.new('scope_unbound', "accumulator #{a['id']} is #{scope}-scoped but no #{scope} id was given") if i.nil?

      scope_key(scope, i)
    end

    def context_state(accs, history, cand, schema)
      state = {}
      accs.each do |a|
        next unless (a['holder'] || {})['kind'] == 'site_local'
        next if !a['key'].nil? && AtlasPca.acc_key_of(a, cand['params']).nil? # the verifier fails the claim (missing key)

        state[a['id']] = AtlasPca.acc_pre_state(a, history, { 'params' => cand['params'], 't' => cand['t'] }, schema.nil? ? V2JS::UNDEF : schema)
      end
      state
    end

    # Admit one action against every non-session accumulator of the root, atomically per key: read each key's snapshot and compute the
    # pre-states, `verify.call(state)` (the host's verifier; returns a Hash with 'allow'), then on allow `reserve` in every key with the snapshot's
    # version. A moved key repeats from the start; a key over its cap denies and releases what the earlier keys reserved. Refuses (raises
    # `not_durable`) a ledger that is not durable. Returns {'admitted' => true, 'verdict', 'reservations', 'state'} or {'admitted' => false,
    # 'reason', 'verdict'?}.
    def admit_aggregate_action(ledger, ids, accumulators, schema, event, verify, expires_at = nil, max_attempts = nil)
      scoped = accumulators.select { |a| !a['scope'].nil? && a['scope'] != 'session' }
      if !scoped.empty? && (!ledger.respond_to?(:durable) || ledger.durable != true)
        raise BudgetLedgerError.new('not_durable', 'a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)')
      end

      by_key = {}
      begin
        scoped.each { |a| (by_key[aggregate_key_of(a, ids)] ||= []) << a }
      rescue BudgetLedgerError => e
        return { 'admitted' => false, 'reason' => "scope_unbound: #{e.message}" } if e.code == 'scope_unbound'

        raise
      end
      keys = by_key.keys.sort_by { |k| k.encode('UTF-16BE').b }
      (max_attempts.nil? ? 256 : max_attempts).times do
        snaps = {}
        state = {}
        keys.each do |k|
          s = ledger.snapshot(k)
          snaps[k] = s
          state.update(context_state(by_key[k], s['events'], event, schema))
        end
        verdict = verify.call(state)
        return { 'admitted' => false, 'reason' => 'verifier denied', 'verdict' => verdict } unless verdict['allow']

        done = []
        moved = false
        keys.each do |k|
          req = { 'event' => event, 'accumulators' => by_key[k], 'schema' => schema, 'expectedVersion' => snaps[k]['version'], 'expiresAt' => expires_at }.compact
          r = ledger.reserve(k, req)
          if r['outcome'] == 'reserved' || (r['outcome'] == 'replayed' && r['status'] == 'reserved')
            done << { 'key' => k, 'id' => event['id'] }
            next
          end
          done.each { |d| ledger.release(d['key'], d['id']) }
          if r['outcome'] == 'conflict'
            moved = true
            break
          end
          why = case r['outcome']
                when 'over_cap' then "over_cap: #{r['acc']} would reach #{js_num(r['post'])} (cap #{js_num(r['cap'])})"
                when 'replayed' then "already #{r['status']}"
                else r['outcome']
                end
          return { 'admitted' => false, 'reason' => "aggregate: #{why}", 'verdict' => verdict }
        end
        return { 'admitted' => true, 'verdict' => verdict, 'reservations' => done, 'state' => state } unless moved
      end
      raise BudgetLedgerError.new('conflict_exhausted', 'the aggregate kept moving under this admission')
    end

    def js_num(x) = AtlasPca::Predicates.js_number_string(x.to_f)

    # BEFORE the effect: mark every reservation started (non-expirable). Returns false when any is refused (released or expired in the meantime):
    # the effect must NOT run then.
    def start_aggregate(ledger, reservations)
      reservations.each { |r| return false unless %w[settled replayed].include?(ledger.start(r['key'], r['id'])['outcome']) }
      true
    end

    # After the effect: 'committed' (it happened) or 'released' (it did not; a signed `evidence` is stored and can be anchored).
    def settle_aggregate(ledger, reservations, status, evidence = nil)
      reservations.map do |r|
        status == 'committed' ? ledger.commit(r['key'], r['id']) : ledger.release(r['key'], r['id'], evidence ? evidence.call(r) : nil)
      end
    end
  end

  # The reference budget ledger: one document per key in an atomic key-value store (#get / #update), so every operation is one atomic
  # read-modify-write. `durable` is declared by the caller (a kv cannot tell): true only for a persistent one (SqliteAtomicKv).
  class KvBudgetLedger
    B = BudgetLedger
    attr_reader :durable

    def initialize(kv, durable)
      raise BudgetLedgerError.new('store_missing', 'KvBudgetLedger needs an atomic kv') unless kv.respond_to?(:get) && kv.respond_to?(:update)
      raise BudgetLedgerError.new('invalid', 'say whether the kv is durable (true or false)') unless [true, false].include?(durable)

      @kv = kv
      @durable = durable
    end

    def snapshot(key)
      d = B.decode_doc(@kv.get(k(key)))
      { 'version' => d['ver'], 'events' => Marshal.load(Marshal.dump(d['events'])) }
    end

    def reserve(key, req) = txn(key, ->(d) { B.reserve_in_doc(d, req) }, ->(r) { r['outcome'] == 'reserved' })
    def start(key, id) = txn(key, ->(d) { B.start_in_doc(d, id) }, ->(r) { r['outcome'] == 'settled' })
    def commit(key, id) = txn(key, ->(d) { B.commit_in_doc(d, id) }, ->(r) { r['outcome'] == 'settled' })
    def release(key, id, evidence = nil) = txn(key, ->(d) { B.release_in_doc(d, key, id, evidence) }, ->(r) { r['outcome'] == 'settled' })
    def expire(key, now) = txn(key, ->(d) { B.expire_in_doc(d, now) }, ->(r) { !r['released'].empty? })

    private

    def k(key)
      raise ::RangeError, 'a ledger key is a non-empty string without control characters' unless B.id_ok?(key)

      B::PREFIX + key
    end

    def txn(key, fn, writes)
      out = nil
      kk = k(key)
      @kv.update(kk) do |prev|
        d = B.decode_doc(prev)
        out = fn.call(d)
        writes.call(out) ? d : nil
      end
      out
    end
  end
end
