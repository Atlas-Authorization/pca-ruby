# frozen_string_literal: true

# Operation records (T3): execute an authorized operation at most once, with a durable record of what happened.
#
# AtlasPca.authorize decides and consumes the PCActn's replay counter. Between that decision and the end of the side effect
# the process can crash, the client can time out and retry, or two workers can pick up the same authorization. This module
# closes that gap with a record per operation id (AuthorizedOperation#id, the digest of the presented PCActn):
#
#   1. execute_authorized creates the record in state `pending` BEFORE anything runs (one atomic create-if-absent: of N
#      concurrent executions of one authorization exactly one gets to run the block);
#   2. for an irreversible operation it re-checks revocation, expiry and approval immediately before the block (`recheck`;
#      required, fail closed); a failed re-check records `aborted` and the block never runs;
#   3. it moves the record to `executing` and only then calls the block with the operation id as the idempotency key for
#      the downstream call;
#   4. the record becomes `committed` (with the block's result) or `failed` (with its error) afterwards.
#
# A second execution of the same id never runs the block again: it is answered from the record. Nothing is re-run after a
# crash either. Once `pending_timeout_ms` has passed, a record still `pending` is settled as `aborted` (the side effect
# never started: the agent may sign a fresh PCActn), and one still `executing` as `uncertain` (the side effect may or may
# not have happened: an operator or a reconciliation job settles it with resolve_operation, asking the downstream system by
# the idempotency key). create_executor combines authorize and execute_authorized so that a retry of the same PCActn (which
# authorize refuses as a replay) is answered from the record instead of a bare replay denial.
#
# Records are Hashes with the reference's String keys (startedAt, executingAt, finishedAt, ...), so a store shared with
# other implementations holds one format. The block's result must be a JSON value for a durable store.
module AtlasPca
  OPERATION_PENDING_TIMEOUT_MS = 5 * 60_000

  # Where an operation is in its execution.
  OPERATION_STATES = %w[pending executing committed failed aborted uncertain].freeze

  # The operation-record store protocol. #create and #transition MUST be atomic across every process and node that shares
  # the store (a unique-key insert and a conditional UPDATE ... WHERE state = ?, a Redis Lua script, a row lock). A call that
  # cannot decide MUST raise; the executor then refuses or reports the outcome as unknown. Implementations need not subclass.
  #
  #   create(record) -> nil | Hash   insert `record` if no record with its id exists (nil); otherwise return the existing one
  #   get(id) -> Hash | nil
  #   transition(id, from_state, next_record) -> true | false   replace the record only if its state is `from_state`
  #   list_open -> [Hash]            optional: records in state pending or executing (for recover_operations)
  #   scope                          'process' (records die with the process) or 'shared'
  class OperationStore
    def scope = 'shared'

    def create(_record) = raise(NotImplementedError)
    def get(_id) = raise(NotImplementedError)
    def transition(_id, _from_state, _next_record) = raise(NotImplementedError)
  end

  # In-memory store for ONE process (tests, a single worker). Its records die with the process.
  class MemoryOperationStore < OperationStore
    def initialize
      super
      @m = {}
      @lock = Mutex.new
    end

    def scope = 'process'

    def create(record)
      @lock.synchronize do
        cur = @m[record['id']]
        return cur.dup unless cur.nil?

        @m[record['id']] = record.dup
        nil
      end
    end

    def get(id)
      @lock.synchronize { @m[id]&.dup }
    end

    def transition(id, from_state, next_record)
      @lock.synchronize do
        cur = @m[id]
        return false if cur.nil? || cur['state'] != from_state

        @m[id] = next_record.merge('id' => id)
        true
      end
    end

    def list_open
      @lock.synchronize { @m.values.select { |r| %w[pending executing].include?(r['state']) }.map(&:dup) }
    end
  end

  # OperationStore over any atomic key/value store with #update (SqliteAtomicKv: crash-safe and multi-process-safe on one
  # host). `prefix` namespaces the keys. It has no list_open; recover a known id with recover_operation.
  class KvOperationStore < OperationStore
    def initialize(kv, prefix: 'pca-op:', scope: 'shared')
      super()
      @kv = kv
      @pre = prefix
      @scope = scope
    end

    attr_reader :scope

    def close = @kv.respond_to?(:close) ? @kv.close : nil

    def create(record)
      existing = nil
      @kv.update(@pre + record['id']) do |prev|
        existing = KvOperationStore.as_record(prev)
        existing.nil? ? record.dup : nil
      end
      existing
    end

    def get(id)
      KvOperationStore.as_record(@kv.get(@pre + id))
    end

    def transition(id, from_state, next_record)
      done = false
      @kv.update(@pre + id) do |prev|
        cur = KvOperationStore.as_record(prev)
        done = !cur.nil? && cur['state'] == from_state
        done ? next_record.merge('id' => id) : nil
      end
      done
    end

    def self.as_record(v)
      v.is_a?(Hash) && v['id'].is_a?(String) && v['state'].is_a?(String) ? v : nil
    end
  end

  # A durable OperationStore on a SQLite file (the sqlite3 gem, required lazily).
  def self.sqlite_operation_store(path)
    KvOperationStore.new(SqliteAtomicKv.new(path))
  end

  # What the executed block receives. `idempotency_key` is the operation id: pass it as the idempotency key of the
  # downstream call (e.g. an Idempotency-Key header).
  ExecutionHandle = Struct.new(:idempotency_key, :operation, :pcactn, :authorization, keyword_init: true)

  # The outcome of an execution attempt. `replayed` means it was answered from an existing record.
  #
  # status: 'committed' (`result`; `recorded` false = the block ran but the record could not be written, it stays executing
  # and becomes uncertain), 'failed' (`error`), 'aborted' (`reason`), 'pending' (another execution of this id is in
  # flight), 'uncertain' (`reason`; an earlier outcome is unknown, reconcile it), 'refused' (nothing recorded: the
  # authorization does not allow this operation, or the configuration is incomplete) or 'denied' (the executor:
  # `authorization` is the denying AuthorizeResult, nothing ran).
  ExecuteOutcome = Struct.new(:status, :operation_id, :result, :replayed, :recorded, :error, :reason, :authorization,
                              keyword_init: true) do
    def initialize(status:, operation_id: nil, result: nil, replayed: false, recorded: true, error: nil, reason: nil,
                   authorization: nil)
      super
    end

    # The reference's outcome object (the shape the shared vectors compare).
    def to_h
      case status
      when 'committed' then { 'status' => status, 'operationId' => operation_id, 'result' => result, 'replayed' => replayed, 'recorded' => recorded }
      when 'failed' then { 'status' => status, 'operationId' => operation_id, 'error' => error, 'replayed' => replayed }
      when 'aborted', 'uncertain' then { 'status' => status, 'operationId' => operation_id, 'reason' => reason, 'replayed' => replayed }
      when 'pending' then { 'status' => status, 'operationId' => operation_id, 'replayed' => true }
      else { 'status' => status, 'reason' => reason }
      end
    end
  end

  module_function

  def op_clock = (Time.now.to_f * 1000).to_i

  def op_store_ok?(store)
    !store.nil? && %i[create get transition].all? { |m| store.respond_to?(m) }
  end

  # [pcactn, operation] of an allowed authorization (an AuthorizeResult), else nil.
  def op_allowed(authorization)
    return nil unless authorization.respond_to?(:allow) && authorization.respond_to?(:pcactn) && authorization.respond_to?(:operation)

    pcactn = authorization.pcactn
    op = authorization.operation
    return nil unless authorization.allow == true && pcactn.is_a?(Hash) && op.respond_to?(:id) && op.id.is_a?(String) && op.id != ''

    [pcactn, op]
  end

  # Settle an open record older than `timeout_ms`: pending -> aborted (never started), executing -> uncertain.
  def op_settle_stale(store, rec, now, timeout_ms)
    st = rec['state']
    return rec unless %w[pending executing].include?(st)

    # `executing` is aged from the moment the block was started (a slow re-check does not count against it)
    start = st == 'executing' ? (rec['executingAt'] || rec['startedAt']) : rec['startedAt']
    return rec unless now - start > timeout_ms

    t = V2JS.js_str(timeout_ms)
    nxt = if st == 'pending'
            rec.merge('state' => 'aborted', 'error' => "not started within #{t} ms of the claim: the side effect never ran", 'finishedAt' => now)
          else
            rec.merge('state' => 'uncertain', 'finishedAt' => now,
                      'error' => "no outcome recorded within #{t} ms of the start: the side effect may or may not have happened")
          end
    store.transition(rec['id'], st, nxt)
    # whatever is stored now (the original execution may have finished in between)
    store.get(rec['id']) || nxt
  end

  # Answer an execution attempt from an existing record (never runs anything).
  def op_from_record(store, rec0, now, timeout_ms)
    rec = op_settle_stale(store, rec0, now, timeout_ms)
    i = rec['id']
    case rec['state']
    when 'committed' then ExecuteOutcome.new(status: 'committed', operation_id: i, result: rec['result'], replayed: true, recorded: true)
    when 'failed' then ExecuteOutcome.new(status: 'failed', operation_id: i, error: V2JS.truthy?(rec['error']) ? rec['error'] : 'failed', replayed: true)
    when 'aborted' then ExecuteOutcome.new(status: 'aborted', operation_id: i, reason: V2JS.truthy?(rec['error']) ? rec['error'] : 'aborted', replayed: true)
    when 'uncertain' then ExecuteOutcome.new(status: 'uncertain', operation_id: i, reason: V2JS.truthy?(rec['error']) ? rec['error'] : 'outcome unknown', replayed: true)
    when 'pending', 'executing' then ExecuteOutcome.new(status: 'pending', operation_id: i, replayed: true)
    else ExecuteOutcome.new(status: 'uncertain', operation_id: i, reason: "unknown record state '#{V2JS.js_str(rec['state'])}'", replayed: true)
    end
  end

  # Leave `executing` (or `uncertain`, when recovery settled a slow execution) for the final state.
  def op_finish(store, rec, nxt)
    out = rec.merge(nxt)
    return true if store.transition(rec['id'], rec['state'], out)

    rec['state'] == 'executing' && store.transition(rec['id'], 'uncertain', out) == true
  end

  def op_answer_current(store, id, now, timeout_ms)
    cur = store.get(id)
    return ExecuteOutcome.new(status: 'uncertain', operation_id: id, reason: 'the operation record disappeared', replayed: true) if cur.nil?

    op_from_record(store, cur, now, timeout_ms)
  end

  # True iff `op` (an AuthorizedOperation) is exactly `operation` ({verb, resource, params}): verb, resource, params digest.
  def op_bound_to?(op, operation)
    o = operation_of(operation)
    !o.nil? && op.verb == o['verb'] && op.resource == o['resource'] && op.params_digest == params_digest(params_copy(o['params']))
  rescue StandardError
    false
  end

  # Execute an allowed authorize result at most once, with a durable record (see the file header). The block runs only if
  # this call created the `pending` record and the re-check (when required) passed; every other outcome is answered from the
  # record. A raise from the block is recorded as `failed` and returned, not re-raised.
  #
  #   store:               REQUIRED: the operation record store (shared and durable in production)
  #   operation:           {verb:, resource:, params:} the handler is about to execute: the authorization must be for exactly it
  #   recheck:             ->(handle) { {'ok' => true} | {'ok' => false, 'reason' => str} } re-checks, immediately before the
  #                        block, that the authorization still stands (the grant is not revoked, the approval has not expired or
  #                        been withdrawn). REQUIRED for an irreversible operation (fail closed); with recheck_for: 'always'
  #                        for every class. The PCActn's own `exp` is always checked with it. A raise counts as a refusal.
  #   reversibility_class: the server's authoritative class; the stricter of it and the signed class applies (missing =
  #                        irreversible)
  #   pending_timeout_ms:  an open record older than this is settled (pending -> aborted, executing -> uncertain). Default 5 min.
  #   now:                 clock, a callable returning epoch ms
  def execute_authorized(authorization, store: nil, operation: nil, recheck: nil, recheck_for: 'irreversible',
                         reversibility_class: nil, pending_timeout_ms: nil, now: nil, &fn)
    unless op_store_ok?(store)
      return ExecuteOutcome.new(status: 'refused', reason: 'executeAuthorized: missing required component: store (fail closed)')
    end
    az = op_allowed(authorization)
    return ExecuteOutcome.new(status: 'refused', reason: 'executeAuthorized: the authorization did not allow an operation') if az.nil?

    pcactn, op = az
    if !operation.nil? && !op_bound_to?(op, operation)
      return ExecuteOutcome.new(status: 'refused', reason: 'executeAuthorized: the authorization is not for this operation (verb, resource or params differ)')
    end
    return ExecuteOutcome.new(status: 'refused', reason: 'executeAuthorized: no block to execute (fail closed)') if fn.nil?

    clock = now || -> { op_clock }
    timeout_ms = pending_timeout_ms.nil? ? OPERATION_PENDING_TIMEOUT_MS : pending_timeout_ms
    action = pcactn['action'].is_a?(Hash) ? pcactn['action'] : {}
    cls = effective_reversibility(reversibility_class, action['reversibility_class'])
    must_recheck = cls == 'irreversible' || recheck_for == 'always'
    if must_recheck && !recheck.respond_to?(:call)
      return ExecuteOutcome.new(status: 'refused',
                                reason: "executeAuthorized: a #{cls} operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)")
    end

    handle = ExecutionHandle.new(idempotency_key: op.id, operation: op, pcactn: pcactn, authorization: authorization)
    rec = { 'id' => op.id, 'state' => 'pending', 'verb' => op.verb, 'resource' => op.resource, 'params_digest' => op.params_digest,
            'reversibility' => cls, 'startedAt' => clock.call }
    existing = store.create(rec)
    return op_from_record(store, existing, clock.call, timeout_ms) unless existing.nil?

    if must_recheck
      rc = begin
        t = clock.call
        exp = pcactn['exp']
        if (exp.is_a?(Integer) || exp.is_a?(Float)) && t > exp
          { 'ok' => false, 'reason' => "the PCActn expired at #{V2JS.js_str(exp)}" }
        else
          recheck.call(handle)
        end
      rescue StandardError => e
        { 'ok' => false, 'reason' => "recheck error (fail closed): #{e.message}" }
      end
      unless rc.is_a?(Hash) && rc['ok'] == true
        why = rc.is_a?(Hash) && rc['ok'] == false && V2JS.truthy?(rc['reason']) ? rc['reason'] : 'refused'
        reason = "recheck: #{why}"
        if op_finish(store, rec, 'state' => 'aborted', 'error' => reason, 'finishedAt' => clock.call)
          return ExecuteOutcome.new(status: 'aborted', operation_id: rec['id'], reason: reason, replayed: false)
        end

        return op_answer_current(store, rec['id'], clock.call, timeout_ms)
      end
    end

    # the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
    running = rec.merge('state' => 'executing', 'executingAt' => clock.call)
    return op_answer_current(store, rec['id'], clock.call, timeout_ms) unless store.transition(rec['id'], 'pending', running)

    begin
      result = fn.call(handle)
    rescue StandardError => e
      error = e.message
      begin
        op_finish(store, running, 'state' => 'failed', 'error' => error, 'finishedAt' => clock.call)
      rescue StandardError
        nil
      end
      return ExecuteOutcome.new(status: 'failed', operation_id: rec['id'], error: error, replayed: false)
    end
    recorded = begin
      op_finish(store, running, 'state' => 'committed', 'result' => result, 'finishedAt' => clock.call)
    rescue StandardError
      false
    end
    ExecuteOutcome.new(status: 'committed', operation_id: rec['id'], result: result, replayed: false, recorded: recorded)
  end

  # recover_operations for one id. Returns the record as it now stands (nil: no record, it never started).
  def recover_operation(store, id, older_than_ms: nil, now: nil)
    r = store.get(id)
    return nil if r.nil?

    op_settle_stale(store, r, (now || -> { op_clock }).call, older_than_ms.nil? ? OPERATION_PENDING_TIMEOUT_MS : older_than_ms)
  end

  # Settle every open record older than `older_than_ms` (run it at startup and periodically): pending -> aborted (the side
  # effect never started), executing -> uncertain. Returns the records it settled. Needs store.list_open. Nothing is re-run:
  # reconcile each `uncertain` one with resolve_operation.
  def recover_operations(store, older_than_ms: nil, now: nil)
    unless store.respond_to?(:list_open)
      raise TypeError, 'recover_operations: the store has no list_open (recover by id with recover_operation)'
    end

    store.list_open.filter_map do |r|
      u = recover_operation(store, r['id'], older_than_ms: older_than_ms, now: now)
      u if !u.nil? && u['state'] != r['state']
    end
  end

  # Settle an `uncertain` record after reconciling with the downstream system (look the idempotency key up there):
  # {'state' => 'committed', 'result' => ...?} or {'state' => 'failed', 'error' => str}. false if the record is not uncertain.
  def resolve_operation(store, id, outcome, now: nil)
    r = store.get(id)
    return false if r.nil? || r['state'] != 'uncertain'

    t = (now || -> { op_clock }).call
    nxt = if outcome['state'] == 'committed'
            n = r.merge('state' => 'committed', 'finishedAt' => t)
            n['result'] = outcome['result'] if outcome.key?('result')
            n
          else
            r.merge('state' => 'failed', 'error' => outcome['error'], 'finishedAt' => t)
          end
    store.transition(id, 'uncertain', nxt) == true
  end

  # authorize + execute_authorized in one call, with retries answered from the record. Build it with create_executor; call
  # executor.call(pcactn, operation) { |handle| ... }.
  class Executor
    def initialize(operations:, options:, audience:, resolve_grant:, recheck: nil, recheck_for: 'irreversible',
                   reversibility_class_of: nil, pending_timeout_ms: nil, now: nil)
      @ops = operations
      @opts = options
      @aud = audience
      @resolve = resolve_grant
      @extra = recheck
      @recheck_for = recheck_for
      @cls_of = reversibility_class_of
      @timeout = pending_timeout_ms.nil? ? OPERATION_PENDING_TIMEOUT_MS : pending_timeout_ms
      @now = now || -> { AtlasPca.op_clock }
    end

    def call(pcactn, operation, intent_policy: nil, intent_v2: nil, escalation_answer: nil, k1: nil, fresh_at: nil, workflow: nil, workflow_call: nil, &fn)
      unless AtlasPca.op_store_ok?(@ops)
        return ExecuteOutcome.new(status: 'refused', reason: 'createExecutor: missing required component: operations (fail closed)')
      end

      o = @opts
      r = AtlasPca.authorize(pcactn, operation: operation, audience: @aud, resolve_grant: @resolve, state_store: o.state_store,
                                     is_revoked: o.is_revoked, now: @now.call, plan: o.plan, context: o.context,
                                     intent_policy: intent_policy, intent_v2: intent_v2, require: o.require,
                                     escalation_principals: o.escalation_principals, escalation_answer: escalation_answer,
                                     revocation_staleness: o.revocation_staleness, plans: o.plans,
                                     require_assurance: o.require_assurance, k1: k1.nil? ? o.k1 : k1, uses_store: o.uses_store,
                                     fresh_at: fresh_at, workflow: workflow, workflow_call: workflow_call)
      if r.allow
        cls = @cls_of.nil? || !operation.is_a?(Hash) ? nil : @cls_of.call(operation)
        return AtlasPca.execute_authorized(r, store: @ops, operation: operation, recheck: method(:recheck), recheck_for: @recheck_for,
                                              reversibility_class: cls, pending_timeout_ms: @timeout, now: @now, &fn)
      end
      failed = r.checks.select { |_, s| s == 'fail' }.keys
      return ExecuteOutcome.new(status: 'denied', authorization: r, reason: r.reason) if r.status != 403 || failed != ['replay']

      # a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
      p, = AtlasPca.coerce_pcactn(pcactn)
      return ExecuteOutcome.new(status: 'denied', authorization: r, reason: r.reason) if p.nil?

      rec = @ops.get(AtlasPca.hash_canonical(p))
      want = AtlasPca.operation_of(operation) || {}
      if rec.nil? || rec['verb'] != want['verb'] || rec['resource'] != want['resource'] ||
         rec['params_digest'] != (want['params'].nil? ? nil : AtlasPca.params_digest(AtlasPca.params_copy(want['params'])))
        return ExecuteOutcome.new(status: 'denied', authorization: r, reason: r.reason)
      end

      AtlasPca.op_from_record(@ops, rec, @now.call, @timeout)
    end

    # Re-run revocation against the grant, then a registered plan's executability, then the caller's extra re-check.
    def recheck(handle)
      p = handle.pcactn
      grant = @resolve.call(p['grant_ref'])
      return { 'ok' => false, 'reason' => 'the grant is no longer known' } unless grant.is_a?(Hash)

      revoked = begin
        @opts.is_revoked.call(p, grant)
      rescue StandardError
        nil
      end
      unless revoked == false
        return { 'ok' => false, 'reason' => revoked == true ? 'the grant has been revoked' : 'revocation could not be checked' }
      end

      # a registered plan must still be executable: not revoked, the principal's approval not expired
      plans = @opts.plans
      pl = p['plan'].is_a?(Hash) ? p['plan'] : {}
      root = pl['root']
      if !plans.nil? && root.is_a?(String) && !plans.get(p['grant_ref'], root).nil?
        ps = plans.check(p['grant_ref'], root, node_id: pl['node_id'], now: @now.call)
        return { 'ok' => false, 'reason' => V2JS.truthy?(ps['reason']) ? ps['reason'] : "plan is #{ps['state']}" } unless ps['executable']
      end
      @extra.nil? ? { 'ok' => true } : @extra.call(handle)
    end
  end

  # Build an Executor: `options` is the AuthorizeOptions of the guard (store, revocation check, plan registry, ...). A second
  # presentation of the same PCActn is refused by authorize as a replay; if that replay is the ONLY failing check (the proof,
  # binding, policy and revocation all still pass now) and a record exists for its operation id and this operation, the
  # record's outcome is returned (replayed: true) instead of the denial. No record means the first attempt never reached
  # execution: the denial stands (the authorization was consumed; the agent signs a fresh PCActn).
  #
  # The executor always re-runs options.is_revoked against the grant from `resolve_grant`, checks the PCActn's expiry and,
  # with options.plans, that a registered plan is still executable; `recheck` adds to them (e.g. a step-up approval still
  # stands). `reversibility_class_of.call(operation)` is the server's catalog class for an operation.
  def create_executor(**kw)
    Executor.new(**kw)
  end
end
