# frozen_string_literal: true

# AtlasPca.authorize: the full authorization pipeline for a Ruby resource server or tool guard (0.5, additive).
#
# verify_pcactn answers "is this a validly signed PCActn for this audience". authorize answers "may THIS operation run
# now", in the same order as the TypeScript authorize() / verifyPCActn:
#
#   1. configuration: audience, resolve_grant, state_store (with #claim) and is_revoked are REQUIRED, and the call must
#      name the operation it will execute (verb, resource, params). A missing one denies with its name; nothing is ever
#      downgraded to "not enforced".
#   2. the core checks (verify_pcactn: wire, version, audience, validity, chain, grant_ref_bound, plan_inclusion,
#      leaf_signature, counter format, intent), then `revocation` (is_revoked), then `zk_compliance` (a carried proof
#      cannot be verified here: fail closed).
#   3. `operation`: the signed action.verb / action.resource equal the operation's, and the signed action.params_digest
#      opens to exactly the operation's params. Those params are what the predicates and caveats read.
#   4. `grant_ref`, `params_digest`, `plan_root_authorized` (plan: 'single-step' or a context plan), `attestation` (a
#      grant whose agent_binding pins the agent needs an attestation verifier this SDK does not have: fail closed),
#      `reversibility` (when the context names an authoritative class).
#   5. policy: the envelope predicates (default deny), the envelope's caveats and the ROOT caveats outside the envelope
#      (`policy`), and the caveats delegation hops appended (`delegated_caveats`). `predicates` and `tool_schema` caveats
#      are enforced against the operation; unknown caveat types fail closed.
#   6. replay: only when everything above passes, the counter is consumed through state_store.claim(key, counter), one
#      atomic compare-and-set per action (key = "<grant id>:<leaf holder>"). A replayed or older counter denies.
#
# Not ported from the TypeScript policy VM: the risk score, trust budget and threshold step-up (risk_policy), revocation
# epochs and liveness beacons. Never raises: any internal error is a denial.
require 'json'

module AtlasPca
  # The checks that must be `pass` (not merely "not failed"): the TypeScript DEFAULT_REQUIRED_CHECKS plus the operation
  # binding and the policy. `require:` can add names, never remove these.
  DEFAULT_REQUIRED_CHECKS = %w[counter_format replay revocation plan_root_authorized audience validity grant_ref_bound
                               operation params_digest policy].freeze

  # A failing one of these is an authentication failure (401); everything else is insufficient authority (403).
  AUTHN_CHECKS = %w[wire version audience validity chain grant_ref_bound leaf_signature malformed grant_ref].freeze

  # What StateStore#claim returns. `ok` is true only when THIS call consumed the counter.
  ClaimResult = Struct.new(:ok, :last_counter) do
    def initialize(ok, last_counter = nil)
      super
    end
  end

  # The operation an allowing decision is bound to. `id` is the digest of the presented PCActn.
  AuthorizedOperation = Struct.new(:verb, :resource, :params_digest, :id, keyword_init: true)

  # Outcome of AtlasPca.authorize. `allow` is the one thing a caller must branch on. `status` is 200, 401 or 403;
  # `checks` maps each check to 'pass' | 'fail' | 'not-enforced'; `reason` is the decisive one (an `operation` failure
  # first); `missing` names absent configuration components (the call was refused before any verification).
  #
  # `decision` is the ternary decision: 'allow' (exactly when `allow`), 'escalate' (refused: `escalation` is the request to put
  # to the principal; an escalate is never an allow) or 'deny'. On an allow admitted by an answer `escalation` is
  # {'answered_by' => principal}.
  #
  # `undo` is the admission of an undo hook ({'id', 'window_end', 'compensation' => {'verb', 'resource'}}) when an escalation was
  # replaced by a veto window; `obligations` then carries the matching `undo_window` obligation the enforcement point performs.
  AuthorizeResult = Struct.new(:allow, :status, :checks, :reasons, :reason, :operation, :pcactn, :verdict, :missing,
                               :decision, :escalation, :degraded, :assurance, :undo, :obligations, keyword_init: true) do
    def initialize(**kw)
      super
      self.decision ||= allow == true ? 'allow' : 'deny'
    end

    # The names of the failing checks, sorted.
    def failed_checks
      (checks || {}).select { |_, s| s == 'fail' }.keys.sort
    end
  end

  # The authorize components a guard adds on top of its audience / resolve_grant (the opt-in for RackMiddleware's
  # `authorize:`). `operation` is the request -> operation mapping (a callable (env) -> {verb, resource, params} | nil).
  #
  # `escalation_principals:` pins the principal keys whose EscalationAnswers count (default none: every escalate is refused).
  # Giving them needs a state store with `last(key)` (the holder's history head the answer is bound to): a store without it
  # is refused at construction.
  # `provenance` configures the provenance gate (always on; see AtlasPca.authorize) and `undo` is the optional undo hook.
  AuthorizeOptions = Struct.new(:state_store, :is_revoked, :plan, :context, :require, :operation, :escalation_principals,
                                :revocation_staleness, :plans, :require_assurance, :k1, :uses_store, :escalation_render, :insecure_unbound_approval,
                                :provenance, :undo, keyword_init: true) do
    def initialize(plan: 'single-step', require: [], **rest)
      super
      return if escalation_principals.nil? || escalation_principals.empty?

      unless state_store.respond_to?(:last)
        raise ArgumentError, 'escalation_principals: the state store must offer last(key) (the history head an answer is bound to)'
      end
    end
  end

  # The replay-store protocol: claim(key, counter) -> ClaimResult. ONE atomic operation of your backend: if a counter is
  # stored for `key` and `counter` is not strictly greater, return ClaimResult.new(false, stored); otherwise store
  # `counter` and return ClaimResult.new(true). A claim that cannot decide must return ok = false or raise (authorize then
  # denies). Implementations need not subclass this.
  class StateStore
    def claim(_key, _counter)
      raise NotImplementedError
    end

    # TTL'd consume-once (max_uses slots): true iff `key` has no live record (retain_until >= now); the record is then kept
    # until `retain_until` (never shortened by a later, shorter horizon). Raises ArgumentError for an empty key, a
    # non-integer clock/horizon or retain_until < now, leaving nothing behind. This default has no expiry: it falls back to
    # claim(key, 1) and remembers the key for the life of the store; override it for a store that can forget.
    def consume_once(key, retain_until, now)
      StateStore.check_consume_once!(key, retain_until, now)
      r = claim(key, 1)
      (r.respond_to?(:ok) ? r.ok : r) == true
    end

    def self.check_consume_once!(key, retain_until, now)
      raise ArgumentError, 'consume_once: key must be a non-empty string' unless key.is_a?(String) && !key.empty?
      raise ArgumentError, 'consume_once: retain_until and now must be integers' unless retain_until.is_a?(Integer) && now.is_a?(Integer)
      raise ArgumentError, 'consume_once: retain_until is before now' if retain_until < now
    end
  end

  # In-process reference store (one Mutex). Correct for ONE process only.
  class MemoryStateStore < StateStore
    def initialize
      super
      @last = {}
      @once = {}
      @lock = Mutex.new
    end

    def consume_once(key, retain_until, now)
      StateStore.check_consume_once!(key, retain_until, now)
      @lock.synchronize do
        @once.delete_if { |_k, until_ms| until_ms < now }
        old = @once[key]
        @once[key] = old.nil? ? retain_until : [old, retain_until].max
        old.nil?
      end
    end

    def claim(key, counter)
      @lock.synchronize do
        last = @last[key]
        return ClaimResult.new(false, last) if !last.nil? && !(counter > last)

        @last[key] = counter
        ClaimResult.new(true)
      end
    end

    # The last claimed counter of `key` (the holder's history head), or nil.
    def last(key)
      @lock.synchronize { @last[key] }
    end
  end

  # Durable reference store over SQL: one row per counter stream, `key` is the PRIMARY KEY. The claim is ONE statement,
  #   INSERT INTO <table> (key, last_counter) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET
  #     last_counter = excluded.last_counter WHERE excluded.last_counter > <table>.last_counter
  # and its changed-row count decides (1 = consumed). The database runs it atomically under its row / write lock, so
  # concurrent threads and processes can never both consume the same counter. SQLite 3.24+ and PostgreSQL 9.5+ accept it.
  #
  # Adapter-neutral: `execute` is a callable (sql, [key, counter]) -> Integer (rows changed by that statement) and
  # `select` a callable (sql, [key]) -> Integer | nil (the stored counter, read only to report a replay). `placeholders`
  # is :question (`?`) or :dollar (`$1`, `$2`). SqliteStateStore wires it to the sqlite3 gem.
  class SqlStateStore < StateStore
    DEFAULT_TABLE = 'pca_replay'

    attr_reader :table, :claim_sql

    def initialize(execute:, select:, placeholders: :question, table: DEFAULT_TABLE)
      super()
      raise ArgumentError, 'table must be a plain identifier' unless table.is_a?(String) && table.match?(/\A[A-Za-z_][A-Za-z0-9_]{0,62}\z/)
      raise ArgumentError, 'placeholders must be :question or :dollar' unless %i[question dollar].include?(placeholders)

      @execute = execute
      @select = select
      @table = table
      a, b = placeholders == :dollar ? %w[$1 $2] : %w[? ?]
      @claim_sql = "INSERT INTO #{table} (key, last_counter) VALUES (#{a}, #{b}) ON CONFLICT(key) DO UPDATE SET " \
                   "last_counter = excluded.last_counter WHERE excluded.last_counter > #{table}.last_counter"
      @select_sql = "SELECT last_counter FROM #{table} WHERE key = #{a}"
      @dollar = placeholders == :dollar
      @once_table = "#{table}_once"
    end

    # The table consume_once needs (portable DDL); a store that never spends max_uses can skip it.
    def create_once_table_sql
      "CREATE TABLE IF NOT EXISTS #{@once_table} (key TEXT NOT NULL PRIMARY KEY, retain_until BIGINT NOT NULL)"
    end

    # One atomic upsert that only takes a missing or expired row (changed rows = 1 means consumed); a repeat extends the
    # horizon with a second statement that can only raise it. Expired rows are pruned first.
    def consume_once(key, retain_until, now)
      StateStore.check_consume_once!(key, retain_until, now)
      t = @once_table
      q = @dollar ? %w[$1 $2 $3] : %w[? ? ?]
      @execute.call("DELETE FROM #{t} WHERE retain_until < #{q[0]}", [now])
      won = @execute.call("INSERT INTO #{t} (key, retain_until) VALUES (#{q[0]}, #{q[1]}) ON CONFLICT(key) DO UPDATE SET " \
                          "retain_until = excluded.retain_until WHERE #{t}.retain_until < #{q[2]}", [key, retain_until, now]) == 1
      unless won
        @execute.call("UPDATE #{t} SET retain_until = #{q[0]} WHERE key = #{q[1]} AND retain_until < #{@dollar ? '$1' : '?'}",
                      @dollar ? [retain_until, key] : [retain_until, key, retain_until])
      end
      won
    end

    # The table this store needs (portable DDL).
    def create_table_sql
      "CREATE TABLE IF NOT EXISTS #{@table} (key TEXT NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)"
    end

    def claim(key, counter)
      return ClaimResult.new(false) unless key.is_a?(String) && counter.is_a?(Integer)

      changed = @execute.call(@claim_sql, [key, counter])
      return ClaimResult.new(true) if changed == 1

      last = @select.call(@select_sql, [key])
      ClaimResult.new(false, last.is_a?(Integer) ? last : nil)
    end

    # The last claimed counter of `key` (the holder's history head), or nil.
    def last(key)
      v = @select.call(@select_sql, [key])
      v.is_a?(Integer) ? v : nil
    end
  end

  # SqlStateStore on a SQLite file through the sqlite3 gem (required lazily, only when this class is instantiated). One
  # connection per thread and process (never shared across a fork); busy waits up to `timeout` seconds.
  class SqliteStateStore < SqlStateStore
    def initialize(path, timeout: 30, table: DEFAULT_TABLE)
      require 'sqlite3'
      @path = path
      @timeout_ms = (timeout * 1000).to_i
      @conn_key = :"atlas_pca_sqlite_#{object_id}"
      @conns = [] # every connection this store opened (all threads), so close can release them all
      @conns_mutex = Mutex.new
      super(execute: ->(sql, binds) { db = conn; db.execute(sql, binds); db.changes },
            select: ->(sql, binds) { row = conn.get_first_row(sql, binds); row && row[0] },
            placeholders: :question, table: table)
      conn.execute(create_table_sql)
      conn.execute(create_once_table_sql)
    end

    # Close every connection this store opened, on any thread (needed before the file is removed on Windows).
    # A later use lazily reopens a fresh connection.
    def close
      handles = @conns_mutex.synchronize { @conns.shift(@conns.size) }
      Thread.current[@conn_key] = nil
      handles.each do |pid, db|
        db.close if pid == Process.pid && !db.closed?
      rescue StandardError
        nil
      end
      nil
    end

    private

    def conn
      cur = Thread.current[@conn_key]
      return cur[1] if cur && cur[0] == Process.pid && !cur[1].closed?

      db = SQLite3::Database.new(@path)
      db.busy_timeout = @timeout_ms
      Thread.current[@conn_key] = [Process.pid, db]
      @conns_mutex.synchronize { @conns << [Process.pid, db] }
      db
    end
  end

  module_function

  # The store key of a holder's counter stream (the TypeScript pcaStateKey default scope).
  def state_key(grant_id, leaf_holder)
    "#{grant_id}:#{leaf_holder}"
  end

  # ---- the envelope (TypeScript envelope.ts readEnvelope / risk.ts validateRiskPolicy) ----------------------------------

  def risk_policy_error(p)
    return 'risk_policy must be an object' unless p.is_a?(Hash)

    w = p['weights']
    return 'risk_policy.weights missing' unless w.is_a?(Hash)

    %w[alpha beta gamma delta epsilon zeta].each do |k|
      v = finite_num(w[k])
      return "risk_policy.weights.#{k} must be finite and >= 0" if v.nil? || v.negative?
    end
    vals = {}
    %w[theta1 theta2 kappa lambda rho bMax].each do |k|
      vals[k] = finite_num(p[k])
      return "risk_policy.#{k} must be finite" if vals[k].nil?
    end
    return 'risk_policy requires 0 <= theta1 <= theta2' if vals['theta1'].negative? || vals['theta2'] < vals['theta1']
    return 'risk_policy.kappa must be > 0' if vals['kappa'] <= 0
    return 'risk_policy lambda/rho/bMax must be >= 0' if vals['lambda'].negative? || vals['rho'].negative? || vals['bMax'].negative?

    nil
  end

  # The grant's policy envelope: its FIRST `envelope` caveat without `type`, or nil when absent or malformed.
  def read_envelope(grant)
    cs = grant.is_a?(Hash) ? grant['caveats'] : nil
    return nil unless cs.is_a?(Array)

    cv = cs.find { |c| c.is_a?(Hash) && c['type'] == ENVELOPE_CAVEAT }
    return nil if cv.nil?

    e = cv.reject { |k, _| k == 'type' }
    return nil unless e['goal_commit'].is_a?(String)
    return nil unless e['predicates'].is_a?(Array) && e['caveats'].is_a?(Array)
    return nil unless e['agent_binding'].is_a?(Hash) || e['agent_binding'].is_a?(Array)
    return nil unless risk_policy_error(e['risk_policy']).nil?

    e
  rescue StandardError
    nil
  end

  # Every root caveat except the first `envelope` one (TypeScript rootCaveats); a non-Array is returned as is.
  def root_caveats(grant)
    cs = grant.is_a?(Hash) ? grant['caveats'] : nil
    return cs unless cs.is_a?(Array)

    out = cs.dup
    i = out.index { |c| c.is_a?(Hash) && c['type'] == ENVELOPE_CAVEAT }
    out.delete_at(i) unless i.nil?
    out
  end

  # TypeScript requiresAttestation: any agent pin in agent_binding requires a bound attestation.
  def requires_attestation?(binding)
    b = binding.is_a?(Hash) ? binding : {}
    ne = ->(x) { x.is_a?(Array) && !x.empty? }
    has_min = b.key?('min_measurement') && b['min_measurement'] != ''
    ne.call(b['model_allowlist']) || has_min || (b['operator'].is_a?(String) && b['operator'] != '') ||
      ne.call(b['weights_allowlist']) || ne.call(b['system_prompt_allowlist']) ||
      ne.call(b['tool_manifest_allowlist']) || b['require_hardware'] == true || b['require_measured_weights'] == true
  end

  # ---- the semantic firewall: `tool_schema` caveats (TypeScript agent-native.ts) --------------------------------------

  MAX_SCHEMA_DEPTH = 8
  MAX_SCHEMA_NODES = 256
  MAX_OBJECT_PROPS = 64
  MAX_ENUM_VALUES = 256
  DEFAULT_MAX_ARRAY_ITEMS = 256
  ABSOLUTE_MAX_ARRAY_ITEMS = 4096
  DEFAULT_MAX_STRING_LEN = 65_536
  ABSOLUTE_MAX_STRING_LEN = 1_048_576
  MAX_VALUE_NODES = 10_000

  # Tool-schema internals (module functions of this inner module; the public API is evaluate_tool_schema and
  # validate_arg_schema on AtlasPca).
  module ToolSchema
    SAFE_NAME = /\A[A-Za-z0-9_]{1,64}\z/
    SPEC_KEYS = {
      'string' => %w[type enum const minLength maxLength prefix],
      'number' => %w[type enum const min max],
      'integer' => %w[type enum const min max],
      'boolean' => %w[type enum const],
      'object' => %w[type props required],
      'array' => %w[type items minItems maxItems]
    }.freeze
    ABSENT = Object.new.freeze

    module_function

    def fin(x) = AtlasPca.finite_num(x)

    # JavaScript string.length (UTF-16 code units).
    def jslen(s)
      s.encode('UTF-16LE').bytesize / 2
    end

    def int?(x)
      f = fin(x)
      !f.nil? && f == f.floor
    end

    def non_neg_int?(x, mx)
      f = fin(x)
      !f.nil? && f == f.floor && f >= 0 && f <= mx
    end

    def only_keys?(o, allowed)
      o.keys.all? { |k| allowed.include?(k) }
    end

    def bool?(x)
      x == true || x == false
    end

    # JavaScript === on the scalars a schema can hold (numbers compare as doubles; a bool is never a number).
    def js_eq?(a, b)
      fa = fin(a)
      fb = fin(b)
      return !fa.nil? && !fb.nil? && fa == fb if !fa.nil? || !fb.nil?
      return bool?(a) && bool?(b) && a == b if bool?(a) || bool?(b)
      return a == b if a.is_a?(String) && b.is_a?(String)

      false
    end

    def opt(h, k)
      h.key?(k) ? h[k] : ABSENT
    end

    def object_schema_error(props, required, depth, budget)
      return 'schema too deep' if depth > MAX_SCHEMA_DEPTH

      budget[:nodes] += 1
      return 'schema too large' if budget[:nodes] > MAX_SCHEMA_NODES
      return 'props must be an object' unless props.is_a?(Hash)
      return 'too many props' if props.length > MAX_OBJECT_PROPS

      props.each do |n, spec|
        return "invalid property name '#{n.is_a?(String) ? n[0, 32] : n}'" unless n.is_a?(String) && SAFE_NAME.match?(n)

        e = spec_error(spec, depth + 1, budget)
        return "#{n}: #{e}" if e
      end
      unless required.equal?(ABSENT)
        return 'required must be a short array' unless required.is_a?(Array) && required.length <= MAX_OBJECT_PROPS

        required.each do |r|
          return 'required names an undeclared property' unless r.is_a?(String) && props.key?(r)
        end
      end
      nil
    end

    def spec_error(spec, depth, budget)
      return 'schema too deep' if depth > MAX_SCHEMA_DEPTH

      budget[:nodes] += 1
      return 'schema too large' if budget[:nodes] > MAX_SCHEMA_NODES
      return 'unknown type' unless spec.is_a?(Hash) && spec['type'].is_a?(String) && SPEC_KEYS.key?(spec['type'])

      t = spec['type']
      return 'unknown spec key' unless only_keys?(spec, SPEC_KEYS[t])

      if t == 'object'
        budget[:nodes] -= 1 # counted once by object_schema_error
        return object_schema_error(spec['props'], opt(spec, 'required'), depth, budget)
      end
      if t == 'array'
        return 'bad minItems' if spec.key?('minItems') && !non_neg_int?(spec['minItems'], ABSOLUTE_MAX_ARRAY_ITEMS)
        return 'bad maxItems' if spec.key?('maxItems') && !non_neg_int?(spec['maxItems'], ABSOLUTE_MAX_ARRAY_ITEMS)
        return 'minItems > maxItems' if spec.key?('minItems') && spec.key?('maxItems') && spec['minItems'] > spec['maxItems']

        return spec_error(spec['items'], depth + 1, budget)
      end

      ok = lambda do |v|
        case t
        when 'string' then v.is_a?(String) && jslen(v) <= 1024
        when 'boolean' then bool?(v)
        else !fin(v).nil? && (t == 'number' || int?(v))
        end
      end
      return 'bad const' if spec.key?('const') && !ok.call(spec['const'])

      if spec.key?('enum')
        en = spec['enum']
        return 'bad enum' unless en.is_a?(Array) && !en.empty? && en.length <= MAX_ENUM_VALUES && en.all? { |x| ok.call(x) }
      end
      if t == 'string'
        return 'bad minLength' if spec.key?('minLength') && !non_neg_int?(spec['minLength'], ABSOLUTE_MAX_STRING_LEN)
        return 'bad maxLength' if spec.key?('maxLength') && !non_neg_int?(spec['maxLength'], ABSOLUTE_MAX_STRING_LEN)
        return 'minLength > maxLength' if spec.key?('minLength') && spec.key?('maxLength') && spec['minLength'] > spec['maxLength']
        return 'bad prefix' if spec.key?('prefix') && (!spec['prefix'].is_a?(String) || jslen(spec['prefix']) > 512)
      elsif %w[number integer].include?(t)
        return 'bad min' if spec.key?('min') && fin(spec['min']).nil?
        return 'bad max' if spec.key?('max') && fin(spec['max']).nil?
        return 'min > max' if spec.key?('min') && spec.key?('max') && fin(spec['min']) > fin(spec['max'])
      end
      nil
    end

    # JSON.stringify of a (possibly shortened) key, for reasons.
    def show(k)
      AtlasPca.js_string(jslen(k) > 48 ? "#{k[0, 48]}…" : k)
    end

    def check_value(spec, v, path, depth, budget)
      return "#{path}: too deep" if depth > MAX_SCHEMA_DEPTH + 1

      budget[:n] += 1
      return "#{path}: too many values" if budget[:n] > MAX_VALUE_NODES

      t = spec['type']
      case t
      when 'object'
        return "#{path}: expected object" unless v.is_a?(Hash)

        return check_object(spec['props'], spec['required'], v, path, depth, budget)
      when 'array'
        return "#{path}: expected array" unless v.is_a?(Array)

        mx = [spec.key?('maxItems') ? spec['maxItems'] : DEFAULT_MAX_ARRAY_ITEMS, ABSOLUTE_MAX_ARRAY_ITEMS].min
        return "#{path}: exceeds maxItems" if v.length > mx
        return "#{path}: below minItems" if spec.key?('minItems') && v.length < spec['minItems']

        v.each_with_index do |x, i|
          e = check_value(spec['items'], x, "#{path}[#{i}]", depth + 1, budget)
          return e if e
        end
        return nil
      when 'string'
        return "#{path}: wrong type (expected string)" unless v.is_a?(String)

        n = jslen(v)
        return "#{path}: exceeds maxLength" if n > [spec.key?('maxLength') ? spec['maxLength'] : DEFAULT_MAX_STRING_LEN, ABSOLUTE_MAX_STRING_LEN].min
        return "#{path}: below minLength" if spec.key?('minLength') && n < spec['minLength']
        return "#{path}: violates prefix" if spec.key?('prefix') && !v.start_with?(spec['prefix'])
      when 'number', 'integer'
        f = fin(v)
        return "#{path}: wrong type (expected #{t})" if f.nil? || (t == 'integer' && f != f.floor)
        return "#{path}: below min" if spec.key?('min') && f < fin(spec['min'])
        return "#{path}: above max" if spec.key?('max') && f > fin(spec['max'])
      when 'boolean'
        return "#{path}: wrong type (expected boolean)" unless bool?(v)
      else
        return "#{path}: unknown type"
      end
      return "#{path}: violates const" if spec.key?('const') && !js_eq?(spec['const'], v)
      return "#{path}: violates enum" if spec.key?('enum') && spec['enum'].none? { |e| js_eq?(e, v) }

      nil
    end

    def check_object(props, required, obj, path, depth, budget)
      obj.each_key { |k| return "#{path}: unexpected argument #{show(k)}" unless props.key?(k) }
      (required || []).each { |r| return "#{path}: missing required argument '#{r}'" unless obj.key?(r) }
      obj.each do |k, x|
        e = check_value(props[k], x, "#{path}.#{k}", depth + 1, budget)
        return e if e
      end
      nil
    end
  end

  # Validate a tool_schema argument schema (closed; shape, depth, node count, bounds). nil when valid.
  def validate_arg_schema(schema)
    return 'schema must be an object' unless schema.is_a?(Hash)
    return 'unknown schema key' unless ToolSchema.only_keys?(schema, %w[props required])

    ToolSchema.object_schema_error(schema['props'], ToolSchema.opt(schema, 'required'), 1, { nodes: 0 })
  rescue StandardError
    'schema evaluation error'
  end

  # Evaluate a tool call {'tool', 'args', 'tool_signature_digest'?} (String keys) against a tool_schema caveat.
  # Returns [ok, reason]. Same rules as the TypeScript evaluateToolSchema. Never raises.
  def evaluate_tool_schema(caveat, call)
    unless caveat.is_a?(Hash) && caveat['type'] == 'tool_schema' && caveat['tool'].is_a?(String) && caveat['tool'] != ''
      return [false, 'malformed tool_schema caveat']
    end

    verr = validate_arg_schema(caveat['schema'])
    return [false, "malformed tool_schema caveat: #{verr}"] if verr
    return [false, 'schema digest mismatch'] if hash_canonical(caveat['schema']) != caveat['schema_digest']

    sig = caveat.key?('signature_digest') ? Predicates.js_string(caveat['signature_digest']) : 'undefined'
    if hash_canonical({ 'tool' => caveat['tool'], 'signature_digest' => sig, 'schema' => caveat['schema'] }) != caveat['binding_digest']
      return [false, 'binding digest mismatch']
    end
    return [false, 'malformed call'] unless call.is_a?(Hash) && call['tool'].is_a?(String) && call['args'].is_a?(Hash)
    return [false, "tool #{ToolSchema.show(call['tool'])} not authorized"] if call['tool'] != caveat['tool']
    if call.key?('tool_signature_digest') && call['tool_signature_digest'] != caveat['signature_digest']
      return [false, 'signed tool_binding differs from the authorized tool signature']
    end

    e = ToolSchema.check_object(caveat['schema']['props'], caveat['schema']['required'], call['args'], 'args', 1, { n: 0 })
    e ? [false, e] : [true, nil]
  rescue StandardError, SystemStackError
    [false, 'evaluation error (fail closed)']
  end

  # ---- the agent-native caveat evaluator (TypeScript evaluateAgentCaveats) --------------------------------------------

  def agent_caveat_satisfied?(cv, ctx, action_ctx, tool_call)
    return false unless cv.is_a?(Hash) && ctx.is_a?(Hash)

    case cv['type']
    when 'tool_schema'
      evaluate_tool_schema(cv, tool_call)[0]
    when 'predicates'
      allow = cv['allow']
      return false unless action_ctx.is_a?(Hash) && allow.is_a?(Array)

      allow.any? { |p| predicate_matches(p, action_ctx) }
    else
      # max_spend and the stock types: the 0.4.1 evaluator (unknown types fail closed there)
      evaluate_caveats([cv], ctx)[0]
    end
  rescue StandardError, SystemStackError
    false
  end

  # Evaluate caveats with the agent-native evaluator: the stock types of evaluate_caveats, plus `predicates` (`allow`:
  # the action must match one predicate; needs action_ctx = {'action' => {...}, 'subject'?, 'env'?}) and `tool_schema`
  # (needs tool_call = {'tool', 'args', 'tool_signature_digest'?}). `ctx` is the stock context ('now', 'action',
  # 'blast_radius', ...). Unknown types fail closed. Returns [ok, failed_types]. Never raises.
  def evaluate_agent_caveats(caveats, ctx, action_ctx = nil, tool_call = nil)
    with_regex_budget do
      next [false, ['<malformed caveats>']] unless caveats.is_a?(Array)

      failed = []
      caveats.each do |cv|
        raise TypeError, 'ctx is not a Hash' unless ctx.is_a?(Hash)
        next if agent_caveat_satisfied?(cv, ctx.dup, action_ctx || {}, tool_call || {})

        t = cv.is_a?(Hash) ? cv['type'] : nil
        failed << (t.is_a?(String) ? t : '<malformed>')
      end
      [failed.empty?, failed]
    end
  rescue StandardError, SystemStackError
    [false, ['<evaluation error>']]
  end

  # ---- authorize ------------------------------------------------------------------------------------------------------

  # Names of the required components that are absent (empty = complete).
  def missing_authorize_components(audience: nil, resolve_grant: nil, state_store: nil, is_revoked: nil)
    missing = []
    missing << 'audience' unless audience.is_a?(String) && audience != ''
    missing << 'resolve_grant' unless resolve_grant.respond_to?(:call)
    missing << 'state_store' unless !state_store.nil? && state_store.respond_to?(:claim)
    missing << 'is_revoked' unless is_revoked.respond_to?(:call)
    missing
  end

  # A top-level member of a caller-supplied Hash by String or Symbol key (String wins).
  def arg_member(h, k)
    return h[k] if h.key?(k)

    h[k.to_sym]
  end

  # The operation as {'verb', 'resource', 'params'} with String keys, or nil when it is not a valid operation.
  def operation_of(op)
    return nil unless op.is_a?(Hash)

    verb = arg_member(op, 'verb')
    resource = arg_member(op, 'resource')
    params = arg_member(op, 'params')
    return nil unless verb.is_a?(String) && verb != '' && resource.is_a?(String) && resource != '' && params.is_a?(Hash)

    { 'verb' => verb, 'resource' => resource, 'params' => params }
  end

  # A JSON value as JavaScript's JSON.parse would hold it: an integral Float within the safe range is that Integer
  # (Ruby's JSON.parse('50.0') is 50.0; JavaScript and the canonical form say 50), -0.0 is 0, Symbol keys are Strings.
  def json_value(v)
    case v
    when Float then v.finite? && v == v.floor && v.abs <= MAX_SAFE ? v.to_i : v
    when Array then v.map { |x| json_value(x) }
    when Hash then v.to_h { |k, x| [k.is_a?(Symbol) ? k.to_s : k, json_value(x)] }
    else v
    end
  end

  # A private canonical copy of the params: what is verified cannot change under the verifier.
  def params_copy(params)
    parse_json(canonicalize(json_value(params)))
  end

  def authorize_refuse(status, check, reason, missing: nil, pcactn: nil)
    AuthorizeResult.new(allow: false, status: status, checks: { check => 'fail' }, reasons: [reason], reason: reason,
                        missing: missing, pcactn: pcactn, assurance: { check => { 'outcome' => 'fail' } })
  end

  def decisive_reason(checks, reasons)
    names = checks.keys.partition { |n| n == 'operation' }.flatten # stable: a binding failure first
    names.each do |n|
      next unless checks[n] == 'fail'

      hit = reasons.find { |r| r.start_with?("#{n}:") }
      return hit if hit
    end
    reasons.empty? ? 'denied' : reasons[0]
  end

  # The workflow admission gate (TypeScript authorize `opts.workflow`): nil to proceed, else the refusal. `workflow` is
  # {principal:, rs_signer:, required: false}; `call` is {commitment:, receipts:, step:, units: {}, goal_digest: nil} (String or
  # Symbol keys). A misconfigured option or an unreadable call input refuses (fail closed).
  def authorize_workflow_gate(workflow, call, pcactn, op, now)
    return authorize_refuse(403, 'workflow', 'workflow: the workflow option must be a Hash (fail closed)') unless workflow.is_a?(Hash)

    if call.nil?
      return arg_member(workflow, 'required') == true ? authorize_refuse(403, 'workflow', 'workflow: this call carries no workflow step (fail closed)') : nil
    end
    return authorize_refuse(403, 'workflow', 'workflow: the call input must be a Hash (fail closed)') unless call.is_a?(Hash)

    # An undecodable PCActn is not the gate's to judge: the pipeline's own wire refusal (401) follows.
    pc, = coerce_pcactn(pcactn)
    return nil unless pc.is_a?(Hash)

    root = pc['plan'].is_a?(Hash) && pc['plan']['root'].is_a?(String) ? pc['plan']['root'] : nil
    units = arg_member(call, 'units')
    d = admit_step({ 'workflow' => arg_member(call, 'commitment'), 'principal' => arg_member(workflow, 'principal'),
                     'rs_signer' => arg_member(workflow, 'rs_signer'), 'receipts' => arg_member(call, 'receipts'), 'now' => now,
                     'request' => { 'step' => arg_member(call, 'step'), 'verb' => op['verb'], 'resource' => op['resource'],
                                    'params' => op['params'], 'units' => units.nil? ? {} : units,
                                    'goal_digest' => arg_member(call, 'goal_digest'), 'plan_root' => root } })
    return nil if d['decision'] == 'allow'

    r = authorize_refuse(403, 'workflow', "workflow: #{d['code'] || 'refused'}#{d['step'].nil? ? '' : " (step #{d['step']})"}")
    r.decision = 'escalate' if d['decision'] == 'escalate'
    r
  rescue StandardError
    authorize_refuse(403, 'workflow', 'workflow: error (fail closed)')
  end

  def coerce_pcactn(pcactn)
    return [pcactn, nil] if pcactn.is_a?(Hash)
    return [nil, pcactn.nil? ? 'absent' : 'undecodable'] unless pcactn.is_a?(String)
    return [nil, 'undecodable'] if pcactn.bytesize > MAX_ARTIFACT_BYTES

    obj = begin
      parse_json(pcactn)
    rescue Malformed, ArgumentError, EncodingError
      nil
    end
    obj.is_a?(Hash) ? [obj, nil] : [nil, 'undecodable']
  end

  # Authorize ONE operation (see the file header for the pipeline). Every keyword is a Ruby keyword with a nil default
  # so that an absent component is REPORTED (result.missing), never raised.
  #
  #   pcactn         the presented PCActn: a parsed Hash, or its JSON text (strict profile).
  #   operation:     {verb:, resource:, params:} (String or Symbol keys): what the handler / tool WILL execute, from the
  #                  server's own routing and parsed input, never from the PCActn. params must be a Hash.
  #   audience:      this resource server's id (the PCActn's signed `aud` must equal it).
  #   resolve_grant: ->(grant_ref) { grant | nil } from your own store.
  #   state_store:   replay store with an atomic claim(key, counter) (MemoryStateStore, SqliteStateStore, SqlStateStore,
  #                  or your database).
  #   is_revoked:    ->(pcactn, grant) { true | false }; only `false` passes (anything else, or an exception, denies).
  #   now:           epoch milliseconds (default: wall clock).
  #   plan:          'single-step': accept a one-node plan whose node is exactly this operation. Otherwise `context` must
  #                  return the principal-authorized 'plan' with 'plan_authorized' => true.
  #   context:       ->(pcactn) { Hash | nil } with optional plan, plan_authorized, subject, env, blast_radius,
  #                  recent_action_times, reversibility_class (String or Symbol keys at the top level).
  #   intent_policy: / intent_v2: / allowed_suites: forwarded to verify_pcactn (intent_v2 may be a callable
  #                  (pcactn) -> Hash; its 'params' default to the operation's).
  #   require:       extra check names that must pass (the defaults always apply).
  #   revocation_staleness: a RevocationStaleness (off when nil): the verifier caps how old the revocation state may be,
  #                  with a stricter window for irreversible actions. The state comes from the `context` member
  #                  'revocation_state' ({'kind' => 'epoch', 'epoch' => <guardian-signed epoch>, 'root'?, 'last_accepted_epoch'?}
  #                  or {'kind' => 'root', 'root', 'issued_at'}, see check_revocation_state); is_revoked still decides
  #                  revocation. A failing age check fails the `freshness` check; an irreversible action with no verifiable
  #                  (guardian-signed) state is refused unless allow_unsigned_root_for_irreversible.
  #   plans:         a PlanRegistry (T10): when `context` supplies no 'plan', the registered plan for the PCActn's plan.root
  #                  and its executability (authorized, approval unexpired, nodes still hash to the root) feed
  #                  `plan_root_authorized`, and the `plan_state` check names the state on a denial. An unknown root is
  #                  refused (`plan_state`) unless plan: 'single-step' applies.
  #   require_assurance: a high-assurance policy, e.g. {'signature' => 'pq'} (see unmet_assurance): weaker, missing, failed
  #                  or unsupported evidence fails the `assurance` check before any replay state is written. Every result
  #                  carries `assurance` (see assurance_report).
  #   k1:            opt-in caveat language v2 (see caveat_lang.rb): a Hash, or a callable (pcactn) -> Hash, of the verifier's
  #                  'pins', the presented 'discharges' / 'narrow' block, 'revoked_discharges', 'spiffe_id' and 'history'. The
  #                  action digest is computed here, never taken from the caller. The K1 caveat types (needs_discharge,
  #                  sealed, max_uses, derive, spiffe_bound) of the chain are then evaluated by evaluate_k1 (check
  #                  `delegated_caveats`) and a verified narrow block's other caveats join the delegated list. Without k1: a
  #                  K1 caveat type stays unsatisfied (refused), as before.
  #   uses_store:    replay store (claim(key, counter)) that spends max_uses slots, only AFTER the counter claim succeeded.
  #                  A chain with a max_uses caveat and no uses_store is refused (check `max_uses`) before the claim.
  #   workflow: / workflow_call: K5 (C-308) workflow admission before verification and replay: see authorize_workflow_gate.
#   fresh_at:      optional consistency-token policy (String-keyed Hash, see verify_pcactn); default nil. A stale verifier
  #                  is an escalate-class failure; a PCActn carrying the member without a policy is refused.
  #   escalation_principals: / escalation_answer: a verdict whose every failing check is escalate-class (an unanswered
  #                  `intent_required` question) has decision 'escalate' and is refused with the request in
  #                  result.escalation; it is admitted only with escalation_answer (a principal-signed EscalationAnswer) from
  #                  one of the pinned escalation_principals, bound to this grant, this PCActn and the holder's history head
  #                  (state_store.last(key)), then spent by the replay claim. An answer never upgrades a deny.
  #   provenance:    PROVENANCE BY DEFAULT (check `provenance_flow`, ALWAYS ON). An operation of a sensitive action (anything
  #                  your `actions` facts do not define as read-only, and every unknown action) is 'escalate' unless its choice
  #                  and every argument derive from the principal: a verified mediator chain whose context was the principal's
  #                  own message, a value the principal typed verbatim, an executable principal-authorized plan from `plans`, or
  #                  an admitted `workflow` step (the choice only). A forged or malformed provenance bundle is a deny. This
  #                  option only configures the gate (a Hash, String or Symbol keys): 'mediators' (pinned mediator keys
  #                  {mediator, kid, pk, pq_pk?}; the grant envelope's `provenance.mediators` adds the principal's own),
  #                  'actions' (->(operation) { {effects, traits, params} | nil }), 'observed' (->(pcactn, operation, session)
  #                  { [{origin, source}] }: untrusted content THIS server saw reach the agent) and 'bundle' (->(pcactn,
  #                  operation) { bundle }; raising = unreadable, which denies). The ONLY opt-out is the grant's signed envelope
  #                  member `provenance: { mode: 'insecure_off' }` (dangerous: injected content can then steer the grant's
  #                  sensitive actions).
  #   provenance_bundle: the bundle presented with this call (ProvenanceRecorder#for_action); wins over provenance['bundle'].
  #   undo:          optional undo hook ->(pcactn, grant, operation) { admission | nil }. It is called ONLY for an 'escalate'
  #                  verdict with no escalation answer presented whose escalation is not a provenance one (`provenance_flow`
  #                  and `provenance` both not failing). Contract: the hook returns an admission {'id', 'window_end',
  #                  'compensation' => {'verb', 'resource'}} only after the window's record is durably opened by your undo
  #                  coordinator (the TypeScript coordinator or the hosted ledger); nil, a malformed admission or an exception is
  #                  no admission and the escalation stands. On admission the call is allowed under a veto window: every failing
  #                  check becomes 'pass', `undo_window` passes, result.undo is the admission and result.obligations carries the
  #                  `undo_window` obligation (due at window_end) your enforcement point must perform.
  def authorize(pcactn, operation: nil, audience: nil, resolve_grant: nil, state_store: nil, is_revoked: nil, now: nil,
                plan: nil, context: nil, intent_policy: nil, intent_v2: nil, allowed_suites: nil, require: nil,
                escalation_principals: nil, escalation_answer: nil, revocation_staleness: nil, plans: nil, require_assurance: nil, k1: nil, uses_store: nil, fresh_at: nil,
                escalation_render: nil, insecure_unbound_approval: false, workflow: nil, workflow_call: nil,
                provenance: nil, provenance_bundle: nil, undo: nil)
    r = authorize_unchecked(pcactn, operation, audience, resolve_grant, state_store, is_revoked, now, plan, context,
                        intent_policy, intent_v2, allowed_suites, require, escalation_principals, escalation_answer,
                        revocation_staleness, plans, require_assurance, k1, uses_store, fresh_at,
                        escalation_render, insecure_unbound_approval, workflow, workflow_call,
                        provenance, provenance_bundle, undo)
    r.assurance = assurance_report(r.pcactn, r.checks, r.degraded) if r.assurance.nil? || r.assurance.empty?
    r
  rescue StandardError, SystemStackError => e
    authorize_refuse(403, 'authorize', "authorize: error (fail closed): #{e.class}")
  end

  def authorize_unchecked(pcactn, operation, audience, resolve_grant, state_store, is_revoked, now, plan, context,
                          intent_policy, intent_v2, allowed_suites, require, escalation_principals = nil,
                          escalation_answer = nil, revocation_staleness = nil, plans = nil, require_assurance = nil, k1 = nil, uses_store = nil, fresh_at = nil,
                          escalation_render = nil, insecure_unbound_approval = false, workflow = nil, workflow_call = nil,
                          provenance = nil, provenance_bundle = nil, undo = nil)
    missing = missing_authorize_components(audience: audience, resolve_grant: resolve_grant, state_store: state_store,
                                           is_revoked: is_revoked)
    missing << 'revocation_staleness (must be a RevocationStaleness)' unless revocation_staleness.nil? || revocation_staleness.is_a?(RevocationStaleness)
    missing << "plan (only 'single-step' or nil)" if !plan.nil? && plan != 'single-step'
    missing << 'provenance (must be a Hash)' unless provenance.nil? || provenance.is_a?(Hash)
    missing << 'undo (must respond to #call)' unless undo.nil? || undo.respond_to?(:call)
    unless missing.empty?
      return authorize_refuse(403, 'authorize_config',
                              "authorize_config: missing required component(s): #{missing.join(', ')} (fail closed)",
                              missing: missing)
    end
    op = operation_of(operation)
    if op.nil?
      return authorize_refuse(403, 'operation', 'operation: authorize needs the operation to execute (verb, resource, ' \
                                                'params) (fail closed)')
    end
    op['params'] = params_copy(op['params'])

    # K5 (C-308): the workflow step is admitted BEFORE any verification or replay state, so a refusal never consumes the counter.
    # An admitted step of the principal-signed workflow is the provenance gate's principal control commitment.
    principal = { 'plan' => false, 'control' => false }
    unless workflow.nil?
      now = (Time.now.to_f * 1000).to_i if now.nil?
      refusal = authorize_workflow_gate(workflow, workflow_call, pcactn, op, now)
      return refusal unless refusal.nil?

      principal['control'] = !workflow_call.nil?
    end

    p, err = coerce_pcactn(pcactn)
    if p.nil?
      return authorize_refuse(401, 'wire', 'wire: no PCActn presented') if err == 'absent'

      return authorize_refuse(401, 'pcactn', 'undecodable PCActn: it is not a readable PCActn object (fail closed)')
    end

    grant_ref = p['grant_ref']
    return authorize_refuse(401, 'malformed', 'malformed: grant_ref is not a string', pcactn: p) unless grant_ref.is_a?(String)

    grant = begin
      resolve_grant.call(grant_ref)
    rescue StandardError
      return authorize_refuse(403, 'resolve_grant', 'resolve_grant: grant resolution failed (fail closed)', pcactn: p)
    end
    return authorize_refuse(401, 'grant_ref', 'grant_ref: does not resolve to a known grant', pcactn: p) unless grant.is_a?(Hash)

    now = (Time.now.to_f * 1000).to_i if now.nil?
    ctx = {}
    unless context.nil?
      begin
        ctx = context.call(p) || {}
      rescue StandardError
        return authorize_refuse(403, 'context', 'context: the context callback failed (fail closed)', pcactn: p)
      end
      unless ctx.is_a?(Hash)
        return authorize_refuse(403, 'context', 'context: the context callback must return a Hash (fail closed)', pcactn: p)
      end

      ctx = ctx.to_h { |k, v| [k.is_a?(Symbol) ? k.to_s : k, v] }
    end

    plan_state = nil
    if !plans.nil? && ctx['plan'].nil?
      pl0 = p['plan'].is_a?(Hash) ? p['plan'] : {}
      root0 = pl0['root'].is_a?(String) ? pl0['root'] : ''
      pc = begin
        plans.context(grant_ref, root0, now)
      rescue StandardError
        return authorize_refuse(403, 'plans', 'plans: the plan registry failed (fail closed)', pcactn: p)
      end
      if !pc.nil?
        ctx = ctx.merge('plan' => pc['plan'], 'plan_authorized' => pc['planAuthorized'])
        plan_state = pc['status']
        # the principal authorized this registered plan (and with it every node's exact params): the provenance gate's plan
        # commitment. A plan the context or the request supplies is never one.
        principal['plan'] = pc['planAuthorized'] == true && pc['status'].is_a?(Hash) && pc['status']['executable'] == true
      elsif plan != 'single-step'
        plan_state = { 'state' => 'unknown', 'executable' => false, 'reason' => "plan #{root0} is unknown to the plan registry" }
      end
    end
    k1_given = !k1.nil?
    k1_in = {}
    if k1_given
      begin
        k1_in = k1.respond_to?(:call) && !k1.is_a?(Hash) ? k1.call(p) : k1
        raise TypeError, 'k1 is not a Hash' unless k1_in.is_a?(Hash)

        k1_in = k1_in.to_h { |k, v| [k.is_a?(Symbol) ? k.to_s : k, v] }
      rescue StandardError
        return authorize_refuse(403, 'k1', 'k1: verifier caveat-language state unavailable (fail closed)', pcactn: p)
      end
    end

    v2 = intent_v2
    if !v2.is_a?(Hash) && v2.respond_to?(:call)
      begin
        v2 = v2.call(p)
      rescue StandardError
        return authorize_refuse(403, 'intent_v2', 'intent_v2: verifier state unavailable (fail closed)', pcactn: p)
      end
    end
    # the host's env (the `context` callback) feeds rule 21; the v2 context's own env replaces same-named members, and a
    # JSON null there is no env
    host_env = ctx['env']
    v2 = {} if v2.nil?
    if v2.is_a?(Hash)
      v2 = v2.dup
      ve = v2['env']
      if ve.nil?
        host_env.is_a?(Hash) ? v2['env'] = host_env : v2.delete('env')
      elsif ve.is_a?(Hash) && host_env.is_a?(Hash)
        v2['env'] = host_env.merge(ve)
      end
    end
    v2 = v2.merge('params' => op['params']) if v2.is_a?(Hash) && v2['params'].nil?

    # ---- 1. the core checks
    core = verify_pcactn(p, grant, now: now, audience: audience, allowed_suites: allowed_suites,
                                   intent_policy: intent_policy, intent_v2: v2, fresh_at: fresh_at)
    if core.checks['wire'] == false
      r = core.reason.nil? || core.reason.empty? ? 'wire: malformed PCActn' : core.reason
      return AuthorizeResult.new(allow: false, status: 401, checks: { 'wire' => 'fail', 'malformed' => 'fail' },
                                 reasons: [r], reason: r, pcactn: p, verdict: core)
    end
    checks = core.checks.to_h { |k, ok| [k, ok ? 'pass' : 'fail'] }
    reasons = if core.allow then []
              elsif core.reasons.is_a?(Array) then core.reasons.dup
              else core.reason.nil? || core.reason.empty? ? [] : [core.reason]
              end
    mark = ->(name, status) { checks[name] = status }
    fail_check = lambda do |name, why|
      checks[name] = 'fail'
      reasons << "#{name}: #{why}"
    end

    # ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
    revoked = begin
      is_revoked.call(p, grant)
    rescue StandardError
      nil
    end
    if revoked == false
      mark.call('revocation', 'pass')
    else
      fail_check.call('revocation', revoked == true ? 'the grant is revoked' : 'the revocation check failed (fail closed)')
    end
    accepted_epoch = nil
    unless revocation_staleness.nil?
      # T9: the revocation state must be recent enough for the action's class (the stricter of the server's and the signed one)
      a0 = p['action'].is_a?(Hash) ? p['action'] : {}
      state = ctx['revocation_state']
      if state.nil?
        if effective_reversibility(ctx['reversibility_class'], a0['reversibility_class']) == 'irreversible' &&
           !revocation_staleness.allow_unsigned_root_for_irreversible
          fail_check.call('freshness', 'no verifiable (guardian-signed) revocation state for an irreversible action')
        else
          mark.call('freshness', 'not-enforced')
        end
      else
        fr = p['freshness']
        # every capability in the chain needs a non-membership proof (policy.ids / policy.proofs override); a hook that raises denies
        ids = begin
          revocation_staleness.ids ? revocation_staleness.ids.call(p) : (p['cap_chain'].is_a?(Array) ? p['cap_chain'] : []).map { |c| c.is_a?(Hash) ? c['id'] : nil }
        rescue StandardError
          [nil]
        end
        src = revocation_staleness.proofs
        pf = src.respond_to?(:call) ? ->(i) { src.call(i, p) } : src
        st = check_revocation_state(revocation_staleness, state, now: now, grant_ref: grant_ref, ids: ids, proofs: pf,
                                    signed_class: a0['reversibility_class'], server_class: ctx['reversibility_class'],
                                    pcactn_epoch: fr.is_a?(Hash) && fr.key?('epoch') ? fr['epoch'] : IntentV2::UNDEF)
        if st['ok']
          mark.call('freshness', 'pass')
          accepted_epoch = st['epoch']
        else
          fail_check.call('freshness', st['reason'])
        end
      end
    end
    if p.key?('zk_compliance')
      fail_check.call('zk_compliance', 'PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed)')
    end

    action = p['action'].is_a?(Hash) ? p['action'] : {}
    signed_digest = action['params_digest']
    op_digest = params_digest(op['params'])

    # ---- 3. the operation binding
    if action['verb'] != op['verb'] || action['resource'] != op['resource']
      fail_check.call('operation', "the proof is for #{js_str_of(action, 'verb')} on #{js_str_of(action, 'resource')}, " \
                                   "but this operation is #{op['verb']} on #{op['resource']}")
    elsif op_digest != signed_digest
      fail_check.call('operation', "the proof's params_digest does not match the params of this #{op['verb']} operation")
    else
      mark.call('operation', 'pass')
    end

    # ---- 4. grant_ref, params, plan, attestation, reversibility
    if grant_ref == grant['id']
      mark.call('grant_ref', 'pass')
    else
      fail_check.call('grant_ref', 'does not reference the supplied grant')
    end
    if op_digest == signed_digest
      mark.call('params_digest', 'pass')
    else
      fail_check.call('params_digest', 'supplied params do not hash to action.params_digest')
    end

    pl = p['plan'].is_a?(Hash) ? p['plan'] : {}
    node_id = pl['node_id']
    plan_nodes = ctx['plan']
    plan_authorized = ctx['plan_authorized']
    if plan == 'single-step' && plan_nodes.nil?
      plan_nodes = [{ 'id' => js_str_of(pl, 'node_id'), 'verb' => op['verb'], 'resource' => op['resource'],
                      'params_digest' => op_digest, 'reversibility_class' => action['reversibility_class'] }]
      plan_authorized = true
    end
    if plan_nodes.nil?
      # default-deny: authorize accepts no insecure_skip_plan_root_check opt-out
      fail_check.call('plan_root_authorized', 'default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecure_skip_plan_root_check)')
    else
      known = begin
        raise TypeError, 'plan is not an Array' unless plan_nodes.is_a?(Array)

        merkle_root(plan_nodes.map { |n| plan_leaf(n['id'], n, conditions_digest(n['pre'], n['post'])) })
      rescue StandardError
        nil
      end
      if known.nil? || known != pl['root']
        fail_check.call('plan_root_authorized', 'known plan does not match plan.root')
      elsif plan_authorized != true
        fail_check.call('plan_root_authorized', 'the plan root has not been authorized by the principal')
      else
        mark.call('plan_root_authorized', 'pass')
      end
    end

    unless plan_state.nil?
      if plan_state['executable']
        mark.call('plan_state', 'pass')
      else
        fail_check.call('plan_state', V2JS.truthy?(plan_state['reason']) ? plan_state['reason'] : "plan is #{plan_state['state']}")
      end
    end

    env = read_envelope(grant)
    if requires_attestation?(env.nil? ? nil : env['agent_binding'])
      fail_check.call('attestation', 'the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED ' \
                                     '(no attestation verifier in this SDK: fail closed)')
    end

    declared = action['reversibility_class']
    effective = declared
    server_class = ctx['reversibility_class']
    unless server_class.nil?
      dr = class_rank(declared)
      sr = class_rank(server_class)
      if dr < sr
        fail_check.call('reversibility', "declared class '#{js_str_of(action, 'reversibility_class')}' is less restrictive " \
                                         "than the authoritative '#{server_class}'")
      else
        mark.call('reversibility', 'pass')
      end
      effective = dr > sr ? declared : server_class
    end

    # ---- 5. policy: envelope predicates + envelope caveats + root caveats; then the delegated caveats
    chain = p['cap_chain'].is_a?(Array) ? p['cap_chain'] : []
    depth = [0, chain.length - 1].max
    inner = { 'verb' => action['verb'], 'resource' => action['resource'], 'params' => op['params'] }
    inner['reversibility_class'] = effective unless effective.nil?
    action_ctx = { 'action' => inner }
    action_ctx['subject'] = ctx['subject'] unless ctx['subject'].nil?
    pred_env = v2_env(p, grant, v2, now, ctx['env'])
    action_ctx['env'] = pred_env unless pred_env.nil?
    tool_call = { 'tool' => inner['verb'].is_a?(String) ? inner['verb'] : '', 'args' => op['params'] }
    tool_call['tool_signature_digest'] = p['tool_binding'] if p['tool_binding'].is_a?(String)
    rev_class = effective
    if rev_class.nil? && node_id.is_a?(String) && plan_nodes.is_a?(Array)
      hit = plan_nodes.find { |n| n.is_a?(Hash) && n['id'] == node_id }
      rev_class = hit.nil? ? nil : hit['reversibility_class']
    end
    cctx = { 'now' => now, 'action' => inner, 'delegation_depth' => depth }
    cctx['blast_radius'] = ctx['blast_radius'] unless ctx['blast_radius'].nil?
    cctx['reversibility_class'] = rev_class unless rev_class.nil?
    cctx['recent_action_times'] = ctx['recent_action_times'] unless ctx['recent_action_times'].nil?

    # Caveat language v2 (opt-in): the K1 caveat types of the whole chain, evaluated here instead of by the stock evaluator.
    k1r = nil
    hops = chain.empty? ? [grant] : chain
    has_k1 = ([grant] + hops).any? { |h| h.is_a?(Hash) && h['caveats'].is_a?(Array) && h['caveats'].any? { |c| k1_type?(c) } }
    if has_k1 || (k1_given && k1_in.key?('narrow'))
      # without a k1 option evaluate_k1 gets nil and refuses every K1 caveat of every hop
      k1r = evaluate_k1(grant, chain, k1_given ? k1_in.merge('action_digest' => discharge_action_digest(p)) : nil,
                        { 'now' => now, 'action' => inner })
    end
    if k1r && k1r[:bound].any? { |b| b['caveat']['type'] == CAVEAT_MAX_USES } && !uses_store.respond_to?(:claim)
      fail_check.call('max_uses', 'the chain carries a max_uses caveat and no uses_store was supplied (fail closed)')
    end

    if !chain.empty? || k1r
      leaf = chain.empty? ? {} : (chain[-1].is_a?(Hash) ? chain[-1] : {})
      gcs = grant['caveats'].is_a?(Array) ? grant['caveats'] : []
      extra = leaf['caveats'].is_a?(Array) ? (leaf['caveats'][gcs.length..] || []) : nil
      extra = chain.empty? ? [] : extra
      extra = extra.reject { |c| k1_type?(c) } + k1r[:plain] if k1r && extra
      ok, failed = evaluate_agent_caveats(extra, cctx, action_ctx, tool_call)
      if ok && (k1r.nil? || k1r[:ok])
        mark.call('delegated_caveats', 'pass')
      else
        why = "delegation caveat(s) not satisfied: #{(failed + (k1r ? k1r[:failed] : [])).join(', ')}"
        why += " (#{k1r[:reasons].join('; ')})" if k1r && !k1r[:ok]
        fail_check.call('delegated_caveats', why)
      end
    end

    policy_why = begin
      with_regex_budget do
        if env.nil?
          ['grant carries no valid envelope']
        else
          why = []
          pr = evaluate_predicates(env['predicates'], action_ctx)
          why << (pr['reason'] || 'action not permitted by envelope predicates') unless pr['allowed']
          ok, failed = evaluate_agent_caveats(env['caveats'], cctx, action_ctx, tool_call)
          why << "caveat(s) not satisfied: #{failed.join(', ')}" unless ok
          rc = root_caveats(grant)
          rc = rc.reject { |c| k1_type?(c) } if k1r && rc.is_a?(Array)
          ok, failed = evaluate_agent_caveats(rc, cctx, action_ctx, tool_call)
          why << "root caveat(s) not satisfied: #{failed.join(', ')}" unless ok
          why
        end
      end
    rescue StandardError, SystemStackError
      ['policy evaluation error (fail closed)']
    end
    if policy_why.empty?
      mark.call('policy', 'pass')
    else
      checks['policy'] = 'fail'
      policy_why.each { |w| reasons << "policy: #{w}" }
    end

    # ---- required checks (default-deny), then the replay counter
    extra_required = (require.is_a?(Array) ? require : [require]).filter_map do |n|
      n.is_a?(Symbol) ? n.to_s : (n if n.is_a?(String))
    end
    # `counter` in `require:` is the documented alias of `replay` (it always meant the stateful check here).
    extra_required = extra_required.map { |n| n == 'counter' ? 'replay' : n }
    # Pass tentatively; flips to fail below if the store refuses the claim (TypeScript order).
    checks['replay'] = 'pass'
    (DEFAULT_REQUIRED_CHECKS + extra_required).each do |name|
      st = checks[name]
      next if %w[pass fail].include?(st)

      checks[name] = 'fail'
      reasons << "#{name}: required check is #{st || 'absent'} (default-deny: not enforced by this resource server)"
    end

    # ---- high-assurance policy (before any replay state is written)
    unless require_assurance.nil?
      unmet = unmet_assurance(assurance_report(p, checks, core.degraded), require_assurance.is_a?(Hash) ? require_assurance : { 'invalid' => true })
      if unmet.nil?
        mark.call('assurance', 'pass')
      else
        checks['assurance'] = 'fail'
        reasons << unmet # already prefixed `assurance: `
      end
    end

    # ---- provenance by default (its own check name: `provenance` is the Intent Layer v2 rule 17 check)
    pv_status, pv_reason = provenance_flow_check(provenance, grant, p, op, provenance_bundle, principal)
    checks['provenance_flow'] = pv_status
    reasons << "provenance_flow: #{pv_reason || 'refused'}" if pv_status == 'fail'

    holder = !chain.empty? && chain[-1].is_a?(Hash) ? chain[-1]['holder'] : nil
    counter = p['counter']
    skey = holder.is_a?(String) && grant['id'].is_a?(String) ? state_key(grant['id'], holder) : nil
    esc = { request: nil, by: nil, undo: nil }
    deny = lambda do
      status = AUTHN_CHECKS.any? { |c| checks[c] == 'fail' } ? 401 : 403
      AuthorizeResult.new(allow: false, status: status, checks: checks, reasons: reasons,
                          reason: decisive_reason(checks, reasons), pcactn: p, verdict: core, degraded: core.degraded,
                          decision: esc[:request].nil? ? 'deny' : 'escalate', escalation: esc[:request])
    end
    if checks.value?('fail')
      return deny.call if skey.nil? || decision_of({ 'allow' => false, 'checks' => checks, 'reasons' => reasons }) != 'escalate'

      # Ternary decision: every failing check is escalate-class. Never admitted by itself.
      last = nil
      head_known = false
      if state_store.respond_to?(:last)
        begin
          last = state_store.last(skey)
          head_known = last.nil? || last.is_a?(Integer)
        rescue StandardError
          head_known = false
        end
      end
      # K7: the verifier's own recomputation of H(R) from the executed params and its definition (nil: none could be derived)
      render_digest = begin
        escalation_render.respond_to?(:call) ? escalation_render.call(p) : nil
      rescue StandardError
        nil
      end
      esc[:request] = build_escalation_request(aud: audience, grant: grant, pcactn: p, last_counter: head_known ? last : nil,
                                               reasons: reasons, now: now, render_digest: render_digest)
      if !insecure_unbound_approval && render_digest.nil? && escalation_principals.is_a?(Array) && !escalation_principals.empty? && !escalation_answer.nil?
        reasons << 'escalation: an approval render is required and none could be recomputed'
      elsif escalation_principals.is_a?(Array) && !escalation_principals.empty? && !escalation_answer.nil? && head_known
        bind = { 'policy_digest' => escalation_policy_digest(grant), 'action_digest' => escalation_action_digest(p),
                 'history_head' => escalation_history_head(last) }
        bind['render_digest'] = render_digest unless render_digest.nil?
        v = verify_escalation_answer(escalation_answer, escalation_principals, bind, now)
        if v[:ok] && v[:decision] == 'allow'
          checks.each_key { |n| checks[n] = 'pass' if checks[n] == 'fail' }
          checks['escalation'] = 'pass'
          reasons << "escalation: answered allow by principal #{v[:principal][0, 8]}"
          esc[:by] = v[:principal]
          esc[:request] = nil
        else
          reasons << "escalation: #{v[:ok] ? 'the principal answered deny' : v[:reason]}"
        end
      end
      # Undo window: an unanswered escalation runs now under a veto window instead of waiting for prior approval. Never for a
      # provenance escalation: reversibility does not make an action injected content chose safe to run.
      answer_presented = escalation_principals.is_a?(Array) && !escalation_principals.empty? && !escalation_answer.nil?
      provenance_escalated = checks['provenance_flow'] == 'fail' || checks['provenance'] == 'fail'
      if !esc[:request].nil? && !undo.nil? && !answer_presented && !provenance_escalated
        adm = undo_admission(undo, p, grant, op)
        unless adm.nil?
          checks.each_key { |n| checks[n] = 'pass' if checks[n] == 'fail' }
          checks['undo_window'] = 'pass'
          reasons << "undo_window: runs now under a veto window until #{adm['window_end']} (compensation #{adm['compensation']['verb']})"
          esc[:request] = nil
          esc[:undo] = adm
        end
      end
      return deny.call unless esc[:request].nil?
    end

    if skey.nil?
      fail_check.call('replay', 'no counter stream for this proof (fail closed)')
      return deny.call
    end
    claimed = begin
      state_store.claim(skey, counter)
    rescue StandardError
      nil
    end
    claimed = ClaimResult.new(claimed) if claimed == true || claimed == false
    ok = (claimed.is_a?(ClaimResult) || claimed.is_a?(Array)) && claimed[0] == true
    unless ok
      last = claimed.is_a?(ClaimResult) || claimed.is_a?(Array) ? claimed[1] : nil
      if claimed.nil?
        fail_check.call('replay', 'the replay store failed (fail closed)')
      elsif !last.nil?
        fail_check.call('replay', "#{counter} is not greater than last seen #{last} (replay)")
      else
        fail_check.call('replay', "#{counter} was already claimed (replay)")
      end
      return deny.call
    end
    # max_uses is spent only now: the counter claim succeeded and every check passed (a refusal here cannot give it back)
    if k1r && k1r[:bound].any? { |b| b['caveat']['type'] == CAVEAT_MAX_USES }
      spent = reserve_max_uses(uses_store, k1r[:bound], now)
      unless spent[:ok]
        fail_check.call('max_uses', spent[:reason])
        return deny.call
      end
    end
    unless accepted_epoch.nil? || revocation_staleness.on_epoch_accepted.nil?
      begin
        revocation_staleness.on_epoch_accepted.call(accepted_epoch, p)
      rescue StandardError
        nil # the pin is the host's; the decision is already made
      end
    end
    AuthorizeResult.new(allow: true, status: 200, checks: checks, reasons: reasons, reason: nil, pcactn: p, verdict: core, degraded: core.degraded,
                        decision: 'allow', escalation: esc[:by].nil? ? nil : { 'answered_by' => esc[:by] }, undo: esc[:undo],
                        obligations: esc[:undo].nil? ? nil : [undo_window_obligation(esc[:undo]['id'], esc[:undo]['window_end'])],
                        operation: AuthorizedOperation.new(verb: op['verb'], resource: op['resource'],
                                                           params_digest: signed_digest, id: hash_canonical(p)))
  end

  # The undo hook's admission, validated (String keys), or nil: a nil, malformed or raising hook is no admission.
  def undo_admission(hook, pcactn, grant, op)
    a = hook.call(pcactn, grant, op)
    return nil unless a.is_a?(Hash)

    a = a.to_h { |k, v| [k.to_s, v] }
    c = a['compensation'].is_a?(Hash) ? a['compensation'].to_h { |k, v| [k.to_s, v] } : nil
    return nil if c.nil? || !c['verb'].is_a?(String) || c['verb'].empty? || !c['resource'].is_a?(String)
    return nil unless obligation_error(undo_window_obligation(a['id'], a['window_end'])).nil?

    { 'id' => a['id'], 'window_end' => a['window_end'], 'compensation' => { 'verb' => c['verb'], 'resource' => c['resource'] } }
  rescue StandardError
    nil
  end

  # JavaScript String(h[k]) ('undefined' for an absent member).
  def js_str_of(h, k)
    Predicates.js_string(h.key?(k) ? h[k] : Predicates::UNDEF)
  end

  # The predicate `env`: the host's, with the verifier-computed Intent Layer v2 members (TypeScript v2Env).
  def v2_env(p, grant, v2, now, env)
    return env unless p.key?('intent_session')

    rest = env.is_a?(Hash) ? env.dup : {}
    %w[acc mon canon world prov class].each { |k| rest.delete(k) }
    d = decide_intent_v2(p, grant, v2, now)['env'] || {}
    d.each { |k, v| rest[k] = v unless v.nil? }
    rest
  end

  # True only if `result` allowed exactly this operation (verb, resource, params digest). Call it where the side effect
  # runs, with the values it is about to use. Never raises.
  def is_authorized_for(result, operation) # rubocop:disable Naming/PredicateName
    b = result.is_a?(AuthorizeResult) && result.allow == true ? result.operation : nil
    op = operation_of(operation)
    return false if b.nil? || op.nil?

    b.verb == op['verb'] && b.resource == op['resource'] && b.params_digest == params_digest(params_copy(op['params']))
  rescue StandardError, SystemStackError
    false
  end
end
