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
  AuthorizeResult = Struct.new(:allow, :status, :checks, :reasons, :reason, :operation, :pcactn, :verdict, :missing,
                               keyword_init: true) do
    # The names of the failing checks, sorted.
    def failed_checks
      (checks || {}).select { |_, s| s == 'fail' }.keys.sort
    end
  end

  # The authorize components a guard adds on top of its audience / resolve_grant (the opt-in for RackMiddleware's
  # `authorize:`). `operation` is the request -> operation mapping (a callable (env) -> {verb, resource, params} | nil).
  AuthorizeOptions = Struct.new(:state_store, :is_revoked, :plan, :context, :require, :operation, keyword_init: true) do
    def initialize(plan: 'single-step', require: [], **rest)
      super
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
  end

  # In-process reference store (one Mutex). Correct for ONE process only.
  class MemoryStateStore < StateStore
    def initialize
      super
      @last = {}
      @lock = Mutex.new
    end

    def claim(key, counter)
      @lock.synchronize do
        last = @last[key]
        return ClaimResult.new(false, last) if !last.nil? && !(counter > last)

        @last[key] = counter
        ClaimResult.new(true)
      end
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
  end

  # SqlStateStore on a SQLite file through the sqlite3 gem (required lazily, only when this class is instantiated). One
  # connection per thread and process (never shared across a fork); busy waits up to `timeout` seconds.
  class SqliteStateStore < SqlStateStore
    def initialize(path, timeout: 30, table: DEFAULT_TABLE)
      require 'sqlite3'
      @path = path
      @timeout_ms = (timeout * 1000).to_i
      @conn_key = :"atlas_pca_sqlite_#{object_id}"
      super(execute: ->(sql, binds) { db = conn; db.execute(sql, binds); db.changes },
            select: ->(sql, binds) { row = conn.get_first_row(sql, binds); row && row[0] },
            placeholders: :question, table: table)
      conn.execute(create_table_sql)
    end

    private

    def conn
      cur = Thread.current[@conn_key]
      return cur[1] if cur && cur[0] == Process.pid

      db = SQLite3::Database.new(@path)
      db.busy_timeout = @timeout_ms
      Thread.current[@conn_key] = [Process.pid, db]
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

  CLASS_RANK = { 'reversible' => 0, 'rate_limited' => 1, 'costly' => 1, 'irreversible' => 2 }.freeze

  def class_rank(c)
    c.is_a?(String) ? CLASS_RANK.fetch(c, 2) : 2
  end

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
                        missing: missing, pcactn: pcactn)
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
  def authorize(pcactn, operation: nil, audience: nil, resolve_grant: nil, state_store: nil, is_revoked: nil, now: nil,
                plan: nil, context: nil, intent_policy: nil, intent_v2: nil, allowed_suites: nil, require: nil)
    authorize_unchecked(pcactn, operation, audience, resolve_grant, state_store, is_revoked, now, plan, context,
                        intent_policy, intent_v2, allowed_suites, require)
  rescue StandardError, SystemStackError => e
    authorize_refuse(403, 'authorize', "authorize: error (fail closed): #{e.class}")
  end

  def authorize_unchecked(pcactn, operation, audience, resolve_grant, state_store, is_revoked, now, plan, context,
                          intent_policy, intent_v2, allowed_suites, require)
    missing = missing_authorize_components(audience: audience, resolve_grant: resolve_grant, state_store: state_store,
                                           is_revoked: is_revoked)
    missing << "plan (only 'single-step' or nil)" if !plan.nil? && plan != 'single-step'
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

    p, err = coerce_pcactn(pcactn)
    if p.nil?
      return authorize_refuse(401, 'wire', err == 'absent' ? 'wire: no PCActn presented' : 'wire: PCActn could not be decoded')
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

    v2 = intent_v2
    if !v2.is_a?(Hash) && v2.respond_to?(:call)
      begin
        v2 = v2.call(p)
      rescue StandardError
        return authorize_refuse(403, 'intent_v2', 'intent_v2: verifier state unavailable (fail closed)', pcactn: p)
      end
    end
    v2 = v2.merge('params' => op['params']) if v2.is_a?(Hash) && v2['params'].nil?

    # ---- 1. the core checks
    core = verify_pcactn(p, grant, now: now, audience: audience, allowed_suites: allowed_suites,
                                   intent_policy: intent_policy, intent_v2: v2)
    if core.checks['wire'] == false
      r = core.reason.nil? || core.reason.empty? ? 'wire: malformed PCActn' : core.reason
      return AuthorizeResult.new(allow: false, status: 401, checks: { 'wire' => 'fail', 'malformed' => 'fail' },
                                 reasons: [r], reason: r, pcactn: p, verdict: core)
    end
    checks = core.checks.to_h { |k, ok| [k, ok ? 'pass' : 'fail'] }
    reasons = core.allow || core.reason.nil? || core.reason.empty? ? [] : [core.reason]
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
      mark.call('plan_root_authorized', 'not-enforced')
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

    unless chain.empty?
      leaf = chain[-1].is_a?(Hash) ? chain[-1] : {}
      gcs = grant['caveats'].is_a?(Array) ? grant['caveats'] : []
      extra = leaf['caveats'].is_a?(Array) ? (leaf['caveats'][gcs.length..] || []) : nil
      ok, failed = evaluate_agent_caveats(extra, cctx, action_ctx, tool_call)
      if ok
        mark.call('delegated_caveats', 'pass')
      else
        fail_check.call('delegated_caveats', "delegation caveat(s) not satisfied: #{failed.join(', ')}")
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
          ok, failed = evaluate_agent_caveats(root_caveats(grant), cctx, action_ctx, tool_call)
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

    deny = lambda do
      status = AUTHN_CHECKS.any? { |c| checks[c] == 'fail' } ? 401 : 403
      AuthorizeResult.new(allow: false, status: status, checks: checks, reasons: reasons,
                          reason: decisive_reason(checks, reasons), pcactn: p, verdict: core)
    end
    return deny.call if checks.value?('fail')

    holder = !chain.empty? && chain[-1].is_a?(Hash) ? chain[-1]['holder'] : nil
    counter = p['counter']
    unless holder.is_a?(String) && grant['id'].is_a?(String)
      fail_check.call('replay', 'no counter stream for this proof (fail closed)')
      return deny.call
    end
    claimed = begin
      state_store.claim(state_key(grant['id'], holder), counter)
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
    AuthorizeResult.new(allow: true, status: 200, checks: checks, reasons: reasons, reason: nil, pcactn: p, verdict: core,
                        operation: AuthorizedOperation.new(verb: op['verb'], resource: op['resource'],
                                                           params_digest: signed_digest, id: hash_canonical(p)))
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
