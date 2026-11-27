# frozen_string_literal: true

require 'json'

module AtlasPca
  # The server stack of the reference (`server/authorize`, `server/require-pca`, `server/verify`, `server/authorize-execution`): the
  # authorizer factory and request guard, the default request extractors, the replay / budget state stores and the small guard
  # helpers. A request is a Hash {'headers' => {name => value}, 'body' => String | Hash, 'method', 'url'} (a Rack env is read through
  # {request_of_rack}). `AtlasPca.authorize` is the per-call pipeline; these build on it.

  # The atomic key/value store a KvStateStore sits on: #get(key), #set(key, value) and #update(key) { |prev| next_or_nil } (atomic across
  # every client of the backend; the block's nil keeps the value) returning the stored value, and #keys. Values are JSON trees.
  class MemoryDurableKv
    def initialize
      @m = {}
      @lock = Mutex.new
    end

    def get(key) = @lock.synchronize { decode(@m[key]) }

    def set(key, value) = @lock.synchronize { (@m[key] = encode(value)) && nil }

    def update(key)
      @lock.synchronize do
        nxt = yield(decode(@m[key]))
        @m[key] = encode(nxt) unless nxt.nil?
        decode(@m[key])
      end
    end

    def keys = @lock.synchronize { @m.keys }
    def snapshot = @lock.synchronize { @m.transform_values { |v| decode(v) } }

    private

    def encode(v) = JSON.generate(v)
    def decode(s) = s.nil? ? nil : JSON.parse(s)
  end

  # A replay + trust-budget StateStore over an atomic key/value store with `update` (a MemoryDurableKv, or a durable backend).
  # Holder state per counter stream: {'lastCounter', 'budget' => {'B','tau','asOf'}, 'lastEpoch', 'lastBeaconSeq'}. `prefix` namespaces the
  # keys; `scope` is :shared (default, a durable shared backend) or :process.
  class KvStateStore < StateStore
    def initialize(kv, prefix: 'pca-state:', scope: :shared)
      super()
      @kv = kv
      @prefix = prefix
      @scope = scope
    end

    def scope = @scope

    def claim(key, counter)
      res = ClaimResult.new(false, nil)
      @kv.update(@prefix + key) do |prev|
        cur = prev.is_a?(Hash) ? prev : {}
        if cur['lastCounter'].is_a?(Numeric) && !(counter > cur['lastCounter'])
          res = ClaimResult.new(false, cur['lastCounter'])
          nil
        else
          res = ClaimResult.new(true)
          cur.merge('lastCounter' => counter)
        end
      end
      res
    end

    def last(key) = holder(key)['lastCounter']
    def pin(key) = holder(key)['lastEpoch']
    def raise_pin(key, value) = raise_field(key, 'lastEpoch', value)
    def beacon_pin(key) = holder(key)['lastBeaconSeq']
    def raise_beacon_pin(key, value) = raise_field(key, 'lastBeaconSeq', value)
    def budget(key) = holder(key)['budget']

    # ONE atomic compare-and-set of the budget: true iff the stored budget equals `old` (nil: none) and is replaced by `new`.
    def budget_cas(key, old, new)
      ok = false
      @kv.update(@prefix + key) do |prev|
        cur = prev.is_a?(Hash) ? prev : {}
        next nil unless cur['budget'] == old

        ok = true
        cur.merge('budget' => new)
      end
      ok
    end

    def consume_once(key, retain_until, now)
      StateStore.check_consume_once!(key, retain_until, now)
      fresh = false
      @kv.update("#{@prefix}once:#{key}") do |prev|
        fresh = prev.nil? || prev < now
        fresh ? retain_until : [prev, retain_until].max
      end
      fresh
    end

    private

    def holder(key)
      h = @kv.get(@prefix + key)
      h.is_a?(Hash) ? h : {}
    end

    def raise_field(key, field, value)
      raise ArgumentError, "#{field}: value must be an Integer" unless value.is_a?(Integer)

      stored = nil
      @kv.update(@prefix + key) do |prev|
        cur = prev.is_a?(Hash) ? prev : {}
        stored = [cur[field], value].compact.max
        cur[field] == stored ? nil : cur.merge(field => stored)
      end
      stored
    end
  end

  module_function

  # The in-memory reference store (ONE process; scope :process, refused with multi_instance) and its atomic twin: Ruby's replay store
  # claim is always one atomic operation, so both are the same object.
  def memory_pca_store = MemoryStateStore.new
  def atomic_memory_pca_store = MemoryStateStore.new

  # A KvStateStore over an atomic key/value store (see MemoryDurableKv).
  def durable_pca_state_store(kv, prefix: 'pca-state:', scope: :shared) = KvStateStore.new(kv, prefix: prefix, scope: scope)

  # True for a store with the atomic claim and the monotone pin (what the stateful verifier needs).
  def atomic_pca_state_store?(store) = !store.nil? && store.respond_to?(:claim) && store.respond_to?(:raise_pin)

  # The ternary decision of a guard result (a refusal without `decision` is deny).
  def decision_of_result(r)
    ok = r.respond_to?(:allow) ? r.allow : (r['ok'] == true || r['allow'] == true)
    dec = r.respond_to?(:decision) ? r.decision : r['decision']
    ok == true ? 'allow' : (dec == 'escalate' ? 'escalate' : 'deny')
  end

  # A Rack env as a request Hash: its HTTP_ headers (name-lowercased with dashes) and the rewound body text.
  def request_of_rack(env)
    headers = env.select { |k, _| k.start_with?('HTTP_') }.to_h { |k, v| [k.sub('HTTP_', '').tr('_', '-').downcase, v] }
    body = env['rack.input']&.then { |i| i.read.tap { i.rewind } }
    { 'headers' => headers, 'body' => body, 'method' => env['REQUEST_METHOD'], 'url' => env['PATH_INFO'] }
  end

  # Header lookup, field names case-insensitive; several spellings with DIFFERENT values make the credential ambiguous (nil).
  def request_header(req, name)
    h = req.is_a?(Hash) ? req['headers'] : nil
    return nil unless h.is_a?(Hash)

    want = name.downcase
    found = nil
    h.each do |k, raw|
      next unless k.to_s.downcase == want

      v = raw.is_a?(Array) ? raw[0] : raw
      next unless v.is_a?(String)
      return nil if !found.nil? && found != v

      found = v
    end
    found
  end

  def strict_header_json(value)
    text = decode_pca_header(value)
    raise ArgumentError, 'header is not canonical base64url' if text.nil?

    parse_json(text)
  end

  # The body as a Hash (a String body is parsed with the strict JSON profile; one that is not strict JSON is nil).
  def request_body_object(req)
    b = req.is_a?(Hash) ? req['body'] : nil
    b = parse_json(b) if b.is_a?(String)
    b.is_a?(Hash) ? b : nil
  rescue Malformed
    nil
  end

  # Default PCActn extraction: the `PCA-Action` header (strict base64url JSON; malformed raises ArgumentError), else the body's `pcactn`.
  def default_extract(req)
    h = request_header(req, 'pca-action')
    return decode_pca_header(h) || raise(ArgumentError, 'PCA-Action is not canonical base64url') unless h.nil? || h.empty?

    x = request_body_object(req)&.fetch('pcactn', nil)
    x.is_a?(String) || x.is_a?(Hash) ? x : nil
  end

  # Default escalation-answer extraction: the `PCA-Escalation-Answer` header (strict base64url JSON), else the body's `escalation_answer`.
  def default_escalation_answer(req)
    h = request_header(req, 'pca-escalation-answer')
    return strict_header_json(h) unless h.nil? || h.empty?

    request_body_object(req)&.fetch('escalation_answer', nil)
  end

  # nil when `a` is a usable undo admission {id, window_end, compensation: {verb}}, else the reason.
  def undo_admission_error(a)
    return 'an admission must be an object' unless a.is_a?(Hash)
    return 'admission id must be a non-empty string of at most 128 characters' unless a['id'].is_a?(String) && !a['id'].empty? && a['id'].length <= 128

    w = a['window_end']
    return 'admission window_end must be a non-negative safe integer' unless wb_safe_int?(w) && w >= 0 && !(w.is_a?(Float) && w.zero? && (1.0 / w).negative?)

    c = a['compensation']
    return 'admission compensation.verb must be a non-empty string' unless c.is_a?(Hash) && c['verb'].is_a?(String) && !c['verb'].empty?

    nil
  end

  # The required components that `opts` ({'audience','grant','resolve_grant','state','is_revoked'}) lacks (empty when complete).
  def missing_execution_components(opts)
    o = opts.is_a?(Hash) ? opts : {}
    missing = []
    missing << 'audience' unless o['audience'].is_a?(String) && !o['audience'].empty?
    missing << 'grant or resolve_grant' if o['grant'].nil? && !o['resolve_grant'].respond_to?(:call)
    missing << 'state' unless o['state'].respond_to?(:get) && o['state'].respond_to?(:put) || (o['state'].respond_to?(:claim) && o['state'].respond_to?(:raise_pin))
    missing << 'is_revoked' unless o['is_revoked'].respond_to?(:call)
    missing
  end

  # Default-deny: every required check of the verdict {'allow','checks','reasons'} that is not pass / fail becomes a failure (a counter
  # alias resolves to replay or counter_format; `unsupported` stays unsupported). Mutates and returns the verdict.
  def enforce_required(verdict, required)
    checks = verdict['checks']
    required.each do |raw|
      name = raw == 'counter' && !checks.key?('counter') ? (checks.key?('replay') ? 'replay' : 'counter_format') : raw
      st = checks[name]
      next if %w[pass fail].include?(st)

      verdict['allow'] = false
      checks[name] = st == 'unsupported' ? 'unsupported' : 'fail'
      verdict['reasons'] << "#{name}: required check is #{st == 'unsupported' ? 'unsupported' : (st || 'absent')} (default-deny: not enforced by this resource server)"
    end
    verdict
  end

  # Build an authorizer once and call it per operation: `az.call(pcactn, operation: {...}, **per_call)`. The configuration is checked here;
  # an incomplete one makes every call refuse (authorize_config, fail closed).
  def create_authorizer(**opts)
    missing = missing_authorize_components(audience: opts[:audience], resolve_grant: opts[:resolve_grant], state_store: opts[:state_store], is_revoked: opts[:is_revoked])
    unless missing.empty?
      reason = "authorize_config: missing required component(s): #{missing.join(', ')} (fail closed)"
      return ->(*, **) { authorize_refuse(403, 'authorize_config', reason, missing: missing) }
    end
    frozen = opts.dup.freeze
    ->(pcactn, **per_call) { authorize(pcactn, **frozen, **per_call) }
  end

  # A request guard over `authorize`: `guard.call(request)` maps the request to its operation with `operation` (server routing, never
  # the PCActn; nil denies), extracts the PCActn (`extract`, default {default_extract}) and returns
  # {'ok','decision','status','verdict','pcactn','operation','escalation'?}.
  def require_authorized(operation:, extract: nil, **opts)
    az = create_authorizer(**opts)
    ex = extract || method(:default_extract)
    lambda do |req|
      op = begin
        operation.call(req)
      rescue StandardError
        nil
      end
      pc = begin
        ex.call(req)
      rescue StandardError
        nil
      end
      r = az.call(pc, operation: op, escalation_answer: (default_escalation_answer(req) rescue nil))
      if r.allow
        out = { 'ok' => true, 'decision' => 'allow', 'verdict' => r.verdict, 'pcactn' => r.pcactn, 'operation' => r.operation }
      else
        out = { 'ok' => false, 'decision' => r.decision, 'status' => r.status, 'verdict' => r.verdict }
      end
      out['escalation'] = r.escalation unless r.escalation.nil?
      out
    end
  end
end
