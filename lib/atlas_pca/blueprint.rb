# frozen_string_literal: true

# Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop
# issued by that key. BlueprintRegistry keeps the newest record per key in a durable kv (pinned operators, a strictly higher epoch replaces, the
# same epoch with different content is a fork). A non-empty ceiling is never evaluated here: it denies (ceiling_unevaluable).
# Every function is total. Hashes use String keys.
module AtlasPca
  AGENT_BLUEPRINT_DOMAIN = "atlas-pca/agent-blueprint/v1\x00".b.freeze
  BLUEPRINT_BODY_KEYS = %w[v id key ceiling max_depth expires_at runtime_pins epoch status issued_at operator].freeze
  BLUEPRINT_PIN_KEYS = %w[runtime_measurement model_id weights_digest operator spiffe_id].freeze

  module_function

  def blueprint_well_formed?(b)
    return false unless b.is_a?(Hash) && b['v'] == 1 && b['v'].is_a?(Integer)
    return false unless k3_str?(b['id'], 128) && k3_str?(b['key'], 128) && k3_str?(b['operator'], 128)
    return false unless k3_int?(b['epoch']) && k3_int?(b['issued_at']) && %w[active disabled].include?(b['status'])
    return false if b.key?('max_depth') && !(k3_int?(b['max_depth']) && b['max_depth'] >= 1)
    return false if b.key?('expires_at') && !k3_int?(b['expires_at'])
    if b.key?('runtime_pins')
      pins = b['runtime_pins']
      return false unless pins.is_a?(Array) && !pins.empty? && pins.length <= 16
      return false unless pins.all? { |x| x.is_a?(Hash) && !x.empty? && x.all? { |k, v| BLUEPRINT_PIN_KEYS.include?(k) && k3_str?(v, 256) } }
    end

    c = b['ceiling']
    c.is_a?(Array) && c.length <= 32 && c.all? { |x| x.is_a?(Hash) && x['type'].is_a?(String) }
  end

  def verify_blueprint(b)
    return false unless blueprint_well_formed?(b)

    body = BLUEPRINT_BODY_KEYS.each_with_object({}) { |k, h| h[k] = b[k] if b.key?(k) }
    k3_verify_body(AGENT_BLUEPRINT_DOMAIN, body, b['operator'], b['sig'])
  end

  # The registry keeps the newest record per key in a durable kv (`blueprint/rec/<key>`, one atomic update per accept) and the
  # highest accepted epoch (`blueprint/epoch`): a disabled blueprint stays disabled across a restart and across instances. The
  # kv is required (MemoryBlueprintKv is for tests and single-process use).
  class BlueprintRegistry
    EPOCH_KEY = 'blueprint/epoch'

    # operators: the operator keys whose records this verifier accepts. kv: get(key) + atomic update(key) { |prev| next }.
    def initialize(operators, kv = nil)
      raise TypeError, 'BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintKv is for tests and single-process use)' unless AtlasPca.kv_usable?(kv)

      @operators = operators
      @kv = kv
      @lock = Mutex.new
    end

    # { 'ok' => true, 'replaced' => bool } or { 'ok' => false, 'code' => ... }
    def accept(b) = @lock.synchronize { accept_locked(b) }

    # The stored record of a blueprint key, or nil.
    def get(key) = @kv.get("blueprint/rec/#{key}")

    # The highest blueprint epoch this verifier has accepted (0 when empty).
    def epoch = @kv.get(EPOCH_KEY)&.fetch('max') || 0

    private

    def accept_locked(b)
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_blueprint(b)
      return { 'ok' => false, 'code' => 'unknown_operator' } unless @operators.include?(b['operator'])

      out = nil
      @kv.update("blueprint/rec/#{b['key']}") do |cur|
        if cur
          if cur['operator'] != b['operator']
            out = { 'ok' => false, 'code' => 'operator_changed' }
          elsif b['epoch'] < cur['epoch']
            out = { 'ok' => false, 'code' => 'stale_epoch' }
          elsif b['epoch'] == cur['epoch']
            out = cur['sig'] == b['sig'] ? { 'ok' => true, 'replaced' => false } : { 'ok' => false, 'code' => 'epoch_fork' }
          end
          next nil unless out.nil?
        end
        out = { 'ok' => true, 'replaced' => true }
        b
      end
      # after the record: a crash between the two leaves the epoch behind (an escalation), never ahead of what is held
      @kv.update(EPOCH_KEY) { |m| m.nil? || m['max'] < b['epoch'] ? { 'v' => 1, 'max' => b['epoch'] } : nil } if out['ok']
      out
    rescue StandardError
      { 'ok' => false, 'code' => 'store_unreachable' }
    end
  end

  def blueprint_deny(code, bp = nil)
    r = { 'decision' => 'deny', 'code' => code }
    r['blueprint'] = bp if bp
    r
  end

  # The admitted hook: true admits; false or a raise does not (never fail open).
  def admitted_by?(hook, holder_key, bp)
    hook.call(holder_key, bp) == true
  rescue StandardError
    false
  end

  # chain: [{ 'issuer' =>, 'holder' => }], root first. mode: 'require' | 'any'. min_epoch: revocation_epoch of the newest fresh_at token shown.
  # admitted: optional ->(holder_key, record) for a blueprint with runtime_pins; absent while pinned: admission_required.
  def check_blueprints(chain, registry, now, mode, min_epoch = nil, admitted: nil)
    ok = chain.is_a?(Array) && !chain.empty? && chain.all? { |h| h.is_a?(Hash) && k3_str?(h['issuer'], 128) && k3_str?(h['holder'], 128) }
    return blueprint_deny('bad_input') unless ok && k3_int?(now)

    if min_epoch && registry.epoch < min_epoch
      return { 'decision' => 'escalate', 'code' => 'stale_blueprint_state', 'have' => registry.epoch, 'need' => min_epoch }
    end

    governed = []
    chain.each_with_index do |hop, i|
      bp = registry.get(hop['issuer'])
      next unless bp

      return blueprint_deny('broken_link', bp['id']) if i.zero? || chain[i - 1]['holder'] != bp['key']
      return blueprint_deny('blueprint_disabled', bp['id']) unless bp['status'] == 'active'
      return blueprint_deny('blueprint_expired', bp['id']) if bp.key?('expires_at') && now >= bp['expires_at']
      return blueprint_deny('too_deep', bp['id']) if bp.key?('max_depth') && chain.length - i > bp['max_depth']
      if bp.key?('runtime_pins')
        return blueprint_deny('admission_required', bp['id']) if admitted.nil?
        return blueprint_deny('not_admitted', bp['id']) unless admitted_by?(admitted, hop['holder'], bp)
      end
      return blueprint_deny('ceiling_unevaluable', bp['id']) unless bp['ceiling'].empty?

      governed << bp['id']
    end
    return blueprint_deny('no_blueprint') if governed.empty? && mode == 'require'

    { 'decision' => 'allow', 'governed' => governed }
  rescue StandardError
    blueprint_deny('store_unreachable')
  end
end
