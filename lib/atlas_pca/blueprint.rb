# frozen_string_literal: true

# Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop
# issued by that key. BlueprintRegistry keeps the newest record per key (pinned operators, a strictly higher epoch replaces, the
# same epoch with different content is a fork). A non-empty ceiling is never evaluated here: it denies (ceiling_unevaluable).
# Every function is total. Hashes use String keys.
module AtlasPca
  AGENT_BLUEPRINT_DOMAIN = "atlas-pca/agent-blueprint/v1\x00".b.freeze
  BLUEPRINT_BODY_KEYS = %w[v id key ceiling max_depth expires_at epoch status issued_at operator].freeze

  module_function

  def blueprint_well_formed?(b)
    return false unless b.is_a?(Hash) && b['v'] == 1 && b['v'].is_a?(Integer)
    return false unless k3_str?(b['id'], 128) && k3_str?(b['key'], 128) && k3_str?(b['operator'], 128)
    return false unless k3_int?(b['epoch']) && k3_int?(b['issued_at']) && %w[active disabled].include?(b['status'])
    return false if b.key?('max_depth') && !(k3_int?(b['max_depth']) && b['max_depth'] >= 1)
    return false if b.key?('expires_at') && !k3_int?(b['expires_at'])

    c = b['ceiling']
    c.is_a?(Array) && c.length <= 32 && c.all? { |x| x.is_a?(Hash) && x['type'].is_a?(String) }
  end

  def verify_blueprint(b)
    return false unless blueprint_well_formed?(b)

    body = BLUEPRINT_BODY_KEYS.each_with_object({}) { |k, h| h[k] = b[k] if b.key?(k) }
    k3_verify_body(AGENT_BLUEPRINT_DOMAIN, body, b['operator'], b['sig'])
  end

  class BlueprintRegistry
    attr_reader :store

    def initialize(operators)
      @operators = operators
      @store = {}
    end

    # { 'ok' => true, 'replaced' => bool } or { 'ok' => false, 'code' => ... }
    def accept(b)
      return { 'ok' => false, 'code' => 'bad_record' } unless AtlasPca.verify_blueprint(b)
      return { 'ok' => false, 'code' => 'unknown_operator' } unless @operators.include?(b['operator'])

      cur = @store[b['key']]
      if cur
        return { 'ok' => false, 'code' => 'operator_changed' } if cur['operator'] != b['operator']
        return { 'ok' => false, 'code' => 'stale_epoch' } if b['epoch'] < cur['epoch']
        if b['epoch'] == cur['epoch']
          return cur['sig'] == b['sig'] ? { 'ok' => true, 'replaced' => false } : { 'ok' => false, 'code' => 'epoch_fork' }
        end
      end
      @store[b['key']] = b
      { 'ok' => true, 'replaced' => true }
    end

    def epoch
      @store.values.map { |r| r['epoch'] }.max || 0
    end
  end

  def blueprint_deny(code, bp = nil)
    r = { 'decision' => 'deny', 'code' => code }
    r['blueprint'] = bp if bp
    r
  end

  # chain: [{ 'issuer' =>, 'holder' => }], root first. mode: 'require' | 'any'. min_epoch: revocation_epoch of the newest fresh_at token shown.
  def check_blueprints(chain, registry, now, mode, min_epoch = nil)
    ok = chain.is_a?(Array) && !chain.empty? && chain.all? { |h| h.is_a?(Hash) && k3_str?(h['issuer'], 128) && k3_str?(h['holder'], 128) }
    return blueprint_deny('bad_input') unless ok && k3_int?(now)

    if min_epoch && registry.epoch < min_epoch
      return { 'decision' => 'escalate', 'code' => 'stale_blueprint_state', 'have' => registry.epoch, 'need' => min_epoch }
    end

    governed = []
    chain.each_with_index do |hop, i|
      bp = registry.store[hop['issuer']]
      next unless bp

      return blueprint_deny('broken_link', bp['id']) if i.zero? || chain[i - 1]['holder'] != bp['key']
      return blueprint_deny('blueprint_disabled', bp['id']) unless bp['status'] == 'active'
      return blueprint_deny('blueprint_expired', bp['id']) if bp.key?('expires_at') && now >= bp['expires_at']
      return blueprint_deny('too_deep', bp['id']) if bp.key?('max_depth') && chain.length - i > bp['max_depth']
      return blueprint_deny('ceiling_unevaluable', bp['id']) unless bp['ceiling'].empty?

      governed << bp['id']
    end
    return blueprint_deny('no_blueprint') if governed.empty? && mode == 'require'

    { 'decision' => 'allow', 'governed' => governed }
  rescue StandardError
    blueprint_deny('store_unreachable')
  end
end
