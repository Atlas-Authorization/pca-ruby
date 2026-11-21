# frozen_string_literal: true

module AtlasPca
  # Policy templates and a fluent authoring builder (the reference's `policy-templates`). A request maps onto a named ROLE template
  # (read-only, support agent, finance bot, dev assistant) or is composed with the typed builder; both compile through
  # `compile_policy`, so what you author is exactly what the verifier enforces. Pure.
  POLICY_TEMPLATES = {
    'read-only' => { 'name' => 'read-only', 'description' => 'Read access only — no side effects anywhere.',
                     'permissions' => { 'github' => ['read'], 'slack' => ['read'], 'files' => ['read'], 'http' => ['get'] } },
    'support-agent' => { 'name' => 'support-agent', 'description' => 'Draft + send customer email and post to Slack, rate-limited.',
                         'permissions' => { 'gmail' => %w[draft send], 'slack' => ['post_message'] },
                         'limits' => { 'send' => '50/day', 'post_message' => '100/day' } },
    'finance-bot' => { 'name' => 'finance-bot', 'description' => 'Issue reversible refunds within a daily cap; no payouts.',
                       'permissions' => { 'stripe' => ['refund'] }, 'limits' => { 'refund' => '$500/day' } },
    'dev-assistant' => { 'name' => 'dev-assistant', 'description' => 'Read repos, open PRs and comment — never merge or delete.',
                         'permissions' => { 'github' => %w[read create_pr comment] }, 'limits' => { 'create_pr' => '20/day' } }
  }.freeze

  # A typed, chainable policy builder: `AtlasPca.policy.allow('stripe', ['refund']).limit('refund', '$500/day').build`.
  class PolicyBuilder
    def initialize
      @perms = {}
      @lims = {}
      @risk = nil
    end

    # Start from a named template (its permissions / limits / risk seed the builder).
    def self.from(name)
      t = name.is_a?(String) ? POLICY_TEMPLATES[name] : nil
      raise ArgumentError, "PolicyBuilder.from: unknown template '#{name}'" if t.nil?

      b = new
      t['permissions'].each { |c, acts| b.allow(c, acts) }
      (t['limits'] || {}).each { |k, v| b.limit(k, v) }
      b.risk(t['riskPolicy']) if t['riskPolicy']
      b
    end

    def allow(connector, actions)
      @perms[connector] = (@perms.fetch(connector, []) + actions).uniq
      self
    end

    def limit(verb_or_action, spec)
      @lims[verb_or_action] = spec
      self
    end

    def risk(partial)
      @risk = (@risk || {}).merge(partial)
      self
    end

    # {'permissions', 'limits', 'riskPolicy'?}; raises when nothing was allowed.
    def build
      raise ArgumentError, 'PolicyBuilder: no permissions added' if @perms.empty?

      out = { 'permissions' => Marshal.load(Marshal.dump(@perms)), 'limits' => Marshal.load(Marshal.dump(@lims)) }
      out['riskPolicy'] = @risk.dup if @risk
      out
    end

    # Mint an agent directly from the built policy.
    def agent(principal:, goal:, aud: nil, holder: nil, now: nil)
      b = build
      AtlasPca.create_agent(principal: principal, goal: goal, permissions: b['permissions'], limits: b['limits'], risk_policy: b['riskPolicy'],
                            aud: aud, holder: holder, now: now)
    end
  end

  module_function

  # The built-in role templates, in definition order.
  def list_templates = POLICY_TEMPLATES.values

  # Mint an agent from a named template. `overrides` ({'permissions','limits','riskPolicy','agentBinding','budgetModel'}) narrows or
  # extends it before minting. Raises on an unknown template.
  def from_template(name, principal:, goal:, aud: nil, holder: nil, now: nil, overrides: nil)
    t = name.is_a?(String) ? POLICY_TEMPLATES[name] : nil
    raise ArgumentError, "fromTemplate: unknown template '#{name}' (have: #{POLICY_TEMPLATES.keys.join(', ')})" if t.nil?

    o = overrides || {}
    create_agent(principal: principal, goal: goal, permissions: o['permissions'] || t['permissions'], limits: o['limits'] || t['limits'],
                 risk_policy: o['riskPolicy'] || t['riskPolicy'], agent_binding: o['agentBinding'], budget_model: o['budgetModel'],
                 aud: aud, holder: holder, now: now)
  end

  # Entry point for the fluent builder.
  def policy = PolicyBuilder.new
end
