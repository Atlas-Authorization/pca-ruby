# frozen_string_literal: true

# e08: PCA 0.5 hardening P3 flip: a guard / AuthorizeOptions with no plan configured denies `plan_root_authorized` (as TS
# authorize()/requireAuthorized); 'single-step' is a host's explicit choice, and protect() keeps it. Reuses the C06 helpers.

module MutationKill
  t('e08 P3: AuthorizeOptions has no default plan; a bare guard denies plan_root_authorized unless single-step is set') do
    f = ENV['MUT_FILE']
    next true unless f.nil? || f.empty? || %w[authorize.rb protect.rb].include?(f)

    o = AtlasPca::AuthorizeOptions
    bare = o.new(state_store: AtlasPca::MemoryStateStore.new)
    explicit = o.new(state_store: AtlasPca::MemoryStateStore.new, plan: 'single-step')
    raise "default plan: #{bare.plan.inspect}" unless bare.plan.nil?
    raise "explicit plan: #{explicit.plan.inspect}" unless explicit.plan == 'single-step'

    denied = C06.go(plan: bare.plan)
    allowed = C06.go(plan: explicit.plan)
    raise "bare: #{[denied.allow, denied.checks['plan_root_authorized']].inspect}" unless [denied.allow, denied.checks['plan_root_authorized']] == [false, 'fail']
    raise "explicit: #{[allowed.allow, allowed.checks['plan_root_authorized']].inspect}" unless [allowed.allow, allowed.checks['plan_root_authorized']] == [true, 'pass']
    raise 'reason' unless denied.reasons.any? { |x| x.start_with?('plan_root_authorized: default-deny: no authorized plan is configured') }

    true
  end
end
