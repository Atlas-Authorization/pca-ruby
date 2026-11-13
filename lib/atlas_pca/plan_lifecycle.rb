# frozen_string_literal: true

# Plan lifecycle (T10): explicit states around the plan commitment (the Merkle root an agent signs into every PCActn) and
# the principal's plan authorization.
#
#   draft --validate--> validated --commit--> committed --authorize--> authorized
#     |_____________________|_______________________|__________revoke______|--> revoked
#
#   draft       the nodes are recorded; the root is computed from them (never taken from the caller)
#   validated   the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed the
#               server's own validator
#   committed   the root is fixed. A committed plan is NOT executable: it still needs the principal
#   authorized  the principal approved this root for this grant, optionally until `expiresAt`
#   revoked     terminal; every later action against the root is denied
#
# "Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is authorized, the approval
# has not expired and its stored nodes still hash to the root. PlanRegistry#check adds the per-action rules a server applies
# immediately before execution: the node exists and the operation's verb, resource and params still match what the
# principal approved.
#
# Records and results are Hashes with String keys named as the reference names them (grantRef, createdAt, ...), so a registry
# on a shared store is interchangeable with the other implementations'. `AtlasPca.authorize(..., plans: registry)` feeds the
# stored plan and its executability into the verification context.
module AtlasPca
  PLAN_STATES = %w[draft validated committed authorized revoked].freeze

  module_function

  # The Merkle root of a plan's nodes (plan-node leaves; equals the TypeScript root). Raises on an unhashable plan.
  def plan_root(nodes)
    merkle_root(nodes.map { |n| plan_leaf(n['id'], n, conditions_digest(n['pre'], n['post'])) })
  end

  # Structural validity of a plan's nodes: the reason, or nil when valid.
  def plan_structural_problem(nodes)
    return 'a plan needs at least one node' unless nodes.is_a?(Array) && !nodes.empty?

    ids = {}
    nodes.each do |n|
      return 'every node needs an id' unless n.is_a?(Hash) && n['id'].is_a?(String) && n['id'] != ''
      return "duplicate node id '#{n['id']}'" if ids.key?(n['id'])

      ids[n['id']] = true
      unless n['verb'].is_a?(String) && n['verb'] != '' && n['resource'].is_a?(String) && n['resource'] != ''
        return "node '#{n['id']}' needs a verb and a resource"
      end
      if n.key?('reversibility_class') && !(n['reversibility_class'].is_a?(String) && CLASS_RANK.key?(n['reversibility_class']))
        return "node '#{n['id']}' has an unknown reversibility class '#{V2JS.js_str(n['reversibility_class'])}'"
      end
    end
    nil
  end

  # encodeURIComponent
  def plan_uri_component(s)
    s.b.gsub(/[^A-Za-z0-9\-_.!~*'()]/n) { |c| format('%%%02X', c.ord) }
  end

  # The plan registry. `kv` is an atomic key/value store (MemoryAtomicKv by default; SqliteAtomicKv for durable,
  # multi-process state). `now` is the clock, a callable returning epoch ms. `validator` is the server's validation, run by
  # #validate after the structural checks: ->(record) { {'ok' => true} | {'ok' => false, 'reason' => str} }; a raise refuses.
  class PlanRegistry
    def initialize(kv: nil, prefix: 'pca-plan:', now: nil, validator: nil)
      @kv = kv.nil? ? MemoryAtomicKv.new : kv
      @pre = prefix
      @clock = now || -> { (Time.now.to_f * 1000).to_i }
      @validator = validator
    end

    def get(grant_ref, root)
      v = @kv.get(key(grant_ref, root))
      record?(v) ? v : nil
    end

    # Record a draft plan for a grant. The root is computed from `nodes`. Re-drafting an existing root is refused.
    def draft(grant_ref, nodes)
      return { 'ok' => false, 'state' => 'unknown', 'reason' => 'a plan needs a grant' } unless grant_ref.is_a?(String) && grant_ref != ''

      # structural problems are reported by #validate (a draft can be inspected first); an unhashable plan has no root
      begin
        root = AtlasPca.plan_root(nodes)
      rescue StandardError => e
        return { 'ok' => false, 'state' => 'unknown', 'reason' => "the plan cannot be committed: merkleRoot: #{e.message}" }
      end
      rec = { 'grantRef' => grant_ref, 'root' => root, 'nodes' => MemoryAtomicKv.copy(nodes), 'state' => 'draft', 'createdAt' => @clock.call }
      out = { 'ok' => true, 'record' => rec }
      @kv.update(key(grant_ref, root)) do |prev|
        if record?(prev)
          out = { 'ok' => false, 'state' => prev['state'], 'reason' => "plan #{root} already exists (#{prev['state']})" }
          nil
        else
          rec
        end
      end
      out
    end

    # draft -> validated (structural checks, then the server's validator).
    def validate(grant_ref, root)
      cur = get(grant_ref, root)
      return unknown(root) if cur.nil?
      return { 'ok' => false, 'state' => cur['state'], 'reason' => "plan #{root} is #{cur['state']}: cannot validate" } unless cur['state'] == 'draft'

      problem = AtlasPca.plan_structural_problem(cur['nodes'])
      if problem.nil?
        same = begin
          AtlasPca.plan_root(cur['nodes']) == root
        rescue StandardError
          false
        end
        problem = 'the stored nodes no longer hash to the root' unless same
      end
      return { 'ok' => false, 'state' => cur['state'], 'reason' => "plan #{root} is invalid: #{problem}" } unless problem.nil?

      unless @validator.nil?
        v = begin
          @validator.call(MemoryAtomicKv.copy(cur))
        rescue StandardError => e
          { 'ok' => false, 'reason' => "validator error (fail closed): #{e.message}" }
        end
        unless v.is_a?(Hash) && v['ok'] == true
          why = v.is_a?(Hash) && v['ok'] == false && V2JS.truthy?(v['reason']) ? v['reason'] : 'refused by the validator'
          return { 'ok' => false, 'state' => cur['state'], 'reason' => "plan #{root} is invalid: #{why}" }
        end
      end
      move(grant_ref, root, %w[draft], 'validate') { |r| r.merge('state' => 'validated', 'validatedAt' => @clock.call) }
    end

    # validated -> committed: the root is fixed; it still needs the principal's authorization to execute.
    def commit(grant_ref, root)
      move(grant_ref, root, %w[validated], 'commit') { |r| r.merge('state' => 'committed', 'committedAt' => @clock.call) }
    end

    # committed -> authorized: the principal's approval (call it only after verifying the principal's consent).
    def authorize(grant_ref, root, approval)
      unless approval.is_a?(Hash) && approval['by'].is_a?(String) && approval['by'] != ''
        return { 'ok' => false, 'state' => state_of(grant_ref, root), 'reason' => 'an approval names who approved (`by`)' }
      end
      if approval.key?('expiresAt') && !finite_num?(approval['expiresAt'])
        return { 'ok' => false, 'state' => state_of(grant_ref, root), 'reason' => 'approval.expiresAt must be a time (epoch ms)' }
      end

      move(grant_ref, root, %w[committed], 'authorize') { |r| r.merge('state' => 'authorized', 'authorizedAt' => @clock.call, 'approval' => approval.dup) }
    end

    # Any state except revoked -> revoked (terminal).
    def revoke(grant_ref, root, reason)
      move(grant_ref, root, %w[draft validated committed authorized], 'revoke') do |r|
        r.merge('state' => 'revoked', 'revokedAt' => @clock.call, 'revokedReason' => reason.nil? ? '' : V2JS.js_str(reason))
      end
    end

    # The state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the root).
    def status(grant_ref, root, now = nil)
      now = @clock.call if now.nil?
      rec = get(grant_ref, root)
      return { 'state' => 'unknown', 'executable' => false, 'reason' => "plan #{root} is unknown for this grant" } if rec.nil?

      if rec['state'] != 'authorized'
        why = if rec['state'] == 'committed' then 'committed but not authorized by the principal'
              elsif rec['state'] == 'revoked' then "revoked (#{rec.key?('revokedReason') ? rec['revokedReason'] : 'no reason given'})"
              else "#{rec['state']}, not authorized"
              end
        return { 'state' => rec['state'], 'executable' => false, 'reason' => "plan #{root} is #{why}", 'record' => rec }
      end
      exp = (rec['approval'].is_a?(Hash) ? rec['approval'] : {})['expiresAt']
      if !exp.nil? && !(now < exp)
        return { 'state' => rec['state'], 'executable' => false, 'record' => rec,
                 'reason' => "plan #{root}: the principal's approval expired at #{V2JS.js_str(exp)}" }
      end
      same = begin
        AtlasPca.plan_root(rec['nodes']) == root
      rescue StandardError
        false
      end
      unless same
        return { 'state' => rec['state'], 'executable' => false, 'reason' => "plan #{root}: the stored nodes no longer hash to the root", 'record' => rec }
      end

      { 'state' => rec['state'], 'executable' => true, 'record' => rec }
    end

    # status plus the per-action staleness rules (the node exists, the operation matches it). Run it immediately before
    # execution. `operation` is {'verb', 'resource', 'params'}.
    def check(grant_ref, root, node_id: nil, operation: nil, now: nil)
      s = status(grant_ref, root, now)
      return s if !s['executable'] || !s.key?('record')
      return s if node_id.nil? && operation.nil?

      node = node_id.nil? ? nil : s['record']['nodes'].find { |n| n['id'] == node_id }
      return s.merge('executable' => false, 'reason' => "plan #{root} has no node '#{node_id}'") if !node_id.nil? && node.nil?

      unless operation.nil?
        candidates = node.nil? ? s['record']['nodes'] : [node]
        digest = begin
          AtlasPca.params_digest(operation['params'])
        rescue StandardError
          return s.merge('executable' => false, 'reason' => "plan #{root}: the operation's params cannot be hashed")
        end
        same = candidates.any? do |n|
          n['verb'] == operation['verb'] && n['resource'] == operation['resource'] &&
            (n['params_digest'].nil? ? AtlasPca.params_digest(nil) : n['params_digest']) == digest
        end
        unless same
          return s.merge('executable' => false,
                         'reason' => "plan #{root}: the operation (#{operation['verb']} on #{operation['resource']} with these params) " \
                                     'is not what the principal approved')
        end
      end
      s
    end

    # True only when the plan is executable now (for hooks that take a yes / no).
    def plan_authorized?(grant_ref, plan_root_)
      status(grant_ref, plan_root_)['executable'] == true
    rescue StandardError
      false
    end

    # The verifier context for an action against `root`: {'plan', 'planAuthorized', 'status'}; nil: unknown root.
    def context(grant_ref, root, now = nil)
      s = status(grant_ref, root, now)
      return nil unless s.key?('record')

      { 'plan' => MemoryAtomicKv.copy(s['record']['nodes']), 'planAuthorized' => s['executable'], 'status' => s }
    end

    private

    def key(grant_ref, root)
      "#{@pre}#{AtlasPca.plan_uri_component(grant_ref)}:#{root}"
    end

    def record?(v)
      v.is_a?(Hash) && v['root'].is_a?(String) && v['nodes'].is_a?(Array)
    end

    def finite_num?(v)
      (v.is_a?(Integer) || v.is_a?(Float)) && v.to_f.finite?
    end

    def unknown(root)
      { 'ok' => false, 'state' => 'unknown', 'reason' => "plan #{root} is unknown for this grant" }
    end

    def state_of(grant_ref, root)
      r = get(grant_ref, root)
      r.nil? ? 'unknown' : r['state']
    end

    # Atomically move `from` -> the block's record.
    def move(grant_ref, root, from, to)
      out = unknown(root)
      @kv.update(key(grant_ref, root)) do |prev|
        next nil unless record?(prev)

        unless from.include?(prev['state'])
          out = { 'ok' => false, 'state' => prev['state'], 'reason' => "plan #{root} is #{prev['state']}: cannot #{to}" }
          next nil
        end
        rec = yield(prev)
        out = { 'ok' => true, 'record' => rec }
        rec
      end
      out
    end
  end

  def create_plan_registry(**kw)
    PlanRegistry.new(**kw)
  end
end
