# frozen_string_literal: true

# Typed missing context and the stored-wins merge (packages/pca/src/missing-context.ts). A condition that cannot be decided because a
# value is absent names what is missing and who may supply it; a request-supplied value never replaces a bound one. Total.
# Replays packages/pca/conformance/missing-context-vectors.json. Hashes use String keys.
module AtlasPca
  SUPPLIERS = %w[principal discharge_issuer rs_observation agent_declared_untrusted].freeze
  MC_FORBIDDEN = %w[__proto__ constructor prototype].freeze
  MC_PATH_RE = /\A(action\.params|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)*\z/

  module_function

  # Longest matching prefix (at a segment boundary) wins; a path matching nothing is `principal`.
  def supplier_of(path, table)
    best = nil
    table.each_key { |k| best = k if (path == k || path.start_with?("#{k}.")) && (best.nil? || k.length > best.length) }
    best.nil? ? 'principal' : table[best]
  end

  def supplier_table_error(t)
    return 'the supplier table must be an object' unless t.is_a?(Hash)

    t.each do |k, v|
      return "bad supplier path '#{k}'" if !k.is_a?(String) || !k.match?(MC_PATH_RE) || k.split('.').any? { |s| MC_FORBIDDEN.include?(s) }
      return "bad supplier for '#{k}'" unless v.is_a?(String) && SUPPLIERS.include?(v)
    end
    nil
  end

  def mc_leaves(v, prefix, out, depth = 0)
    if depth > 16
      out[prefix] = v
    elsif v.is_a?(Hash) && !v.empty?
      v.keys.sort.each { |k| mc_leaves(v[k], "#{prefix}.#{k}", out, depth + 1) unless MC_FORBIDDEN.include?(k) }
    else
      out[prefix] = v
    end
  end

  def mc_set_path(root, segs, value)
    cur = root
    segs[0...-1].each do |s|
      cur[s] = {} unless cur[s].is_a?(Hash)
      cur = cur[s]
    end
    cur[segs[-1]] = value
  end

  def mc_clone(v) = Marshal.load(Marshal.dump(v))

  # -> { 'context' =>, 'conflicts' => [], 'dropped' => [] }. Bound wins; see the TypeScript module comment.
  def bind_context(bound, supplied, table = {})
    ctx = mc_clone(bound)
    conflicts = []
    dropped = []
    return { 'context' => ctx, 'conflicts' => conflicts, 'dropped' => dropped } unless supplied.is_a?(Hash) && ctx.is_a?(Hash)

    flat = {}
    mc_leaves(supplied['action']['params'], 'action.params', flat) if supplied['action'].is_a?(Hash) && supplied['action']['params'].is_a?(Hash)
    mc_leaves(supplied['subject'], 'subject', flat) if supplied['subject'].is_a?(Hash)
    mc_leaves(supplied['env'], 'env', flat) if supplied['env'].is_a?(Hash)
    flat.keys.sort.each do |path|
      value = flat[path]
      if supplier_of(path, table) == 'agent_declared_untrusted'
        dropped << path
        next
      end
      r = resolve_path(ctx, path)
      if r['found']
        conflicts << path if hash_canonical({ 'v' => r['value'] }) != hash_canonical({ 'v' => value })
        next
      end
      segs = path.split('.')
      # a bound leaf above the supplied path: writing it would replace the bound value
      blocked = (2...segs.length).any? do |i|
        r2 = resolve_path(ctx, segs[0...i].join('.'))
        r2['found'] && !r2['value'].is_a?(Hash)
      end
      if blocked
        conflicts << path
        next
      end
      if path.start_with?('action.params')
        a = ctx['action'].nil? ? { 'verb' => '', 'resource' => '' } : ctx['action']
        if a.is_a?(Hash)
          a['params'] = {} unless a['params'].is_a?(Hash)
          ctx['action'] = a
        end
      end
      mc_set_path(ctx, segs, mc_clone(value))
    end
    { 'context' => ctx, 'conflicts' => conflicts, 'dropped' => dropped }
  end

  def mc_collect(c, ctx, out, ill, depth = 0)
    if depth > 64 || !c.is_a?(Hash)
      ill[:v] = true
      return
    end
    if group_condition?(c)
      kids = c.key?('all_of') ? c['all_of'] : c.key?('any_of') ? c['any_of'] : [c['not']]
      if !kids.is_a?(Array) || kids.empty?
        ill[:v] = true
        return
      end
      kids.each { |k| mc_collect(k, ctx, out, ill, depth + 1) }
      return
    end
    return unless evaluate_condition_tri(c, ctx) == 'unknown'

    absent = false
    [c['field'], c['ref']].each do |p|
      next unless p.is_a?(String) && !p.empty? && !resolve_path(ctx, p)['found']

      out << p
      absent = true
    end
    f = c['field']
    if f == 'action.params' || (f.is_a?(String) && f.start_with?('action.params.'))
      p = ctx.is_a?(Hash) && ctx['action'].is_a?(Hash) ? ctx['action']['params'] : nil
      unless p.is_a?(Hash) || p.is_a?(Array)
        out << f
        absent = true
      end
    end
    ill[:v] = true unless absent
  end

  # -> { 'decision' =>, 'reason' => (absent for allow), 'missing' => [{ 'path', 'supplier' }] }
  def decide_with_missing(where, bound, supplied = nil, suppliers = nil)
    deny = ->(reason, missing = []) { { 'decision' => 'deny', 'reason' => reason, 'missing' => missing } }
    return deny.call('bad_context') unless bound.is_a?(Hash) && bound['action'].is_a?(Hash)

    table = suppliers.nil? ? {} : suppliers
    te = supplier_table_error(table)
    return deny.call("bad supplier table: #{te}") if te
    return deny.call('condition_false') unless where.is_a?(Array) && !where.empty?

    b = bind_context(bound, supplied, table)
    return deny.call("context_shadow: #{b['conflicts'].join(',')}") unless b['conflicts'].empty?

    t = evaluate_condition_tri({ 'all_of' => where }, b['context'])
    return { 'decision' => 'allow', 'missing' => [] } if t == 'true'
    return deny.call('condition_false') if t == 'false'

    paths = []
    ill = { v: false }
    where.each { |c| mc_collect(c, b['context'], paths, ill) }
    paths = paths.uniq.sort
    return deny.call('ill_typed_context') if paths.empty? || ill[:v]

    missing = paths.map { |p| { 'path' => p, 'supplier' => supplier_of(p, table) } }
    untrusted = missing.select { |m| m['supplier'] == 'agent_declared_untrusted' }
    return deny.call("missing_context_untrusted: #{untrusted.map { |m| m['path'] }.join(',')}", missing) unless untrusted.empty?

    { 'decision' => 'escalate', 'reason' => "escalate: missing_context #{missing.map { |m| "#{m['supplier']}:#{m['path']}" }.join(',')}", 'missing' => missing }
  rescue StandardError, SystemStackError
    { 'decision' => 'deny', 'reason' => 'evaluation error (fail closed)', 'missing' => [] }
  end
end
