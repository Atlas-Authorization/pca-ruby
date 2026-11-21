# frozen_string_literal: true

require_relative 'intent_omega'

# Outcome-space dimensions filled by the verifier: world facts (env.world.*), provenance (env.prov.*) and attested classifier
# labels (env.class.*). Every helper only adds a dimension, which refines the space. Native port of the TypeScript reference
# (@atlasauth/pca-intent).
module AtlasPca
  module IntentWorld
    WORLD_PREFIX = 'env.world.'
    PROV_PREFIX = 'env.prov.'
    CLASS_PREFIX = 'env.class.'
    MISSING = Object.new.freeze
    INDEX_RE = /\A(?:0|[1-9][0-9]*)\z/

    module_function

    # A numeric world dimension env.world.<name> with the given domain and cuts.
    def world_dim(name, o)
      cuts = []
      (o['cuts'] || []).each { |c| cuts << c unless cuts.include?(c) }
      cuts = cuts.select { |c| o['lo'] <= c && c <= o['hi'] }.sort
      dist = o['dist']
      { 'kind' => 'num', 'path' => WORLD_PREFIX + name, 'lo' => o['lo'], 'hi' => o['hi'], 'cuts' => cuts, 'dist' => dist.nil? ? 'uniform' : dist }
    end

    # The optimality dimension: excess >= 0, cuts at 0 and at every slack literal.
    def excess_dim(name, hi, slacks = nil) = world_dim(name, { 'lo' => 0, 'hi' => hi, 'cuts' => [0] + (slacks || []), 'dist' => 'loguniform' })

    # The default slot compiler's optimality constraint: excess <= slack.
    def optimality_condition(name, slack = 0) = { 'field' => WORLD_PREFIX + name, 'op' => 'lte', 'value' => slack }

    # env.prov.<path> with the cells {first_party}, {trusted} and the OTHER cell = the tainted values.
    def provenance_dim(param_path)
      { 'kind' => 'cat', 'path' => PROV_PREFIX + param_path,
        'values' => [{ 'kind' => 'exact', 'value' => 'first_party' }, { 'kind' => 'exact', 'value' => 'trusted' }, { 'kind' => 'other', 'value' => IntentOmega::OTHER }] }
    end

    # env.class.<id> over the classifier's closed label set (the OTHER cell is never output).
    def classifier_dim(id, labels)
      uniq = labels.uniq.sort_by(&:b)
      { 'kind' => 'cat', 'path' => CLASS_PREFIX + id, 'values' => uniq.map { |v| { 'kind' => 'exact', 'value' => v } } + [{ 'kind' => 'other', 'value' => IntentOmega::OTHER }] }
    end

    # A copy of the space with dims added to verb (dimensions kept sorted by path).
    def with_dims(omega, verb, dims)
      verbs = omega['verbs'].map do |vs|
        next vs.merge('dims' => vs['dims'].dup) if vs['verb'] != verb

        have = vs['dims'].map { |d| d['path'] }
        dims.each { |d| raise ArgumentError, "withDims: #{verb} already has a dimension #{d['path']}" if have.include?(d['path']) }
        vs.merge('dims' => (vs['dims'] + dims).sort_by { |d| IntentOmega.u16key(d['path']) })
      end
      raise ArgumentError, "withDims: no verb #{verb} in Ω" unless verbs.any? { |v| v['verb'] == verb }

      omega.merge('verbs' => verbs)
    end

    def get(root, segs)
      cur = root
      segs.each do |s|
        if cur.is_a?(Hash) && cur.key?(s)
          cur = cur[s]
        elsif cur.is_a?(Array) && s.match?(INDEX_RE) && s.to_i < cur.length
          cur = cur[s.to_i]
        else
          return MISSING
        end
      end
      cur
    end

    # Lift a concrete outcome with the verifier-computed env: fill every world / prov / class dimension path from it. A provenance
    # dimension with no computed label is `agent` (fail closed: the tainted cell).
    def lift_outcome(o, env, dim_paths)
      values = o['values'].dup
      world = env['world']
      prov = env['prov']
      cls = env['class']
      dim_paths.each do |p|
        if p.start_with?(WORLD_PREFIX)
          v = get(world, [p[WORLD_PREFIX.length..]])
          values[p] = v if IntentOmega.number?(v) || v.is_a?(String)
        elsif p.start_with?(PROV_PREFIX)
          rest = p[PROV_PREFIX.length..]
          v = get(prov, rest.empty? ? [''] : rest.split('.', -1))
          values[p] = v.is_a?(String) ? v : 'agent'
        elsif p.start_with?(CLASS_PREFIX)
          v = get(cls, [p[CLASS_PREFIX.length..]])
          values[p] = v if v.is_a?(String)
        end
      end
      { 'verb' => o['verb'], 'values' => values }
    end
  end
end
