# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_learner'
require_relative 'intent_v2'

# The outcome space derived from a site's signed action schema: dimensions only for parameters whose effective sensitivity (after
# the wallet floor) is material or critical, canonical projections for boolean / set / array parameters, and default sets for silent
# parameters. Native port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentSchema
    WALLET_FLOOR_PREFIXES = %w[money. party. contact. person. credential.].freeze
    WALLET_FLOOR_EXACT = ['text.message'].freeze
    REV = %w[reversible rate_limited irreversible].freeze

    module_function

    def utf8(s) = s.b

    def floor_applies?(semantic, floor)
      floor ||= {}
      pre = floor['prefixes'].nil? ? WALLET_FLOOR_PREFIXES : floor['prefixes']
      ex = floor['exact'].nil? ? WALLET_FLOOR_EXACT : floor['exact']
      ex.include?(semantic) || pre.any? { |p| semantic.start_with?(p) }
    end

    # A site `free` on a floored semantic type becomes `material`.
    def effective_sensitivity(d, floor = nil) = d['sensitivity'] == 'free' && floor_applies?(d['semantic'], floor) ? 'material' : d['sensitivity']

    # rev(v) = max over outcomes of the declared reversibility (the conservative projection).
    def verb_reversibility(v)
      rb = v['reversibility_by']
      unless IntentLearner.truthy(rb)
        return v['reversibility'] if IntentLearner.truthy(v['reversibility'])

        return v['kind'] == 'read' ? 'reversible' : 'irreversible'
      end
      d = v['params'][rb['param']]
      mapped = rb['map'].values
      dtype = d ? d['type'] : nil
      domain = if dtype == 'boolean' then %w[true false]
               elsif dtype == 'string' && IntentLearner.truthy(d['values']) then d['values']
               end
      covered = !domain.nil? && domain.all? { |x| rb['map'].key?(x) }
      items = covered ? mapped : mapped + [IntentLearner.truthy(rb['default']) ? rb['default'] : 'irreversible']
      return 'reversible' if items.empty?

      best = items[0]
      items.each { |r| best = r if (REV.index(r) || -1) > (REV.index(best) || -1) }
      best
    end

    # Every override the wallet floor makes on a schema.
    def wallet_floor_overrides(doc, floor = nil)
      out = []
      doc['verbs'].each do |v|
        v['params'].keys.sort_by { |k| utf8(k) }.each do |path|
          d = v['params'][path]
          eff = effective_sensitivity(d, floor)
          out << { 'verb' => v['verb'], 'path' => path, 'semantic' => d['semantic'], 'declared' => d['sensitivity'], 'effective' => eff } if eff != d['sensitivity']
        end
      end
      out
    end

    def canon_path(param_path) = "env.canon.#{param_path['action.params.'.length..]}"
    def uses_canon?(d) = %w[boolean set array].include?(d['type'])

    # The canonical text a value of a canon-projected parameter has.
    def canon_value(d, x)
      return x.equal?(true) ? 'true' : 'false' if d['type'] == 'boolean'
      return strict_text(x.sort_by { |v| utf8(v) }) if d['type'] == 'set'

      strict_text(x)
    end

    def strict_text(v) = AtlasPca.strict_bytes(v).force_encoding('UTF-8')

    def safe_int_num?(x) = IntentOmega.number?(x) && (x.is_a?(Integer) || (x.finite? && x == x.floor)) && x.abs <= 9_007_199_254_740_991

    # Derive the schema outcome space: {omega, overrides, defaults, canonOf}.
    def derive_omega_from_schema(o)
      schema_verbs = o['schema']['verbs']
      slots = o['slots']
      verb_names = if !o['verbs'].nil?
                     o['verbs'].dup
                   else
                     (schema_verbs.select { |v| v['kind'] == 'write' }.map { |v| v['verb'] } + ((slots || {})['verbs'] || [])).uniq
                   end
      base = IntentOmega.derive_omega({ 'policies' => o['policies'] || [], 'slots' => slots, 'extraVerbs' => verb_names })
      defaults = []
      canon_of = {}
      verbs = []
      confirmed = o['confirmed'] || {}
      floor = o['floor']
      verb_names.sort_by { |s| utf8(s) }.each do |verb|
        decl = schema_verbs.find { |v| v['verb'] == verb }
        next if decl.nil?

        lits = base['verbs'].find { |v| v['verb'] == verb }
        dims = (lits ? lits['dims'] : []).reject { |d| d['path'].start_with?('action.params.') }
        decl['params'].keys.sort_by { |k| utf8(k) }.each do |path|
          pd = decl['params'][path]
          next if effective_sensitivity(pd, floor) == 'free'

          lit = lits ? lits['dims'].find { |d| d['path'] == path } : nil
          silent = lit.nil?
          conf = (confirmed[path] || []).dup
          neutral = pd['principal_neutral_default'] == true && pd.key?('default') ? [pd['default']] : []
          default_set = conf + neutral
          if pd['type'] == 'integer'
            cuts = !lit.nil? && lit['kind'] == 'num' ? lit['cuts'].dup : []
            default_set.each { |x| cuts << x.to_i if safe_int_num?(x) && !cuts.include?(x) }
            srt = cuts.uniq.sort
            max_cut = srt.empty? ? 0 : srt[-1]
            dom = (o['domains'] || {})[path]
            lo = if dom && !dom['lo'].nil? then dom['lo']
                 elsif !pd['min'].nil? then pd['min']
                 else [0, srt.empty? ? 0 : srt[0] - 1].min
                 end
            hi = if dom && !dom['hi'].nil? then dom['hi']
                 elsif !pd['max'].nil? then pd['max']
                 else [10, 2 * max_cut, max_cut + 10].max
                 end
            dims << { 'kind' => 'num', 'path' => path, 'lo' => lo, 'hi' => hi, 'cuts' => srt.select { |c| lo <= c && c <= hi },
                      'dist' => lo >= 0 ? 'loguniform' : 'uniform' }
            nums = default_set.select { |x| IntentOmega.number?(x) }
            defaults << { 'verb' => verb, 'path' => path, 'min' => nums[0], 'max' => nums[0] } if silent && nums.length == 1
            next
          end
          canon = uses_canon?(pd)
          dim_path = canon ? canon_path(path) : path
          canon_of[dim_path] = path if canon
          exacts = {}
          prefixes = {}
          if !lit.nil? && lit['kind'] == 'cat'
            lit['values'].each do |v|
              if v['kind'] == 'exact' then exacts[v['value']] = nil
              elsif v['kind'] == 'prefix' then prefixes[v['value']] = nil
              end
            end
          end
          (pd['values'] || []).each { |v| exacts[v] = nil } if pd['type'] == 'string' && IntentLearner.truthy(pd['values'])
          if pd['type'] == 'boolean'
            exacts['false'] = nil
            exacts['true'] = nil
          end
          def_texts = default_set.map { |x| canon ? canon_value(pd, x) : V2JS.js_str(x) }
          def_texts.each { |t| exacts[t] = nil }
          values = exacts.keys.sort_by { |s| utf8(s) }.map { |v| { 'kind' => 'exact', 'value' => v } }
          values += prefixes.keys.sort_by { |s| utf8(s) }.map { |v| { 'kind' => 'prefix', 'value' => v } }
          values << { 'kind' => 'other', 'value' => IntentOmega::OTHER }
          dims << { 'kind' => 'cat', 'path' => dim_path, 'values' => values }
          defaults << { 'verb' => verb, 'path' => dim_path, 'oneOf' => def_texts.uniq.sort_by { |s| utf8(s) } } if silent && !def_texts.empty?
        end
        dims = dims.sort_by { |d| utf8(d['path']) }
        verbs << { 'verb' => verb, 'reversibility' => verb_reversibility(decl), 'weight' => 0, 'dims' => dims }
      end
      verbs.each { |v| v['weight'] = 1.0 / (verbs.empty? ? 1 : verbs.length) }
      overrides = wallet_floor_overrides({ 'verbs' => schema_verbs.select { |v| verb_names.include?(v['verb']) } }, floor)
      { 'omega' => { 'v' => 1, 'verbs' => verbs, 'approximate' => base['approximate'] }, 'overrides' => overrides, 'defaults' => defaults, 'canonOf' => canon_of }
    end
  end
end
