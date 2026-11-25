# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_policy'
require_relative 'intent_slots'
require_relative 'intent_v2'
require_relative 'predicates'
require_relative 'catalog_builtin'

# Deterministic plain-language rendering and the back-translation diff. Every sentence is a fixed template over the grant's own data
# (no language model anywhere); anything the templates do not know is rendered as an explicit "not understood" line. Native port of
# the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentRender
    UNDEF = V2JS::UNDEF
    OPS = {
      'eq' => '%s is %s', 'ne' => '%s is not %s', 'in' => '%s is one of %s', 'nin' => '%s is none of %s', 'lt' => '%s is less than %s',
      'lte' => '%s is at most %s', 'gt' => '%s is more than %s', 'gte' => '%s is at least %s', 'prefix' => '%s starts with %s',
      'like' => '%s matches the pattern %s', 'matches' => '%s matches the regular expression %s', 'is_a' => '%s is of type %s',
      'member_of' => '%s belongs to %s'
    }.freeze
    UNREADABLE = 'an unreadable condition (not understood)'
    NUM_RE = /\A[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?\z/

    module_function

    def js(v) = V2JS.js_str(v)

    # The analyzer's catalog lookup: a spec of the verb, the last one of a list, nil when absent.
    def cat_get(catalog, verb)
      catalog = BUILTIN_ACTIONS if catalog.nil? || catalog.equal?(UNDEF)
      return catalog.get(verb) if catalog.respond_to?(:get)
      return catalog[verb] if catalog.is_a?(Hash)

      found = nil
      catalog.each { |a| found = a if a.is_a?(Hash) && a['verb'] == verb }
      found
    end

    # o.k of a JSON value: undefined for a non-object, a TypeError for null (as the reference).
    def g(o, k)
      raise TypeError, "cannot read properties of null (reading '#{k}')" if o.nil?

      o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    end

    def label_of(path)
      return 'resource' if path == 'action.resource'

      path.rpartition('.')[2].tr('_', ' ')
    end

    def fmt(v)
      return "\"#{v}\"" if v.is_a?(String)
      return v.map { |x| fmt(x) }.join(', ') if v.is_a?(Array)

      js(v)
    end

    def arr(x)
      return [] if x.nil? || x.equal?(UNDEF)
      raise TypeError, 'map is not a function' unless x.is_a?(Array)

      x
    end

    def render_condition(c)
      return UNREADABLE unless c.is_a?(Hash)

      if Predicates.group?(c)
        return "all of: #{arr(c['all_of']).map { |x| "(#{render_condition(x)})" }.join(' and ')}" if c.key?('all_of')
        return "either #{arr(c['any_of']).map { |x| "(#{render_condition(x)})" }.join(' or ')}" if c.key?('any_of')

        return "it is not the case that #{render_condition(c.key?('not') ? c['not'] : UNDEF)}"
      end
      return UNREADABLE unless Predicates.leaf?(c)

      l = "the #{label_of(c['field'])}"
      v = c.key?('ref') ? "the #{label_of(c['ref'])}" : fmt(c.key?('value') ? c['value'] : UNDEF)
      op = c.key?('op') ? c['op'] : UNDEF
      return format(OPS[op], l, v) if op.is_a?(String) && OPS.key?(op)
      return (c.key?('value') && c['value'] == false ? "#{l} is absent" : "#{l} is present") if op == 'exists'

      "#{l} has an unrecognised test \"#{js(op)}\" (not understood)"
    end

    def render_resource(r)
      return 'on any resource' if r.equal?(UNDEF) || (r.is_a?(String) && r == '*')
      return 'on an unreadable resource matcher (not understood)' unless r.is_a?(String)
      return "on resources matching the regular expression \"#{r[3..]}\"" if r.start_with?('re:')
      return "on resources under \"#{r[0...-1]}\"" if r.end_with?('*')

      "only on resource \"#{r}\""
    end

    def lower_first(s) = !s.empty? && s[0] != "\n" ? s[0].downcase + s[1..] : s

    def desc(s)
      d = s['description']
      d.end_with?('.') ? d[0...-1] : d
    end

    def render_verb(v, catalog)
      one = lambda do |x|
        return 'ANY action of any connector' if x == '*'

        s = cat_get(catalog, x)
        next "#{lower_first(desc(s))} [#{x}, #{s['reversibility'].sub('_', '-')}]" if s && !s.empty?

        "\"#{x}\" [uncatalogued: treated as irreversible]"
      end
      return v.map { |x| one.call(js(x)) }.join('; or ') if v.is_a?(Array)

      one.call(js(v))
    end

    # new Date(Number(t)).toISOString(); a RangeError (ArgumentError) for an invalid date.
    def iso(t)
      if t.nil?
        t = 0
      elsif t.equal?(UNDEF)
        raise ArgumentError, 'Invalid time value'
      elsif t == true || t == false
        t = t ? 1 : 0
      elsif t.is_a?(String)
        s = t.strip
        raise ArgumentError, 'Invalid time value' if t.include?('_')

        t = s.empty? ? 0.0 : (NUM_RE.match?(s) ? s.to_f : raise(ArgumentError, 'Invalid time value'))
      elsif !t.is_a?(Numeric)
        raise ArgumentError, 'Invalid time value'
      end
      raise ArgumentError, 'Invalid time value' if (t.is_a?(Float) && (t.nan? || t.infinite?)) || t.abs > 8.64e15

      ms = t.to_i # TimeClip truncates toward zero
      days, rem = ms.divmod(86_400_000)
      z = days + 719_468
      era = z.div(146_097)
      doe = z - (era * 146_097)
      yoe = (doe - doe.div(1460) + doe.div(36_524) - doe.div(146_096)).div(365)
      y = yoe + (era * 400)
      doy = doe - ((365 * yoe) + yoe.div(4) - yoe.div(100))
      mp = ((5 * doy) + 2).div(153)
      d = doy - ((153 * mp) + 2).div(5) + 1
      m = mp < 10 ? mp + 3 : mp - 9
      y += 1 if m <= 2
      ys = y >= 0 && y <= 9999 ? format('%04d', y) : (y.positive? ? '+' : '-') + format('%06d', y.abs)
      h, rem = rem.divmod(3_600_000)
      mi, rem = rem.divmod(60_000)
      s, milli = rem.divmod(1000)
      format('%s-%02d-%02dT%02d:%02d:%02d.%03dZ', ys, m, d, h, mi, s, milli)
    end

    def render_caveat(c)
      h = c.is_a?(Hash)
      t = h && c.key?('type') ? c['type'] : UNDEF
      get = ->(k) { h && c.key?(k) ? c[k] : UNDEF }
      case t
      when 'expires' then "The grant expires at #{iso(get.call('at'))}."
      when 'not_before' then "The grant is not valid before #{iso(get.call('at'))}."
      when 'rate' then "At most #{js(get.call('max'))} actions in any #{js(get.call('per_secs'))} seconds."
      when 'max_blast_radius' then "No action whose blast radius exceeds #{js(get.call('max'))} (on a 0–1 scale)."
      when 'reversibility_max' then "Nothing more severe than \"#{js(get.call('class')).sub('_', '-')}\" (reversible < rate-limited < irreversible)."
      when 'delegation_depth' then "It may be re-delegated at most #{js(get.call('max'))} level(s) deep."
      when 'budget_alloc' then "A trust-budget allocation of #{js(get.call('limit'))} is carried for sub-delegation."
      else "An unrecognised constraint of type \"#{js(t)}\" (NOT UNDERSTOOD: do not rely on this grant until it is explained)."
      end
    end

    # Render a grant as numbered plain-language sentences. Deterministic: same grant, same text.
    def render_grant(policy, catalog = nil)
      n = IntentPolicy.normalize_policy(policy)
      preds = n['predicates']
      caveats = n['caveats']
      return 'This grant allows nothing.' if preds.empty?

      lines = ['The agent may do the following, and nothing else:']
      preds.each_with_index do |p, i|
        w = g(p, 'where')
        conds = arr(w).map { |x| render_condition(x) }
        lines << "#{i + 1}. #{render_verb(g(p, 'verb'), catalog)}, #{render_resource(g(p, 'resource'))}#{conds.empty? ? '' : ", only when #{conds.join(', and ')}"}."
      end
      unless caveats.empty?
        lines << 'Limits that apply to everything above:'
        caveats.each { |c| lines << "- #{render_caveat(c)}" }
      end
      lines.join("\n")
    end

    def render_dim_cell(d, i)
      l = label_of(d['path'])
      if d['kind'] == 'num'
        c = IntentOmega.num_cells(d)[i]
        return "#{l} exactly #{js(c['lo'])}" if c['lo'] == c['hi']

        return "any #{l} from #{js(c['lo'])} to #{js(c['hi'])} (e.g. #{js(i.positive? ? c['lo'] : c['hi'])})"
      end
      v = d['values'][i]
      return "#{l} \"#{v['value']}\"" if v['kind'] == 'exact'
      return "a #{l} under \"#{v['value']}\" (not otherwise named)" if v['kind'] == 'prefix'

      "a #{l} not named anywhere in the grant or your request"
    end

    def render_question(vs, cell, catalog = nil)
      s = cat_get(catalog, vs['verb'])
      what = s && !s.empty? ? "#{desc(s)} [#{vs['verb']}]" : "perform \"#{vs['verb']}\""
      parts = vs['dims'].each_with_index.map { |d, k| render_dim_cell(d, cell[k]) }
      "Should the agent be allowed to: #{what}#{parts.empty? ? '' : ", with #{parts.join(', ')}"}?"
    end

    # ---- back-translation diff -------------------------------------------------------------------------------------

    # The claim IR of a policy over the outcome space: verb by verb and dimension by dimension.
    def claims_of(policy, omega)
      a = IntentPolicy.admitter(policy)
      omega['verbs'].map do |vs|
        n = IntentOmega.verb_cell_count(vs)
        acc = []
        n.times do |c|
          idx = IntentOmega.decode_cell(vs, c)
          acc << idx if a.admits(vs, IntentOmega.cell_rep(vs, idx))
        end
        proj = vs['dims'].each_index.map { |k| acc.map { |x| x[k] }.uniq }
        box_count = proj.reduce(1) { |m, s| m * s.length }
        dims = vs['dims'].each_with_index.map do |d, k|
          s = proj[k]
          total = d['kind'] == 'num' ? IntentOmega.num_cells(d).length : d['values'].length
          ids = s.sort
          if d['kind'] == 'num'
            cells = IntentOmega.num_cells(d)
            dc = { 'path' => d['path'], 'any' => s.length == total }
            dc['range'] = [cells[ids[0]]['lo'], cells[ids[-1]]['hi']] unless ids.empty?
            dc
          else
            { 'path' => d['path'], 'any' => s.length == total,
              'values' => ids.map { |i| d['values'][i]['kind'] == 'prefix' ? "#{d['values'][i]['value']}*" : d['values'][i]['value'] } }
          end
        end
        { 'verb' => vs['verb'], 'allowed' => !acc.empty?, 'boxShaped' => acc.length == box_count, 'dims' => dims }
      end
    end

    def dim_text(c)
      return 'anything' if c.nil? || c.empty?
      return 'any value' if c['any']
      return "#{js(c['range'][0])} to #{js(c['range'][1])}" if c.key?('range')

      c['values'] && !c['values'].empty? ? c['values'].join(', ') : 'nothing'
    end

    def diff_claims(gs, ss, w)
      out = []
      gs.each_with_index do |gc, i|
        sc = ss[i]
        if gc['allowed'] && !sc['allowed']
          out << { 'verb' => gc['verb'], 'kind' => 'extra-verb', 'text' => w['extra'].call(gc['verb']) }
          next
        end
        if !gc['allowed'] && sc['allowed']
          out << { 'verb' => gc['verb'], 'kind' => 'missing-verb', 'text' => w['missing'].call(gc['verb']) }
          next
        end
        next unless gc['allowed']

        out << { 'verb' => gc['verb'], 'kind' => 'shape', 'text' => w['shape'].call(gc['verb']) } if (!gc['boxShaped'] || !sc['boxShaped']) && gc['boxShaped'] != sc['boxShaped']
        gc['dims'].each_with_index do |gd, k|
          sd = sc['dims'][k]
          next if gd == sd

          kind = 'different'
          if gd.key?('range') && sd.key?('range')
            gr = gd['range']
            sr = sd['range']
            kind = if gr[0] <= sr[0] && gr[1] >= sr[1] then 'looser'
                   elsif gr[0] >= sr[0] && gr[1] <= sr[1] then 'tighter'
                   else 'different'
                   end
          elsif gd.key?('values') && sd.key?('values')
            kind = if sd['values'].all? { |v| gd['values'].include?(v) } then 'looser'
                   elsif gd['values'].all? { |v| sd['values'].include?(v) } then 'tighter'
                   else 'different'
                   end
          elsif gd['any'] && !sd['any']
            kind = 'looser'
          end
          out << { 'verb' => gc['verb'], 'kind' => kind, 'path' => gd['path'], 'text' => w['dim'].call(gc['verb'], gd['path'], dim_text(gd), dim_text(sd)) }
        end
      end
      out
    end

    # Render the grant and the intent slots into the same claim IR and list every difference.
    def back_translation_diff(grant, slots, omega)
      diff_claims(claims_of(grant, omega), claims_of(IntentSlots.slots_to_policy(slots), omega), {
                    'extra' => ->(v) { "The grant allows #{v}, which your request did not mention." },
                    'missing' => ->(v) { "Your request mentions #{v}, but the grant does not allow it." },
                    'shape' => ->(v) { "The grant's rule for #{v} is a combination of cases that your request did not describe." },
                    'dim' => ->(v, path, a, b) { "For #{v}, the grant allows #{label_of(path)} #{a}; your request said #{b}." }
                  })
    end

    # The same claim diff between two grants (two readings); kind is from a's point of view.
    def claim_diff(a, b, omega, names = ['the first reading', 'the second reading'])
      n0, n1 = names
      diff_claims(claims_of(a, omega), claims_of(b, omega), {
                    'extra' => ->(v) { "#{n0} allows #{v}; #{n1} does not." },
                    'missing' => ->(v) { "#{n1} allows #{v}; #{n0} does not." },
                    'shape' => ->(v) { "#{n0} and #{n1} describe #{v} with differently shaped rules." },
                    'dim' => ->(v, path, x, y) { "For #{v}, #{n0} allows #{label_of(path)} #{x}; #{n1} allows #{y}." }
                  })
    end

    # A concrete action in plain language; values are printed verbatim so nothing is hidden.
    def render_action(vs, values, catalog = nil)
      s = cat_get(catalog, vs['verb'])
      rev = js(vs.key?('reversibility') ? vs['reversibility'] : UNDEF).sub('_', '-')
      what = s && !s.empty? ? "#{desc(s)} [#{vs['verb']}, #{rev}]" : "perform \"#{vs['verb']}\" [uncatalogued: treated as irreversible]"
      parts = values.keys.sort_by { |k| IntentOmega.u16key(k) }.map do |k|
        v = values[k]
        "#{label_of(k)} #{v.is_a?(String) ? "\"#{v}\"" : js(v)}"
      end
      "The agent wants to: #{what}#{parts.empty? ? '' : ", with #{parts.join(', ')}"}."
    end
  end
end
