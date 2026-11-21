# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_policy'
require_relative 'intent_render'

# Specification by example for a fixed grant: boundary, verb and unconstrained witness actions to ask the principal about. Native
# port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentWitnesses
    module_function

    def boundary_witnesses(grant, omega, catalog = nil)
      o = IntentOmega
      g = IntentPolicy.admitter(grant)
      out = []
      seen = {}
      push = lambda do |vs, kind, idx, allows, facet|
        key = "#{vs['verb']}|#{idx.join(',')}"
        next if seen.key?(key)

        seen[key] = true
        out << { 'kind' => kind, 'side' => allows ? 'inside' : 'outside', 'verb' => vs['verb'], 'cell' => idx, 'outcome' => o.cell_rep(vs, idx),
                 'grantAllows' => allows, 'facet' => facet, 'question' => IntentRender.render_question(vs, idx, catalog) }
      end
      omega['verbs'].each do |vs|
        n = o.verb_cell_count(vs)
        acc = Array.new(n, 0)
        mass = Array.new(n, 0.0)
        typical = -1
        typical_out = -1
        n.times do |c|
          idx = o.decode_cell(vs, c)
          acc[c] = g.admits(vs, o.cell_rep(vs, idx)) ? 1 : 0
          mass[c] = o.cell_stats(vs, idx)['mass']
          typical = c if acc[c] != 0 && (typical.negative? || mass[c] > mass[typical])
          typical_out = c if typical_out.negative? || mass[c] > mass[typical_out]
        end
        if typical.negative?
          push.call(vs, 'verb', o.decode_cell(vs, typical_out), false, "#{vs['verb']}|verb")
          next
        end
        base = o.decode_cell(vs, typical)
        push.call(vs, 'verb', base, true, "#{vs['verb']}|verb")
        best = {}
        n.times do |c|
          next if acc[c].zero?

          idx = o.decode_cell(vs, c)
          vs['dims'].each_with_index do |d, k|
            nk = o.cell_count(d)
            neigh = if d['kind'] == 'num'
                      [idx[k] - 1, idx[k] + 1].select { |x| x >= 0 && x < nk }
                    else
                      (0...nk).reject { |x| x == idx[k] }
                    end
            neigh.each do |x|
              j = idx.dup
              j[k] = x
              next if acc[o.encode_cell(vs, j)] != 0

              facet = if d['kind'] == 'num'
                        "#{vs['verb']}|#{d['path']}|#{[x, idx[k]].min}~#{[x, idx[k]].max}"
                      else
                        "#{vs['verb']}|#{d['path']}|#{x}"
                      end
              shared = idx.each_with_index.count { |v, t| t != k && v == base[t] }
              score = (shared * 10) + mass[c]
              prev = best[facet]
              best[facet] = { 'ins' => idx, 'outs' => j, 'score' => score } if prev.nil? || score > prev['score']
            end
          end
        end
        best.keys.sort_by { |s| o.u16key(s) }.each do |facet|
          b = best[facet]
          push.call(vs, 'boundary', b['ins'], true, facet)
          push.call(vs, 'boundary', b['outs'], false, facet)
        end
        vs['dims'].each_with_index do |d, k|
          nk = o.cell_count(d)
          next if nk < 2

          depends = false
          c = 0
          while c < n && !depends
            idx = o.decode_cell(vs, c)
            x = 0
            while x < nk && !depends
              j = idx.dup
              j[k] = x
              depends = true if acc[o.encode_cell(vs, j)] != acc[c]
              x += 1
            end
            c += 1
          end
          next if depends

          j = base.dup
          j[k] = d['kind'] == 'num' ? nk - 1 : (d['values'].index { |v| v['kind'] == 'other' } || -1)
          push.call(vs, 'unconstrained', j, true, "#{vs['verb']}|#{d['path']}|unconstrained")
        end
      end
      out
    end

    # Ask an oracle (the principal) about each witness; a mismatch is a place where grant and intent disagree.
    def check_witnesses(witnesses, oracle)
      { 'questions' => witnesses.length, 'mismatches' => witnesses.select { |w| oracle.call(w) != w['grantAllows'] } }
    end
  end
end
