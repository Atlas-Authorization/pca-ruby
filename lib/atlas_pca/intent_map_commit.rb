# frozen_string_literal: true

require_relative 'intent_map'
require_relative 'intent_v2'

# The wallet side of the committed (Merkle, per-leaf salted) form of an Intent Map: maps an Intent Map onto the leaf layout of
# IntentMap.commit_map. Native port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentMapCommit
    module_function

    def num_cell_count(lo, hi, cuts)
      n = 0
      cur = lo
      cuts.each do |c|
        next if c < lo || c > hi

        n += 1 if cur <= c - 1
        n += 1
        cur = c + 1
      end
      cur <= hi ? n + 1 : n
    end

    # Commit an Intent Map; `secret` (32 random bytes kept per session) derives every leaf salt.
    def commit_intent_map(m, secret)
      headers = m['omega']['verbs'].map do |v|
        dims = v['dims'].map do |d|
          if d['kind'] == 'num'
            { 'kind' => 'num', 'path' => d['path'], 'lo' => d['lo'], 'hi' => d['hi'], 'cuts' => (d['cuts'] || []).select { |c| d['lo'] <= c && c <= d['hi'] } }
          else
            { 'kind' => 'cat', 'path' => d['path'], 'values' => (d['values'] || []).map { |x| { 'kind' => x['kind'], 'value' => x['value'] } } }
          end
        end
        { 'verb' => v['verb'], 'dims' => dims }
      end
      cells = {}
      m['omega']['verbs'].each do |v|
        counts = v['dims'].map { |d| d['kind'] == 'num' ? num_cell_count(d['lo'], d['hi'], d['cuts'] || []) : (d['values'] || []).length }
        total = counts.reduce(1) { |a, c| a * c }
        slots = Array.new(total)
        m['cells'].each do |c|
          next if c['verb'] != v['verb']
          raise ArgumentError, "commitIntentMap: cell of #{v['verb']} has the wrong arity" if c['cell'].length != counts.length

          flat = 0
          c['cell'].each_with_index do |i, j|
            raise ArgumentError, "commitIntentMap: cell index out of range for #{v['verb']}" unless i.is_a?(Integer) && i >= 0 && i < counts[j]

            flat = (flat * counts[j]) + i
          end
          slots[flat] = { 'cell' => c['cell'].dup, 'p_ppm' => c['p_ppm'], 'in_grant' => c['in_grant'] }
        end
        raise ArgumentError, "commitIntentMap: the map does not list every cell of #{v['verb']}" if slots.any?(&:nil?) || slots.length != total

        cells[v['verb']] = slots
      end
      metrics = m['metrics'].reject { |k, _| k == 'log2_vs_mbits' }
      metrics['log2_vs_mbits'] = m['metrics']['log2_vs_mbits'] unless m['metrics']['log2_vs_mbits'].nil?
      IntentMap.commit_map(headers, cells, metrics, AtlasPca.hash_canonical(m['learner']), secret)
    end
  end
end
