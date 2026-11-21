# frozen_string_literal: true

require_relative 'intent_omega'

# Regions: the part of the outcome space a cell question was about, written in value terms so an observation keeps its meaning
# when the space is refined. Native port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentRegion
    module_function

    def region_of_cell(vs, idx)
      dims = {}
      vs['dims'].each_with_index do |d, k|
        if d['kind'] == 'num'
          c = IntentOmega.at(IntentOmega.num_cells(d), idx[k])
          dims[d['path']] = { 'kind' => 'num', 'lo' => c['lo'], 'hi' => c['hi'] }
        else
          dims[d['path']] = { 'kind' => 'cat', 'values' => d['values'].map(&:dup), 'cells' => [idx[k]] }
        end
      end
      { 'verb' => vs['verb'], 'dims' => dims }
    end

    def restrict_region(r, d, part)
      dims = r['dims'].dup
      if d['kind'] == 'num' && part.key?('lo')
        dims[d['path']] = { 'kind' => 'num', 'lo' => part['lo'], 'hi' => part['hi'] }
      elsif d['kind'] == 'cat' && part.key?('cells')
        dims[d['path']] = { 'kind' => 'cat', 'values' => d['values'].map(&:dup), 'cells' => part['cells'].dup }
      else
        raise ArgumentError, "restrictRegion: part does not match the kind of #{d['path']}"
      end
      { 'verb' => r['verb'], 'dims' => dims }
    end

    def ref_dim(path, rd) = { 'kind' => 'cat', 'path' => path, 'values' => rd['values'] }

    # The cells of dimension d covered by the region dimension: 'inner' (wholly inside) or 'outer' (meeting it).
    def dim_cells_in(d, rd, mode)
      n = d['kind'] == 'num' ? IntentOmega.num_cells(d).length : d['values'].length
      all = (0...n).to_a
      return all if rd.nil? || (rd.respond_to?(:empty?) && rd.empty?)

      if d['kind'] == 'num'
        raise ArgumentError, "region: #{d['path']} is numeric in Ω but categorical in the region" if rd['kind'] != 'num'

        cells = IntentOmega.num_cells(d)
        return all.select do |i|
          c = cells[i]
          mode == 'inner' ? (c['lo'] >= rd['lo'] && c['hi'] <= rd['hi']) : (c['hi'] >= rd['lo'] && c['lo'] <= rd['hi'])
        end
      end
      raise ArgumentError, "region: #{d['path']} is categorical in Ω but numeric in the region" if rd['kind'] != 'cat'

      ref = ref_dim(d['path'], rd)
      in_set = rd['cells']
      all.select { |i| in_set.include?(IntentOmega.cat_cell_of(ref, IntentOmega.cat_rep(d, i))) }
    end

    # Flat cell indices of vs covered by the region (row-major, last dimension fastest); refuses a restriction the space lacks.
    def region_cells(vs, r, mode)
      raise ArgumentError, "region: verb #{r['verb']} does not match #{vs['verb']}" if r['verb'] != vs['verb']

      r['dims'].each_key do |p|
        raise ArgumentError, "region: restricts #{p}, which Ω has no dimension for" unless vs['dims'].any? { |d| d['path'] == p }
      end
      per = vs['dims'].map { |d| dim_cells_in(d, r['dims'][d['path']], mode) }
      return [] if per.any?(&:empty?)

      sizes = vs['dims'].map { |d| d['kind'] == 'num' ? IntentOmega.num_cells(d).length : d['values'].length }
      acc = [0]
      per.each_with_index { |cells, k| acc = acc.flat_map { |f| cells.map { |c| (f * sizes[k]) + c } } }
      acc
    end

    def value_in_region_dim?(path, rd, x)
      return IntentOmega.number?(x) && x >= rd['lo'] && x <= rd['hi'] if rd['kind'] == 'num'

      x.is_a?(String) && rd['cells'].include?(IntentOmega.cat_cell_of(ref_dim(path, rd), x))
    end
    alias value_in_region_dim value_in_region_dim?
  end
end
